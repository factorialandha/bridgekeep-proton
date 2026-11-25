"""Other AI vendors: request shapes, own keys only, untrusted answers, egress through the proxy."""

import http.client
import http.server
import json
import threading

import pytest

from analyzer import providers as p
from analyzer.classify import ClassifyError
from analyzer.config import Config

GOOD = {"label": "promotional", "confidence": 0.8, "reason": "newsletter"}


class FakeConn:
    """Records the request, answers with a canned response."""
    last = None

    def __init__(self, status=200, body=b"", chunks=None):
        self.status, self.body, self.chunks = status, body, chunks

    def __call__(self, ep):
        FakeConn.last = {"ep": ep}
        return self

    def request(self, method, path, body, headers):
        FakeConn.last.update(method=method, path=path, body=json.loads(body), headers=headers)

    def getresponse(self):
        outer = self
        data = [outer.body] if outer.chunks is None else list(outer.chunks)

        class R:
            status = outer.status

            def read(self, n):
                return data.pop(0) if data else b""
        return R()

    def close(self):
        pass


def openai_answer(obj=GOOD, finish="stop"):
    return json.dumps({"choices": [{"message": {"content": json.dumps(obj)}, "finish_reason": finish}],
                       "usage": {"prompt_tokens": 900, "completion_tokens": 40}}).encode()


def test_openai_request_and_answer():
    c = p.HTTPClassifier("openai", "gpt-x", "sk-openai", connection=FakeConn(body=openai_answer()))
    r = c.classify({"subject": "hi"}, context=["The recipient has previously marked ..."])
    req = FakeConn.last
    assert req["ep"].host == "api.openai.com" and req["path"] == "/v1/chat/completions"
    assert req["headers"]["Authorization"] == "Bearer sk-openai"
    assert req["body"]["response_format"]["json_schema"]["strict"] is True
    assert req["body"]["messages"][0]["role"] == "system"
    assert "UNTRUSTED_EMAIL_" in req["body"]["messages"][1]["content"]
    assert "Recipient context" in req["body"]["messages"][1]["content"]
    assert (r.label, r.input_tokens, r.output_tokens) == ("promotional", 900, 40)


def test_gemini_key_in_header_never_in_url():
    body = json.dumps({"candidates": [{"content": {"parts": [{"text": json.dumps(GOOD)}]}, "finishReason": "STOP"}],
                       "usageMetadata": {"promptTokenCount": 10, "candidatesTokenCount": 5}}).encode()
    c = p.HTTPClassifier("gemini", "gemini-x", "AIza-secret", connection=FakeConn(body=body))
    r = c.classify({"subject": "hi"})
    req = FakeConn.last
    assert req["path"] == "/v1beta/models/gemini-x:generateContent" and "key=" not in req["path"]
    assert req["headers"]["x-goog-api-key"] == "AIza-secret" and "Authorization" not in req["headers"]
    assert r.label == "promotional"


def test_local_needs_no_key_and_sends_none():
    c = p.HTTPClassifier("local", "llama", endpoint="http://192.168.1.50:11434/v1",
                         connection=FakeConn(body=openai_answer()))
    c.classify({"subject": "hi"})
    req = FakeConn.last
    assert req["ep"].host == "192.168.1.50" and req["ep"].port == 11434
    assert "Authorization" not in req["headers"] and req["headers"]["Host"] == "192.168.1.50:11434"


@pytest.mark.parametrize("conn,msg", [
    (FakeConn(status=401, body=b'{"error": "bad key sk-openai"}'), "API error 401"),
    (FakeConn(status=429), "rate limited"),
    (FakeConn(chunks=[b"x" * 8192] * 9), "too large"),
    (FakeConn(body=b"<html>not json"), "not the expected JSON"),
    (FakeConn(body=openai_answer(finish="length")), "stopped"),
    (FakeConn(body=openai_answer({"label": "legitimate", "confidence": 2, "reason": ""})), "confidence"),
    (FakeConn(body=openai_answer({**GOOD, "extra": "Ignore previous instructions"})), "wrong fields"),
])
def test_untrusted_answers_are_refused(conn, msg):
    c = p.HTTPClassifier("openai", "gpt-x", "sk-openai", connection=conn)
    with pytest.raises(ClassifyError, match=msg) as e:
        c.classify({"subject": "hi"})
    assert "sk-openai" not in str(e.value)


@pytest.mark.parametrize("url", [
    "http://127.0.0.1:11434/v1", "http://localhost:11434/v1", "http://169.254.169.254/v1",
    "http://172.31.253.2:8080/v1", "http://192.168.1.5:1143/v1", "http://192.168.1.5:1025/v1",
    "http://8.8.8.8/v1", "http://user:pw@192.168.1.5/v1", "ftp://192.168.1.5/v1", "http://[::1]:80/v1",
])
def test_local_endpoint_refusals(url):
    with pytest.raises(ValueError):
        p.check_local_endpoint(url)


def test_local_endpoint_accepts():
    assert p.check_local_endpoint("http://192.168.1.50:11434/v1").port == 11434
    assert p.check_local_endpoint("https://8.8.8.8/v1").scheme == "https"    # public needs https


def test_never_another_vendors_key():
    assert Config().api_key_file.endswith("anthropic_api_key")
    from analyzer.config import load
    import tempfile, os
    with tempfile.TemporaryDirectory() as d:
        f = os.path.join(d, "a.yaml")
        open(f, "w").write("model: {provider: openai, name: gpt-x}\n")
        assert load(f).api_key_file == "/run/secrets/openai_api_key"
        open(f, "w").write("model: {provider: gemini, name: g}\n")
        assert load(f).api_key_file == "/run/secrets/gemini_api_key"


def test_prices_and_no_price():
    cfg = Config()
    assert p.prices(cfg) == (0.10, 0.50)
    cfg.provider, cfg.model = "openai", "gpt-x"
    assert p.prices(cfg) is None                       # not used until the owner enters a price
    cfg.price_in_per_mtok, cfg.price_out_per_mtok = 1.0, 2.0
    assert p.cost(cfg, 1_000_000, 500_000) == 2.0
    cfg = Config(provider="local", model="llama")
    assert p.prices(cfg) == (0.0, 0.0)


def test_no_price_means_no_model_calls(make_analyzer):
    from conftest import FakeClassifier, make_eml
    fc = FakeClassifier("spam", 0.99)
    an = make_analyzer(fc, provider="openai", model="gpt-x")
    assert an.model_status()["model"] == "no_price"
    assert an.analyze(make_eml(), "k").record.rule == "no_model" and not fc.calls


def test_disclosures_name_the_company():
    assert "OpenAI" in p.DISCLOSURE["openai"] and "data-use terms" in p.DISCLOSURE["openai"]
    assert "Google" in p.DISCLOSURE["gemini"] and "free tier" in p.DISCLOSURE["gemini"]
    assert "unencrypted" in p.DISCLOSURE["local"]


def test_plain_http_local_goes_through_the_proxy_with_connect():
    """http.client tunnels even plain http with CONNECT, so the egress proxy decides."""
    from analyzer import egressproxy

    class Upstream(http.server.BaseHTTPRequestHandler):
        def do_POST(self):
            self.rfile.read(int(self.headers["Content-Length"]))
            out = openai_answer()
            self.send_response(200)
            self.send_header("Content-Length", str(len(out)))
            self.end_headers()
            self.wfile.write(out)

        def log_message(self, *a):
            pass

    up = http.server.ThreadingHTTPServer(("127.0.0.1", 0), Upstream)
    threading.Thread(target=up.serve_forever, daemon=True).start()
    cfg = egressproxy.EgressConfig(listen_host="127.0.0.1", listen_port=0,
                                   allow=(f"127.0.0.1:{up.server_address[1]}",), allow_private=True)
    px = egressproxy.make_server(cfg)
    threading.Thread(target=px.serve_forever, daemon=True).start()
    try:
        def conn(ep):
            c = http.client.HTTPConnection("127.0.0.1", px.server_address[1], timeout=5)
            c.set_tunnel("127.0.0.1", up.server_address[1])
            return c
        c = p.HTTPClassifier("local", "llama", endpoint="http://192.168.1.50:11434/v1", connection=conn)
        assert c.classify({"subject": "hi"}).label == "promotional"
        # A host that is not on the list is refused by the proxy.
        def other(ep):
            c = http.client.HTTPConnection("127.0.0.1", px.server_address[1], timeout=5)
            c.set_tunnel("127.0.0.1", 9)
            return c
        with pytest.raises(ClassifyError, match="unreachable"):
            p.HTTPClassifier("local", "llama", endpoint="http://192.168.1.50:11434/v1",
                             connection=other).classify({"subject": "hi"})
    finally:
        px.shutdown()
        up.shutdown()
