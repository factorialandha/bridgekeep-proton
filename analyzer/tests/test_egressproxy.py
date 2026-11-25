import socket
import socketserver
import threading
import time

import pytest

from analyzer import egressproxy
from analyzer.classify import AnthropicClassifier, ClassifyError
from analyzer.egressproxy import EgressConfig


@pytest.fixture
def echo():
    """An upstream that echoes bytes back and counts connections."""
    seen = []

    class Handler(socketserver.BaseRequestHandler):
        def handle(self):
            seen.append(1)
            while True:
                data = self.request.recv(65536)
                if not data:
                    return
                self.request.sendall(data)

    srv = socketserver.ThreadingTCPServer(("127.0.0.1", 0), Handler)
    srv.daemon_threads = True
    threading.Thread(target=srv.serve_forever, daemon=True).start()
    yield srv.server_address[1], seen
    srv.shutdown()
    srv.server_close()


def start(cfg):
    srv = egressproxy.make_server(cfg)
    threading.Thread(target=srv.serve_forever, daemon=True).start()
    return srv


@pytest.fixture
def proxy_for():
    servers = []

    def _make(**kw):
        cfg = EgressConfig(listen_host="127.0.0.1", listen_port=0, **kw)
        srv = start(cfg)
        servers.append(srv)
        return srv.server_address[1]

    yield _make
    for s in servers:
        s.shutdown()
        s.server_close()


def ask(port, request: bytes) -> tuple[bytes, socket.socket]:
    s = socket.create_connection(("127.0.0.1", port), timeout=5)
    s.sendall(request)
    head = b""
    while b"\r\n\r\n" not in head:
        chunk = s.recv(1)
        if not chunk:
            break
        head += chunk
    return head, s


def test_allowed_host_is_tunnelled(echo, proxy_for):
    up, seen = echo
    port = proxy_for(allow=(f"127.0.0.1:{up}",), allow_private=True)
    head, s = ask(port, f"CONNECT 127.0.0.1:{up} HTTP/1.1\r\nHost: x\r\n\r\n".encode())
    assert head.startswith(b"HTTP/1.1 200")
    s.sendall(b"ping")
    assert s.recv(4) == b"ping"
    s.close()
    assert seen == [1]


@pytest.mark.parametrize("request_line", [
    "CONNECT 127.0.0.1:{other} HTTP/1.1",     # right host, other port
    "CONNECT evil.example:443 HTTP/1.1",       # other host
    "CONNECT api.anthropic.com.evil.example:443 HTTP/1.1",
])
def test_other_destinations_are_refused(echo, proxy_for, request_line):
    up, seen = echo
    port = proxy_for(allow=(f"127.0.0.1:{up}", "api.anthropic.com:443"), allow_private=True)
    head, s = ask(port, (request_line.format(other=up + 1) + "\r\n\r\n").encode())
    assert head.startswith(b"HTTP/1.1 403")
    s.close()
    assert seen == []


def test_only_connect(echo, proxy_for):
    up, seen = echo
    port = proxy_for(allow=(f"127.0.0.1:{up}",), allow_private=True)
    head, s = ask(port, f"GET http://127.0.0.1:{up}/ HTTP/1.1\r\nHost: x\r\n\r\n".encode())
    assert head.startswith(b"HTTP/1.1 405")
    s.close()
    assert seen == []


def test_data_before_the_tunnel_is_refused(echo, proxy_for):
    up, seen = echo
    port = proxy_for(allow=(f"127.0.0.1:{up}",), allow_private=True)
    head, s = ask(port, f"CONNECT 127.0.0.1:{up} HTTP/1.1\r\n\r\nsmuggled".encode())
    assert head.startswith(b"HTTP/1.1 400")
    s.close()
    assert seen == []


def test_private_addresses_are_refused_even_if_listed(echo, proxy_for):
    up, seen = echo
    port = proxy_for(allow=(f"localhost:{up}", f"127.0.0.1:{up}"))
    for host in ("localhost", "127.0.0.1"):
        head, s = ask(port, f"CONNECT {host}:{up} HTTP/1.1\r\n\r\n".encode())
        assert head.startswith(b"HTTP/1.1 403")
        s.close()
    assert seen == []


def test_byte_limit_closes_the_tunnel(echo, proxy_for):
    """The limit counts both directions together."""
    up, _ = echo
    port = proxy_for(allow=(f"127.0.0.1:{up}",), allow_private=True, max_bytes=1000)
    head, s = ask(port, f"CONNECT 127.0.0.1:{up} HTTP/1.1\r\n\r\n".encode())
    assert head.startswith(b"HTTP/1.1 200")
    s.settimeout(5)
    s.sendall(b"x" * 400)                 # 800 of 1000 once echoed
    got = b""
    while len(got) < 400:
        got += s.recv(1000)
    s.sendall(b"y" * 400)                 # passes the limit
    while True:
        chunk = s.recv(1000)
        if not chunk:
            break
        got += chunk
    assert len(got) < 800                 # closed before the second echo came back
    s.close()


def test_config_section(tmp_path):
    p = tmp_path / "a.yaml"
    p.write_text("egress_proxy:\n  allow: [api.anthropic.com:443]\n  listen_port: 3129\n")
    cfg = egressproxy.load_config(str(p))
    assert cfg.allow == ("api.anthropic.com:443",) and cfg.listen_port == 3129
    p.write_text("egress_proxy:\n  allow: ['*']\n")
    with pytest.raises(SystemExit):
        egressproxy.load_config(str(p))


@pytest.mark.parametrize("model,allow", [
    ("", ("api.anthropic.com:443",)),
    ("model: {provider: openai, name: some-model}", ("api.openai.com:443",)),
    ("model: {provider: gemini, name: some-model}", ("generativelanguage.googleapis.com:443",)),
    ("model: {provider: local, name: llama, endpoint: 'http://192.168.1.50:11434/v1'}", ("192.168.1.50:11434",)),
])
def test_allowlist_follows_the_provider(tmp_path, model, allow):
    p = tmp_path / "a.yaml"
    p.write_text(model + "\n")
    cfg = egressproxy.load_config(str(p))
    assert cfg.allow == allow
    assert cfg.local_ip == ("192.168.1.50" if "local" in model else "")


@pytest.mark.parametrize("body", [
    "model: {provider: openai}\negress_proxy: {allow: [api.anthropic.com:443]}",   # hand-set list disagrees
    "model: {provider: local, endpoint: 'http://127.0.0.1:11434/v1'}",
    "model: {provider: local, endpoint: 'http://172.31.253.2:1143/v1'}",
    "model: {provider: local, endpoint: 'http://8.8.8.8:80/v1'}",
    "model: {provider: someone-else}",
])
def test_bad_provider_settings_refuse_to_start(tmp_path, body):
    p = tmp_path / "a.yaml"
    p.write_text(body + "\n")
    with pytest.raises(SystemExit):
        egressproxy.load_config(str(p))


def test_classifier_goes_through_the_proxy(echo, proxy_for):
    """The SDK client uses the configured proxy, not a direct connection."""
    up, seen = echo
    port = proxy_for(allow=(f"127.0.0.1:{up}",), allow_private=True)
    c = AnthropicClassifier("sk-test", base_url=f"https://127.0.0.1:{up}", timeout=30,
                            proxy=f"http://127.0.0.1:{port}")
    with pytest.raises(ClassifyError):
        c.classify({"subject": "x"})   # the echo server is not TLS, so the call fails
    for _ in range(100):                # under emulation the echo thread can lag
        if seen:
            break
        time.sleep(0.05)
    assert seen                         # but it arrived through the tunnel
