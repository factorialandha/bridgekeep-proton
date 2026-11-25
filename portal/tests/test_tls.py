"""Network mode: HTTPS with the portal's own certificate (security review P9)."""

import datetime as dt
import http.client
import socket
import ssl
import threading
from urllib.parse import urlencode

import pytest
from cryptography import x509

from portal import auth, tls
from portal.app import Context, build, make_env
from portal.db import DB
from portal.settings import Settings
from portal.web import serve

HOSTS = ("nas.local", "192.168.1.20")


def test_certificate_is_made_once_and_kept(tmp_path):
    cert, key, fp, made = tls.ensure(str(tmp_path), HOSTS)
    assert made and len(fp.split(":")) == 32
    assert (tmp_path / "tls" / "key.pem").stat().st_mode & 0o077 == 0
    c = x509.load_pem_x509_certificate(open(cert, "rb").read())
    san = c.extensions.get_extension_for_class(x509.SubjectAlternativeName).value
    assert "nas.local" in san.get_values_for_type(x509.DNSName)
    assert c.not_valid_after_utc - c.not_valid_before_utc <= dt.timedelta(days=826)
    # Same names: same certificate, same fingerprint.
    assert tls.ensure(str(tmp_path), HOSTS)[2:] == (fp, False)
    # New names: a new certificate.
    _, _, fp2, made2 = tls.ensure(str(tmp_path), HOSTS + ("bridgekeep.lan",))
    assert made2 and fp2 != fp


@pytest.fixture
def https_portal(tmp_path):
    s = Settings(data_dir=str(tmp_path / "data"), analyzer_data=str(tmp_path / "an"), listen_host="127.0.0.1",
                 listen_port=0, lan=True, address="192.168.1.20", extra_hosts=HOSTS, idle_timeout=3600)
    (tmp_path / "an").mkdir()
    cert, key, s.fingerprint, _ = tls.ensure(s.data_dir, HOSTS)
    ctx = Context(s, DB(s.db_path), make_env())
    server = serve(build(ctx), "127.0.0.1", 0, tls.server_context(cert, key))
    s.public_port = server.server_address[1]
    threading.Thread(target=server.serve_forever, daemon=True).start()
    client_ctx = ssl.create_default_context(cafile=cert)
    client_ctx.check_hostname = False   # we connect to 127.0.0.1 and send Host: nas.local
    ctx.client_ctx = client_ctx
    yield ctx
    server.shutdown()
    server.server_close()


def _req(p, method, path, body=None, headers=None):
    c = http.client.HTTPSConnection("127.0.0.1", p.settings.public_port, timeout=10, context=p.client_ctx)
    h = {"Host": f"nas.local:{p.settings.public_port}"}
    h.update(headers or {})
    c.request(method, path, body=body, headers=h)
    r = c.getresponse()
    r.body = r.read().decode()
    return r


def test_https_headers_cookie_and_origin(https_portal):
    p = https_portal
    r = _req(p, "GET", "/claim")
    assert r.status == 200
    assert "max-age" in r.getheader("Strict-Transport-Security")
    cookie = r.getheader("Set-Cookie")
    assert cookie.startswith("__Host-bk_session=") and "Secure" in cookie and "HttpOnly" in cookie
    # A form posted from the https origin is accepted; the http origin is not.
    code = auth.new_claim_code(p.db, 3600)
    import re
    csrf = re.search(r'name="csrf" value="([^"]+)"', r.body).group(1)
    jar = cookie.split(";")[0]
    form = urlencode({"code": code, "csrf": csrf})
    base = {"Cookie": jar, "Content-Type": "application/x-www-form-urlencoded"}
    bad = _req(p, "POST", "/claim", form, {**base, "Origin": f"http://nas.local:{p.settings.public_port}"})
    assert bad.status == 403
    ok = _req(p, "POST", "/claim", form, {**base, "Origin": f"https://nas.local:{p.settings.public_port}"})
    assert ok.status == 303, ok.body


def test_foreign_host_refused_over_https(https_portal):
    assert _req(https_portal, "GET", "/claim", headers={"Host": "evil.example"}).status == 421


def test_certificate_download(https_portal):
    r = _req(https_portal, "GET", "/portal.crt")
    assert r.status == 200 and "BEGIN CERTIFICATE" in r.body


def test_plain_http_and_stalled_handshake_dont_block(https_portal):
    port = https_portal.settings.public_port
    # A client that connects and says nothing must not hold up anyone else.
    idle = socket.create_connection(("127.0.0.1", port))
    plain = socket.create_connection(("127.0.0.1", port))
    plain.sendall(b"GET / HTTP/1.1\r\nHost: nas.local\r\n\r\n")
    try:
        assert _req(https_portal, "GET", "/healthz").status == 200
    finally:
        idle.close()
        plain.close()


def test_fingerprint_shown_in_four_lines_of_eight():
    from portal.app import fingerprint_lines
    fp = ":".join(f"{i:02X}" for i in range(32))
    lines = fingerprint_lines(fp)
    assert len(lines) == 4 and all(len(line.split()) == 8 for line in lines)
    assert fingerprint_lines("") == []
