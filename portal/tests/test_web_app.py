"""The React frontend's shell: who may load it, and the headers it gets."""
from portal import web


def test_app_needs_sign_in_and_gets_its_own_csp(portal, claimed):
    p, c = claimed
    dist = web.resources.files("portal").joinpath("web_dist")
    r = c.get("/app/review")
    if not dist.joinpath("index.html").is_file():
        assert r.status == 404      # not built in this checkout
        return
    assert r.status == 200 and '<div id="root">' in r.body
    csp = r.headers["Content-Security-Policy"]
    assert "script-src 'self';" in csp and "style-src-attr 'unsafe-inline'" in csp
    assert "unsafe-eval" not in csp and "script-src 'self' 'unsafe" not in csp
    assert r.headers["Cache-Control"] == "no-store"
    assert "<script>" not in r.body          # no inline script in the build


def test_app_redirects_when_signed_out(portal):
    from conftest import Client
    c = Client(portal.settings.public_port)
    r = c.get("/app/")
    assert r.status in (303, 302) and r.headers["Location"] in ("/login", "/claim")


def test_web_assets_only_by_exact_hashed_name(portal):
    from conftest import Client
    c = Client(portal.settings.public_port)
    for bad in ("/app/assets/../app.py", "/app/assets/x.py", "/app/assets/.hidden.js"):
        assert c.get(bad).status == 404
