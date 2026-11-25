"""Old server-rendered pages hand over to the React frontend at /app once it is built."""
import pytest

from portal import app as app_module


@pytest.fixture
def built(monkeypatch):
    monkeypatch.setattr(app_module, "web_built", lambda: True)


@pytest.mark.parametrize("old,new", sorted(app_module.SPA_PAGES.items()))
def test_signed_in_old_pages_go_to_app(claimed, built, old, new):
    _, c = claimed
    r = c.get(old)
    assert r.status == 303 and r.getheader("Location") == new


def test_query_is_kept(claimed, built):
    _, c = claimed
    r = c.get("/lists?add=protect&value=billing@bank.example")
    assert r.status == 303
    assert r.getheader("Location") == "/app/lists?add=protect&value=billing%40bank.example"


def test_log_entry_keeps_its_id(claimed, built):
    _, c = claimed
    r = c.get("/log/entry?id=812")
    assert r.status == 303 and r.getheader("Location") == "/app/log/entry?id=812"


def test_signed_out_still_goes_to_sign_in(claimed, built):
    portal, _ = claimed
    from conftest import Client
    fresh = Client(portal.port)
    r = fresh.get("/")
    assert r.status == 303 and r.getheader("Location") == "/login"
    r = fresh.get("/review")
    assert r.status in (303, 401) and r.getheader("Location") != "/app/review"


def test_sign_in_pages_stay(claimed, built):
    _, c = claimed
    r = c.get("/claim")       # signed in already: the claim page doesn't hand over to /app
    assert r.getheader("Location") is None or not r.getheader("Location").startswith("/app")


def test_unbuilt_install_keeps_old_pages(claimed):
    _, c = claimed
    r = c.get("/review")
    assert r.status == 200
