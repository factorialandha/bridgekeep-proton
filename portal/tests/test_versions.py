"""Version numbers on every page and on Status, so an update can be checked."""
from pathlib import Path

from portal import __version__
from conftest import Client

ROOT = Path(__file__).resolve().parents[2]


def host_env(portal, text):
    (portal.tmp / "status").mkdir(exist_ok=True)
    (portal.tmp / "status" / "host.env").write_text(text)


def test_portal_version_matches_the_checkout():
    assert (ROOT / "VERSION").read_text().strip() == __version__


def test_versions_on_every_page_and_status(claimed):
    portal, c = claimed
    host_env(portal, f"docker_version=28.1.0\nbridgekeep_version={__version__}\nbridgekeep_commit=1a2b3c4d5e\n"
                     "bridge_version=3.21.2\nts=9999999999\n")
    for path in ("/", "/lists", "/analyzer", "/settings"):
        body = c.get(path).body
        assert f"Bridgekeep {__version__} (1a2b3c4) · Portal {__version__} · Bridge 3.21.2" in body, path
    assert "Update ready" not in c.get("/").body


def test_a_stale_portal_is_flagged_and_junk_is_dropped(claimed):
    portal, c = claimed
    host_env(portal, "bridgekeep_version=9.9.9\nbridgekeep_commit=<script>\nbridge_version=3.21.2;rm\n")
    body = c.get("/").body
    assert "Bridgekeep 9.9.9 · Portal" in body and "Update ready" in body
    assert "<script>" not in body and "rm" not in body.split("Versions")[1][:300]


def test_no_versions_before_sign_in(portal):
    host_env(portal, f"bridgekeep_version={__version__}\nbridge_version=3.21.2\n")
    body = Client(portal.port).get("/claim").body
    assert "3.21.2" not in body and "Bridgekeep " + __version__ not in body


def test_update_ready_follows_the_built_tree_not_the_version(claimed):
    portal, c = claimed
    a, b = "a" * 40, "b" * 40
    host_env(portal, f"bridgekeep_version={__version__}\nportal_built={a}\nportal_checkout={b}\n"
                     f"analyzer_built={a}\nanalyzer_checkout={a}\n")
    body = c.get("/").body
    assert "Update ready" in body and "(the portal)" in body
    host_env(portal, f"bridgekeep_version=9.9.9\nportal_built={a}\nportal_checkout={a}\n"
                     f"analyzer_built=none\nanalyzer_checkout={b}\n")
    assert "Update ready" not in c.get("/").body      # trees known and equal: the version number doesn't decide


def test_footer_before_the_first_report(claimed):
    portal, c = claimed
    assert "Bridgekeep (version shows within 5 minutes)" in c.get("/lists").body
