"""Lists page: portal.yaml written for the analyzer, validated like the analyzer does."""
import os
from pathlib import Path

import pytest
import yaml

from portal import auth
from portal._analyzer import lists as L
from portal.portal_config import ConfigError, PortalConfig

ROOT = Path(__file__).resolve().parents[2]


def test_vendored_validator_matches_the_analyzer():
    for name in ("lists.py", "text.py"):
        ours = ROOT / "portal" / "src" / "portal" / "_analyzer" / name
        theirs = ROOT / "analyzer" / "src" / "analyzer" / name
        if not theirs.exists():
            pytest.skip("analyzer source not next to the portal")
        assert ours.read_bytes() == theirs.read_bytes(), f"{name} drifted: copy analyzer/src/analyzer/{name}"


def test_add_remove_and_the_analyzer_reads_it(tmp_path):
    cfg = PortalConfig(str(tmp_path))
    assert cfg.add("protect", "domain", "Amazon.com", "Orders", subdomains=True) == "amazon.com"
    cfg.add("block", "address", "Offers@Spam.example", "Junk")
    cfg.add("keywords", "pattern", "Verification code", "Codes")
    assert oct(os.stat(tmp_path / "portal.yaml").st_mode & 0o777) == "0o640"
    got = L.load(tmp_path / "nolists", portal_dir=tmp_path)      # the analyzer's own loader
    assert not got.problems
    assert [(e.value, e.subdomains, e.source) for e in got.protect] == [("amazon.com", True, "portal")]
    assert got.block[0].value == "offers@spam.example" and got.keywords[0].value == "verification code"
    with pytest.raises(ConfigError, match="already"):
        cfg.add("protect", "domain", "amazon.com", "again")
    with pytest.raises(ConfigError, match="free-mail"):
        cfg.add("protect", "domain", "gmail.com", "nope")
    with pytest.raises(ConfigError, match="reason"):
        cfg.add("protect", "address", "a@b.example", "  ")
    with pytest.raises(ConfigError, match="changed"):
        cfg.remove("protect", 0, "other.example")
    cfg.remove("protect", 0, "amazon.com")
    assert L.load(tmp_path / "nolists", portal_dir=tmp_path).protect == []
    assert not list(tmp_path.glob(".*.tmp"))


def test_a_planted_symlink_is_replaced_not_followed(tmp_path):
    target = tmp_path / "target"
    target.write_text("secret")
    d = tmp_path / "cfg"
    d.mkdir()
    (d / "portal.yaml").symlink_to(target)
    cfg = PortalConfig(str(d))
    with pytest.raises(ConfigError):     # the analyzer's reader refuses links too
        cfg.portal_data()
    (d / "PAUSE").symlink_to(target)
    cfg.set_paused(False)
    assert target.read_text() == "secret" and not os.path.lexists(d / "PAUSE")


def test_lists_page_add_remove_with_step_up_and_audit(claimed):
    portal, c = claimed
    (portal.tmp / "lists").mkdir()
    (portal.tmp / "lists" / "curated.yaml").write_text("protect:\n  - address: me@bank.example\n    reason: Bank\n")
    body = c.get("/lists").body
    assert "me@bank.example" in body and "Came with setup" in body
    r = c.post("/lists/add", {"target": "protect:domain", "value": "amazon.com", "reason": "Orders",
                              "subdomains": "on", "back": "/lists"})
    assert r.status == 303, r.body
    body = c.get("/lists").body
    assert "*.amazon.com" in body and "Remove" in body
    assert ("list: added domain", "protect: amazon.com") in [tuple(a) for a in portal.db.all(
        "SELECT action, target FROM audit")]
    r = c.post("/lists/add", {"list": "protect", "kind": "domain", "value": "gmail.com", "reason": "x"})
    assert r.status == 400 and "free-mail" in r.body
    r = c.post("/lists/add", {"target": "block:domain", "value": "spam.example", "reason": "x"})
    assert r.status == 400 and "exact addresses only" in r.body
    r = c.post("/lists/add", {"target": "protect:pattern", "value": "invoice", "reason": "x"})
    assert r.status == 400 and "Protected subject words list" in r.body
    assert 'aria-label="Remove amazon.com from Never trash"' in c.get("/lists").body
    # Remove asks first, then removes.
    r = c.post("/lists/remove", {"list": "protect", "index": "0", "value": "amazon.com"})
    assert r.status == 200 and "Remove amazon.com?" in r.body
    assert "amazon.com" in (portal.tmp / "pc" / "portal.yaml").read_text()
    assert c.post("/lists/remove", {"list": "protect", "index": "0", "value": "amazon.com",
                                    "confirm": "yes"}).status == 303
    assert "*.amazon.com" not in c.get("/lists").body
    # Without a recent password confirmation, a change asks for it first.
    portal.db.execute("UPDATE sessions SET reauth_at = 0")
    r = c.post("/lists/add", {"list": "block", "kind": "address", "value": "x@y.example", "reason": "junk"})
    assert r.status == 401 and "Confirm it" in r.body
    assert "x@y.example" not in (portal.tmp / "pc" / "portal.yaml").read_text()


def test_pause_is_free_but_resume_needs_step_up(claimed):
    portal, c = claimed
    (portal.tmp / "analyzer" / "health.json").write_text('{"status": "ok", "ts": 9999999999, "mode": "shadow"}')
    c.get("/")
    assert c.post("/analyzer/pause").status == 303
    assert (portal.tmp / "pc" / "PAUSE").exists() and "! Paused" in c.get("/").body
    portal.db.execute("UPDATE sessions SET reauth_at = 0")
    assert c.post("/analyzer/resume").status == 401
    assert (portal.tmp / "pc" / "PAUSE").exists()
    actions = [a[0] for a in portal.db.all("SELECT action FROM audit")]
    assert "analyzer paused" in actions


def test_concurrent_adds_lose_nothing_and_stale_temp_files_are_cleared(tmp_path):
    import threading
    (tmp_path / ".portal.yaml.123.tmp").write_text("left by a crash")
    cfg = PortalConfig(str(tmp_path))
    assert not (tmp_path / ".portal.yaml.123.tmp").exists()
    threads = [threading.Thread(target=cfg.add, args=("protect", "domain", f"d{i}.example", "test"))
               for i in range(20)]
    for t in threads:
        t.start()
    for t in threads:
        t.join()
    assert len(cfg.portal_data()["protect"]) == 20


def test_analyzer_settings_page_saves_validates_and_audits(claimed):
    portal, c = claimed
    body = c.get("/analyzer").body
    assert "<title>Analyzer" in body and body.count('id="api-key"') == 1
    import re
    title = re.search(r"<title>(.*?)</title>", body, re.S).group(1)
    assert "<" not in title and "API key" not in title, title
    assert 'value="97"' in body and 'value="120"' in body and "97.0" not in body
    form = {"model_enabled": "on", "model_monthly_budget_usd": "35", "thresholds_quarantine": "95",
            "thresholds_review": "60", "limits_max_per_hour": "50", "limits_max_per_day": "400",
            "limits_max_moves_per_day": "50", "imap_poll_seconds": "120"}
    assert c.post("/analyzer/settings", form).status == 303
    data = yaml.safe_load((portal.tmp / "pc" / "settings.yaml").read_text())
    assert data == {"model": {"enabled": True, "monthly_budget_usd": 35.0},
                    "thresholds": {"quarantine": 0.95, "review": 0.6},
                    "limits": {"max_per_hour": 50, "max_per_day": 400, "max_moves_per_day": 50},
                    "imap": {"poll_seconds": 120}}
    audit = [tuple(a) for a in portal.db.all("SELECT action, target FROM audit")]
    assert ("analyzer settings changed", "model.monthly_budget_usd, thresholds.quarantine, thresholds.review, "
            "limits.max_per_hour, limits.max_per_day, limits.max_moves_per_day, imap.poll_seconds") in audit
    # Review above trash, out of range, model off.
    c.get("/analyzer")
    r = c.post("/analyzer/settings", {**form, "thresholds_review": "99"})
    assert r.status == 400 and "Review has to be lower than Trash" in r.body and 'value="99"' in r.body
    assert c.post("/analyzer/settings", {**form, "imap_poll_seconds": "5"}).status == 400
    c.get("/analyzer")
    c.post("/analyzer/settings", {k: v for k, v in form.items() if k != "model_enabled"})
    assert yaml.safe_load((portal.tmp / "pc" / "settings.yaml").read_text())["model"]["enabled"] is False
    # The analyzer's report of a setting it ignored is shown.
    (portal.tmp / "analyzer" / "health.json").write_text(
        '{"status": "ok", "ts": 9999999999, "settings_problems": ["imap.poll_seconds: too low"]}')
    assert "imap.poll_seconds: too low" in c.get("/analyzer").body
    portal.db.execute("UPDATE sessions SET reauth_at = 0")
    assert c.post("/analyzer/settings", form).status == 401


def test_refused_entries_are_shown_with_a_fix_and_remove(claimed):
    portal, c = claimed
    (portal.tmp / "lists").mkdir(exist_ok=True)
    (portal.tmp / "lists" / "curated.yaml").write_text("protect:\n  - domain: sendgrid.net\n    reason: Old\n")
    (portal.tmp / "pc" / "portal.yaml").write_text(
        "protect:\n  - domain: amazonses.com\n    reason: Orders\n    added: '2026-11-01'\n"
        "block:\n  - domain: spam.example\n    reason: junk\n    added: '2026-11-01'\n")
    body = c.get("/lists").body
    assert "ignoring 3 entries" in body
    assert 'href="/lists?add=protect:address&amp;hint=amazonses.com#add"' in body
    assert 'href="/lists?add=protect:address&amp;hint=sendgrid.net#add"' in body
    assert ".." not in body.split("ignoring")[1].split("</ul>")[0].replace("...", "")
    assert 'aria-label="Remove amazonses.com from Never trash"' in body
    assert 'aria-label="Remove spam.example from Always trash"' in body
    assert "curated.yaml</code> on the host" not in body and 'aria-label="Remove sendgrid.net from Never trash"' in body
    b = c.get("/lists?add=protect:address&hint=amazonses.com").body
    assert 'class="ladd" id="add"' in b and 'placeholder="someone@amazonses.com"' in b
    assert 'placeholder="Address or domain"' in c.get("/lists?add=protect:address&hint=%3Cscript%3E").body
    # A refused portal entry can still be removed.
    c.get("/lists")
    assert c.post("/lists/remove", {"list": "protect", "index": "0", "value": "amazonses.com",
                                    "confirm": "yes"}).status == 303
    assert "amazonses.com" not in (portal.tmp / "pc" / "portal.yaml").read_text()


def test_refused_hand_edited_entries_can_still_be_removed(claimed):
    portal, c = claimed
    long = "x" * 300
    (portal.tmp / "pc" / "portal.yaml").write_text(
        "block:\n  - domain: ' Spam.Example '\n    reason: junk\n"
        "protect:\n  - address: ' A@B.com'\n    reason: old\n    expires: '2020-01-01'\n"
        f"  - domain: '{long}'\n    reason: not a domain\n")
    body = c.get("/lists").body
    assert 'aria-label="Remove spam.example from Always trash"' in body
    assert 'aria-label="Remove a@b.com from Never trash"' in body
    for lst, idx, val in (("block", "0", "spam.example"), ("protect", "0", "a@b.com"), ("protect", "0", long[:254])):
        c.get("/lists")
        r = c.post("/lists/remove", {"list": lst, "index": idx, "value": val, "confirm": "yes"})
        assert r.status == 303, (val, r.status)
    assert "protect" not in (portal.tmp / "pc" / "portal.yaml").read_text()
    assert "block" not in (portal.tmp / "pc" / "portal.yaml").read_text()


def test_each_list_has_its_own_add_box(claimed):
    portal, c = claimed
    body = c.get("/lists").body
    for name in ("protect", "block", "keywords"):
        assert f'id="list-{name}"' in body and f'id="v-{name}"' in body
    assert "Add one" not in body and "curated.yaml" not in body
    # One field is enough: "@" means an address, otherwise a domain; the reason is optional.
    r = c.post("/lists/add", {"list": "protect", "kind": "auto", "value": "anna@friends.example"})
    assert r.status == 303 and r.headers["Location"].endswith("#list-protect")
    c.get("/lists")
    assert c.post("/lists/add", {"list": "protect", "kind": "auto", "value": "school.example"}).status == 303
    c.get("/lists")
    assert c.post("/lists/add", {"list": "keywords", "kind": "auto", "value": "password reset"}).status == 303
    data = yaml.safe_load((portal.tmp / "pc" / "portal.yaml").read_text())
    assert {"address": "anna@friends.example", "reason": "Added in the portal"}.items() <= data["protect"][0].items()
    assert data["protect"][1]["domain"] == "school.example"
    # Always trash stays exact addresses only, and the error shows in that list's panel.
    c.get("/lists")
    r = c.post("/lists/add", {"list": "block", "kind": "auto", "value": "spam.example"})
    assert r.status == 400
    panel = r.body.split('id="list-block"')[1].split("</section>")[0]
    assert "exact addresses only" in panel and 'value="spam.example"' in panel
