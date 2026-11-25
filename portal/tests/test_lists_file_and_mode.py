"""Removing entries from the host's list file, clearing the shipped examples,
and the shadow / live switch (mode.json)."""
import json
import os
import shutil
import subprocess
import sys
from pathlib import Path

import yaml

ROOT = Path(__file__).resolve().parents[2]
CURATED = ("protect:\n  - address: me@bank.example\n    reason: Bank\n"
           "  - domain: sendgrid.net\n    reason: Old\n"
           "block:\n  - address: offers@spam.example\n    reason: Junk\n")


def curated(portal, text=CURATED):
    (portal.tmp / "lists").mkdir(exist_ok=True)
    (portal.tmp / "lists" / "curated.yaml").write_text(text)


def audit(portal):
    return [tuple(a) for a in portal.db.all("SELECT action, target FROM audit")]


def test_file_entries_can_be_removed_and_restored(claimed):
    portal, c = claimed
    curated(portal)
    body = c.get("/lists").body
    assert 'aria-label="Remove me@bank.example from Never trash"' in body
    assert 'aria-label="Remove offers@spam.example from Always trash"' in body
    # Asks first, saying the file itself is left alone.
    r = c.post("/lists/remove", {"list": "block", "value": "offers@spam.example", "source": "file"})
    assert r.status == 200 and 'name="source" value="file"' in r.body
    assert c.post("/lists/remove", {"list": "block", "value": "offers@spam.example", "source": "file",
                                    "confirm": "yes"}).status == 303
    assert (portal.tmp / "lists" / "curated.yaml").read_text() == CURATED     # the file is never written
    data = yaml.safe_load((portal.tmp / "pc" / "portal.yaml").read_text())
    assert data["removed"] == [{"list": "block", "value": "offers@spam.example"}]
    body = c.get("/lists").body
    assert 'aria-label="Remove offers@spam.example' not in body and ">Removed (1)<" in body
    assert 'aria-label="Restore offers@spam.example to Always trash"' in body and "config/lists/curated.yaml" not in body
    assert ("list: removed (from file)", "block: offers@spam.example") in audit(portal)
    # Something not in the file can't be "removed" into the list.
    c.get("/lists")
    assert c.post("/lists/remove", {"list": "block", "value": "nobody@x.example", "source": "file",
                                    "confirm": "yes"}).status == 409
    assert c.post("/lists/remove", {"list": "nope", "value": "x", "source": "file", "confirm": "yes"}).status == 303
    # Restore.
    c.get("/lists")
    assert c.post("/lists/restore", {"list": "block", "value": "offers@spam.example"}).status == 303
    assert (yaml.safe_load((portal.tmp / "pc" / "portal.yaml").read_text()) or {}).get("removed", []) == []
    assert 'aria-label="Remove offers@spam.example from Always trash"' in c.get("/lists").body
    assert ("list: restored (from file)", "block: offers@spam.example") in audit(portal)


def test_restore_needs_step_up(claimed):
    portal, c = claimed
    curated(portal)
    c.post("/lists/remove", {"list": "block", "value": "offers@spam.example", "source": "file", "confirm": "yes"})
    portal.db.execute("UPDATE sessions SET reauth_at = 0")
    c.get("/lists")
    assert c.post("/lists/restore", {"list": "block", "value": "offers@spam.example"}).status == 401
    assert c.post("/lists/remove", {"list": "protect", "value": "me@bank.example", "source": "file",
                                    "confirm": "yes"}).status == 401


def test_refused_file_entry_can_be_removed(claimed):
    portal, c = claimed
    curated(portal)
    body = c.get("/lists").body
    assert "sendgrid.net" in body and "curated.yaml</code> on the host" not in body
    assert c.post("/lists/remove", {"list": "protect", "value": "sendgrid.net", "source": "file",
                                    "confirm": "yes"}).status == 303
    assert "sendgrid.net" not in c.get("/lists").body.split(">Removed (")[0]


def test_the_analyzer_drops_removed_file_entries(tmp_path):
    lists_dir, portal_dir = tmp_path / "lists", tmp_path / "portal"
    lists_dir.mkdir()
    portal_dir.mkdir()
    (lists_dir / "curated.yaml").write_text(CURATED)
    (portal_dir / "portal.yaml").write_text(
        "block:\n  - address: offers@spam.example\n    reason: mine\n    added: '2026-11-01'\n"
        "removed:\n  - {list: block, value: offers@spam.example}\n  - {list: protect, value: me@bank.example}\n")
    for src in (ROOT / "analyzer" / "src", ROOT / "portal" / "src"):
        sys.path.insert(0, str(src))
        try:
            mod = "analyzer.lists" if "analyzer" in src.parts[-2] else "portal._analyzer.lists"
            L = __import__(mod, fromlist=["load"])
            got = L.load(lists_dir, portal_dir=portal_dir)
            protect = [e.value for e in got.protect if e.kind == "address"]
            block = [(e.value, e.origin) for e in got.block]
            assert "me@bank.example" not in protect
            # Only the file's copy goes: the portal's own entry of the same address stays.
            assert len(block) == 1 and block[0][0] == "offers@spam.example" and "portal" in str(block[0][1])
            assert got.removed == {("block", "offers@spam.example"), ("protect", "me@bank.example")}
        finally:
            sys.path.remove(str(src))
            for k in [k for k in sys.modules if k == "analyzer" or k.startswith("analyzer.")]:
                del sys.modules[k]
    assert (ROOT / "analyzer/src/analyzer/lists.py").read_text() == \
        (ROOT / "portal/src/portal/_analyzer/lists.py").read_text()


def test_setup_clears_the_shipped_examples_only(tmp_path):
    shutil.copytree(ROOT / "analyzer" / "examples" / "lists", tmp_path / "analyzer" / "examples" / "lists")
    (tmp_path / "config" / "lists").mkdir(parents=True)
    src = (ROOT / "bridgekeep").read_text()
    fns = src[src.index("lists_content() {"):src.index("s7_analyzer() {")]
    script = f'ok() {{ echo "ok: $*"; }}\n{fns}\nclear_example_lists\n'
    f = tmp_path / "config" / "lists" / "curated.yaml"
    examples = (tmp_path / "analyzer" / "examples" / "lists" / "curated.yaml").read_text()
    f.write_text("# my comment\n" + examples)
    out = subprocess.run(["bash", "-c", script], cwd=tmp_path, capture_output=True, text=True)
    assert "Removed the example entries" in out.stdout
    assert f.read_text() == (tmp_path / "analyzer" / "examples" / "lists" / "empty.yaml").read_text()
    assert "@" not in f.read_text()
    f.write_text(examples + "  - address: mine@real.example\n    reason: Mine\n")
    before = f.read_text()
    subprocess.run(["bash", "-c", script], cwd=tmp_path, check=True, capture_output=True)
    assert f.read_text() == before                          # edited: left alone
    init = (ROOT / "scripts" / "analyzer-init.sh").read_text()
    assert "examples/lists/curated.yaml" not in init and "empty.yaml" in init


def health(portal, **kw):
    data = {"status": "ok", "ts": 9999999999, "mode": "shadow"}
    data.update(kw)
    (portal.tmp / "analyzer" / "health.json").write_text(json.dumps(data))


def mode_file(portal):
    p = portal.tmp / "pc" / "mode.json"
    return json.loads(p.read_text()) if p.exists() else None


def test_live_is_shown_as_not_available_until_the_analyzer_supports_it(claimed):
    portal, c = claimed
    health(portal)
    body = c.get("/analyzer").body
    assert 'id="mode"' in body and "Shadow" in body and "Live isn&#39;t available yet" not in body
    assert "Live isn't available yet" in body
    live_button = body.split('action="/analyzer/live"')[1].split("</form>")[0]
    assert "disabled" in live_button
    r = c.post("/analyzer/live", {"confirm": "yes"})
    assert r.status == 409 and "isn't available yet" in r.body and mode_file(portal) is None


def test_going_live_asks_with_shadow_numbers_and_needs_step_up(claimed):
    portal, c = claimed
    health(portal, mode_requested="shadow", move_cap=200, would_review=12, would_quarantine=30,
           shadow_since=1764000000, agreement={"corrections": 20, "model_agreed": 18, "said_spam_was_fine": 1,
                                               "missed_spam": 1})
    body = c.get("/analyzer").body
    assert "disabled" not in body.split('action="/analyzer/live"')[1].split("</form>")[0]
    r = c.post("/analyzer/live", {})
    assert r.status == 200 and mode_file(portal) is None
    assert "Only new mail moves, into AI-Review and AI-Quarantine in Proton. Nothing is deleted." in r.body
    assert "At most 200 moves a day" in r.body and "12 to AI-Review, 30 to AI-Quarantine" in r.body
    assert "Of 20 answers, the analyzer agreed with 18" in r.body
    assert c.post("/analyzer/live", {"confirm": "yes"}).status == 303
    m = mode_file(portal)
    assert m["mode"] == "live" and m["by"] == "portal" and isinstance(m["ts"], int)
    assert ("analyzer: live mode", None) in audit(portal) or any(a[0] == "analyzer: live mode" for a in audit(portal))
    assert "starts at the analyzer&#39;s next check" in c.get("/analyzer").body or \
        "starts at the analyzer's next check" in c.get("/analyzer").body
    # Back to shadow: no step-up.
    portal.db.execute("UPDATE sessions SET reauth_at = 0")
    c.get("/analyzer")
    assert c.post("/analyzer/live", {"confirm": "yes"}).status == 401
    assert c.post("/analyzer/mode", {"mode": "shadow"}).status == 303 and mode_file(portal)["mode"] == "shadow"
    assert any(a[0] == "analyzer: shadow mode" for a in audit(portal))


def test_live_status_and_problem_are_shown(claimed):
    portal, c = claimed
    health(portal, mode="live", mode_requested="live", moved_today=7, move_cap=200, moved_back_today=1)
    body = c.get("/analyzer").body
    assert "Moved today: 7 of at most 200, 1 moved back." in body
    health(portal, mode="shadow", mode_requested="live", mode_problem="paused <b>")
    body = c.get("/analyzer").body
    assert "Live mode isn't running: paused &lt;b&gt;" in body and "next check" not in body


def test_mode_file_is_written_whole_and_odd_files_mean_shadow(claimed):
    portal, c = claimed
    from portal.portal_config import PortalConfig
    cfg = PortalConfig(str(portal.tmp / "pc"))
    p = portal.tmp / "pc" / "mode.json"
    for junk in ('{"mode": "LIVE"}', "live", '["live"]', '{"mode": "live", "pad": "' + "a" * 2000 + '"}'):
        p.write_text(junk)
        assert cfg.mode_requested() == "shadow", junk
    p.unlink()
    target = portal.tmp / "elsewhere.json"
    target.write_text('{"mode": "live"}')
    p.symlink_to(target)
    assert cfg.mode_requested() == "shadow"
    cfg.set_mode("shadow")
    assert not p.is_symlink() and target.read_text() == '{"mode": "live"}'
    assert oct(os.stat(p).st_mode & 0o777) == "0o640"
