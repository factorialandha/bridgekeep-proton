"""Corrections from the portal: incremental, hardened reads; domain hints; never-quarantine rule."""

import json
import os

from analyzer import feedback
from conftest import FakeClassifier, make_eml


def _line(key, label="legitimate", scope="message", ts=1764000000):
    return json.dumps({"message_key": key, "label": label, "scope": scope, "ts": ts, "by": "portal"}) + "\n"


def _setup(make_analyzer, tmp_path, fc):
    portal = tmp_path / "portal"
    portal.mkdir()
    return make_analyzer(fc, portal_dir=str(portal)), portal


def test_reads_only_new_complete_lines(make_analyzer, tmp_path):
    an, portal = _setup(make_analyzer, tmp_path, FakeClassifier())
    f = portal / "feedback.jsonl"
    f.write_text(_line("k1") + _line("k2", "spam") + '{"message_key": "k3", "lab')   # last line half written
    assert an.feedback.step() == 2
    assert an.feedback.step() == 0                  # nothing new
    with f.open("a") as fh:
        fh.write('el": "spam", "ts": 1}\n')
    assert an.feedback.step() == 1 and an.feedback.bad_lines == 0   # the finished line, read once
    labels = {r["message_key"]: r["label"] for r in an.store.feedback_rows()}
    assert labels == {"k1": "legitimate", "k2": "spam", "k3": "spam"}


def test_bad_lines_are_skipped(make_analyzer, tmp_path):
    an, portal = _setup(make_analyzer, tmp_path, FakeClassifier())
    (portal / "feedback.jsonl").write_text(
        "not json\n" + _line("k", "trash") + _line("k", scope="everything") + _line("x" * 300)
        + json.dumps({"message_key": "k", "label": "spam", "ts": True}) + "\n"
        + '{"message_key": "' + "a" * 2000 + '", "label": "spam", "ts": 1}\n' + _line("ok"))
    assert an.feedback.step() == 1 and an.feedback.bad_lines == 6


def test_symlink_is_refused(make_analyzer, tmp_path):
    an, portal = _setup(make_analyzer, tmp_path, FakeClassifier())
    target = tmp_path / "elsewhere"
    target.write_text(_line("k1"))
    os.symlink(target, portal / "feedback.jsonl")
    assert an.feedback.step() == 0 and not an.store.feedback_rows()


def test_rotation_finishes_the_old_file(make_analyzer, tmp_path):
    an, portal = _setup(make_analyzer, tmp_path, FakeClassifier())
    f = portal / "feedback.jsonl"
    f.write_text(_line("k1"))
    assert an.feedback.step() == 1
    with f.open("a") as fh:
        fh.write(_line("k2"))
    os.rename(f, portal / "feedback.jsonl.1")       # the portal rotates at 1 MB
    f.write_text(_line("k3"))
    assert an.feedback.step() == 2                  # k2 from the old file, k3 from the new
    assert {r["message_key"] for r in an.store.feedback_rows()} == {"k1", "k2", "k3"}


def test_verified_domain_with_two_not_spam_answers_is_never_quarantined(make_analyzer, tmp_path):
    fc = FakeClassifier("spam", 0.99)
    an, portal = _setup(make_analyzer, tmp_path, fc)
    amazon = "Amazon <shipment-tracking@amazon.com>"
    assert an.analyze(make_eml(frm=amazon), "INBOX:7:1").record.action == "quarantine"
    an.analyze(make_eml(frm=amazon), "INBOX:7:2")
    (portal / "feedback.jsonl").write_text(_line("INBOX:7:1"))
    an.refresh()
    r = an.analyze(make_eml(frm=amazon), "INBOX:7:3").record
    assert r.action == "quarantine"                 # one answer: a hint, not yet a rule
    assert "as not spam once and as spam never" in fc.contexts[-1][0]
    with (portal / "feedback.jsonl").open("a") as fh:
        fh.write(_line("INBOX:7:2"))
    an.refresh()
    r = an.analyze(make_eml(frm=amazon), "INBOX:7:4").record
    assert r.action == "review" and r.rule == "feedback_trusted"


def test_spam_answer_cancels_the_trust_and_unverified_mail_gets_nothing(make_analyzer, tmp_path):
    fc = FakeClassifier("spam", 0.99)
    an, portal = _setup(make_analyzer, tmp_path, fc)
    frm = "Shop <news@shop.example>"
    for i in (1, 2, 3):
        an.analyze(make_eml(frm=frm), f"k{i}")
    (portal / "feedback.jsonl").write_text(_line("k1") + _line("k2") + _line("k3", "spam"))
    an.refresh()
    assert an.analyze(make_eml(frm=frm), "k4").record.action == "quarantine"
    # A spoofed copy (DMARC not passing) gets no hint and no protection.
    (portal / "feedback.jsonl").write_text("")
    an.store.db.execute("DELETE FROM feedback WHERE label='spam'")
    r = an.analyze(make_eml(frm=frm, auth=""), "k5").record
    assert fc.contexts[-1] is None and r.rule != "feedback_trusted"


def test_agreement_stats(make_analyzer, tmp_path):
    fc = FakeClassifier("spam", 0.99)
    an, portal = _setup(make_analyzer, tmp_path, fc)
    an.analyze(make_eml(), "a")
    an.analyze(make_eml(), "b")
    (portal / "feedback.jsonl").write_text(_line("a") + _line("b", "spam") + _line("never-seen"))
    an.refresh()
    stats = feedback.agreement(an.store)
    assert stats == {"corrections": 3, "with_model_answer": 2, "model_agreed": 1,
                     "said_spam_was_fine": 1, "missed_spam": 0}


def test_free_mail_and_shared_senders_are_keyed_by_address(make_analyzer, tmp_path):
    """Anyone can get a verified gmail.com address: two answers for a@gmail.com
    say nothing about b@gmail.com."""
    fc = FakeClassifier("spam", 0.99)
    an, portal = _setup(make_analyzer, tmp_path, fc)
    a, b = "A <a@gmail.com>", "B <b@gmail.com>"
    an.analyze(make_eml(frm=a), "k1")
    an.analyze(make_eml(frm=a), "k2")
    (portal / "feedback.jsonl").write_text(_line("k1") + _line("k2"))
    an.refresh()
    rb = an.analyze(make_eml(frm=b), "k3").record
    assert rb.action == "quarantine" and fc.contexts[-1] is None
    ra = an.analyze(make_eml(frm=a), "k4").record
    assert ra.action == "review" and ra.rule == "feedback_trusted"
    assert "a@gmail.com" in fc.contexts[-1][0] and "a@gmail.com" in ra.explain
    # Shared sending services and their subdomains count as shared too.
    from analyzer.lists import shared_domain
    assert shared_domain("em123.sendgrid.net") and shared_domain("contoso.onmicrosoft.com")
    assert not shared_domain("amazon.com")


def test_withdrawn_clears_the_answer(make_analyzer, tmp_path):
    an, portal = _setup(make_analyzer, tmp_path, FakeClassifier())
    f = portal / "feedback.jsonl"
    f.write_text(_line("k1") + _line("k2", "spam"))
    an.feedback.step()
    with f.open("a") as fh:
        fh.write(_line("k1", "withdrawn") + _line("never-seen", "withdrawn"))
    assert an.feedback.step() == 2 and an.feedback.bad_lines == 0
    assert [r["message_key"] for r in an.store.feedback_rows()] == ["k2"]
    with f.open("a") as fh:                          # answering again after clearing counts again
        fh.write(_line("k1", "spam"))
    an.feedback.step()
    assert {r["message_key"]: r["label"] for r in an.store.feedback_rows()} == {"k1": "spam", "k2": "spam"}
