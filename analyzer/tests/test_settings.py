"""Portal settings (settings.yaml): whitelisted keys, range checks, last good kept."""

import os

from analyzer.pipeline import Analyzer
from analyzer.store import Store
from conftest import FakeClassifier, make_eml


def _write(portal, text):
    p = portal / "settings.yaml"
    tmp = portal / "settings.yaml.tmp"
    tmp.write_text(text, encoding="utf-8")
    os.replace(tmp, p)          # what the portal does: a new inode every write


def _an(make_analyzer, tmp_path, classifier=None):
    portal = tmp_path / "portal"
    portal.mkdir(exist_ok=True)
    return make_analyzer(classifier, portal_dir=str(portal)), portal


def test_no_file_means_analyzer_yaml_values(make_analyzer, tmp_path):
    an, _ = _an(make_analyzer, tmp_path)
    assert an.cfg.monthly_budget_usd == 20.0 and an.settings.problems == []


def test_portal_settings_apply_within_one_reload(make_analyzer, tmp_path):
    an, portal = _an(make_analyzer, tmp_path)
    _write(portal, "model:\n  monthly_budget_usd: 5\n  enabled: true\nthresholds:\n  quarantine: 0.99\n"
                   "  review: 0.8\nlimits:\n  max_per_hour: 30\n  max_per_day: 200\nimap:\n  poll_seconds: 120\n")
    assert an.settings.maybe_reload()
    c = an.cfg
    assert (c.monthly_budget_usd, c.quarantine_threshold, c.review_threshold,
            c.max_per_hour, c.max_per_day, c.poll_seconds) == (5.0, 0.99, 0.8, 30, 200, 120)
    assert an.settings.problems == []
    assert not an.settings.maybe_reload()           # unchanged file is not re-read
    os.remove(portal / "settings.yaml")
    assert an.settings.maybe_reload() and an.cfg.monthly_budget_usd == 20.0


def test_bad_values_keep_the_previous_value_and_are_reported(make_analyzer, tmp_path):
    an, portal = _an(make_analyzer, tmp_path, FakeClassifier())
    _write(portal, "model:\n  monthly_budget_usd: 7\n")
    an.settings.maybe_reload()
    _write(portal, "model:\n  monthly_budget_usd: 5000\n  enabled: 'yes'\nthresholds:\n  review: 0.99\n"
                   "limits:\n  max_per_hour: 1.5\nlists_dir: /etc\nmode: live\n")
    an.settings.maybe_reload()
    assert an.cfg.monthly_budget_usd == 7.0            # last good, not the default
    assert an.cfg.model_enabled is True and an.cfg.max_per_hour == 120
    assert an.cfg.review_threshold == 0.70 and an.cfg.quarantine_threshold == 0.97
    assert an.cfg.lists_dir != "/etc" and an.cfg.mode == "shadow"   # not settings at all
    text = " | ".join(an.settings.problems)
    for want in ("model.monthly_budget_usd: must be between 0 and 1000", "model.enabled: must be true or false",
                 "limits.max_per_hour: must be a whole number", "thresholds.review: must be at most",
                 "lists_dir: not a setting", "mode: not a setting"):
        assert want in text
    assert an.model_status()["settings_problems"] == an.settings.problems


def test_unreadable_file_keeps_last_good(make_analyzer, tmp_path):
    an, portal = _an(make_analyzer, tmp_path)
    _write(portal, "limits:\n  max_per_day: 50\n")
    an.settings.maybe_reload()
    _write(portal, "limits: [unclosed\n")
    an.settings.maybe_reload()
    assert an.cfg.max_per_day == 50 and "keeping the settings from before" in an.settings.problems[0]
    os.remove(portal / "settings.yaml")
    os.symlink("/etc/passwd", portal / "settings.yaml")
    an.settings.maybe_reload()
    assert an.cfg.max_per_day == 50 and "not a regular file" in an.settings.problems[0]


def test_switching_the_model_off_and_on_from_the_portal(make_analyzer, tmp_path):
    fc = FakeClassifier("spam", 0.99)
    an, portal = _an(make_analyzer, tmp_path, fc)
    _write(portal, "model:\n  enabled: false\n")
    an.settings.maybe_reload()
    assert an.model_status()["model"] == "off"
    assert an.analyze(make_eml(), "k1").record.rule == "no_model" and not fc.calls
    _write(portal, "model:\n  enabled: true\n")
    an.settings.maybe_reload()
    an.analyze(make_eml(), "k2")
    assert len(fc.calls) == 1


def test_enabling_without_a_key_stays_off(tmp_path):
    from analyzer.config import Config
    portal = tmp_path / "portal"
    portal.mkdir()
    _write(portal, "model:\n  enabled: true\n")
    an = Analyzer(Config(lists_dir=str(tmp_path), portal_dir=str(portal), model_enabled=False),
                  Store(":memory:"), None)
    an.key_missing = True
    assert an.cfg.model_enabled and an.model_status()["model"] == "no_key"
    assert "no API key" in an.model_status()["settings_problems"][0]
    assert an.analyze(make_eml(), "k").record.rule == "no_model"
