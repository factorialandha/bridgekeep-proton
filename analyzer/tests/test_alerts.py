import os

from analyzer import alerts
from conftest import FakeClassifier, make_eml


def test_alert_file_format(tmp_path):
    assert alerts.send("budget_cap", "monthly budget 20 USD reached\nsecond line \x1b[31m", str(tmp_path))
    files = os.listdir(tmp_path)
    assert len(files) == 1 and files[0].endswith(".alert")
    body = (tmp_path / files[0]).read_text()
    assert body == "event=budget_cap\ndetail=monthly budget 20 USD reached second line [31m\n"
    assert len(body.encode()) <= alerts.MAX_FILE


def test_missing_folder_is_not_fatal(tmp_path):
    assert not alerts.send("login_expired", "x", str(tmp_path / "missing"))


def test_unknown_event_is_a_bug():
    import pytest
    with pytest.raises(ValueError):
        alerts.send("anything", "x", "/tmp")


def test_budget_cap_alerts_once_per_month(make_analyzer, tmp_path):
    an = make_analyzer(FakeClassifier("spam", 0.99), monthly_budget_usd=0.0)
    out = tmp_path / "alerts"
    out.mkdir()
    an.cfg.alert_dir = str(out)
    for i in range(3):
        assert an.analyze(make_eml(), f"k{i}").record.rule == "budget_cap"
    files = os.listdir(out)
    assert len(files) == 1
    assert "event=budget_cap" in (out / files[0]).read_text()
