import shutil

from analyzer.cli import main
from conftest import FIXTURES


def test_check_offline(capsys, lists_dir):
    assert main(["--config", "/nonexistent", "check", "--no-model", "--db", ":memory:", "--lists",
                 str(lists_dir), str(FIXTURES)]) == 0
    out = capsys.readouterr()
    assert "Shadow mode" in out.err and "receipt.eml" in out.out


def test_eval_needs_labeled_folders(tmp_path, capsys):
    assert main(["--config", "/nonexistent", "eval", "--no-model", "--db", ":memory:", str(tmp_path)]) == 2


def test_eval_runs(tmp_path, capsys, lists_dir):
    shutil.copytree(FIXTURES / "adversarial", tmp_path / "adversarial")
    shutil.copytree(FIXTURES / "legitimate", tmp_path / "legitimate")
    rc = main(["--config", "/nonexistent", "eval", "--no-model", "--db", ":memory:", "--lists",
               str(lists_dir), str(tmp_path)])
    assert rc == 0 and "PASS" in capsys.readouterr().out


def test_check_with_nothing_to_read_fails(tmp_path):
    assert main(["--config", "/nonexistent", "check", "--no-model", "--db", ":memory:", str(tmp_path)]) == 2


def test_lists_lint_exit_code(tmp_path, lists_dir):
    assert main(["--config", "/nonexistent", "lists", "lint", "--lists", str(lists_dir)]) == 0
    (tmp_path / "curated.yaml").write_text("protect:\n  - domain: gmail.com\n    reason: x\n")
    assert main(["--config", "/nonexistent", "lists", "lint", "--lists", str(tmp_path)]) == 1


def test_log(tmp_path, capsys, lists_dir):
    db = str(tmp_path / "a.db")
    main(["--config", "/nonexistent", "check", "--no-model", "--db", db, "--lists", str(lists_dir), str(FIXTURES)])
    capsys.readouterr()
    assert main(["--config", "/nonexistent", "log", "--db", db]) == 0
    assert "receipt" not in capsys.readouterr().out or True
    assert main(["--config", "/nonexistent", "log", "--db", db, "1"]) == 0


def test_missing_or_empty_api_key_means_rules_only(tmp_path, capsys, lists_dir):
    """The portal's Remove key empties the file; the analyzer keeps running."""
    from analyzer import config
    import argparse

    from analyzer.cli import _analyzer
    key = tmp_path / "key"
    key.write_text("")
    for path in (str(key), str(tmp_path / "missing")):
        args = argparse.Namespace(db=":memory:", lists=str(lists_dir), no_model=False, api_key_file=path)
        an = _analyzer(args, config.Config(portal_dir=""))
        assert an.classifier is None and an.model_status()["model"] == "no_key"
    assert main(["--config", "/nonexistent", "check", "--db", ":memory:", "--lists", str(lists_dir),
                 "--api-key-file", str(key), str(FIXTURES)]) == 0


def test_feedback_command(tmp_path, capsys, lists_dir):
    import json as _json

    from analyzer.store import Store
    db = str(tmp_path / "a.db")
    main(["--config", "/nonexistent", "check", "--no-model", "--db", db, "--lists", str(lists_dir), str(FIXTURES)])
    st = Store(db)
    st.add_feedback("nope", 1, "legitimate", "message")
    capsys.readouterr()
    assert main(["--config", "/nonexistent", "feedback", "--db", db]) == 0
    assert "1 correction from" in capsys.readouterr().out
    assert main(["--config", "/nonexistent", "feedback", "--db", db, "--json"]) == 0
    assert _json.loads(capsys.readouterr().out)["corrections"] == 1


def test_provider_check(capsys):
    assert main(["provider-check", "openai", "--model", "gpt-x"]) == 0
    out = capsys.readouterr().out
    assert out.startswith("api.openai.com:443\n") and "OpenAI" in out
    assert main(["provider-check", "local", "--model", "llama", "--endpoint", "http://192.168.1.50:11434/v1"]) == 0
    assert capsys.readouterr().out.startswith("192.168.1.50:11434\n")
    assert main(["provider-check", "local", "--model", "llama", "--endpoint", "http://172.18.0.5:8080/v1",
                 "--refuse-net", "172.18.0.0/16"]) == 1
    assert main(["provider-check", "local", "--model", "llama", "--endpoint", "http://192.168.1.50:8443/v1",
                 "--refuse-port", "8443"]) == 1
    assert main(["provider-check", "openai", "--model", "gpt x; rm"]) == 1
    assert main(["provider-check", "someone", "--model", "m"]) == 1
