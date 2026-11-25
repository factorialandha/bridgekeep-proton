import datetime as dt

from analyzer import lists


def write(d, curated="", learned=None):
    (d / "curated.yaml").write_text(curated)
    if learned is not None:
        (d / "learned.yaml").write_text(learned)
    return lists.load(d, today=dt.date(2026, 11, 23))


def test_lint_rules(tmp_path):
    loaded = write(tmp_path, """
protect:
  - address: a@bank.com
  - domain: gmail.com
    reason: everyone
  - address: alice@gmail.com
    reason: Alice
  - domain: old.example
    reason: gone
    expires: 2026-01-01
  - display_name: Bank
    reason: names are forgeable
""", learned="""
protect:
  - domain: learned.example
    reason: should be refused
  - address: bob@learned.example
    reason: replied 3 times
""")
    joined = "\n".join(loaded.problems)
    assert "missing reason" in joined
    assert "free-mail or shared sending domain" in joined
    assert "expired" in joined
    assert "needs exactly one" in joined
    assert "learned entries must be exact addresses" in joined
    assert sorted(e.value for e in loaded.protect) == ["alice@gmail.com", "bob@learned.example"]
    assert [e.trusted for e in loaded.protect if e.value == "bob@learned.example"] == [False]


def test_matching(lists_dir):
    loaded = lists.load(lists_dir)
    assert lists.check(loaded, "billing@mybank.com", "mybank.com", "").protected
    assert not lists.check(loaded, "other@mybank.com", "mybank.com", "").protected
    assert lists.check(loaded, "x@mail.employer.com", "mail.employer.com", "").protected
    assert lists.check(loaded, "x@a.example", "a.example", "Your Verification Code").keyword
    assert lists.check(loaded, "spammer@junk.example", "junk.example", "").blocked


def test_lookalikes(lists_dir):
    loaded = lists.load(lists_dir)
    for dom in ("mybenk.com", "myb4nk.com", "rnybank.com", "employer.co", "emp1oyer.com",
                "xn--mybnk-6ve.com"):   # Cyrillic а in "mybаnk.com"
        assert lists.check(loaded, f"x@{dom}", dom, "").lookalike_of, dom
    assert not lists.check(loaded, "x@unrelated.org", "unrelated.org", "").lookalike_of


def test_missing_and_broken_files(tmp_path):
    assert not lists.load(tmp_path).protect
    (tmp_path / "curated.yaml").write_text("protect: [unclosed")
    assert lists.load(tmp_path).problems


def test_portal_file_is_trusted_like_curated(tmp_path):
    portal = tmp_path / "portal"
    portal.mkdir()
    (portal / "portal.yaml").write_text("protect:\n  - address: mum@example.org\n    reason: added in the portal\n")
    (tmp_path / "curated.yaml").write_text("protect:\n  - address: a@bank.com\n    reason: bank\n")
    loaded = lists.load(tmp_path, portal_dir=portal)
    assert not loaded.problems
    mum = [e for e in loaded.protect if e.value == "mum@example.org"]
    assert mum and mum[0].trusted and mum[0].source == "portal"
    assert lists.check(loaded, "mum@example.org", "example.org", "").protected
    assert str(portal / "portal.yaml") in loaded.mtimes   # hot reload watches it
    assert not lists.load(tmp_path).protect[1:]           # no portal_dir: not read


def test_portal_cannot_claim_another_source(tmp_path):
    (tmp_path / "portal.yaml").write_text("protect:\n  - address: x@example.org\n    reason: r\n    source: manual\n")
    loaded = lists.load(tmp_path, portal_dir=tmp_path)
    assert [e.source for e in loaded.protect] == ["portal"]


def test_portal_blocks_are_addresses_only(tmp_path):
    portal = tmp_path / "portal"
    portal.mkdir()
    (portal / "portal.yaml").write_text("block:\n  - domain: shop.example\n    reason: r\n"
                                        "  - address: spam@shop.example\n    reason: r\n")
    (tmp_path / "curated.yaml").write_text("block:\n  - domain: junk.example\n    reason: mine\n")
    loaded = lists.load(tmp_path, portal_dir=portal)
    assert sorted(e.value for e in loaded.block) == ["junk.example", "spam@shop.example"]
    assert any("blocks from the portal must be exact addresses" in p for p in loaded.problems)


def test_oversized_list_file_is_ignored_whole(tmp_path):
    many = "".join(f"  - address: u{i}@example.org\n    reason: r\n" for i in range(lists.MAX_LIST_ENTRIES + 1))
    (tmp_path / "portal.yaml").write_text("protect:\n" + many)
    (tmp_path / "curated.yaml").write_text("protect:\n  - address: a@bank.com\n    reason: bank\n")
    loaded = lists.load(tmp_path, portal_dir=tmp_path)
    assert [e.value for e in loaded.protect] == ["a@bank.com"]
    assert any("more than" in p for p in loaded.problems)
    (tmp_path / "portal.yaml").write_text("#" * (lists.MAX_LIST_BYTES + 1))
    assert any("larger than" in p for p in lists.load(tmp_path, portal_dir=tmp_path).problems)


def test_portal_pause_file_pauses(tmp_path):
    from analyzer.config import Config
    cfg = Config(pause_file=str(tmp_path / "PAUSE"), portal_dir=str(tmp_path / "portal"))
    assert not cfg.paused()
    (tmp_path / "portal").mkdir()
    (tmp_path / "portal" / "PAUSE").touch()
    assert cfg.paused()


def test_reload_notices_an_atomic_replace(tmp_path):
    portal = tmp_path / "portal"
    portal.mkdir()
    f = portal / "portal.yaml"
    f.write_text("protect: []\n")
    before = lists.load(tmp_path, portal_dir=portal).mtimes[str(f)]
    tmp = portal / ".portal.yaml.tmp"
    tmp.write_text("protect:\n  - address: m@example.org\n    reason: r\n")
    import os
    os.utime(tmp, ns=(before[0], before[0]))   # same mtime: only the inode differs
    os.replace(tmp, f)
    assert lists.file_signature(f.stat()) != before


def test_planted_symlink_or_fifo_is_never_opened(tmp_path):
    import os
    secret = tmp_path / "secret"
    secret.write_text("protect:\n  - address: sk-ant-leak@example.org\n    reason: r\n")
    (tmp_path / "portal.yaml").symlink_to(secret)
    loaded = lists.load(tmp_path, portal_dir=tmp_path)
    assert not loaded.protect
    assert loaded.problems == ["portal.yaml: not a regular file or not readable, ignored"]
    (tmp_path / "portal.yaml").unlink()
    os.mkfifo(tmp_path / "portal.yaml")      # would block a plain open() forever
    loaded = lists.load(tmp_path, portal_dir=tmp_path)
    assert not loaded.protect and "not a regular file" in loaded.problems[0]


def test_portal_file_has_a_smaller_cap(tmp_path):
    (tmp_path / "portal.yaml").write_text("#" * (lists.MAX_PORTAL_BYTES + 1))
    assert any("larger than 256 KB" in p for p in lists.load(tmp_path, portal_dir=tmp_path).problems)


def test_a_broken_reload_keeps_the_last_good_entries(tmp_path):
    f = tmp_path / "portal.yaml"
    f.write_text("protect:\n  - address: mum@example.org\n    reason: r\n")
    good = lists.load(tmp_path, portal_dir=tmp_path)
    f.write_text("protect:\n  - address: mum@exa")          # half-written
    f.write_text("protect: [unclosed")
    again = lists.load(tmp_path, portal_dir=tmp_path, previous=good)
    assert [e.value for e in again.protect] == ["mum@example.org"]
    assert "kept the last good 1 entries" in again.problems[0]
    assert not lists.load(tmp_path, portal_dir=tmp_path).protect   # a cold start has nothing to keep


def test_public_suffix_cannot_be_protected(tmp_path):
    loaded = write(tmp_path, "protect:\n  - domain: co.uk\n    reason: r\n    subdomains: true\n"
                             "  - domain: mybank.co.uk\n    reason: bank\n")
    assert [e.value for e in loaded.protect] == ["mybank.co.uk"]
    assert any("public suffix" in p for p in loaded.problems)


def test_shared_sending_domains_are_refused_for_protect_and_say_so(tmp_path):
    (tmp_path / "curated.yaml").write_text("protect:\n  - domain: sendgrid.net\n    reason: r\n"
                                           "  - domain: contoso.onmicrosoft.com\n    reason: r\n")
    loaded = lists.load(tmp_path)
    assert not loaded.protect
    assert sum("now refused. Protect the exact address instead" in p for p in loaded.problems) == 2
