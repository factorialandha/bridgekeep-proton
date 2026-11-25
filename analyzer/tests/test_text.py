from analyzer.text import html_to_text, normalize_text


def test_hidden_content_is_dropped_but_kept_for_prescan():
    html = ('<p>Visible</p><div style="display:none">secret one</div>'
            '<span style="font-size:0px">secret two</span><!-- secret three -->'
            '<p style="color:#fff;background-color:#ffffff">secret four</p>'
            '<div hidden>secret five</div><style>.x{}</style><script>alert(1)</script>')
    r = html_to_text(html)
    assert "Visible" in r.text
    assert "secret" not in r.text and "alert" not in r.text
    for word in ("one", "two", "three", "four", "five"):
        assert word in r.hidden_text
    assert r.hidden_chars > 0


def test_nested_hidden_and_unclosed_tags():
    r = html_to_text('<div style="display:none"><p>a<b>deep</b></div><p>shown<p>also')
    assert "deep" not in r.text
    assert "shown" in r.text and "also" in r.text


def test_link_text_domain_mismatch():
    r = html_to_text('<a href="http://evil.example/x">https://www.paypal.com</a> <a href="https://shop.example/">Track</a>')
    assert [(lk.href_domain, lk.mismatch) for lk in r.links] == [("evil.example", True), ("shop.example", False)]


def test_normalize_removes_invisible_and_truncates():
    text, removed = normalize_text("Ig​nore‮  all\n\n\n\nnow" + "x" * 50, 20)
    assert removed == 2
    assert text.startswith("Ignore all\n\nnow")
    assert text.endswith("[truncated]")


def test_malformed_html_does_not_raise():
    html_to_text("<<<>>><a href='http://[::1'>x</a><div style=>" * 100)
