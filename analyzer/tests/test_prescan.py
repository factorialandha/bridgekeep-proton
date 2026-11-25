from analyzer.extract import extract
from analyzer.prescan import scan
from conftest import FIXTURES


def test_every_adversarial_fixture_is_flagged():
    for f in sorted((FIXTURES / "adversarial").glob("*.eml")):
        ex = extract(f.read_bytes())
        assert scan(ex.from_display, ex.subject, ex.body, ex.hidden_text), f.name


def test_ordinary_mail_is_not_flagged():
    for text in ["Your order has shipped. Track it at https://shop.example/track/1234",
                 "Hi Sam, can we move the meeting to 3pm? Thanks, Alice",
                 "Your verification code is 123456. It expires in 10 minutes.",
                 "Please ignore the previous email, the invoice amount was wrong."]:
        assert not scan(text), text
