import time

from conftest import PASSWORD, Client, next_code
from portal import auth, totp


def test_totp_matches_rfc6238_vector():
    # RFC 6238 appendix B, SHA-1, T=59: 94287082 -> last 6 digits.
    secret = "GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQ"  # base32("12345678901234567890")
    assert totp.code_at(secret, 59 // 30) == "287082"


def test_totp_refuses_replay():
    s = totp.new_secret()
    code, step = next_code(s)
    assert totp.verify(s, code) == step
    assert totp.verify(s, code, last_step=step) is None


def test_unclaimed_portal_sends_everyone_to_claim(portal):
    c = Client(portal.port)
    for path in ("/", "/login", "/settings", "/audit"):
        r = c.get(path)
        assert r.status == 303 and r.getheader("Location") == "/claim", path


def test_wrong_claim_code_is_refused_and_backs_off(portal):
    auth.new_claim_code(portal.db, 3600)
    c = Client(portal.port)
    c.get("/claim")
    for _ in range(auth.FREE_ATTEMPTS):
        assert c.post("/claim", {"code": "AAAA-BBBB-CCCC-DDDD-EEEE-FFFF"}).status == 401
    assert c.post("/claim", {"code": "AAAA-BBBB-CCCC-DDDD-EEEE-FFFF"}).status == 401
    r = c.post("/claim", {"code": "anything"})
    assert r.status == 429 and "Too many attempts" in r.body


def test_expired_claim_code_is_refused(portal):
    code = auth.new_claim_code(portal.db, -1)
    c = Client(portal.port)
    c.get("/claim")
    assert c.post("/claim", {"code": code}).status == 401


def test_claim_code_is_single_use_and_admin_is_created(claimed):
    portal, c = claimed
    assert auth.is_claimed(portal.db)
    assert portal.db.one("SELECT COUNT(*) FROM claim")[0] == 0
    r = c.get("/")
    assert r.status == 200 and "Status" in r.body
    # A second visitor can no longer claim.
    other = Client(portal.port)
    assert other.get("/claim").getheader("Location") == "/login"


def test_claim_code_is_consumed_on_accept(portal):
    code = auth.new_claim_code(portal.db, 3600)
    a, b = Client(portal.port), Client(portal.port)
    a.get("/claim")
    b.get("/claim")
    assert a.post("/claim", {"code": code}).status == 303
    assert b.post("/claim", {"code": code}).status == 401


def test_claim_needs_a_long_password_and_a_working_code(portal):
    code = auth.new_claim_code(portal.db, 3600)
    c = Client(portal.port)
    c.get("/claim")
    c.post("/claim", {"code": code.lower()})  # case and dashes don't matter
    c.get("/claim/admin")
    r = c.post("/claim/admin", {"password": "short", "confirm": "short", "code": "000000"})
    assert r.status == 400 and "12 characters" in r.body
    r = c.post("/claim/admin", {"password": PASSWORD, "confirm": PASSWORD, "code": "000000"})
    assert r.status == 400 and not auth.is_claimed(portal.db)


def test_sign_in_needs_password_and_code(claimed):
    portal, c = claimed
    c.post("/logout")
    assert c.get("/").getheader("Location") == "/login"
    c.get("/login")
    otp, step = next_code(c.secret, c.step)
    assert c.post("/login", {"password": "wrong password!!", "code": otp}).status == 401
    assert c.post("/login", {"password": PASSWORD, "code": "123456"}).status == 401
    r = c.post("/login", {"password": PASSWORD, "code": otp})
    assert r.status == 303 and r.getheader("Location") == "/"
    # The same code can't be used again.
    c2 = Client(portal.port)
    c2.get("/login")
    assert c2.post("/login", {"password": PASSWORD, "code": otp}).status == 401


def test_session_id_changes_at_sign_in(claimed):
    portal, c = claimed
    c.post("/logout")
    c.get("/login")
    before = c.cookie
    otp, _ = next_code(c.secret, c.step)
    c.post("/login", {"password": PASSWORD, "code": otp})
    assert c.cookie and c.cookie != before


def test_idle_session_expires(claimed):
    portal, c = claimed
    portal.db.execute("UPDATE sessions SET last_seen = ?", (time.time() - 13 * 3600,))
    assert c.get("/").getheader("Location") == "/login"


def test_password_change_needs_step_up(claimed):
    portal, c = claimed
    portal.db.execute("UPDATE sessions SET reauth_at = 0")
    c.get("/settings")
    r = c.post("/settings/password", {"password": "a new long password", "confirm": "a new long password",
                                      "back": "/settings"})
    assert r.status == 401 and "Confirm it" in r.body
    assert 'name="next" value="/settings"' in r.body
    otp, step = next_code(c.secret, c.step)
    r = c.post("/reauth", {"password": PASSWORD, "code": otp, "next": "/settings"})
    assert r.status == 303 and r.getheader("Location") == "/settings"
    c.get("/settings")
    r = c.post("/settings/password", {"password": "a new long password", "confirm": "a new long password"})
    assert r.status == 303
    assert auth.check_password(portal.db.one("SELECT pw_hash FROM admin")[0], "a new long password")


def test_reset_admin_forgets_everything(claimed):
    portal, c = claimed
    auth.reset_admin(portal.db)
    assert not auth.is_claimed(portal.db)
    assert c.get("/").getheader("Location") == "/claim"


def test_audit_log_is_append_only(claimed):
    portal, _ = claimed
    import sqlite3

    import pytest
    with pytest.raises(sqlite3.DatabaseError):
        portal.db.execute("DELETE FROM audit")
    with pytest.raises(sqlite3.DatabaseError):
        portal.db.execute("UPDATE audit SET action = 'x'")
    actions = [r[0] for r in portal.db.all("SELECT action FROM audit ORDER BY id")]
    assert actions == ["claim code accepted", "admin created"]


def _claim_password_only(portal, pw="seven unrelated words here"):
    code = auth.new_claim_code(portal.db, 3600)
    c = Client(portal.port)
    c.get("/claim")
    c.post("/claim", {"code": code})
    c.get("/claim/admin")
    r = c.post("/claim/admin", {"password": pw, "confirm": pw, "code": ""})
    return c, r


def test_authenticator_is_optional_with_a_longer_password(portal):
    c, r = _claim_password_only(portal, "fourteen chars")
    assert r.status == 400 and "15 characters" in r.body
    c.get("/claim/admin")
    pw = "seven unrelated words here"
    r = c.post("/claim/admin", {"password": pw, "confirm": pw, "code": ""})
    assert r.status == 303 and not auth.has_totp(portal.db)
    c.get("/")
    c.post("/logout")
    r = c.get("/login")
    assert 'name="code"' not in r.body
    assert c.post("/login", {"password": "wrong but long enough"}).status == 401
    assert c.post("/login", {"password": pw}).status == 303


def test_common_and_product_passwords_are_refused():
    assert "easy to guess" in auth.password_problem("Scandinavian", "Scandinavian", True)
    assert "easy to guess" in auth.password_problem("my proton mail box!!", "my proton mail box!!", False)
    assert "easy to guess" in auth.password_problem("BridgeKeep forever and ever", "BridgeKeep forever and ever", True)
    assert "15 characters" in auth.password_problem("twelve chars", "twelve chars", False)
    assert auth.password_problem("twelve chars", "twelve chars", True) is None
    assert auth.password_problem("seven unrelated words here", "seven unrelated words here", False) is None


def test_turn_authenticator_on_and_off(portal):
    from conftest import SECRET
    c, _ = _claim_password_only(portal)
    r = c.get("/settings")
    assert "! Off" in r.body
    secret = SECRET.search(r.body).group(1).replace(" ", "")
    other = auth.new_session(portal.db, "admin", "192.0.2.9")   # another browser
    otp, step = next_code(secret)
    r = c.post("/settings/totp/on", {"code": otp})
    assert r.status == 303 and auth.has_totp(portal.db)
    assert auth.load_session(portal.db, other.token, 3600, 86400) is None   # signed out
    r = c.get("/settings")
    assert "✓ On" in r.body
    otp2, _ = next_code(secret, step)
    # Turning it off needs the password and a current code, every time.
    assert c.post("/settings/totp/off", {"password": "seven unrelated words here", "code": "000000"}).status == 401
    assert auth.has_totp(portal.db)
    r = c.post("/settings/totp/off", {"password": "seven unrelated words here", "code": otp2})
    assert r.status == 303 and not auth.has_totp(portal.db)
    actions = [a[0] for a in portal.db.all("SELECT action FROM audit")]
    assert "authenticator turned on" in actions and "authenticator turned off" in actions


def test_turning_off_needs_a_password_long_enough_alone(claimed):
    portal, c = claimed  # PASSWORD is 28 characters: fine
    portal.db.execute("UPDATE admin SET pw_hash = ?", (auth.hash_password("short but ok12"),))
    otp, _ = next_code(c.secret, c.step)
    r = c.post("/settings/totp/off", {"password": "short but ok12", "code": otp})
    assert r.status == 400 and "Change your password first" in r.body
    assert auth.has_totp(portal.db)


def test_status_nudges_password_only_accounts(portal):
    c, _ = _claim_password_only(portal)
    assert "Add an authenticator app" in c.get("/").body
