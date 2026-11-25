from analyzer.auth import evaluate

PROTON = "mailin021.protonmail.ch; dkim=pass header.d=bank.com; dmarc=pass (p=reject) header.from=bank.com; spf=pass smtp.mailfrom=bank.com"


def test_proton_dmarc_pass_verifies():
    v = evaluate([PROTON], "bank.com")
    assert v.trusted_header and v.verified and v.dmarc == "pass" and v.dkim == ["pass:bank.com"]


def test_forged_header_below_proton_is_ignored():
    forged = "mailin021.protonmail.ch; dmarc=pass header.from=bank.com"
    real = "mailin021.protonmail.ch; dmarc=fail header.from=bank.com"
    v = evaluate([real, forged], "bank.com")
    assert not v.verified and v.failed and v.duplicate_trusted


def test_topmost_not_proton_means_nothing_trusted():
    v = evaluate(["attacker.example; dmarc=pass header.from=bank.com", PROTON], "bank.com")
    assert not v.trusted_header and not v.verified


def test_lookalike_authserv_not_trusted():
    v = evaluate(["mailin.protonmail.ch.evil.example; dmarc=pass header.from=bank.com"], "bank.com")
    assert not v.trusted_header


def test_dmarc_for_other_domain_does_not_verify():
    v = evaluate([PROTON], "bank-login.example")
    assert not v.verified


def test_forwarded_mail_is_unverified():
    assert not evaluate([PROTON], "bank.com", has_arc=True).verified


def test_missing_header():
    v = evaluate([], "bank.com")
    assert not v.trusted_header and not v.verified and v.dmarc == "none"


def test_two_headers_claiming_proton_are_both_distrusted():
    """If Proton's own header were ever missing, a forged one would be on top."""
    forged = "mx.protonmail.ch; dmarc=pass header.from=bank.com"
    real = "mailin021.protonmail.ch; dmarc=fail header.from=bank.com"
    v = evaluate([forged, real], "bank.com")
    assert not v.verified and not v.trusted_header and v.duplicate_trusted
    v = evaluate([forged, "evil.example; dmarc=pass header.from=bank.com"], "bank.com")
    assert v.verified  # a lower, untrusted header does not count
