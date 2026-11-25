"""Authentication-Results handling (security review A6).

Anyone can put an Authentication-Results header in their own message, so
only one header is trusted: the topmost one in the message, and only if its
authserv-id is Proton's inbound server. Proton prepends its header on
arrival, so a forged one always sits below it. If the topmost header is not
Proton's, nothing is trusted and the message counts as unverified.

"Verified" means DMARC passed for exactly the From domain we parsed. SPF or
DKIM on their own never verify a sender.
"""

from __future__ import annotations

import re
from dataclasses import dataclass, field

# Proton's inbound servers stamp an authserv-id under these domains. This
# MUST be checked against a real message from the owner's mailbox before
# go-live (`analyzer check` prints the authserv-id it saw).
DEFAULT_TRUSTED_AUTHSERV_SUFFIXES = ("protonmail.ch", "proton.me", "protonmail.com")

_COMMENT = re.compile(r"\([^()]*\)")
_RESULT = re.compile(r"^\s*([a-z0-9_-]+)\s*=\s*([a-z0-9_-]+)(.*)$", re.I | re.S)
_PROP = re.compile(r"([a-z0-9_-]+\.[a-z0-9_.-]+)\s*=\s*(\"[^\"]*\"|[^\s;]+)", re.I)


@dataclass
class MethodResult:
    method: str
    result: str
    props: dict[str, str] = field(default_factory=dict)


@dataclass
class AuthVerdict:
    trusted_header: bool = False
    authserv_id: str = ""
    dmarc: str = "none"
    dmarc_from: str = ""
    dkim: list[str] = field(default_factory=list)   # "pass:example.com"
    spf: str = "none"
    forwarded: bool = False
    # DMARC pass, for the From domain we parsed, from Proton's own header.
    verified: bool = False
    # Proton's header says DMARC failed (a strong signal, but not proof).
    failed: bool = False
    # More than one header claimed a trusted authserv-id: none is trusted.
    duplicate_trusted: bool = False

    def summary(self) -> dict:
        return {
            "trusted_header": self.trusted_header,
            "dmarc": self.dmarc,
            "spf": self.spf,
            "dkim": self.dkim[:4],
            "verified_from_domain": self.verified,
            "forwarded": self.forwarded,
        }


def _split_results(value: str) -> tuple[str, list[MethodResult]]:
    value = _COMMENT.sub(" ", _COMMENT.sub(" ", value))
    parts = [p.strip() for p in value.split(";")]
    authserv = parts[0].split()[0].lower() if parts and parts[0].split() else ""
    results = []
    for part in parts[1:]:
        m = _RESULT.match(part)
        if not m:
            continue
        props = {k.lower(): v.strip('"').lower() for k, v in _PROP.findall(m.group(3))}
        results.append(MethodResult(m.group(1).lower(), m.group(2).lower(), props))
    return authserv, results


def _trusted(authserv: str, suffixes: tuple[str, ...]) -> bool:
    return any(authserv == s or authserv.endswith("." + s) for s in suffixes)


def evaluate(
    auth_results_headers: list[str],
    from_domain: str,
    *,
    has_arc: bool = False,
    trusted_suffixes: tuple[str, ...] = DEFAULT_TRUSTED_AUTHSERV_SUFFIXES,
) -> AuthVerdict:
    """`auth_results_headers` must be in message order (topmost first)."""
    v = AuthVerdict(forwarded=has_arc)
    if not auth_results_headers:
        return v
    authserv, results = _split_results(auth_results_headers[0])
    v.authserv_id = authserv[:100]
    if not _trusted(authserv, trusted_suffixes):
        return v
    # Proton adds exactly one header of its own. If a second header further
    # down also claims a trusted authserv-id, either Proton's own is missing
    # and the top one is the sender's forgery, or something is off: either
    # way, nothing is verified (security review follow-up). A "fail" on top
    # is still kept as a signal: a forger gains nothing by adding one.
    v.duplicate_trusted = any(
        _trusted(_split_results(h)[0], trusted_suffixes) for h in auth_results_headers[1:])
    v.trusted_header = not v.duplicate_trusted
    for r in results:
        if r.method == "dmarc":
            v.dmarc = r.result
            v.dmarc_from = r.props.get("header.from", "")
        elif r.method == "dkim":
            v.dkim.append(f"{r.result}:{r.props.get('header.d') or r.props.get('header.i', '')}")
        elif r.method == "spf":
            v.spf = r.result
    v.failed = v.dmarc == "fail"
    v.verified = (
        v.trusted_header
        and v.dmarc == "pass"
        and bool(from_domain)
        and v.dmarc_from == from_domain
        and not v.forwarded
    )
    return v
