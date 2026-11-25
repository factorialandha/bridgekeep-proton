"""Deterministic policy: code decides, the model only advises.

Possible outcomes are exactly three: keep (leave in the inbox), review
(move to the review folder) and quarantine (move to AI-Quarantine). There is
no delete, no Trash, no forward and no reply anywhere in the analyzer.

In shadow mode the outcome is recorded as what *would* have happened and
nothing moves.
"""

from __future__ import annotations

from dataclasses import dataclass

from .classify import Classification
from .extract import Extracted
from .lists import ListHits
from .prescan import Injection

KEEP, REVIEW, QUARANTINE = "keep", "review", "quarantine"
_RANK = {KEEP: 0, REVIEW: 1, QUARANTINE: 2}


@dataclass
class Decision:
    action: str          # keep | review | quarantine
    rule: str            # the code rule that produced the action
    explain: str         # one human sentence
    skip_model: bool = False


def pre_model(ex: Extracted, hits: ListHits) -> Decision | None:
    """Rules that settle a message before any model call, or None."""
    if ex.limits_hit:
        return Decision(KEEP, "parse_limit", f"Parse limit hit ({', '.join(ex.limits_hit)}); left in place.", True)
    # Zero or several From addresses: no list match is trusted.
    single_from = ex.from_count == 1
    if single_from and hits.protected and hits.protected.trusted and ex.auth.verified:
        return Decision(KEEP, "protected_verified",
                        f"Protected sender ({hits.protected.reason}), DMARC verified.", True)
    if (single_from and hits.blocked and not hits.protected and not hits.keyword
            and ex.auth.verified and hits.blocked.kind == "address"):
        return Decision(QUARANTINE, "blocklist",
                        f"Blocklisted sender ({hits.blocked.reason}), DMARC verified.", True)
    return None


def _cap(d: Decision, ceiling: str, rule: str, explain: str) -> Decision:
    if _RANK[d.action] > _RANK[ceiling]:
        return Decision(ceiling, rule, explain)
    return d


def _floor(d: Decision, floor: str, rule: str, explain: str) -> Decision:
    if _RANK[d.action] < _RANK[floor]:
        return Decision(floor, rule, explain)
    return d


def post_model(ex: Extracted, hits: ListHits, injections: list[Injection], c: Classification,
               quarantine_at: float, review_at: float, feedback_trusted: str | None = None) -> Decision:
    bad = c.label in ("spam", "phishing")
    if bad and c.confidence >= quarantine_at:
        d = Decision(QUARANTINE, "threshold", f"Model: {c.label} {c.confidence:.2f}, at or above {quarantine_at}.")
    elif bad and c.confidence >= review_at:
        d = Decision(REVIEW, "review_band", f"Model: {c.label} {c.confidence:.2f}, in the review band.")
    else:
        d = Decision(KEEP, "model_keep", f"Model: {c.label} {c.confidence:.2f}.")

    # Disagreement check (6A.5a): the model says fine but deterministic
    # signals say otherwise. Never trust "legitimate" on the email's say-so.
    if not bad:
        if injections:
            d = _floor(d, REVIEW, "disagree_injection",
                       f"Model said {c.label}, but the message contains text aimed at AI filters.")
        elif ex.auth.failed:
            d = _floor(d, REVIEW, "disagree_auth", f"Model said {c.label}, but DMARC failed.")
    if hits.lookalike_of:
        d = _floor(d, REVIEW, "lookalike_domain",
                   f"Sender domain looks like protected {hits.lookalike_of}.")

    # Protections only ever lower the action, never raise it.
    if hits.protected:
        # Reached only when the protected match was NOT DMARC-verified
        # (verified matches skip the model): spoofing is possible.
        d = _cap(d, REVIEW, "protected_unverified",
                 f"Protected sender ({hits.protected.reason}) but not verified; review instead of quarantine.")
    if feedback_trusted:
        # feedback_trusted names the sender (domain, or exact address for free
        # mail). The recipient has said twice or more that its verified mail is fine, and never that it is spam (feedback.py).
        d = _cap(d, REVIEW, "feedback_trusted",
                 f"You've marked mail from {feedback_trusted} as not spam before, so it goes to review, never quarantine.")
    if hits.keyword:
        # Security review A9: a keyword only stops quarantine. Phishing that
        # uses "password reset" wording still goes to review with a warning.
        d = _cap(d, REVIEW, "protected_keyword",
                 f"Subject matches protected keyword '{hits.keyword.value}'; never quarantined.")
    return d
