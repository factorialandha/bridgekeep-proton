"""Extract the fields the classifier sees from a raw message.

The model never sees the raw message: only the fields built here, all
plain one-line strings or a bounded plain-text body. Attachments are listed
by type only, never opened. Every limit hit is recorded in `limits_hit`;
the decision step then leaves the message where it is (security review A5).
"""

from __future__ import annotations

import email
import email.policy
import re
import time
from dataclasses import asdict, dataclass, field
from email.header import Header, decode_header, make_header
from email.message import Message
from email.utils import getaddresses

from . import auth
from .text import Link, clean_line, html_to_text, link_domain, normalize_domain, normalize_text

_URL = re.compile(r"https?://[^\s<>\"')]+", re.I)


@dataclass
class Limits:
    max_bytes: int = 1_000_000
    max_depth: int = 8
    max_parts: int = 60
    max_seconds: float = 2.0
    body_chars: int = 3000
    part_bytes: int = 400_000


@dataclass
class Extracted:
    from_addr: str = ""
    from_display: str = ""
    from_domain: str = ""
    from_count: int = 0
    reply_to_domain: str = ""
    return_path_domain: str = ""
    subject: str = ""
    to_count: int = 0
    has_list_unsubscribe: bool = False
    list_unsubscribe: str = ""        # raw header, capped; never sent to the model
    list_unsubscribe_post: str = ""
    auto_submitted: bool = False
    has_arc: bool = False
    auth_results: list[str] = field(default_factory=list)
    body: str = ""
    had_html: bool = False
    hidden_chars: int = 0
    hidden_text: str = ""          # pre-scan only, never sent to the model
    invisible_chars: int = 0
    links: list[Link] = field(default_factory=list)
    attachments: list[str] = field(default_factory=list)
    message_id: str = ""
    limits_hit: list[str] = field(default_factory=list)
    auth: auth.AuthVerdict = field(default_factory=auth.AuthVerdict)

    def model_fields(self) -> dict:
        """The exact, minimal data the hosted model is shown."""
        link_domains = sorted({lk.href_domain for lk in self.links if lk.href_domain})[:20]
        return {
            "from_display_name": self.from_display,
            "from_address": self.from_addr,
            "reply_to_domain": self.reply_to_domain or None,
            "return_path_domain": self.return_path_domain or None,
            "subject": self.subject,
            "authentication": self.auth.summary(),
            "has_list_unsubscribe": self.has_list_unsubscribe,
            "link_domains": link_domains,
            "links_with_mismatched_text": sum(1 for lk in self.links if lk.mismatch),
            "attachment_types": self.attachments[:10],
            "hidden_html_text_removed_chars": self.hidden_chars,
            "body_text": self.body,
        }

    def to_dict(self) -> dict:
        d = asdict(self)
        d["links"] = [asdict(lk) for lk in self.links]
        return d


def _utf8(value: str) -> str:
    """Raw 8-bit (SMTPUTF8) headers arrive as surrogate escapes; decode them as UTF-8."""
    try:
        return value.encode("ascii", "surrogateescape").decode("utf-8", "replace")
    except UnicodeEncodeError:
        return value


def _hdr(msg: Message, name: str) -> str:
    raw = msg.get(name)
    if raw is None:
        return ""
    if isinstance(raw, Header):
        # compat32 wraps raw 8-bit headers in a Header with an unknown-8bit charset.
        out = []
        for chunk, charset in decode_header(raw):
            if isinstance(chunk, bytes):
                cs = "utf-8" if not charset or charset == "unknown-8bit" else charset
                try:
                    out.append(chunk.decode(cs, "replace"))
                except LookupError:
                    out.append(chunk.decode("utf-8", "replace"))
            else:
                out.append(chunk)
        return "".join(out)
    raw = _utf8(str(raw))
    if "=?" not in raw:
        return raw
    try:
        return str(make_header(decode_header(raw)))
    except Exception:  # noqa: BLE001 - undecodable header: keep the raw form
        return str(raw)


def _domain_of(addr: str) -> str:
    return normalize_domain(addr.rpartition("@")[2]) if "@" in addr else ""


def _payload_text(part: Message, limit: int) -> str:
    try:
        data = part.get_payload(decode=True) or b""
    except Exception:  # noqa: BLE001
        return ""
    data = data[:limit]
    charset = part.get_content_charset() or "utf-8"
    try:
        return data.decode(charset, errors="replace")
    except LookupError:
        return data.decode("utf-8", errors="replace")


def extract(raw: bytes, limits: Limits | None = None,
            trusted_authserv: tuple[str, ...] = auth.DEFAULT_TRUSTED_AUTHSERV_SUFFIXES) -> Extracted:
    lim = limits or Limits()
    ex = Extracted()
    if len(raw) > lim.max_bytes:
        ex.limits_hit.append("max_bytes")
        raw = raw[: lim.max_bytes]
    deadline = time.monotonic() + lim.max_seconds
    try:
        msg = email.message_from_bytes(raw, policy=email.policy.compat32)
    except Exception:  # noqa: BLE001
        ex.limits_hit.append("unparseable")
        return ex

    froms = getaddresses([_hdr(msg, "From")])
    froms = [(n, a) for n, a in froms if a]
    ex.from_count = len(froms)
    if froms:
        name, addr = froms[0]
        ex.from_display = clean_line(name, 80)
        local, _, dom = addr.strip().rpartition("@")
        ex.from_domain = normalize_domain(dom)
        ex.from_addr = clean_line(f"{local.lower()}@{ex.from_domain}", 120) if local else ""
    reply = getaddresses([_hdr(msg, "Reply-To")])
    ex.reply_to_domain = _domain_of(reply[0][1]) if reply and reply[0][1] else ""
    ex.return_path_domain = _domain_of(_hdr(msg, "Return-Path").strip("<> "))
    ex.subject = clean_line(_hdr(msg, "Subject"), 200)
    ex.to_count = len(getaddresses([str(h) for h in msg.get_all("To", []) + msg.get_all("Cc", [])]))
    ex.has_list_unsubscribe = msg.get("List-Unsubscribe") is not None
    ex.list_unsubscribe = _hdr(msg, "List-Unsubscribe")[:2048]
    ex.list_unsubscribe_post = _hdr(msg, "List-Unsubscribe-Post")[:200]
    ex.auto_submitted = (
        (_hdr(msg, "Auto-Submitted").strip().lower() not in ("", "no"))
        or msg.get("X-Autoreply") is not None
        or msg.get("X-Autorespond") is not None
    )
    ex.has_arc = msg.get("ARC-Seal") is not None
    ex.message_id = clean_line(_hdr(msg, "Message-ID"), 200)
    ex.auth_results = [str(h) for h in msg.get_all("Authentication-Results", [])][:10]
    ex.auth = auth.evaluate(ex.auth_results, ex.from_domain, has_arc=ex.has_arc,
                            trusted_suffixes=trusted_authserv)

    plain: list[str] = []
    html: list[str] = []
    parts = 0

    def walk(part: Message, depth: int) -> None:
        nonlocal parts
        if time.monotonic() > deadline:
            if "max_seconds" not in ex.limits_hit:
                ex.limits_hit.append("max_seconds")
            return
        parts += 1
        if parts > lim.max_parts:
            if "max_parts" not in ex.limits_hit:
                ex.limits_hit.append("max_parts")
            return
        if depth > lim.max_depth:
            if "max_depth" not in ex.limits_hit:
                ex.limits_hit.append("max_depth")
            return
        ctype = part.get_content_type()
        if part.is_multipart():
            payload = part.get_payload()
            for sub in payload if isinstance(payload, list) else []:
                walk(sub, depth + 1)
            return
        disp = (part.get("Content-Disposition") or "").lower()
        if "attachment" in disp or part.get_filename() or not ctype.startswith("text/"):
            # Never opened or parsed: type only.
            ex.attachments.append(clean_line(ctype, 60))
            return
        if ctype == "text/plain":
            plain.append(_payload_text(part, lim.part_bytes))
        elif ctype == "text/html":
            html.append(_payload_text(part, lim.part_bytes))

    walk(msg, 0)

    # Prefer the HTML part when both exist: it is what a mail client shows,
    # and hiding text there is where injections live.
    if html:
        ex.had_html = True
        rendered = [html_to_text(h) for h in html]
        body = "\n".join(r.text for r in rendered)
        ex.hidden_chars = sum(r.hidden_chars for r in rendered)
        ex.hidden_text, _ = normalize_text(" ".join(r.hidden_text for r in rendered), 20_000)
        ex.links = [lk for r in rendered for lk in r.links][:40]
    else:
        body = "\n".join(plain)
        for url in _URL.findall(body)[:40]:
            ex.links.append(Link(link_domain(url), "", False))
    ex.body, ex.invisible_chars = normalize_text(body, lim.body_chars)
    return ex
