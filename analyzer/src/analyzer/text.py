"""Turn hostile HTML and text into plain, visible, normalized text.

Everything here handles attacker-controlled bytes, so it is deliberately
small: the standard library's HTMLParser, no rendering, no URL fetching,
no CSS engine. Hidden content (the most common prompt-injection route) is
dropped and counted, never passed to the model.
"""

from __future__ import annotations

import re
import unicodedata
from dataclasses import dataclass, field
from html.parser import HTMLParser
from urllib.parse import urlsplit

# Elements whose text is never visible.
_INVISIBLE_TAGS = {"script", "style", "head", "template", "noscript", "object", "embed", "iframe", "svg", "math"}
_VOID_TAGS = {
    "area", "base", "br", "col", "embed", "hr", "img", "input", "link", "meta",
    "param", "source", "track", "wbr",
}
_BLOCK_TAGS = {"p", "div", "br", "tr", "li", "h1", "h2", "h3", "h4", "h5", "h6", "table", "blockquote", "section"}

_HIDDEN_STYLE = re.compile(
    r"display\s*:\s*none|visibility\s*:\s*hidden|opacity\s*:\s*0(\.0*)?\s*(;|$)"
    r"|font-size\s*:\s*0*(\.\d+)?(px|pt|em|rem|%)?\s*(;|$)|font-size\s*:\s*[01]px"
    r"|max-height\s*:\s*0|(?<![-\w])height\s*:\s*0(px)?\s*(;|$)|(?<![-\w])width\s*:\s*0(px)?\s*(;|$)"
    r"|text-indent\s*:\s*-\d{3,}|left\s*:\s*-\d{3,}|clip\s*:\s*rect\(\s*0",
    re.I,
)
_COLOR = re.compile(r"(?<![-\w])color\s*:\s*([^;]+)", re.I)
_BGCOLOR = re.compile(r"background(?:-color)?\s*:\s*([^;]+)", re.I)

MAX_LINKS = 40


@dataclass
class Link:
    href_domain: str
    text: str
    # Visible text names a different domain than the href goes to.
    mismatch: bool = False


@dataclass
class HtmlText:
    text: str
    hidden_chars: int = 0
    # Kept only for the injection pre-scan; never shown to the model.
    hidden_text: str = ""
    links: list[Link] = field(default_factory=list)


def _norm_color(value: str) -> str:
    v = value.strip().lower().replace(" ", "").removesuffix("!important")
    aliases = {"#fff": "#ffffff", "white": "#ffffff", "#000": "#000000", "black": "#000000",
               "rgb(255,255,255)": "#ffffff", "rgb(0,0,0)": "#000000"}
    return aliases.get(v, v)


def _style_hides(style: str) -> bool:
    if _HIDDEN_STYLE.search(style):
        return True
    c, b = _COLOR.search(style), _BGCOLOR.search(style)
    return bool(c and b and _norm_color(c.group(1)) == _norm_color(b.group(1)))


def link_domain(href: str) -> str:
    try:
        host = urlsplit(href.strip()).hostname or ""
    except ValueError:
        return ""
    return normalize_domain(host)


def normalize_domain(host: str) -> str:
    host = host.strip().strip(".").lower()
    if not host:
        return ""
    try:
        return host.encode("idna").decode("ascii")
    except UnicodeError:
        # Not valid IDNA: keep a visibly odd but inert form.
        return "invalid-idna:" + host.encode("unicode_escape").decode("ascii")[:80]


_DOMAINISH = re.compile(r"\b((?:[a-z0-9-]+\.)+[a-z]{2,})\b", re.I)


class _Parser(HTMLParser):
    def __init__(self) -> None:
        super().__init__(convert_charrefs=True)
        self.stack: list[tuple[str, bool]] = []
        self.out: list[str] = []
        self.hidden_chars = 0
        self.hidden_out: list[str] = []
        self._hidden_len = 0
        self.links: list[Link] = []
        self._link: tuple[str, list[str]] | None = None

    @property
    def hidden(self) -> bool:
        return bool(self.stack) and self.stack[-1][1]

    def handle_starttag(self, tag, attrs):
        a = {k.lower(): (v or "") for k, v in attrs}
        hide = (
            self.hidden
            or tag in _INVISIBLE_TAGS
            or "hidden" in a
            or a.get("aria-hidden", "").lower() == "true"
            or _style_hides(a.get("style", ""))
        )
        if tag in _BLOCK_TAGS and not hide:
            self.out.append("\n")
        if tag == "a" and not hide and "href" in a:
            self._link = (a["href"], [])
        if tag not in _VOID_TAGS:
            self.stack.append((tag, hide))

    def handle_startendtag(self, tag, attrs):
        if tag in _BLOCK_TAGS and not self.hidden:
            self.out.append("\n")

    def handle_endtag(self, tag):
        if tag == "a" and self._link is not None:
            href, parts = self._link
            self._link = None
            if len(self.links) < MAX_LINKS:
                dom = link_domain(href)
                text = " ".join("".join(parts).split())[:80]
                shown = {normalize_domain(m) for m in _DOMAINISH.findall(text)}
                self.links.append(Link(dom, text, bool(shown) and dom not in shown))
        # Pop up to the matching tag; tolerate unclosed tags.
        for i in range(len(self.stack) - 1, -1, -1):
            if self.stack[i][0] == tag:
                del self.stack[i:]
                break
        if tag in _BLOCK_TAGS and not self.hidden:
            self.out.append("\n")

    def handle_data(self, data):
        if self.hidden:
            self._keep_hidden(data)
            return
        self.out.append(data)
        if self._link is not None:
            self._link[1].append(data)

    # Comments, processing instructions and declarations are never text.
    def handle_comment(self, data):
        self._keep_hidden(data)

    def _keep_hidden(self, data: str) -> None:
        self.hidden_chars += len(data.strip())
        if self._hidden_len < 20_000:
            self.hidden_out.append(data[:20_000])
            self._hidden_len += len(data)


def html_to_text(html: str, max_input: int = 500_000) -> HtmlText:
    p = _Parser()
    try:
        p.feed(html[:max_input])
        p.close()
    except Exception:  # noqa: BLE001 - malformed HTML must never crash the analyzer
        pass
    return HtmlText("".join(p.out), p.hidden_chars, " ".join(p.hidden_out), p.links)


# Zero-width, bidi controls, tag characters and other invisible format chars.
def _visible_char(ch: str) -> bool:
    if ch in "\n\t":
        return True
    cat = unicodedata.category(ch)
    return not (cat in ("Cc", "Cf", "Co", "Cs", "Cn") or "\U000e0000" <= ch <= "\U000e007f")


def normalize_text(text: str, limit: int) -> tuple[str, int]:
    """NFKC-normalize, drop invisible characters, collapse whitespace, truncate.

    Returns the text and the number of invisible characters removed.
    """
    text = unicodedata.normalize("NFKC", text[: limit * 4])
    kept = [ch for ch in text if _visible_char(ch)]
    removed = len(text) - len(kept)
    text = "".join(kept).replace("\t", " ")
    text = re.sub(r"[  ]+", " ", text)
    text = re.sub(r" *\n *", "\n", text)
    text = re.sub(r"\n{3,}", "\n\n", text).strip()
    if len(text) > limit:
        text = text[:limit].rstrip() + " [truncated]"
    return text, removed


def clean_line(value: str, limit: int = 200) -> str:
    """A single header-like value: one line, no invisible characters."""
    text, _ = normalize_text(value or "", limit)
    return " ".join(text.split())
