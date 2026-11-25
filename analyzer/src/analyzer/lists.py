"""Never-trash list and blocklist (scoping doc 6A.4a, security review A7-A12).

Three files, mounted read-only:

* ``curated.yaml``: written only by the owner (a Git repo they own).
* ``portal.yaml``: written by the admin portal, same format and same trust
  as curated.yaml, so the portal never rewrites the owner's file.
  Its ``removed`` list names curated.yaml entries the admin removed in the
  portal (``{list, value}``); those are dropped on load, so every entry can be
  removed from the portal without the portal ever writing the owner's file.
* ``learned.yaml``: entries suggested by deterministic rules; lower trust.
  This release only reads it; nothing writes it yet.

Entries without a reason are rejected on load. Free-mail domains can only be
protected as exact addresses. Nothing in an email and nothing the model says
can change any of them.
"""

from __future__ import annotations

import datetime as dt
import os
import stat
from dataclasses import dataclass, field
from pathlib import Path

import yaml

from .text import normalize_domain

# Common multi-part public suffixes. A protect entry on one of these (with
# subdomains: true) would cover a whole country's or host's domains.
PUBLIC_SUFFIXES = frozenset(
    """co.uk org.uk me.uk ac.uk gov.uk ltd.uk plc.uk net.uk com.au net.au org.au edu.au gov.au
    co.nz org.nz net.nz co.jp ne.jp or.jp ac.jp co.kr co.in net.in org.in co.za org.za
    com.br net.br org.br com.mx com.ar com.cn net.cn org.cn com.hk com.sg com.tw com.tr
    com.my com.ph com.pk com.ng co.il co.id gov.in github.io gitlab.io herokuapp.com
    netlify.app vercel.app pages.dev workers.dev blogspot.com appspot.com web.app
    firebaseapp.com azurewebsites.net cloudfront.net s3.amazonaws.com""".split()
)

FREEMAIL = frozenset(
    """gmail.com googlemail.com outlook.com hotmail.com live.com msn.com yahoo.com ymail.com
    aol.com icloud.com me.com mac.com proton.me protonmail.com protonmail.ch pm.me gmx.com gmx.de
    gmx.net web.de mail.com yandex.com yandex.ru mail.ru zoho.com tutanota.com tuta.io
    fastmail.com hey.com qq.com 163.com 126.com
    sendgrid.net mcsv.net mailchimpapp.net mandrillapp.com amazonses.com onmicrosoft.com
    mailgun.org mailgun.net sparkpostmail.com mailjet.com sendinblue.com brevo.com
    postmarkapp.com mtasv.net hubspotemail.net""".split()
)
# The second half are shared sending services: anyone can send verified
# mail from them, so like free mail they never stand for one sender.


def shared_domain(domain: str) -> bool:
    """Free-mail or shared-sending domain (or a subdomain of one, such as
    tenant.onmicrosoft.com): trust must be keyed by the exact address."""
    domain = (domain or "").lower().rstrip(".")
    return any(domain == d or domain.endswith("." + d) for d in FREEMAIL)

# Characters attackers swap into lookalike domains, mapped to what they imitate.
_CONFUSABLE = str.maketrans({"0": "o", "1": "l", "3": "e", "5": "s", "@": "a", "$": "s", "|": "l",
                             "а": "a", "е": "e", "о": "o", "р": "p", "с": "c", "х": "x", "у": "y",
                             "і": "i", "ј": "j", "ԁ": "d", "ɡ": "g", "ո": "n", "ս": "u"})


@dataclass
class Entry:
    kind: str                 # "address" | "domain" | "keyword"
    value: str
    reason: str
    list: str                 # "protect" | "block" | "keywords"
    source: str = "manual"    # manual | learned | imported
    file: str = "curated"     # curated | learned
    added: str = ""
    expires: str = ""
    subdomains: bool = False
    origin: str = ""          # the file it came from, for keeping the last good copy

    @property
    def trusted(self) -> bool:
        return self.file == "curated"

    def expired(self, today: dt.date) -> bool:
        if not self.expires:
            return False
        try:
            return dt.date.fromisoformat(str(self.expires)) < today
        except ValueError:
            return True


@dataclass
class Lists:
    protect: list[Entry] = field(default_factory=list)
    block: list[Entry] = field(default_factory=list)
    keywords: list[Entry] = field(default_factory=list)
    problems: list[str] = field(default_factory=list)
    mtimes: dict[str, tuple] = field(default_factory=dict)   # path -> file_signature()
    removed: set = field(default_factory=set)                 # (list, value) from portal.yaml


def _skeleton(domain: str) -> str:
    return domain.translate(_CONFUSABLE).replace("rn", "m").replace("vv", "w")


def _unicode(domain: str) -> str:
    try:
        return domain.encode("ascii").decode("idna")
    except UnicodeError:
        return domain


def _within_one_edit(a: str, b: str) -> bool:
    if a == b or abs(len(a) - len(b)) > 1:
        return a == b
    if len(a) > len(b):
        a, b = b, a
    i = j = edits = 0
    while i < len(a) and j < len(b):
        if a[i] != b[j]:
            edits += 1
            if edits > 1:
                return False
            if len(a) == len(b):
                i += 1
            j += 1
        else:
            i += 1
            j += 1
    return edits + (len(b) - j) + (len(a) - i) <= 1


def _parse_entry(raw: dict, list_name: str, file_label: str, problems: list[str], where: str) -> Entry | None:
    if not isinstance(raw, dict):
        problems.append(f"{where}: entry is not a mapping")
        return None
    reason = str(raw.get("reason") or "").strip()
    keys = [k for k in ("address", "domain", "pattern") if raw.get(k)]
    if list_name == "keywords":
        keys = ["pattern"] if raw.get("pattern") else []
    if len(keys) != 1:
        problems.append(f"{where}: needs exactly one of address/domain" + ("/pattern" if list_name == "keywords" else ""))
        return None
    if not reason:
        problems.append(f"{where}: missing reason")
        return None
    key = keys[0]
    value = str(raw[key]).strip()
    if key == "address":
        local, _, dom = value.rpartition("@")
        if not local or not dom:
            problems.append(f"{where}: '{value}' is not an email address")
            return None
        value = f"{local.lower()}@{normalize_domain(dom)}"
    elif key == "domain":
        value = normalize_domain(value.lstrip("*."))
        if shared_domain(value) and list_name == "protect":
            problems.append(
                f"{where}: {value} is a free-mail or shared sending domain that anyone can send from, "
                "so it is now refused. Protect the exact address instead"
            )
            return None
        if "." not in value:
            problems.append(f"{where}: '{value}' is not a domain")
            return None
        if value in PUBLIC_SUFFIXES and list_name == "protect":
            problems.append(f"{where}: {value} is a public suffix shared by many owners. Protect the full domain")
            return None
    else:
        value = value.lower()
        if len(value) < 4:
            problems.append(f"{where}: keyword '{value}' is too short")
            return None
    return Entry(
        kind="keyword" if key == "pattern" else key,
        value=value,
        reason=reason[:200],
        list=list_name,
        source=str(raw.get("source") or ("manual" if file_label == "curated" else "learned")),
        file=file_label,
        added=str(raw.get("added") or ""),
        expires=str(raw.get("expires") or ""),
        subdomains=bool(raw.get("subdomains", False)),
    )


# portal.yaml is written by the admin portal into its own directory (mounted
# read-write into the portal only, so it can replace the file atomically). It is
# trusted like curated.yaml, so the owner's hand-edited file is never rewritten.
def list_files(directory: str | os.PathLike, portal_dir: str | os.PathLike | None = None) -> list[tuple[Path, str]]:
    """(path, trust) of every list file, in load order."""
    files = [(Path(directory) / "curated.yaml", "curated")]
    if portal_dir:
        files.append((Path(portal_dir) / "portal.yaml", "curated"))
    files.append((Path(directory) / "learned.yaml", "learned"))
    return files


# A file over either limit is skipped whole (and reported), so a runaway
# writer cannot stall the analyzer with a huge YAML file.
MAX_LIST_BYTES = 1024 * 1024
MAX_PORTAL_BYTES = 256 * 1024
MAX_LIST_ENTRIES = 5000


class _Unusable(Exception):
    pass


def _read_list_file(path: Path, max_bytes: int):
    """Parse one list file, or raise _Unusable with a message that never
    quotes the file. Symlinks, FIFOs and devices are refused, so a planted
    link to /run/secrets/... is never opened, let alone echoed."""
    try:
        fd = os.open(path, os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0) | getattr(os, "O_NONBLOCK", 0))
    except OSError:
        raise _Unusable("not a regular file or not readable, ignored") from None
    with os.fdopen(fd, "rb") as f:
        st = os.fstat(f.fileno())
        if not stat.S_ISREG(st.st_mode):
            raise _Unusable("not a regular file, ignored")
        raw = f.read(max_bytes + 1)
    if len(raw) > max_bytes:
        raise _Unusable(f"larger than {max_bytes // 1024} KB, ignored")
    try:
        data = yaml.safe_load(raw.decode("utf-8")) or {}
    except (yaml.YAMLError, UnicodeDecodeError) as e:
        raise _Unusable(f"cannot read ({type(e).__name__})") from None
    if not isinstance(data, dict):
        raise _Unusable("top level must be a mapping")
    count = sum(len(v) for k, v in data.items() if k in ("protect", "block", "keywords", "removed") and isinstance(v, list))
    if count > MAX_LIST_ENTRIES:
        raise _Unusable(f"more than {MAX_LIST_ENTRIES} entries, ignored")
    return data


def removed_entries(data: dict, problems: list[str], where: str = "portal.yaml") -> set[tuple[str, str]]:
    """portal.yaml's ``removed``: (list, value) pairs of curated.yaml entries to drop."""
    out: set[tuple[str, str]] = set()
    items = data.get("removed") or []
    if not isinstance(items, list):
        problems.append(f"{where} removed: must be a list, ignored")
        return out
    for i, raw in enumerate(items):
        ok = (isinstance(raw, dict) and raw.get("list") in ("protect", "block", "keywords")
              and isinstance(raw.get("value"), str) and 0 < len(raw["value"]) <= 254)
        if not ok:
            problems.append(f"{where} removed[{i}]: needs a list and a value, ignored")
            continue
        out.add((raw["list"], raw["value"]))
    return out


def file_signature(st: os.stat_result) -> tuple:
    """Changes whenever a file is rewritten in place or replaced by a rename."""
    return (st.st_mtime_ns, st.st_ino, st.st_size)


def load(directory: str | os.PathLike, today: dt.date | None = None,
         portal_dir: str | os.PathLike | None = None, previous: Lists | None = None) -> Lists:
    """Load curated.yaml, portal.yaml and learned.yaml. Missing files mean empty lists.

    With ``previous`` (a hot reload), a file that has become unusable keeps
    the entries it had last time, so a bad write never drops protected senders."""
    today = today or dt.date.today()
    out = Lists()
    removed: set[tuple[str, str]] = set()
    curated_path = str(Path(directory) / "curated.yaml")
    for path, file_label in list_files(directory, portal_dir):
        file_name = path.name
        try:
            out.mtimes[str(path)] = file_signature(os.lstat(path))
        except OSError:
            continue  # missing
        try:
            data = _read_list_file(path, MAX_PORTAL_BYTES if file_name == "portal.yaml" else MAX_LIST_BYTES)
        except _Unusable as e:
            kept = 0
            for list_name in ("protect", "block", "keywords"):
                for old in getattr(previous, list_name, []) if previous else []:
                    if old.origin == str(path):
                        getattr(out, list_name).append(old)
                        kept += 1
            out.problems.append(f"{file_name}: {e}" + (f"; kept the last good {kept} entries" if kept else ""))
            if file_name == "portal.yaml" and previous is not None:
                removed |= previous.removed
            continue
        if file_name == "portal.yaml":
            removed = removed_entries(data, out.problems)
        for list_name in ("protect", "block", "keywords"):
            if file_label == "learned" and list_name == "keywords":
                continue
            for i, raw in enumerate(data.get(list_name) or []):
                where = f"{path.name} {list_name}[{i}]"
                e = _parse_entry(raw, list_name, file_label, out.problems, where)
                if e is None:
                    continue
                e.origin = str(path)
                if file_name == "portal.yaml":
                    e.source = "portal"   # whatever the file says, so the log can't claim the owner added it
                if file_name == "portal.yaml" and list_name == "block" and e.kind != "address":
                    out.problems.append(f"{where}: blocks from the portal must be exact addresses")
                    continue
                if file_label == "learned" and e.kind != "address":
                    out.problems.append(f"{where}: learned entries must be exact addresses")
                    continue
                if e.expired(today):
                    out.problems.append(f"{where}: expired {e.expires}, ignored")
                    continue
                getattr(out, list_name).append(e)
    # Entries of the owner's file that they removed in the portal.
    out.removed = removed
    for list_name in ("protect", "block", "keywords"):
        kept = [e for e in getattr(out, list_name)
                if not (e.origin == curated_path and (list_name, e.value) in removed)]
        setattr(out, list_name, kept)
    protected = {e.value for e in out.protect}
    for e in out.block:
        if e.value in protected:
            out.problems.append(f"block {e.value}: also protected; the never-trash list wins")
    return out


def _domain_match(entry: Entry, domain: str) -> bool:
    return domain == entry.value or (entry.subdomains and domain.endswith("." + entry.value))


def _match(entries: list[Entry], addr: str, domain: str) -> Entry | None:
    for e in entries:
        if e.kind == "address" and addr and addr == e.value:
            return e
    for e in entries:
        if e.kind == "domain" and domain and _domain_match(e, domain):
            return e
    return None


@dataclass
class ListHits:
    protected: Entry | None = None
    blocked: Entry | None = None
    keyword: Entry | None = None
    lookalike_of: str = ""


def check(lists: Lists, addr: str, domain: str, subject: str) -> ListHits:
    hits = ListHits(
        protected=_match(lists.protect, addr, domain),
        blocked=_match(lists.block, addr, domain),
    )
    low = subject.lower()
    hits.keyword = next((k for k in lists.keywords if k.value in low), None)
    if domain and not hits.protected:
        sk = _skeleton(_unicode(domain))
        for e in lists.protect:
            target = e.value.rpartition("@")[2] if e.kind == "address" else e.value
            if target in FREEMAIL or domain == target or domain.endswith("." + target):
                continue
            tsk = _skeleton(target)
            if sk == tsk or _within_one_edit(sk, tsk):
                hits.lookalike_of = target
                break
    return hits
