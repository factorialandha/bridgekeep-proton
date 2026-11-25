"""The portal's own writable folder (/portal-config, read-only to the analyzer
as /config/portal): portal.yaml (never-trash list, blocklist, keywords) and
PAUSE, backfill-request.json.

The folder belongs to the portal (10003:10002, 2750). Every write is a temp
file in the same folder, fsync, then rename, with umask 027, and nothing here
follows a symlink. Entries are checked with the analyzer's own validator (a
vendored copy, CI keeps it identical) before they are written, so the
analyzer never sees an entry it would reject.
"""

from __future__ import annotations

import datetime as dt
import json
import os
import secrets
import stat
import threading
import time
from dataclasses import dataclass
from pathlib import Path

import yaml

from ._analyzer import lists as L

LIST_NAMES = ("protect", "block", "keywords")
# Always trash takes exact addresses only: the analyzer acts on address
# blocks alone (DMARC-verified), and refuses domain blocks from the portal.
KINDS = {"protect": ("address", "domain"), "block": ("address",), "keywords": ("pattern",)}
KIND_ERRORS = {"protect": "Never trash takes an address or a domain.",
               "block": "Always trash takes exact addresses only.",
               "keywords": "Subject words only go in the Protected subject words list."}


class ConfigError(Exception):
    """Shown to the admin as is: never contains file contents."""


@dataclass
class Row:
    list: str
    kind: str
    value: str
    reason: str
    added: str
    expires: str
    subdomains: bool
    index: int          # position in portal.yaml, -1 for curated entries
    source: str         # "portal" | "file"


# settings.yaml, agreed with the analyzer: key -> (type, min, max, default).
SETTINGS = {
    "model.enabled": (bool, None, None, True),
    "model.monthly_budget_usd": (float, 0, 1000, 20.0),
    "thresholds.quarantine": (float, 0.5, 1.0, 0.97),
    "thresholds.review": (float, 0.3, 1.0, 0.70),
    "limits.max_per_hour": (int, 1, 10000, 120),
    "limits.max_per_day": (int, 1, 100000, 1000),
    "limits.max_moves_per_day": (int, 0, 5000, 200),
    "imap.poll_seconds": (int, 15, 3600, 60),
}
MAX_SETTINGS_BYTES = 64 * 1024


def _flatten(data: dict) -> dict:
    out = {}
    for key in SETTINGS:
        group, _, name = key.partition(".")
        sect = data.get(group)
        if isinstance(sect, dict) and name in sect:
            out[key] = sect[name]
    return out


def check_settings(values: dict) -> tuple[dict, list[str]]:
    """Coerce and range-check. Returns (clean values for every key, problems)."""
    clean, problems = {}, []
    for key, (typ, lo, hi, default) in SETTINGS.items():
        v = values.get(key, default)
        try:
            if typ is bool:
                if not isinstance(v, bool):
                    raise ValueError
            elif typ is int:
                if isinstance(v, bool) or float(v) != int(float(v)):
                    raise ValueError
                v = int(float(v))
            else:
                if isinstance(v, bool):
                    raise ValueError
                v = round(float(v), 4)
                if v != v:
                    raise ValueError
        except (TypeError, ValueError):
            problems.append(key)
            clean[key] = default
            continue
        if lo is not None and not lo <= v <= hi:
            problems.append(key)
            v = default
        clean[key] = v
    if clean["thresholds.review"] > clean["thresholds.quarantine"]:
        problems.append("thresholds.review")
    return clean, problems


@dataclass
class Problem:
    text: str
    list: str = ""
    index: int = -1      # position in portal.yaml when the portal can remove it
    value: str = ""      # the raw value, for Remove
    fix: str = ""        # "address": offer "protect an exact address instead"


def _raw_value(raw) -> str:
    if isinstance(raw, dict):
        for k in ("address", "domain", "pattern"):
            if raw.get(k):
                return str(raw[k])[:254]
    return ""


class PortalConfig:
    def __init__(self, directory: str, curated_dir: str = "") -> None:
        self.dir = Path(directory)
        self.curated_dir = Path(curated_dir) if curated_dir else None
        self._lock = threading.Lock()      # read-modify-write of portal.yaml
        self._clean_temp()

    def _clean_temp(self) -> None:
        """Remove temp files a crashed write left behind (regular files we own)."""
        try:
            names = os.listdir(self.dir)
        except OSError:
            return
        for n in names:
            if n.startswith(".") and n.endswith(".tmp"):
                try:
                    st = os.lstat(self.dir / n)
                    if stat.S_ISREG(st.st_mode) and st.st_uid == os.geteuid():
                        os.unlink(self.dir / n)
                except OSError:
                    pass

    # -- state ----------------------------------------------------------------

    @property
    def yaml_path(self) -> Path:
        return self.dir / "portal.yaml"

    def writable(self) -> bool:
        try:
            st = os.lstat(self.dir)
        except OSError:
            return False
        return stat.S_ISDIR(st.st_mode) and os.access(self.dir, os.W_OK)

    def paused(self) -> bool:
        return os.path.lexists(self.dir / "PAUSE")

    # -- reading ----------------------------------------------------------------

    def _read(self, path: Path, max_bytes: int) -> dict:
        if not os.path.lexists(path):
            return {}
        try:
            return L._read_list_file(path, max_bytes)
        except L._Unusable as e:
            raise ConfigError(f"{path.name}: {e}") from None

    def portal_data(self) -> dict:
        data = self._read(self.yaml_path, L.MAX_PORTAL_BYTES)
        out = {k: list(data.get(k) or []) for k in LIST_NAMES}
        out["removed"] = list(data.get("removed") or []) if isinstance(data.get("removed"), list) else []
        return out

    def rows(self, today: dt.date | None = None) -> tuple[list[Row], list[Problem]]:
        """Every entry the analyzer will use from curated.yaml and portal.yaml,
        plus problems to show (a file that can't be read, an entry it refuses),
        following the analyzer's own load() checks."""
        today = today or dt.date.today()
        problems: list[Problem] = []
        out: list[Row] = []
        removed = self.removed()
        sources = [("portal", self.yaml_path, L.MAX_PORTAL_BYTES)]
        if self.curated_dir:
            sources.insert(0, ("file", self.curated_dir / "curated.yaml", L.MAX_LIST_BYTES))
        for source, path, cap in sources:
            try:
                data = self._read(path, cap)
            except ConfigError as e:
                problems.append(Problem(str(e)))
                continue
            for list_name in LIST_NAMES:
                for i, raw in enumerate(data.get(list_name) or []):
                    where = f"{path.name} {list_name}[{i}]"
                    found: list[str] = []
                    e = L._parse_entry(raw, list_name, "curated", found, where)
                    parsed = e.value if e is not None else _raw_value(raw)
                    if e is not None and source == "portal" and list_name == "block" and e.kind != "address":
                        found.append(f"{where}: blocks from the portal must be exact addresses")
                        e = None
                    if e is not None and e.expired(today):
                        found.append(f"{where}: expired {e.expires}, ignored")
                        e = None
                    if e is None:
                        if source == "file" and (list_name, parsed) in removed:
                            continue      # a refused file entry the admin removed
                        for text in found or [f"{where}: not a valid entry, ignored"]:
                            problems.append(Problem(
                                text, list_name, i if source == "portal" else -1, parsed,
                                "address" if list_name == "protect" and "exact address" in text else ""))
                        continue
                    if source == "file" and (list_name, e.value) in removed:
                        continue          # removed in the portal (portal.yaml "removed")
                    out.append(Row(list_name, "pattern" if e.kind == "keyword" else e.kind, e.value, e.reason,
                                   e.added, e.expires, e.subdomains, i if source == "portal" else -1, source))
        return out, problems

    # -- writing -----------------------------------------------------------------

    def add(self, list_name: str, kind: str, value: str, reason: str, subdomains: bool = False,
            expires: str = "", today: dt.date | None = None) -> str:
        """Validate and append one entry. Returns its normalised value."""
        if list_name not in LIST_NAMES:
            raise ConfigError("Choose a list.")
        if kind not in KINDS[list_name]:
            raise ConfigError(KIND_ERRORS["keywords"] if kind == "pattern" else KIND_ERRORS[list_name])
        value, reason = value.strip(), " ".join(reason.split())
        if not value or len(value) > 254:
            raise ConfigError("Enter an address, domain or phrase (up to 254 characters).")
        if not reason or len(reason) > 200:
            raise ConfigError("Say why, in up to 200 characters. Every entry needs a reason.")
        if any(not ch.isprintable() for ch in value + reason):
            raise ConfigError("Remove the special characters.")
        raw: dict = {kind: value, "reason": reason, "added": (today or dt.date.today()).isoformat(),
                     "added_by": "portal"}
        if expires:
            try:
                if dt.date.fromisoformat(expires) <= (today or dt.date.today()):
                    raise ConfigError("The expiry date must be in the future.")
            except ValueError:
                raise ConfigError("Expiry must be a date (YYYY-MM-DD).") from None
            raw["expires"] = expires
        if subdomains and kind == "domain":
            raw["subdomains"] = True
        problems: list[str] = []
        entry = L._parse_entry(raw, list_name, "curated", problems, "new entry")
        if entry is None:
            raise ConfigError(problems[0].removeprefix("new entry: ") if problems else "Not a valid entry.")
        raw[kind] = entry.value
        with self._lock:
            self._append(list_name, entry, raw)
        return entry.value

    def _append(self, list_name: str, entry, raw: dict) -> None:
        data = self.portal_data()
        for old in data[list_name]:
            p: list[str] = []
            e = L._parse_entry(old, list_name, "curated", p, "")
            if e is not None and e.kind == entry.kind and e.value == entry.value:
                raise ConfigError(f"{entry.value} is already on this list.")
        if sum(len(v) for v in data.values()) >= L.MAX_LIST_ENTRIES:
            raise ConfigError(f"The portal's lists are full ({L.MAX_LIST_ENTRIES} entries).")
        data[list_name].append(raw)
        self._write(data)

    # Entries of the host's curated.yaml can't be edited here (the portal never
    # writes that file); removing one lists it under portal.yaml "removed",
    # which the analyzer's load() drops.
    def removed(self) -> set[tuple[str, str]]:
        try:
            data = self._read(self.yaml_path, L.MAX_PORTAL_BYTES)
        except ConfigError:
            return set()
        return L.removed_entries(data, [])

    def remove_file_entry(self, list_name: str, value: str) -> None:
        with self._lock:
            rows, problems = self.rows()
            if not (any(r.source == "file" and r.list == list_name and r.value == value for r in rows)
                    or any(p.index < 0 and p.list == list_name and p.value == value for p in problems)):
                raise ConfigError("That entry has changed. Reload the page.")
            data = self.portal_data()
            data["removed"].append({"list": list_name, "value": value})
            self._write(data)

    def restore_file_entry(self, list_name: str, value: str) -> None:
        with self._lock:
            data = self.portal_data()
            keep = [r for r in data["removed"]
                    if not (isinstance(r, dict) and r.get("list") == list_name and r.get("value") == value)]
            if len(keep) == len(data["removed"]):
                raise ConfigError("That entry has changed. Reload the page.")
            data["removed"] = keep
            self._write(data)

    def remove(self, list_name: str, index: int, value: str) -> None:
        """Remove entry `index` of `list_name`, only if it still holds `value`
        (so two tabs can't remove the wrong one)."""
        with self._lock:
            self._remove(list_name, index, value)

    def _remove(self, list_name: str, index: int, value: str) -> None:
        data = self.portal_data()
        items = data.get(list_name)
        if items is None or not 0 <= index < len(items):
            raise ConfigError("That entry has changed. Reload the page.")
        p: list[str] = []
        e = L._parse_entry(items[index], list_name, "curated", p, "")
        # The page shows (and sends back) the normalised value when the entry
        # parses, else the raw one capped by _raw_value; compare the same way.
        current = e.value if e is not None else _raw_value(items[index])
        if current != value:
            raise ConfigError("That entry has changed. Reload the page.")
        del items[index]
        self._write(data)

    def _write(self, data: dict) -> None:
        body = ("# Written by the Bridgekeep admin portal. Edit it there; your own entries\n"
                "# belong in config/lists/curated.yaml.\n"
                + yaml.safe_dump({k: v for k, v in data.items() if v}, sort_keys=False, allow_unicode=True))
        raw = body.encode("utf-8")
        if len(raw) > L.MAX_PORTAL_BYTES:
            raise ConfigError(f"The portal's lists would be over {L.MAX_PORTAL_BYTES // 1024} KB.")
        self._replace("portal.yaml", raw)

    def _replace(self, name: str, raw: bytes) -> None:
        if not self.writable():
            raise ConfigError("The portal can't write its settings folder. Run ./bridgekeep setup on the host.")
        tmp = self.dir / f".{name}.{secrets.token_hex(4)}.tmp"
        old = os.umask(0o027)
        try:
            fd = os.open(tmp, os.O_WRONLY | os.O_CREAT | os.O_EXCL | getattr(os, "O_NOFOLLOW", 0), 0o640)
            with os.fdopen(fd, "wb") as f:
                f.write(raw)
                f.flush()
                os.fsync(f.fileno())
            os.replace(tmp, self.dir / name)     # replaces a planted symlink rather than following it
            dfd = os.open(self.dir, os.O_RDONLY)
            try:
                os.fsync(dfd)
            finally:
                os.close(dfd)
        except OSError as e:
            try:
                os.unlink(tmp)
            except OSError:
                pass
            raise ConfigError(f"Couldn't save ({e.strerror}).") from None
        finally:
            os.umask(old)

    @property
    def settings_path(self) -> Path:
        return self.dir / "settings.yaml"

    def settings(self) -> dict:
        """Current analyzer settings (defaults for anything not set)."""
        data = self._read(self.settings_path, MAX_SETTINGS_BYTES)
        clean, _ = check_settings(_flatten(data))
        return clean

    def saved_settings(self) -> set[str]:
        """The keys settings.yaml actually sets. For the others the analyzer
        uses its own analyzer.yaml, which may differ from SETTINGS' defaults."""
        return set(_flatten(self._read(self.settings_path, MAX_SETTINGS_BYTES)))

    def save_settings(self, values: dict) -> list[str]:
        """Validate and write every key. Returns the keys that changed."""
        clean, problems = check_settings(values)
        if problems:
            raise ConfigError("Check " + ", ".join(problems) + ".")
        with self._lock:
            old = self.settings()
            out: dict = {}
            for key, v in clean.items():
                group, _, name = key.partition(".")
                out.setdefault(group, {})[name] = v
            body = ("# Written by the Bridgekeep admin portal. Change these on its Analyzer page.\n"
                    + yaml.safe_dump(out, sort_keys=False))
            self._replace("settings.yaml", body.encode("utf-8"))
        return [k for k in SETTINGS if old[k] != clean[k]]

    # Corrections (analyzer feedback.py): one JSON line each, rotated at 1 MB.
    FEEDBACK = "feedback.jsonl"
    FEEDBACK_ROTATE = 1024 * 1024
    FEEDBACK_LABELS = ("legitimate", "promotional", "spam", "phishing", "withdrawn")   # withdrawn: Clear

    def append_feedback(self, message_key: str, label: str, ts: int | None = None) -> None:
        if label not in self.FEEDBACK_LABELS or not 0 < len(message_key) <= 200 or not message_key.isprintable():
            raise ConfigError("Not a correction the analyzer can use.")
        line = (json.dumps({"message_key": message_key, "label": label, "scope": "message",
                            "ts": int(ts if ts is not None else time.time()), "by": "portal"}) + "\n").encode("utf-8")
        if len(line) > 1024:
            raise ConfigError("Not a correction the analyzer can use.")
        if not self.writable():
            raise ConfigError("The portal can't write its settings folder. Run ./bridgekeep setup on the host.")
        path = self.dir / self.FEEDBACK
        with self._lock:
            try:
                st = os.lstat(path)
                if not stat.S_ISREG(st.st_mode) or st.st_size >= self.FEEDBACK_ROTATE:
                    os.replace(path, self.dir / (self.FEEDBACK + ".1"))   # a planted link is moved aside, never followed
            except FileNotFoundError:
                pass
            except OSError as e:
                raise ConfigError(f"Couldn't save ({e.strerror}).") from None
            old = os.umask(0o027)
            try:
                fd = os.open(path, os.O_WRONLY | os.O_APPEND | os.O_CREAT | getattr(os, "O_NOFOLLOW", 0), 0o640)
                try:
                    if not stat.S_ISREG(os.fstat(fd).st_mode):
                        raise ConfigError("Couldn't save (not a regular file).")
                    os.write(fd, line)
                    os.fsync(fd)
                finally:
                    os.close(fd)
            except OSError as e:
                raise ConfigError(f"Couldn't save ({e.strerror}).") from None
            finally:
                os.umask(old)

    # Older mail (analyzer backfill.py): one request file, replaced each time.
    # The analyzer reads it each poll and acts on a new id once.
    BACKFILL = "backfill-request.json"

    def request_backfill(self, req: dict) -> None:
        raw = json.dumps(req, sort_keys=True).encode("utf-8")
        if len(raw) > 1024:
            raise ConfigError("Not a request the portal can make.")
        with self._lock:
            self._replace(self.BACKFILL, raw)

    def backfill_requested_at(self) -> float:
        try:
            st = os.lstat(self.dir / self.BACKFILL)
        except OSError:
            return 0.0
        return st.st_mtime if stat.S_ISREG(st.st_mode) else 0.0

    # Shadow / live (contract with the analyzer, 2026-11-24): mode.json holds
    # {"mode": "live"|"shadow", "ts": <unix>, "by": "portal"}. A missing or
    # invalid file means shadow, and PAUSE always wins over live. The analyzer
    # and its IMAP proxy read it; the portal only ever writes it whole.
    MODE = "mode.json"
    MAX_MODE_BYTES = 1024

    def mode_requested(self) -> str:
        try:
            fd = os.open(self.dir / self.MODE, os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0) | getattr(os, "O_NONBLOCK", 0))
        except OSError:
            return "shadow"
        try:
            with os.fdopen(fd, "rb") as f:
                if not stat.S_ISREG(os.fstat(f.fileno()).st_mode):
                    return "shadow"
                raw = f.read(self.MAX_MODE_BYTES + 1)
            data = json.loads(raw.decode("utf-8")) if len(raw) <= self.MAX_MODE_BYTES else None
        except (OSError, ValueError, UnicodeDecodeError):
            return "shadow"
        return "live" if isinstance(data, dict) and data.get("mode") == "live" else "shadow"

    def set_mode(self, mode: str) -> None:
        if mode not in ("live", "shadow"):
            raise ValueError(mode)
        raw = json.dumps({"mode": mode, "ts": int(time.time()), "by": "portal"}).encode("utf-8") + b"\n"
        self._replace(self.MODE, raw)

    def set_paused(self, on: bool) -> None:
        p = self.dir / "PAUSE"
        if on:
            if not os.path.lexists(p):
                self._replace("PAUSE", b"Paused from the admin portal\n")
        else:
            try:
                os.unlink(p)                      # removes a link itself, never its target
            except FileNotFoundError:
                pass
            except OSError as e:
                raise ConfigError(f"Couldn't resume ({e.strerror}).") from None
