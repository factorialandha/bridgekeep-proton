"""Settings from the admin portal (``<portal_dir>/settings.yaml``).

The owner changes settings in the portal, never by editing files. The portal
writes settings.yaml; the analyzer re-reads it when it changes and lays it
over analyzer.yaml. Only the keys in ``KEYS`` are honoured, each range
checked. A bad value keeps the value from before and is reported in
health.json ``settings_problems``; an unreadable file keeps the last good
settings. The file is opened the same hardened way as the list files.
"""

from __future__ import annotations

import os
from pathlib import Path

from . import lists
from .config import Config

FILE_NAME = "settings.yaml"
MAX_BYTES = 64 * 1024

# key in settings.yaml -> (Config field, kind, low, high)
KEYS: dict[str, tuple[str, type, float, float]] = {
    "model.enabled": ("model_enabled", bool, 0, 1),
    "model.monthly_budget_usd": ("monthly_budget_usd", float, 0, 1000),
    "thresholds.quarantine": ("quarantine_threshold", float, 0.5, 1.0),
    "thresholds.review": ("review_threshold", float, 0.3, 1.0),
    "limits.max_per_hour": ("max_per_hour", int, 1, 10_000),
    "limits.max_per_day": ("max_per_day", int, 1, 100_000),
    "imap.poll_seconds": ("poll_seconds", int, 15, 3600),
    "limits.max_moves_per_day": ("max_moves_per_day", int, 0, 5000),
}
FIELDS = tuple(f for f, *_ in KEYS.values())


def _flatten(data: dict) -> dict[str, object]:
    out: dict[str, object] = {}
    for section, body in data.items():
        if isinstance(body, dict):
            for k, v in body.items():
                out[f"{section}.{k}"] = v
        else:
            out[str(section)] = body
    return out


def _value(raw, kind: type, lo: float, hi: float):
    """The checked value, or a problem string."""
    if kind is bool:
        if isinstance(raw, bool):
            return raw
        return ValueError("must be true or false")
    if isinstance(raw, bool) or not isinstance(raw, (int, float)):
        return ValueError("must be a number")
    if kind is int and float(raw) != int(raw):
        return ValueError("must be a whole number")
    if not lo <= raw <= hi:
        return ValueError(f"must be between {lo:g} and {hi:g}")
    return kind(raw)


class Settings:
    """Keeps the analyzer.yaml values and re-applies the portal's on change."""

    def __init__(self, cfg: Config) -> None:
        self.cfg = cfg
        self.base = {f: getattr(cfg, f) for f in FIELDS}
        self.signature: tuple | None = None
        self.applied: dict[str, object] = {}     # last good overlay, by Config field
        self.problems: list[str] = []

    @property
    def path(self) -> Path | None:
        return Path(self.cfg.portal_dir) / FILE_NAME if self.cfg.portal_dir else None

    def maybe_reload(self) -> bool:
        """Re-read settings.yaml if it changed. True when something was re-read."""
        path = self.path
        try:
            sig = lists.file_signature(os.lstat(path)) if path else None
        except OSError:
            sig = None
        if sig == self.signature:
            return False
        self.signature = sig
        if sig is None:                      # no file (or removed): analyzer.yaml only
            self.applied, self.problems = {}, []
        else:
            self._read(path)
        self._apply()
        return True

    def _read(self, path: Path) -> None:
        try:
            data = lists._read_list_file(path, MAX_BYTES)
        except lists._Unusable as e:
            self.problems = [f"{FILE_NAME}: {e}; keeping the settings from before"]
            return
        problems: list[str] = []
        overlay: dict[str, object] = {}
        for key, raw in _flatten(data).items():
            spec = KEYS.get(key)
            if spec is None:
                problems.append(f"{key[:60]}: not a setting, ignored")
                continue
            field, kind, lo, hi = spec
            v = _value(raw, kind, lo, hi)
            if isinstance(v, ValueError):
                problems.append(f"{key}: {v}; keeping {self._current(field)!r}")
                if field in self.applied:
                    overlay[field] = self.applied[field]
                continue
            overlay[field] = v
        review = overlay.get("review_threshold", self.base["review_threshold"])
        quarantine = overlay.get("quarantine_threshold", self.base["quarantine_threshold"])
        if review > quarantine:
            problems.append("thresholds.review: must be at most thresholds.quarantine; keeping both from before")
            for f in ("review_threshold", "quarantine_threshold"):
                overlay.pop(f, None)
                if f in self.applied:
                    overlay[f] = self.applied[f]
        self.applied, self.problems = overlay, problems[:20]

    def _current(self, field: str):
        return self.applied.get(field, self.base[field])

    def _apply(self) -> None:
        for f in FIELDS:
            setattr(self.cfg, f, self.applied.get(f, self.base[f]))

