"""Configuration. Every failure direction is "shadow mode, move nothing".

A missing or unreadable config, a config problem, the pause file existing or
being unreadable, a missing or odd mode.json: all mean shadow mode (security
review A15). Live mode is switched on only from the portal (or turned off
with ``./bridgekeep analyzer shadow``), never in analyzer.yaml: see mode.py.
"""

from __future__ import annotations

import os
from dataclasses import dataclass, field
from pathlib import Path

import yaml

from . import auth
from . import mode as modes
from .classify import DEFAULT_MODEL

DEFAULT_CONFIG_PATH = "/config/analyzer.yaml"


@dataclass
class Config:
    mode: str = "shadow"
    quarantine_threshold: float = 0.97
    review_threshold: float = 0.70
    quarantine_folder: str = "AI-Quarantine"
    review_folder: str = "AI-Review"
    digest_folder: str = "AI-Digest"
    model: str = DEFAULT_MODEL
    provider: str = "anthropic"        # anthropic | openai | gemini | local (set by the host, never settings.yaml)
    endpoint: str = ""                 # local only: http(s)://IP:port/v1
    price_in_per_mtok: float | None = None    # USD per million tokens; None = the built-in price
    price_out_per_mtok: float | None = None
    api_key_file: str = "/run/secrets/anthropic_api_key"
    api_proxy: str = ""
    model_enabled: bool = True  # false: rules and lists only, no API calls  # e.g. http://egress-proxy:3128 in the compose setup
    monthly_budget_usd: float = 20.0   # owner decision, 2026-11-24
    max_per_hour: int = 120
    max_per_day: int = 1000
    max_moves_per_day: int = 200       # live mode: moves a day before falling back to log only
    body_chars: int = 3000
    lists_dir: str = "/config/lists"
    db_path: str = "/data/analyzer.db"
    pause_file: str = "/config/PAUSE"
    alert_dir: str = "/run/bridgekeep/alerts"   # the host's notifier picks alerts up here
    portal_dir: str = "/config/portal"   # the admin portal's own folder: portal.yaml, PAUSE
    store_subjects: bool = True
    retention_days: int = 90
    trusted_authserv: tuple[str, ...] = auth.DEFAULT_TRUSTED_AUTHSERV_SUFFIXES
    # By default the analyzer reaches Bridge only through the allowlisting
    # proxy (imapproxy.py), with a token instead of the Bridge password.
    imap_host: str = "imap-proxy"
    imap_port: int = 1143
    imap_tls: str = "none"  # "none" to the proxy on its private network; "starttls" direct
    imap_username: str = "analyzer"
    imap_password_file: str = "/run/secrets/analyzer_imap_token"
    imap_cert_file: str = "/config/bridge-cert.pem"
    imap_folder: str = "INBOX"
    poll_seconds: int = 60
    health_file: str = "/data/health.json"
    problems: list[str] = field(default_factory=list)

    def paused(self) -> bool:
        """The kill switch, checked before every decision, not only at start."""
        return modes.paused(self.portal_dir, self.pause_file)

    def requested_mode(self) -> modes.Requested:
        return modes.requested(self.portal_dir)

    def live_since(self) -> int | None:
        """When live mode was switched on, if it is in effect now; read fresh."""
        r = modes.live_allowed(self.portal_dir, self.pause_file)
        if r.mode != "live" or self.problems or self.imap_folder.upper() != "INBOX":
            return None
        return r.since

    def effective_mode(self) -> str:
        return "live" if self.live_since() is not None else "shadow"

    def mode_problem(self) -> str | None:
        r = modes.requested(self.portal_dir)
        if r.mode != "live":
            return r.problem
        if self.paused():
            return "paused"
        if self.problems:
            return "the analyzer's configuration has a problem: " + self.problems[0][:120]
        if self.imap_folder.upper() != "INBOX":
            return "live mode only moves mail out of INBOX"
        return None

    def review_mailbox(self) -> str:
        return modes.mailbox(self.review_folder)

    def quarantine_mailbox(self) -> str:
        return modes.mailbox(self.quarantine_folder)

    def read_api_key(self) -> str:
        return read_secret(self.api_key_file, "API key")

    def read_imap_password(self) -> str:
        return read_secret(self.imap_password_file, "IMAP password or token")


FOLDER_NAME = __import__("re").compile(r"[A-Za-z0-9][A-Za-z0-9 _.-]{0,59}")
RESERVED_FOLDERS = {"inbox", "trash", "spam", "junk", "sent", "drafts", "all mail", "archive", "starred",
                    "folders", "labels"}


def read_secret(path: str, what: str) -> str:
    try:
        value = Path(path).read_text(encoding="utf-8").strip()
    except OSError as e:
        raise SystemExit(f"Cannot read the {what} file {path}: {e.strerror}") from None
    if not value:
        raise SystemExit(f"The {what} file {path} is empty")
    return value


def _num(d: dict, key: str, default, lo, hi, problems: list[str], kind=float):
    if key not in d:
        return default
    try:
        v = kind(d[key])
    except (TypeError, ValueError):
        problems.append(f"{key}: not a number")
        return default
    if not lo <= v <= hi:
        problems.append(f"{key}: must be between {lo} and {hi}")
        return default
    return v


def load(path: str | None = None) -> Config:
    path = path or os.environ.get("ANALYZER_CONFIG", DEFAULT_CONFIG_PATH)
    cfg = Config()
    p = Path(path)
    if not p.exists():
        return cfg  # defaults are shadow mode
    try:
        data = yaml.safe_load(p.read_text(encoding="utf-8")) or {}
        if not isinstance(data, dict):
            raise ValueError("top level must be a mapping")
    except (OSError, yaml.YAMLError, ValueError, UnicodeDecodeError) as e:
        cfg.problems.append(f"{p.name}: cannot read ({e.__class__.__name__}); staying in shadow mode")
        return cfg

    mode = str(data.get("mode", "shadow"))
    if mode != "shadow":
        cfg.problems.append(
            f"mode: '{mode}' is not set here; switch live mode on in the portal (Analyzer page)"
        )
    th = data.get("thresholds") or {}
    cfg.quarantine_threshold = _num(th, "quarantine", cfg.quarantine_threshold, 0.5, 1.0, cfg.problems)
    cfg.review_threshold = _num(th, "review", cfg.review_threshold, 0.3, 1.0, cfg.problems)
    if cfg.review_threshold > cfg.quarantine_threshold:
        cfg.problems.append("thresholds: review must not be above quarantine")
        cfg.review_threshold, cfg.quarantine_threshold = 0.70, 0.97
    folders = data.get("folders") or {}
    cfg.quarantine_folder = str(folders.get("quarantine", cfg.quarantine_folder))
    cfg.review_folder = str(folders.get("review", cfg.review_folder))
    cfg.digest_folder = str(folders.get("digest", cfg.digest_folder))
    for key, default in (("quarantine_folder", "AI-Quarantine"), ("review_folder", "AI-Review")):
        name = getattr(cfg, key)
        base = name[len("Folders/"):] if name.startswith("Folders/") else name
        if (not FOLDER_NAME.fullmatch(base) or base.strip().lower() in RESERVED_FOLDERS):
            cfg.problems.append(f"folders.{key.split('_')[0]}: must be a folder of its own "
                                "(letters, digits, space, - _ .), not Inbox, Trash, Spam, Sent, Drafts or All Mail")
            setattr(cfg, key, default)
    if cfg.quarantine_folder == cfg.review_folder:
        cfg.problems.append("folders: review and quarantine must be different folders")
        cfg.quarantine_folder, cfg.review_folder = "AI-Quarantine", "AI-Review"
    model = data.get("model") or {}
    from .providers import PROVIDERS, check_local_endpoint
    cfg.provider = str(model.get("provider", cfg.provider)).lower()
    if cfg.provider not in PROVIDERS:
        cfg.problems.append(f"model.provider: must be one of {', '.join(PROVIDERS)}")
        cfg.provider, cfg.model_enabled = "anthropic", False
    cfg.model = str(model.get("name", cfg.model if cfg.provider == "anthropic" else ""))[:100]
    if not cfg.model:
        cfg.problems.append("model.name: needed for this provider")
    cfg.endpoint = str(model.get("endpoint", "") or "")
    if cfg.provider == "local":
        try:
            check_local_endpoint(cfg.endpoint)
        except ValueError as e:
            cfg.problems.append(f"model.endpoint: {e}")
    for key in ("price_in_per_mtok", "price_out_per_mtok"):
        if model.get(key) is not None:
            setattr(cfg, key, _num(model, key, 0.0, 0, 1000, cfg.problems))
    # One key file per vendor; a key is never sent to another vendor.
    cfg.api_key_file = str(model.get("api_key_file", f"/run/secrets/{cfg.provider}_api_key"))
    cfg.model_enabled = bool(model.get("enabled", cfg.model_enabled))
    cfg.api_proxy = str(model.get("proxy", cfg.api_proxy) or "")
    if cfg.api_proxy and not cfg.api_proxy.startswith("http://"):
        cfg.problems.append("model.proxy: must be an http:// URL such as http://egress-proxy:3128")
        cfg.api_proxy = ""
    cfg.monthly_budget_usd = _num(model, "monthly_budget_usd", cfg.monthly_budget_usd, 0, 1000, cfg.problems)
    lim = data.get("limits") or {}
    cfg.max_per_hour = _num(lim, "max_per_hour", cfg.max_per_hour, 1, 10_000, cfg.problems, int)
    cfg.max_per_day = _num(lim, "max_per_day", cfg.max_per_day, 1, 100_000, cfg.problems, int)
    cfg.max_moves_per_day = _num(lim, "max_moves_per_day", cfg.max_moves_per_day, 0, 5000, cfg.problems, int)
    cfg.body_chars = _num(lim, "body_chars", cfg.body_chars, 200, 20_000, cfg.problems, int)
    cfg.lists_dir = str(data.get("lists_dir", cfg.lists_dir))
    cfg.db_path = str(data.get("db", cfg.db_path))
    cfg.pause_file = str(data.get("pause_file", cfg.pause_file))
    cfg.portal_dir = str(data.get("portal_dir", cfg.portal_dir) or "")
    log = data.get("log") or {}
    cfg.store_subjects = bool(log.get("store_subjects", cfg.store_subjects))
    cfg.retention_days = _num(log, "retention_days", cfg.retention_days, 1, 3650, cfg.problems, int)
    imap = data.get("imap") or {}
    cfg.imap_host = str(imap.get("host", cfg.imap_host))
    cfg.imap_port = _num(imap, "port", cfg.imap_port, 1, 65535, cfg.problems, int)
    cfg.imap_tls = str(imap.get("tls", cfg.imap_tls)).lower()
    if cfg.imap_tls not in ("none", "starttls"):
        cfg.problems.append("imap.tls: must be none (through the proxy) or starttls")
        cfg.imap_tls = "starttls"
    cfg.imap_username = str(imap.get("username", cfg.imap_username))
    cfg.imap_password_file = str(imap.get("password_file", cfg.imap_password_file))
    cfg.imap_cert_file = str(imap.get("cert_file", cfg.imap_cert_file))
    cfg.imap_folder = str(imap.get("folder", cfg.imap_folder))
    cfg.poll_seconds = _num(imap, "poll_seconds", cfg.poll_seconds, 15, 3600, cfg.problems, int)
    cfg.health_file = str(data.get("health_file", cfg.health_file))
    if data.get("trusted_authserv"):
        cfg.trusted_authserv = tuple(str(s).lower() for s in data["trusted_authserv"])
    return cfg
