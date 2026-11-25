"""IMAP command-allowlist proxy between the analyzer and Bridge (review A1).

The analyzer never holds the Bridge password. It logs in to this proxy with
a separate token; the proxy holds the Bridge password, logs in to Bridge
itself (STARTTLS, pinned certificate) and then forwards only commands on a
short list. Everything else is answered with NO and never reaches Bridge:

* before login: CAPABILITY, NOOP, LOGOUT, LOGIN <any user> <token>
* after login:  CAPABILITY, NOOP, LOGOUT,
                EXAMINE <allowed folder>              (read-only open)
                UID SEARCH ALL | UID SEARCH UID <n>:<m|*>
                UID FETCH <uid set> (<items>)         where every item is
                    UID, FLAGS, RFC822.SIZE, INTERNALDATE, ENVELOPE,
                    BODYSTRUCTURE or BODY.PEEK[<section>]<<start>.<len>>

So no SELECT, STORE, COPY, MOVE, EXPUNGE, DELETE, APPEND, CREATE, RENAME,
AUTHENTICATE, ENABLE or IDLE, no plain FETCH or BODY[] (which would mark mail
read), no client literals and no search keys that could be abused. A client
that sends three refused commands is disconnected: a well-behaved analyzer
never sends one, so that is treated as a sign it has been compromised.

Live mode (security review of live mode) adds exactly these, each checked
again here whatever the analyzer believes:

* SELECT INBOX                     only while mode.json says live, no PAUSE
* SELECT <AI-Review|AI-Quarantine>  while there is no PAUSE (for the undo)
* CREATE <AI-Review|AI-Quarantine>  only while live
* UID MOVE <one uid> <AI-Review|AI-Quarantine>   from INBOX, only while live,
  at most ``max_moves_per_day`` a day (counted on a volume; fail closed)
* UID MOVE <one uid> INBOX         from AI-Review or AI-Quarantine, only for a
  message this proxy itself moved there (the undo ledger, from COPYUID)

mode.json and PAUSE are read again for every one of these. A uid is one
number (no ranges, no ``*``, no lists); folder names are compared exactly,
with no literals and no modified UTF-7. Still never: STORE, EXPUNGE, COPY,
DELETE, RENAME, APPEND, plain FETCH or BODY[], or any other folder. In live
mode every refused command also sends an alert (at most one an hour).

The link from the analyzer to the proxy is plain text on an internal Docker
network that only those two containers join. The token on it opens nothing
but this allowlist.
"""

from __future__ import annotations

import hmac
import json
import logging
import os
import re
import socket
import socketserver
import ssl
import threading
import time
from dataclasses import dataclass, field
from pathlib import Path

import yaml

from . import alerts
from . import mode as modes
from .config import FOLDER_NAME, RESERVED_FOLDERS, read_secret
from .imap import tls_context

log = logging.getLogger("analyzer.imapproxy")

DEFAULT_CONFIG_PATH = "/config/analyzer.yaml"
MAX_CLIENT_LINE = 8192
MAX_SERVER_LINE = 256 * 1024
MAX_LITERAL = 4 * 1024 * 1024
MAX_REFUSALS = 3
MAX_LOGIN_FAILURES = 3
MAX_MOVES_CEILING = 5000        # the portal's highest setting; the analyzer's own cap is lower
LEDGER_MAX = 50_000
REFUSED_ALERT_EVERY = 3600


@dataclass
class ProxyConfig:
    listen_host: str = "0.0.0.0"
    listen_port: int = 1143
    upstream_host: str = "bridge"
    upstream_port: int = 1143
    username: str = ""
    password_file: str = "/run/secrets/bridge_password"
    # Where the sign-in broker saves the Bridge password (and the address)
    # after a sign-in from the admin portal. When it holds one, it wins over
    # password_file and username, and it is read again for every login, so
    # a new sign-in needs no restart.
    credential_dir: str = "/run/bridge-credential"
    cert_file: str = "/config/bridge-cert.pem"
    token_file: str = "/run/secrets/analyzer_imap_token"
    folders: tuple[str, ...] = ("INBOX",)
    max_clients: int = 2
    idle_timeout: int = 600
    upstream_tls: bool = True  # tests only turn this off
    # Live mode
    portal_dir: str = "/config/portal"
    pause_file: str = "/config/PAUSE"
    state_dir: str = "/proxy-state"
    alert_dir: str = alerts.ALERT_DIR
    review_mailbox: str = "Folders/AI-Review"
    quarantine_mailbox: str = "Folders/AI-Quarantine"
    max_moves_per_day: int = MAX_MOVES_CEILING
    problems: list[str] = field(default_factory=list)

    @property
    def ai_mailboxes(self) -> tuple[str, str]:
        return self.review_mailbox, self.quarantine_mailbox


def load_config(path: str | None = None) -> ProxyConfig:
    cfg = ProxyConfig()
    p = Path(path or DEFAULT_CONFIG_PATH)
    if not p.exists():
        return cfg
    try:
        data = yaml.safe_load(p.read_text(encoding="utf-8")) or {}
    except (OSError, yaml.YAMLError, UnicodeDecodeError) as e:
        raise SystemExit(f"{p.name}: cannot read ({e.__class__.__name__})") from None
    sec = data.get("imap_proxy") or {} if isinstance(data, dict) else {}
    for key in ("listen_host", "upstream_host", "username", "password_file", "credential_dir", "cert_file", "token_file"):
        if key in sec:
            setattr(cfg, key, str(sec[key]))
    for key in ("listen_port", "upstream_port", "max_clients", "idle_timeout"):
        if key in sec:
            try:
                setattr(cfg, key, int(sec[key]))
            except (TypeError, ValueError):
                raise SystemExit(f"imap_proxy.{key}: not a number") from None
    for key in ("portal_dir", "pause_file", "state_dir"):
        if key in sec:
            setattr(cfg, key, str(sec[key]))
    if "max_moves_per_day" in sec:
        try:
            cfg.max_moves_per_day = max(0, min(MAX_MOVES_CEILING, int(sec["max_moves_per_day"])))
        except (TypeError, ValueError):
            raise SystemExit("imap_proxy.max_moves_per_day: not a number") from None
    top = (data.get("folders") or {}) if isinstance(data, dict) else {}
    for key, attr in (("review", "review_mailbox"), ("quarantine", "quarantine_mailbox")):
        if key in top:
            name = str(top[key])
            base = name[len("Folders/"):] if name.startswith("Folders/") else name
            if not FOLDER_NAME.fullmatch(base) or base.strip().lower() in RESERVED_FOLDERS:
                raise SystemExit(f"folders.{key}: must be a folder of its own, such as AI-Review")
            setattr(cfg, attr, modes.mailbox(base))
    if cfg.review_mailbox == cfg.quarantine_mailbox:
        raise SystemExit("folders: review and quarantine must be different folders")
    if "folders" in sec:
        folders = tuple(str(f) for f in (sec["folders"] or []))
        bad = [f for f in folders if not _FOLDER_RE.fullmatch(f)]
        if bad or not folders:
            raise SystemExit("imap_proxy.folders: use plain folder names such as INBOX")
        cfg.folders = folders
    return cfg


# -- command checking ------------------------------------------------------

class Refused(Exception):
    """A client command that is not on the allowlist. The text is for the log."""


_TAG_RE = re.compile(rb"([A-Za-z0-9]{1,32}) (.+)")
_FOLDER_RE = re.compile(r"[A-Za-z0-9 _./-]{1,100}")
_ASTRING = r'(?:"((?:[^"\\]|\\["\\])*)"|([!#-\'*+,./0-9:;<=>?@A-Z^-z|~-]+))'
_LOGIN_RE = re.compile(rf"LOGIN {_ASTRING} {_ASTRING}", re.IGNORECASE)
_EXAMINE_RE = re.compile(r'EXAMINE (?:"([A-Za-z0-9 _./-]{1,100})"|([A-Za-z0-9_./-]{1,100}))', re.IGNORECASE)
_SEQ = r"[0-9]{1,10}(?::(?:[0-9]{1,10}|\*))?"
_SEARCH_RE = re.compile(rf"UID SEARCH (?:ALL|UID {_SEQ})", re.IGNORECASE)
_FETCH_RE = re.compile(rf"UID FETCH ({_SEQ}(?:,{_SEQ})*) (\([^()]*\)|[^ ()]+)", re.IGNORECASE)
_SIMPLE_ITEMS = {"UID", "FLAGS", "RFC822.SIZE", "INTERNALDATE", "ENVELOPE", "BODYSTRUCTURE"}
_PEEK_RE = re.compile(
    r"BODY\.PEEK\[(?:|HEADER|TEXT|[0-9]{1,3}(?:\.[0-9]{1,3}){0,7}(?:\.(?:HEADER|TEXT|MIME))?)\]"
    r"(?:<[0-9]{1,10}\.[0-9]{1,10}>)?",
    re.IGNORECASE,
)


_MBOX = r'(?:"([A-Za-z0-9 _./-]{1,100})"|([A-Za-z0-9_./-]{1,100}))'
_UID = r"([1-9][0-9]{0,9})"
_SELECT_RE = re.compile(rf"SELECT {_MBOX}", re.IGNORECASE)
_CREATE_RE = re.compile(rf"CREATE {_MBOX}", re.IGNORECASE)
_MOVE_RE = re.compile(rf"UID MOVE {_UID} {_MBOX}", re.IGNORECASE)
_UIDVALIDITY_RE = re.compile(rb"\[UIDVALIDITY ([0-9]{1,10})\]")
_COPYUID_RE = re.compile(rb"\[COPYUID ([0-9]{1,10}) ([0-9]{1,10}) ([0-9]{1,10})\]")
LIVE_VERBS = ("SELECT", "CREATE", "UID MOVE")


def _unquote(quoted: str | None, atom: str | None) -> str:
    if quoted is not None:
        return re.sub(r"\\(.)", r"\1", quoted)
    return atom or ""


def _decode(rest: bytes) -> str:
    try:
        text = rest.decode("ascii")
    except UnicodeDecodeError:
        raise Refused("non-ASCII command") from None
    if any(ord(c) < 0x20 or ord(c) == 0x7F for c in text):
        raise Refused("control character in command")
    if text.endswith("}"):
        raise Refused("literal")
    return text


def _folder_key(name: str) -> str:
    """INBOX is case-insensitive in IMAP; every other name is exact."""
    return "INBOX" if name.upper() == "INBOX" else name


def verb_of(text: str) -> str:
    parts = text.split(" ", 2)
    verb = parts[0].upper()
    if verb == "UID" and len(parts) > 1:
        return f"UID {parts[1].upper()}"
    return verb


def check_authenticated(text: str, folders: tuple[str, ...]) -> str:
    """Return the command to forward to Bridge, or raise Refused."""
    verb = verb_of(text)
    if verb in ("NOOP", "LOGOUT") and text.upper() == verb:
        return verb
    if verb == "EXAMINE":
        m = _EXAMINE_RE.fullmatch(text)
        if not m:
            raise Refused("EXAMINE syntax")
        name = _folder_key(m.group(1) or m.group(2))
        if name not in {_folder_key(f) for f in folders}:
            raise Refused("EXAMINE of a folder not on the list")
        return f'EXAMINE "{name}"'
    if verb == "UID SEARCH":
        if not _SEARCH_RE.fullmatch(text):
            raise Refused("UID SEARCH criteria")
        return "UID SEARCH " + text.split(" ", 2)[2].upper()
    if verb == "UID FETCH":
        m = _FETCH_RE.fullmatch(text)
        if not m:
            raise Refused("UID FETCH syntax")
        items = m.group(2)
        inner = items[1:-1] if items.startswith("(") else items
        tokens = inner.split()
        if not tokens:
            raise Refused("UID FETCH with no items")
        for tok in tokens:
            if tok.upper() not in _SIMPLE_ITEMS and not _PEEK_RE.fullmatch(tok):
                raise Refused("UID FETCH item not allowed")
        return f"UID FETCH {m.group(1)} ({' '.join(t.upper() for t in tokens)})"
    raise Refused(f"{verb} is not allowed")


# -- live mode: the proxy's own record -----------------------------------------

class LiveState:
    """The daily move count and the undo ledger, on the proxy's own volume.

    Fail closed: if the count can't be written, the move is refused. The
    ledger holds (folder, uidvalidity, uid) for every message this proxy
    moved into an AI folder; only those may be moved back to INBOX.
    """

    def __init__(self, cfg: ProxyConfig, clock=time.time) -> None:
        self.cfg = cfg
        self.clock = clock
        self.lock = threading.Lock()
        self.dir = Path(cfg.state_dir)
        self.ledger: set[tuple[str, int, int]] = set()
        self.order: list[tuple[str, int, int]] = []
        try:
            raw = json.loads((self.dir / "ledger.json").read_text(encoding="utf-8"))
            for item in raw if isinstance(raw, list) else []:
                if (isinstance(item, list) and len(item) == 3 and item[0] in cfg.ai_mailboxes
                        and all(isinstance(x, int) and not isinstance(x, bool) for x in item[1:])):
                    t = (item[0], item[1], item[2])
                    if t not in self.ledger:
                        self.ledger.add(t)
                        self.order.append(t)
        except (OSError, ValueError):
            pass

    def _write(self, name: str, obj) -> None:
        tmp = self.dir / (name + ".tmp")
        fd = os.open(tmp, os.O_WRONLY | os.O_CREAT | os.O_TRUNC | getattr(os, "O_NOFOLLOW", 0), 0o600)
        try:
            os.write(fd, json.dumps(obj).encode())
            os.fsync(fd)
        finally:
            os.close(fd)
        os.replace(tmp, self.dir / name)

    def _day(self) -> str:
        return time.strftime("%Y-%m-%d", time.gmtime(self.clock()))

    def take_move(self) -> str | None:
        """Count one move. Returns None when allowed, or why not."""
        with self.lock:
            day = self._day()
            try:
                cur = json.loads((self.dir / "moves.json").read_text(encoding="utf-8"))
                if not isinstance(cur, dict):
                    raise ValueError
            except FileNotFoundError:
                cur = {}
            except (OSError, ValueError):
                return "the move count can't be read"
            n = cur.get("n", 0) if cur.get("day") == day else 0
            if not isinstance(n, int) or isinstance(n, bool):
                return "the move count can't be read"
            if n >= self.cfg.max_moves_per_day:
                if cur.get("alerted") != day:
                    cur = {"day": day, "n": n, "alerted": day}
                    try:
                        self._write("moves.json", cur)
                    except OSError:
                        pass
                    alerts.send("move_cap", f"the IMAP proxy stopped moves for today after {n}",
                                self.cfg.alert_dir)
                return "daily move cap reached"
            try:
                self._write("moves.json", {"day": day, "n": n + 1, "alerted": cur.get("alerted", "")})
            except OSError:
                return "the move count can't be written"
            return None

    def remember(self, mailbox: str, uidvalidity: int, uid: int) -> None:
        with self.lock:
            t = (mailbox, uidvalidity, uid)
            if t in self.ledger:
                return
            self.ledger.add(t)
            self.order.append(t)
            while len(self.order) > LEDGER_MAX:
                self.ledger.discard(self.order.pop(0))
            self._save()

    def knows(self, mailbox: str, uidvalidity: int, uid: int) -> bool:
        with self.lock:
            return (mailbox, uidvalidity, uid) in self.ledger

    def forget(self, mailbox: str, uidvalidity: int, uid: int) -> None:
        with self.lock:
            t = (mailbox, uidvalidity, uid)
            if t in self.ledger:
                self.ledger.discard(t)
                self.order.remove(t)
                self._save()

    def _save(self) -> None:
        try:
            self._write("ledger.json", [list(t) for t in self.order])
        except OSError as e:
            log.error("could not save the undo ledger (%s); a later move back may be refused", type(e).__name__)


_refused_alert_at = [0.0]


def _alert_refused(cfg: ProxyConfig, reason: str) -> None:
    """In live mode a refusal means a bug or a compromise: tell the owner (at most hourly)."""
    now = time.time()
    if now - _refused_alert_at[0] < REFUSED_ALERT_EVERY:
        return
    _refused_alert_at[0] = now
    alerts.send("imap_refused", f"the IMAP proxy refused an analyzer command in live mode: {reason[:80]}. "
                "If this repeats, pause the analyzer on the portal.", cfg.alert_dir)


# -- upstream (Bridge) -------------------------------------------------------

_login_alerted = threading.Event()


def _note_login(rejected: bool) -> None:
    """One login_expired alert per outage; cleared by the next good login."""
    if rejected and not _login_alerted.is_set():
        _login_alerted.set()
        alerts.send("login_expired", "Bridge refused the analyzer's login; sign Bridge in again (./bridgekeep relogin)")


class LoginRejected(OSError):
    """Bridge answered LOGIN with NO/BAD: its sign-in to Proton has expired or the password changed."""


class Upstream:
    """One logged-in connection to Bridge. Only the proxy writes to it."""

    def __init__(self, cfg: ProxyConfig) -> None:
        self.cfg = cfg
        raw = socket.create_connection((cfg.upstream_host, cfg.upstream_port), timeout=60)
        self.sock: socket.socket | ssl.SSLSocket = raw
        self.rfile = raw.makefile("rb")
        greeting = self._line()
        if not greeting.startswith(b"* OK"):
            raise OSError("unexpected Bridge greeting")
        if cfg.upstream_tls:
            self._simple(b"P1", b"STARTTLS")
            self.rfile.close()
            self.sock = tls_context(cfg.cert_file).wrap_socket(raw, server_hostname=cfg.upstream_host)
            self.rfile = self.sock.makefile("rb")
        username, secret = bridge_login(cfg)
        user = _quote(username)
        password = _quote(secret)
        try:
            self._simple(b"P2", b"LOGIN " + user + b" " + password)
        except OSError as e:
            if str(e).startswith("Bridge refused"):
                raise LoginRejected("Bridge refused LOGIN") from None
            raise

    def _line(self) -> bytes:
        line = self.rfile.readline(MAX_SERVER_LINE + 1)
        if not line:
            raise EOFError("Bridge closed the connection")
        if len(line) > MAX_SERVER_LINE:
            raise OSError("Bridge response line too long")
        return line

    def _simple(self, tag: bytes, command: bytes) -> None:
        self.sock.sendall(tag + b" " + command + b"\r\n")
        while True:
            line = self._line()
            if line.startswith(tag + b" "):
                if not line[len(tag) + 1:].upper().startswith(b"OK"):
                    raise OSError(f"Bridge refused {command.split()[0].decode()}")
                return

    def relay(self, tag: bytes, command: str, client: socket.socket, watch=None) -> bytes:
        """Send one command and copy every response line (and literal) to the client.

        Returns the status word of the tagged completion. Literals are read by
        their announced length, so message text that looks like a tagged reply
        cannot end the command early.
        """
        self.sock.sendall(tag + b" " + command.encode("ascii") + b"\r\n")
        while True:
            line = self._line()
            client.sendall(line)
            if watch is not None:
                watch(line)
            while True:
                m = re.search(rb"\{([0-9]{1,10})\}\r\n$", line)
                if not m:
                    break
                n = int(m.group(1))
                if n > MAX_LITERAL:
                    raise OSError("literal from Bridge too large")
                data = self.rfile.read(n)
                if len(data) != n:
                    raise EOFError("Bridge closed mid-literal")
                client.sendall(data)
                line = self._line()
                client.sendall(line)
            if line.startswith(tag + b" "):
                return line[len(tag) + 1:].split(b" ", 1)[0].upper()

    def close(self) -> None:
        try:
            self.sock.sendall(b"P9 LOGOUT\r\n")
        except OSError:
            pass
        try:
            self.sock.close()
        except OSError:
            pass


def _quote(value: str) -> bytes:
    if any(ord(c) < 0x20 or ord(c) > 0x7E for c in value):
        raise SystemExit("The Bridge username and password must be printable ASCII")
    return b'"' + value.replace("\\", "\\\\").replace('"', '\\"').encode("ascii") + b'"'


# -- one client session ------------------------------------------------------

class Session:
    def __init__(self, cfg: ProxyConfig, client: socket.socket, token: str,
                 upstream_factory=Upstream, live_state: LiveState | None = None) -> None:
        self.cfg = cfg
        self.live_state = live_state
        self.selected: tuple[str, int] | None = None   # (folder, uidvalidity) opened with SELECT
        self.client = client
        self.token = token
        self.upstream_factory = upstream_factory
        self.upstream: Upstream | None = None
        self.refusals = 0
        self.login_failures = 0

    def send(self, data: bytes) -> None:
        self.client.sendall(data)

    def run(self) -> None:
        self.client.settimeout(self.cfg.idle_timeout)
        rfile = self.client.makefile("rb")
        self.send(b"* OK [CAPABILITY IMAP4rev1] analyzer IMAP proxy ready\r\n")
        try:
            while True:
                line = rfile.readline(MAX_CLIENT_LINE + 1)
                if not line:
                    return
                if len(line) > MAX_CLIENT_LINE or not line.endswith(b"\r\n"):
                    self.send(b"* BYE line too long\r\n")
                    return
                if not self.handle(line[:-2]):
                    return
        except (OSError, EOFError) as e:
            log.warning("session ended: %s", type(e).__name__)
        finally:
            if self.upstream is not None:
                self.upstream.close()
            try:
                rfile.close()
            except OSError:
                pass

    def handle(self, line: bytes) -> bool:
        """Handle one client line. Returns False when the session must end."""
        m = _TAG_RE.fullmatch(line)
        if not m:
            self.send(b"* BAD malformed command\r\n")
            return self._refused("malformed")
        tag, rest = m.group(1), m.group(2)
        try:
            text = _decode(rest)
        except Refused as e:
            self.send(tag + b" NO [CANNOT] not allowed by the analyzer proxy\r\n")
            return self._refused(str(e))
        verb = verb_of(text)

        if verb == "CAPABILITY" and text.upper() == "CAPABILITY":
            self.send(b"* CAPABILITY IMAP4rev1\r\n" + tag + b" OK CAPABILITY completed\r\n")
            return True
        if verb == "LOGOUT" and self.upstream is None:
            self.send(b"* BYE logging out\r\n" + tag + b" OK LOGOUT completed\r\n")
            return False
        if self.upstream is None:
            if verb == "NOOP" and text.upper() == "NOOP":
                self.send(tag + b" OK NOOP completed\r\n")
                return True
            if verb == "LOGIN":
                return self._login(tag, text)
            self.send(tag + b" NO [CANNOT] log in first\r\n")
            return self._refused(f"{verb} before login")
        if verb == "LOGIN":
            self.send(tag + b" BAD already logged in\r\n")
            return True

        if verb in LIVE_VERBS:
            return self._live(tag, verb, text)
        try:
            command = check_authenticated(text, self.cfg.folders)
        except Refused as e:
            self.send(tag + b" NO [CANNOT] not allowed by the analyzer proxy\r\n")
            return self._refused(str(e))
        if verb == "EXAMINE":
            self.selected = None             # read-only from here on
        status = self.upstream.relay(tag, command, self.client)
        return not (verb == "LOGOUT" or status == b"BYE")

    # -- live mode ------------------------------------------------------
    def _is_live(self) -> bool:
        return modes.live_allowed(self.cfg.portal_dir, self.cfg.pause_file).mode == "live"

    def _paused(self) -> bool:
        return modes.paused(self.cfg.portal_dir, self.cfg.pause_file)

    def _live(self, tag: bytes, verb: str, text: str) -> bool:
        try:
            if self.live_state is None:
                raise Refused("live mode is not set up in this proxy")
            if verb == "SELECT":
                return self._select(tag, text)
            if verb == "CREATE":
                return self._create(tag, text)
            return self._move(tag, text)
        except Refused as e:
            self.send(tag + b" NO [CANNOT] not allowed by the analyzer proxy\r\n")
            return self._refused(str(e))

    def _select(self, tag: bytes, text: str) -> bool:
        m = _SELECT_RE.fullmatch(text)
        if not m:
            raise Refused("SELECT syntax")
        name = _folder_key(m.group(1) or m.group(2))
        if name == "INBOX":
            if not self._is_live():
                raise Refused("SELECT INBOX outside live mode")
        elif name in self.cfg.ai_mailboxes:
            if self._paused():
                raise Refused("SELECT while paused")
        else:
            raise Refused("SELECT of a folder not on the list")
        self.selected = None                 # a failed SELECT leaves nothing selected
        seen: list[int] = []

        def watch(line: bytes) -> None:
            mm = _UIDVALIDITY_RE.search(line)
            if mm:
                seen.append(int(mm.group(1)))

        status = self.upstream.relay(tag, f'SELECT "{name}"', self.client, watch)
        if status == b"OK" and seen:
            self.selected = (name, seen[-1])
        return status != b"BYE"

    def _create(self, tag: bytes, text: str) -> bool:
        m = _CREATE_RE.fullmatch(text)
        if not m:
            raise Refused("CREATE syntax")
        name = m.group(1) or m.group(2)
        if name not in self.cfg.ai_mailboxes:
            raise Refused("CREATE of a folder that is not an AI folder")
        if not self._is_live():
            raise Refused("CREATE outside live mode")
        return self.upstream.relay(tag, f'CREATE "{name}"', self.client) != b"BYE"

    def _move(self, tag: bytes, text: str) -> bool:
        m = _MOVE_RE.fullmatch(text)
        if not m:
            raise Refused("UID MOVE syntax")
        uid, dest = int(m.group(1)), _folder_key(m.group(2) or m.group(3))
        if self.selected is None:
            raise Refused("UID MOVE with no folder selected")
        src, validity = self.selected
        if src == "INBOX" and dest in self.cfg.ai_mailboxes:
            if not self._is_live():
                raise Refused("UID MOVE outside live mode")
            why = self.live_state.take_move()
            if why:
                raise Refused(f"UID MOVE: {why}")
            got: list[tuple[int, int]] = []

            def watch(line: bytes) -> None:
                mm = _COPYUID_RE.search(line)
                if mm and int(mm.group(2)) == uid:
                    got.append((int(mm.group(1)), int(mm.group(3))))

            status = self.upstream.relay(tag, f'UID MOVE {uid} "{dest}"', self.client, watch)
            if status == b"OK":
                if got:
                    self.live_state.remember(dest, *got[-1])
                else:
                    log.warning("Bridge sent no COPYUID for a move; that message can't be moved back automatically")
            return status != b"BYE"
        if src in self.cfg.ai_mailboxes and dest == "INBOX":
            if self._paused():
                raise Refused("UID MOVE while paused")
            if not self.live_state.knows(src, validity, uid):
                raise Refused("UID MOVE back of a message this proxy did not move")
            status = self.upstream.relay(tag, f"UID MOVE {uid} INBOX", self.client)
            if status == b"OK":
                self.live_state.forget(src, validity, uid)
            return status != b"BYE"
        raise Refused("UID MOVE between these folders is not allowed")

    def _login(self, tag: bytes, text: str) -> bool:
        m = _LOGIN_RE.fullmatch(text)
        given = _unquote(m.group(3), m.group(4)) if m else ""
        if not m or not hmac.compare_digest(given.encode(), self.token.encode()):
            self.login_failures += 1
            log.warning("login with a wrong token (%d)", self.login_failures)
            self.send(tag + b" NO [AUTHENTICATIONFAILED] wrong token\r\n")
            return self.login_failures < MAX_LOGIN_FAILURES
        try:
            self.upstream = self.upstream_factory(self.cfg)
        except (OSError, EOFError, ssl.SSLError) as e:
            log.warning("cannot log in to Bridge: %s", e)
            _note_login(isinstance(e, LoginRejected))
            self.send(tag + b" NO [UNAVAILABLE] Bridge is unreachable or signed out\r\n")
            return False
        _login_alerted.clear()
        self.send(tag + b" OK LOGIN completed\r\n")
        return True

    def _refused(self, reason: str) -> bool:
        self.refusals += 1
        try:
            if self._is_live():
                _alert_refused(self.cfg, reason)
        except Exception:  # noqa: BLE001 - an alert must never keep a session alive
            pass
        log.warning("refused a command: %s (%d of %d)", reason, self.refusals, MAX_REFUSALS)
        if self.refusals >= MAX_REFUSALS:
            log.error("too many refused commands; disconnecting the client")
            try:
                self.send(b"* BYE too many refused commands\r\n")
            except OSError:
                pass
            return False
        return True


# -- server ------------------------------------------------------------------

class _Server(socketserver.ThreadingTCPServer):
    allow_reuse_address = True
    daemon_threads = True


def make_server(cfg: ProxyConfig, token: str, upstream_factory=Upstream,
                live_state: LiveState | None = None) -> socketserver.TCPServer:
    slots = threading.BoundedSemaphore(cfg.max_clients)
    if live_state is None and cfg.state_dir and Path(cfg.state_dir).is_dir():
        live_state = LiveState(cfg)

    class Handler(socketserver.BaseRequestHandler):
        def handle(self) -> None:
            if not slots.acquire(blocking=False):
                try:
                    self.request.sendall(b"* BYE too many connections\r\n")
                except OSError:
                    pass
                return
            try:
                Session(cfg, self.request, token, upstream_factory, live_state).run()
            finally:
                slots.release()

    return _Server((cfg.listen_host, cfg.listen_port), Handler)


def bridge_login(cfg: ProxyConfig) -> tuple[str, str]:
    """The address and Bridge password to sign in to Bridge with: the
    broker's copy when it has one, else the configured ones."""
    d = Path(cfg.credential_dir)
    pw = d / "bridge_password"
    if pw.is_file() and not pw.is_symlink():
        user = ""
        u = d / "bridge_username"
        if u.is_file() and not u.is_symlink():
            try:
                user = u.read_text(encoding="utf-8").strip()
            except OSError:
                user = ""
        if any(ord(c) < 32 or ord(c) == 127 for c in user):
            user = ""
        return user or cfg.username, read_secret(str(pw), "Bridge password")
    return cfg.username, read_secret(cfg.password_file, "Bridge password")


def serve(cfg: ProxyConfig) -> None:
    user, _ = bridge_login(cfg)  # fail at start, not at first login
    if not user:
        raise SystemExit("Set imap_proxy.username (your Proton address, as Bridge shows it)")
    token = read_secret(cfg.token_file, "analyzer IMAP token")
    if len(token) < 16:
        raise SystemExit("The analyzer IMAP token must be at least 16 characters")
    if cfg.upstream_tls and not Path(cfg.cert_file).is_file():
        raise SystemExit(f"Bridge certificate {cfg.cert_file} is missing; run: make analyzer-init "
                         "(it exports it to config/bridge-cert.pem)")
    server = make_server(cfg, token)
    log.info("listening on %s:%d, forwarding to %s:%d, folders %s",
             cfg.listen_host, cfg.listen_port, cfg.upstream_host, cfg.upstream_port, ", ".join(cfg.folders))
    server.serve_forever()
