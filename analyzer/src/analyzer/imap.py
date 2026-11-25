"""Read new mail from Bridge over IMAP; in live mode, move what was flagged.

In shadow mode, read-only by construction:

* The folder is opened with EXAMINE (imaplib's ``readonly=True``), so the
  server itself refuses any change for the whole session.
* Messages are read with ``BODY.PEEK``, which never sets \\Seen (review A4).
* Only UID commands are used, and UIDVALIDITY is checked every poll. If it
  changes, the position resets to "new mail only" and nothing is replayed.
* The first run starts at UIDNEXT: only mail that arrives after go-live is
  analyzed (product scope), so an old mailbox never floods the API.
* ``ReadOnlyIMAP`` refuses, client-side, every command outside a short list.
  STORE, COPY, MOVE, EXPUNGE, DELETE, APPEND and the rest cannot be sent.

In live mode (mode.json from the portal, see mode.py) INBOX is opened with
SELECT so that exactly one more thing can happen: ``UID MOVE <uid>`` of a
message analyzed in live mode into Folders/AI-Review or Folders/AI-Quarantine,
and, after a "not spam" answer, ``UID MOVE`` back to INBOX. The client also
may CREATE those two folders. Nothing is ever deleted, expunged, flagged or
marked read, and nothing goes to Trash.

Code rules for a move (security review of live mode):
* the message was analyzed in live mode, now, and Proton received it after
  live mode was switched on; shadow, backfill and older mail never move;
* nothing on the protect list moves; trusted senders go to review at most;
* at most ``limits.max_moves_per_day`` moves a day, then log only and one alert;
* mode.json and PAUSE are read again right before every move.

In the compose setup this client talks to the allowlisting proxy
(imapproxy.py), never to Bridge, and holds only the proxy token. The proxy
checks all of this again for itself. This module is the client-side half.
"""

from __future__ import annotations

import imaplib
import json
import logging
import re
import socket
import ssl
import time
from dataclasses import dataclass
from pathlib import Path
from typing import Callable

from . import alerts
from .config import Config
from .pipeline import Analyzer

log = logging.getLogger("analyzer.imap")

ALLOWED_COMMANDS = frozenset({"CAPABILITY", "NOOP", "LOGIN", "LOGOUT", "STARTTLS", "EXAMINE", "SEARCH", "FETCH"})
MAX_PER_POLL = 50
SIGNED_OUT_AFTER = 15 * 60  # review B8: alert when logins fail this long


class ForbiddenCommand(Exception):
    pass


LIVE_COMMANDS = frozenset({"SELECT", "CREATE"})


class ReadOnlyIMAP(imaplib.IMAP4):
    """imaplib client that can only send the commands in ALLOWED_COMMANDS,
    plus SELECT, CREATE and UID MOVE while ``allow_moves`` is set (live mode)."""

    allow_moves = False

    def _command(self, name, *args):
        verb = name.upper()
        if verb == "UID":
            sub = str(args[0]).upper() if args else ""
            if sub not in ("SEARCH", "FETCH") and not (sub == "MOVE" and self.allow_moves):
                raise ForbiddenCommand(f"UID {sub}")
        elif verb not in ALLOWED_COMMANDS and not (verb in LIVE_COMMANDS and self.allow_moves):
            raise ForbiddenCommand(verb)
        return super()._command(name, *args)


def tls_context(cert_file: str) -> ssl.SSLContext:
    """Trust exactly Bridge's exported self-signed certificate.

    Hostname checking is off because Bridge's certificate names 127.0.0.1,
    not the container name; trusting only that one certificate is the pin.
    """
    ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
    ctx.minimum_version = ssl.TLSVersion.TLSv1_2
    ctx.check_hostname = False
    ctx.verify_mode = ssl.CERT_REQUIRED
    # The exported certificate is the only trust anchor; partial-chain lets
    # it be trusted directly even if Bridge ever serves a non-self-signed leaf.
    ctx.verify_flags |= ssl.VERIFY_X509_PARTIAL_CHAIN
    ctx.load_verify_locations(cafile=cert_file)
    return ctx


def connect(cfg: Config) -> imaplib.IMAP4:
    conn = ReadOnlyIMAP(cfg.imap_host, cfg.imap_port, timeout=60)
    if cfg.imap_tls == "starttls":
        conn.starttls(tls_context(cfg.imap_cert_file))
    conn.login(cfg.imap_username, cfg.read_imap_password())
    return conn


_UID_RE = re.compile(rb"UID (\d+)")


def _parse_uids(data) -> list[int]:
    out: list[int] = []
    for chunk in data or []:
        if isinstance(chunk, bytes):
            out.extend(int(x) for x in chunk.split() if x.isdigit())
    return sorted(set(out))


def _fetch_raw(conn, uid: int, max_bytes: int) -> bytes | None:
    typ, data = conn.uid("FETCH", str(uid), f"(UID BODY.PEEK[]<0.{max_bytes}>)")
    if typ != "OK":
        return None
    for item in data or []:
        if isinstance(item, tuple) and len(item) == 2:
            m = _UID_RE.search(item[0])
            if m and int(m.group(1)) == uid:
                return item[1]
    return None


GOLIVE_GRACE = 15 * 60   # mail received this long before go-live still counts as new


UNDATED_RETRIES = 3      # polls a dateless message may hold things up before it is analyzed anyway


def _internaldates(conn, uids: list[int]) -> dict[int, float]:
    """UID -> when Proton received it (Unix time).

    Bridge takes INTERNALDATE from Proton's own message time, not from the
    sender's Date header, so a sender cannot backdate mail past the gate.
    A chunk that fails to fetch is simply missing from the result: the caller
    stops there and asks again next poll, it never skips missing dates.
    """
    out: dict[int, float] = {}
    for i in range(0, len(uids), 200):
        chunk = uids[i:i + 200]
        typ, data = conn.uid("FETCH", ",".join(map(str, chunk)), "(UID INTERNALDATE)")
        if typ != "OK":
            break
        for item in data or []:
            line = item[0] if isinstance(item, tuple) else item
            if not isinstance(line, bytes):
                continue
            m = _UID_RE.search(line)
            t = imaplib.Internaldate2tuple(line)
            if m and t:
                out[int(m.group(1))] = time.mktime(t)
    return out


@dataclass
class PollResult:
    skipped_old: int = 0
    waiting_on_date: bool = False
    analyzed: int = 0
    reset: bool = False
    moved: int = 0
    moved_back: int = 0


_COPYUID_RE = re.compile(rb"COPYUID ([0-9]{1,10}) ([0-9]{1,10}) ([0-9]{1,10})")


def _quote(mailbox: str) -> str:
    return '"' + mailbox.replace("\\", "\\\\").replace('"', '\\"') + '"'


def _copyuid(conn, data) -> tuple[int, int] | None:
    """(destination uidvalidity, destination uid) from a MOVE answer, if the server sent one."""
    found = []
    try:
        found += list(conn.untagged_responses.pop("COPYUID", []) or [])
    except AttributeError:
        pass
    found += [d for d in (data or []) if isinstance(d, bytes)]
    for chunk in found:
        if isinstance(chunk, bytes):
            m = _COPYUID_RE.search(b"COPYUID " + chunk) or _COPYUID_RE.search(chunk)
            if m:
                return int(m.group(1)), int(m.group(3))
    return None


class ShadowRunner:
    def __init__(self, cfg: Config, analyzer: Analyzer,
                 connect_fn: Callable[[Config], imaplib.IMAP4] = connect,
                 sleep: Callable[[float], None] = time.sleep,
                 clock: Callable[[], float] = time.time) -> None:
        self.cfg = cfg
        self.an = analyzer
        self.store = analyzer.store
        self.connect_fn = connect_fn
        self.sleep = sleep
        self.clock = clock
        self.conn: imaplib.IMAP4 | None = None
        self._created: set[str] = set()     # folders CREATEd on this connection
        self.failing_since: float | None = None
        self.last_prune = 0.0
        from .backfill import Backfill
        self.backfill = Backfill(self)

    # -- state --------------------------------------------------------
    def _key(self, name: str) -> str:
        return f"imap:{self.cfg.imap_folder}:{name}"

    def health(self, status: str, detail: str = "") -> None:
        data = {"status": status, "detail": detail[:200], "ts": int(self.clock()),
                "mode": self.cfg.effective_mode()}
        try:
            data.update(self.an.model_status())
        except Exception:  # noqa: BLE001 - health must always be written
            data["model"] = "unknown"
        data["skipped_pre_go_live"] = int(self.store.get_state(self._key("skipped_pre_go_live")) or 0)
        try:
            data.update(self.live_status())
        except Exception:  # noqa: BLE001
            pass
        self.store.set_state("health", json.dumps(data))
        try:
            Path(self.cfg.health_file).write_text(json.dumps(data), encoding="utf-8")
        except OSError:
            pass

    def live_status(self) -> dict:
        """The live-mode part of health.json, also shown on the portal's confirm page."""
        from .feedback import agreement
        req = self.cfg.requested_mode()
        golive = self.store.get_state(self._key("golive"))
        return {"mode_requested": req.mode, "mode_problem": self.cfg.mode_problem(),
                "live_since": self.cfg.live_since(),
                "moved_today": self.store.moves_today("move"), "moved_back_today": self.store.moves_today("undo"),
                "move_cap": self.cfg.max_moves_per_day,
                "shadow_since": int(golive) if golive else None,
                **self.store.shadow_counts(), "agreement": agreement(self.store)}

    # -- live mode ----------------------------------------------------
    def _note_mode(self) -> str:
        """The mode for this poll; one alert whenever it changes."""
        mode = self.cfg.effective_mode()
        before = self.store.get_state("mode:last") or "shadow"
        if mode != before:
            self.store.set_state("mode:last", mode)
            why = "" if mode == "live" else f" ({self.cfg.mode_problem() or 'switched off'})"
            alerts.send("analyzer_mode_changed",
                        f"analyzer is now in {mode} mode{why}" + (
                            ": new mail it flags moves to AI-Review or AI-Quarantine" if mode == "live" else
                            ": it only logs, nothing moves"), self.cfg.alert_dir)
            log.warning("mode changed: %s -> %s", before, mode)
        return mode

    def _undos(self, conn, res: PollResult) -> None:
        """Move mail back to INBOX after a "not spam" answer on a moved message."""
        if self.cfg.paused():
            return
        pending = self.store.pending_undos()
        if not pending:
            return
        conn.allow_moves = True
        for row in pending:
            mailbox = row["mailbox"]
            error = None
            uidvalidity, uid = None, None
            try:
                typ, _ = conn.select(_quote(mailbox))
                if typ != "OK":
                    error = f"cannot open {mailbox}"
                elif int((conn.response("UIDVALIDITY")[1] or [b"0"])[0]) != row["uidvalidity"]:
                    error = f"{mailbox} was recreated; move it back in Proton"
                else:
                    typ, data = conn.uid("MOVE", str(row["uid"]), "INBOX")
                    if typ == "OK":
                        uidvalidity, uid = _copyuid(conn, data) or (None, None)
                    else:
                        error = "the server refused the move back (moved or deleted already?)"
            except imaplib.IMAP4.abort:
                self.store.add_move(row["decision_id"], "undo", mailbox, "INBOX", None, None, False, "connection lost")
                raise
            except imaplib.IMAP4.error as e:
                error = f"IMAP error ({type(e).__name__})"
            self.store.add_move(row["decision_id"], "undo", mailbox, "INBOX", uidvalidity, uid, error is None, error)
            if error is None:
                res.moved_back += 1
                log.info("moved %s back to INBOX (marked not spam)", row["message_key"])
            else:
                log.warning("could not move %s back: %s", row["message_key"], error)

    def _maybe_move(self, conn, uid: int, received: float | None, result, res: PollResult) -> None:
        from . import decide
        rec = result.record
        if rec.mode != "live" or rec.action not in (decide.REVIEW, decide.QUARANTINE) or result.hold:
            return
        since = self.cfg.live_since()          # mode.json and PAUSE, read again right now
        if since is None or received is None or received < since:
            return                             # switched off meanwhile, or older than the switch
        if self.store.moved_back_before(rec.from_addr, rec.subject):
            log.info("left %s in place: you moved it back before", rec.message_key)
            return
        if self.store.moves_today("move") >= self.cfg.max_moves_per_day:
            day = time.strftime("%Y-%m-%d", time.gmtime(self.clock()))
            if self.store.get_state("alert:move_cap") != day:
                self.store.set_state("alert:move_cap", day)
                alerts.send("move_cap", f"{self.cfg.max_moves_per_day} moves today; log only until midnight UTC "
                            "(change it on the portal's Analyzer page)", self.cfg.alert_dir)
            return
        target = self.cfg.review_mailbox() if rec.action == decide.REVIEW else self.cfg.quarantine_mailbox()
        error, dest = None, None
        try:
            if target not in self._created:
                conn.create(_quote(target))    # NO when it exists already: that is fine
                self._created.add(target)
            typ, data = conn.uid("MOVE", str(uid), _quote(target))
            if typ == "OK":
                dest = _copyuid(conn, data)
            else:
                error = "the server refused the move"
        except imaplib.IMAP4.abort:
            self.store.add_move(result.record_id, "move", self.cfg.imap_folder, target, None, None, False,
                                "connection lost")
            raise
        except imaplib.IMAP4.error as e:
            error = f"IMAP error ({type(e).__name__})"
        self.store.add_move(result.record_id, "move", self.cfg.imap_folder, target,
                            dest[0] if dest else None, dest[1] if dest else None, error is None, error)
        if error is None:
            res.moved += 1
            log.info("moved %s to %s (%s)", rec.message_key, target, rec.rule)
        else:
            log.warning("could not move %s to %s: %s", rec.message_key, target, error)

    # -- one poll -----------------------------------------------------
    def poll(self, conn) -> PollResult:
        res = PollResult()
        self.an.refresh()   # portal settings and corrections take effect within one poll
        mode = self._note_mode()
        self._undos(conn, res)
        live = mode == "live"
        conn.allow_moves = live
        # EXAMINE in shadow mode; SELECT only when this session may move mail.
        typ, _ = conn.select(self.cfg.imap_folder, readonly=not live)
        if typ != "OK":
            raise imaplib.IMAP4.error(f"cannot open {self.cfg.imap_folder}")
        uidvalidity = int((conn.response("UIDVALIDITY")[1] or [b"0"])[0])
        uidnext = int((conn.response("UIDNEXT")[1] or [b"0"])[0] or 0)

        # Go-live time, set once and kept across UIDVALIDITY changes. Bridge
        # numbers messages as it syncs, so on a fresh install old mail keeps
        # arriving with new UIDs for a while: the date, not the UID, decides
        # what counts as new.
        golive = self.store.get_state(self._key("golive"))
        if golive is None:
            golive = str(int(self.clock()))
            self.store.set_state(self._key("golive"), golive)
        cutoff = int(golive) - GOLIVE_GRACE

        stored_validity = self.store.get_state(self._key("uidvalidity"))
        last = self.store.get_state(self._key("last_uid"))
        if stored_validity is None or last is None or int(stored_validity) != uidvalidity:
            if stored_validity is not None and int(stored_validity) != uidvalidity:
                log.warning("UIDVALIDITY changed (%s -> %s); starting again from new mail only",
                            stored_validity, uidvalidity)
                res.reset = True
            start = uidnext - 1 if uidnext else self._highest_uid(conn)
            self.store.set_state(self._key("uidvalidity"), uidvalidity)
            self.store.set_state(self._key("last_uid"), start)
            return res
        last_uid = int(last)

        typ, data = conn.uid("SEARCH", None, f"UID {last_uid + 1}:*")
        if typ != "OK":
            raise imaplib.IMAP4.error("UID SEARCH failed")
        # "n:*" always returns the highest UID even when it is below n.
        uids = [u for u in _parse_uids(data) if u > last_uid][:MAX_PER_POLL]
        dates = _internaldates(conn, uids)
        for uid in uids:
            key = f"{self.cfg.imap_folder}:{uidvalidity}:{uid}"
            when = dates.get(uid)
            if when is None:
                # No date read: never skip on missing data. Stop here and try
                # again next poll; after a few tries analyze it rather than drop it.
                prev_uid, prev_n = (self.store.get_state(self._key("undated")) or "0:0").split(":")
                n = int(prev_n) + 1 if int(prev_uid) == uid else 1
                if n < UNDATED_RETRIES:
                    self.store.set_state(self._key("undated"), f"{uid}:{n}")
                    log.warning("no INTERNALDATE for %s yet; trying again next poll", key)
                    res.waiting_on_date = True
                    break
                log.warning("still no INTERNALDATE for %s; analyzing it as new", key)
            elif when < cutoff:
                # From before go-live: only a confirmed backfill may look at it.
                res.skipped_old += 1
                log.info("skipped %s rule=pre_go_live", key)
                self.store.set_state(self._key("last_uid"), uid)
                continue
            if self.cfg.paused():
                break
            if self.store.moved_back_uid(uidvalidity, uid):
                # Back in INBOX after a "not spam" answer: already decided.
                self.store.set_state(self._key("last_uid"), uid)
                continue
            self.an.maybe_reload_lists()
            raw = _fetch_raw(conn, uid, 1_000_000)
            self.store.set_state(self._key("last_uid"), uid)
            if raw is not None:
                result = self.an.analyze(raw, key)
                res.analyzed += 1
                if live:
                    self._maybe_move(conn, uid, when, result, res)
        if res.skipped_old:
            total = int(self.store.get_state(self._key("skipped_pre_go_live")) or 0) + res.skipped_old
            self.store.set_state(self._key("skipped_pre_go_live"), total)
            log.info("%d message(s) from before go-live left alone (see: backfill)", res.skipped_old)
        # Older mail, only after new mail and only when someone asked for it.
        self.backfill.step(conn, uidvalidity)
        return res

    def _highest_uid(self, conn) -> int:
        typ, data = conn.uid("SEARCH", None, "ALL")
        uids = _parse_uids(data) if typ == "OK" else []
        return uids[-1] if uids else 0

    # -- the loop -----------------------------------------------------
    def run_once(self) -> PollResult | None:
        try:
            if self.conn is None:
                self.conn = self.connect_fn(self.cfg)
            res = self.poll(self.conn)
        except (imaplib.IMAP4.error, imaplib.IMAP4.abort, OSError, ssl.SSLError, socket.timeout, EOFError) as e:
            self._drop()
            now = self.clock()
            self.failing_since = self.failing_since or now
            down_for = now - self.failing_since
            if down_for >= SIGNED_OUT_AFTER:
                self.health("bridge_unreachable",
                            f"IMAP failing for {int(down_for // 60)} min ({type(e).__name__}). "
                            "If Bridge is signed out, run: docker compose run --rm bridge-init")
            else:
                self.health("retrying", type(e).__name__)
            log.warning("IMAP error (%s); retrying", type(e).__name__)
            return None
        self.failing_since = None
        self.health("ok", f"analyzed {res.analyzed}")
        if self.clock() - self.last_prune > 86400:
            self.store.prune(self.cfg.retention_days)
            self.last_prune = self.clock()
        return res

    def _drop(self) -> None:
        self._created = set()
        if self.conn is not None:
            try:
                self.conn.logout()
            except Exception:  # noqa: BLE001
                pass
        self.conn = None

    def run_forever(self) -> None:
        backoff = self.cfg.poll_seconds
        while True:
            res = self.run_once()
            if res is None:
                backoff = min(backoff * 2, 900)
                self.sleep(backoff)
            else:
                backoff = self.cfg.poll_seconds
                self.sleep(self.cfg.poll_seconds)
