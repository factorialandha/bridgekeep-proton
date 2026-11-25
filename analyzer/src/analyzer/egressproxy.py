"""Outbound proxy that lets the analyzer reach the Claude API and nothing else.

Security review A2: the analyzer's own networks are internal (no route out),
so the only way out is this proxy. It speaks just enough HTTP to accept
``CONNECT api.anthropic.com:443`` and then copies bytes both ways. TLS runs
end to end between the analyzer and the API, so the proxy never sees
message content, and it logs only the host, the verdict and byte counts.

The one allowed host:port follows ``model.provider`` (and, for a local
server, ``model.endpoint``) in the host-written analyzer.yaml: the vendor's
API host on 443, or the local server's pinned IP:port. Only that local IP may
be private; it was checked by the host and again by providers.py.

Refused: every other host or port, every method but CONNECT (no plain HTTP
forwarding), names that resolve to private, loopback or link-local
addresses (so DNS tricks cannot turn it into a door into the local
network), oversized requests and idle or very large tunnels.
"""

from __future__ import annotations

import ipaddress
import logging
import re
import socket
import socketserver
import threading
from dataclasses import dataclass, field
from pathlib import Path

import yaml

log = logging.getLogger("analyzer.egressproxy")

DEFAULT_CONFIG_PATH = "/config/analyzer.yaml"
DEFAULT_ALLOW = ("api.anthropic.com:443",)
MAX_HEAD = 8192
_CONNECT_RE = re.compile(rb"CONNECT ([A-Za-z0-9.-]{1,253}):([0-9]{1,5}) HTTP/1\.[01]")


@dataclass
class EgressConfig:
    listen_host: str = "0.0.0.0"
    listen_port: int = 3128
    allow: tuple[str, ...] = DEFAULT_ALLOW
    max_clients: int = 8
    idle_timeout: int = 120
    max_bytes: int = 64 * 1024 * 1024
    allow_private: bool = False  # tests only
    local_ip: str = ""           # the one private address allowed (provider "local")
    problems: list[str] = field(default_factory=list)

    def allowed(self, host: str, port: int) -> bool:
        return f"{host.lower()}:{port}" in {a.lower() for a in self.allow}


def load_config(path: str | None = None) -> EgressConfig:
    cfg = EgressConfig()
    p = Path(path or DEFAULT_CONFIG_PATH)
    if not p.exists():
        return cfg
    try:
        data = yaml.safe_load(p.read_text(encoding="utf-8")) or {}
    except (OSError, yaml.YAMLError, UnicodeDecodeError) as e:
        raise SystemExit(f"{p.name}: cannot read ({e.__class__.__name__})") from None
    if not isinstance(data, dict):
        raise SystemExit(f"{p.name}: top level must be a mapping")
    sec = data.get("egress_proxy") or {}
    if "listen_port" in sec:
        cfg.listen_port = int(sec["listen_port"])
    from .providers import PROVIDERS, egress_entry
    model = data.get("model") or {}
    provider = str(model.get("provider", "anthropic")).lower()
    if provider not in PROVIDERS:
        raise SystemExit("model.provider: unknown; refusing to start")
    try:
        entry = egress_entry(provider, str(model.get("endpoint", "") or ""))
    except ValueError as e:
        raise SystemExit(f"model.endpoint: {e}; refusing to start") from None
    if "allow" in sec and [str(a).lower() for a in (sec["allow"] or [])] != [entry.lower()]:
        # Fail closed: the allowlist is not set by hand any more.
        raise SystemExit(f"egress_proxy.allow: remove it; the proxy allows only {entry} (from model.provider)")
    cfg.allow = (entry,)
    if provider == "local":
        cfg.local_ip = entry.rpartition(":")[0]
    return cfg


def _public(addr: str) -> bool:
    ip = ipaddress.ip_address(addr)
    return ip.is_global and not ip.is_multicast


def _reply(sock: socket.socket, code: int, text: str) -> None:
    try:
        sock.sendall(f"HTTP/1.1 {code} {text}\r\nContent-Length: 0\r\nConnection: close\r\n\r\n".encode())
    except OSError:
        pass


def _read_head(sock: socket.socket) -> bytes | None:
    buf = b""
    while b"\r\n\r\n" not in buf:
        chunk = sock.recv(1024)
        if not chunk:
            return None
        buf += chunk
        if len(buf) > MAX_HEAD:
            return None
    head, _, rest = buf.partition(b"\r\n\r\n")
    if rest:  # a client must wait for 200 before sending TLS
        return None
    return head


def _pipe(src: socket.socket, dst: socket.socket, budget: list[int], lock: threading.Lock) -> None:
    try:
        while True:
            data = src.recv(65536)
            if not data:
                break
            with lock:
                budget[0] -= len(data)
                over = budget[0] < 0
            if over:
                log.warning("tunnel closed: byte limit reached")
                break
            dst.sendall(data)
    except OSError:
        pass
    finally:
        for s in (src, dst):
            try:
                s.shutdown(socket.SHUT_RDWR)
            except OSError:
                pass


def handle(cfg: EgressConfig, client: socket.socket) -> None:
    client.settimeout(cfg.idle_timeout)
    head = _read_head(client)
    if head is None:
        _reply(client, 400, "Bad Request")
        return
    first = head.split(b"\r\n", 1)[0]
    m = _CONNECT_RE.fullmatch(first)
    if not m:
        log.warning("refused: not a CONNECT request")
        _reply(client, 405, "Only CONNECT is allowed")
        return
    host, port = m.group(1).decode().lower().rstrip("."), int(m.group(2))
    if not cfg.allowed(host, port):
        log.warning("refused: %s:%d is not on the allow list", host, port)
        _reply(client, 403, "Forbidden")
        return
    try:
        infos = socket.getaddrinfo(host, port, type=socket.SOCK_STREAM)
    except OSError:
        _reply(client, 502, "Cannot resolve")
        return
    addrs = [i[4] for i in infos if cfg.allow_private or _public(i[4][0])
             or (cfg.local_ip and host == cfg.local_ip and i[4][0] == cfg.local_ip)]
    if not addrs:
        log.warning("refused: %s resolves only to non-public addresses", host)
        _reply(client, 403, "Forbidden")
        return
    upstream = None
    for addr in addrs:
        try:
            upstream = socket.create_connection(addr[:2], timeout=10)
            break
        except OSError:
            continue
    if upstream is None:
        _reply(client, 502, "Cannot connect")
        return
    upstream.settimeout(cfg.idle_timeout)
    client.sendall(b"HTTP/1.1 200 Connection established\r\n\r\n")
    budget, lock = [cfg.max_bytes], threading.Lock()
    t = threading.Thread(target=_pipe, args=(upstream, client, budget, lock), daemon=True)
    t.start()
    _pipe(client, upstream, budget, lock)
    t.join(timeout=5)
    upstream.close()
    log.info("tunnel to %s:%d closed, %d bytes", host, port, cfg.max_bytes - max(budget[0], 0))


class _Server(socketserver.ThreadingTCPServer):
    allow_reuse_address = True
    daemon_threads = True


def make_server(cfg: EgressConfig) -> socketserver.TCPServer:
    slots = threading.BoundedSemaphore(cfg.max_clients)

    class Handler(socketserver.BaseRequestHandler):
        def handle(self) -> None:
            if not slots.acquire(blocking=False):
                _reply(self.request, 503, "Busy")
                return
            try:
                handle(cfg, self.request)
            except OSError as e:
                log.warning("connection error: %s", type(e).__name__)
            finally:
                slots.release()

    return _Server((cfg.listen_host, cfg.listen_port), Handler)


def serve(cfg: EgressConfig) -> None:
    log.info("listening on %s:%d, allowing %s", cfg.listen_host, cfg.listen_port, ", ".join(cfg.allow))
    make_server(cfg).serve_forever()
