"""Runtime settings, all from the environment. Every failure direction is
"localhost only, no LAN".
"""

from __future__ import annotations

import ipaddress
import os
from dataclasses import dataclass, field

LOOPBACK_NAMES = ("localhost", "127.0.0.1", "[::1]")


@dataclass
class Settings:
    data_dir: str = "/data"
    analyzer_data: str = "/analyzer"
    host_status: str = "/host-status"   # /var/lib/bridgekeep/status on the host, read-only
    portal_config: str = "/portal-config"   # the portal's writable folder (the analyzer's /config/portal)
    curated_lists: str = "/config-lists"    # config/lists on the host, read-only (shown, never edited)
    unsubscribe_url: str = "http://unsubscribe:8025/unsubscribe"   # the analyzer's unsubscribe service
    broker_socket: str = "/run/broker/broker.sock"   # the Bridge container's login broker
    secret_requests: str = "/secret-requests"   # write-only drop box for the API key and webhook (host applies)
    listen_host: str = "0.0.0.0"      # inside the container; compose publishes it on PORTAL_ADDRESS only
    listen_port: int = 8443
    public_port: int = 8443           # what the host publishes, for the URL we print
    lan: bool = False                 # network mode: HTTPS, reachable from the LAN
    address: str = "127.0.0.1"        # the host address compose publishes on (PORTAL_ADDRESS)
    fingerprint: str = ""             # of the TLS certificate, in network mode
    extra_hosts: tuple[str, ...] = ()
    idle_timeout: int = 12 * 3600     # P10
    absolute_timeout: int = 7 * 24 * 3600
    reauth_window: int = 5 * 60       # P8: how long a step-up lasts
    claim_ttl: int = 3600             # P6
    product_name: str = "Bridgekeep"
    problems: list[str] = field(default_factory=list)

    @property
    def db_path(self) -> str:
        return os.path.join(self.data_dir, "portal.db")

    def host_allowed(self, host: str) -> bool:
        """P10: reject any Host we were not told about (DNS rebinding)."""
        host = host.strip().lower()
        if not host or any(c in host for c in "/\\@ \t"):
            return False
        if host.startswith("["):
            name, _, rest = host.partition("]")
            name += "]"
            port = rest[1:] if rest.startswith(":") else ""
        else:
            name, _, port = host.partition(":")
        if port and not port.isdigit():
            return False
        if name in LOOPBACK_NAMES:
            return True
        return name in self.extra_hosts


def load() -> Settings:
    s = Settings()
    s.data_dir = os.environ.get("PORTAL_DATA", s.data_dir)
    s.analyzer_data = os.environ.get("PORTAL_ANALYZER_DATA", s.analyzer_data)
    s.host_status = os.environ.get("PORTAL_HOST_STATUS", s.host_status)
    s.portal_config = os.environ.get("PORTAL_CONFIG", s.portal_config)
    s.curated_lists = os.environ.get("PORTAL_CURATED_LISTS", s.curated_lists)
    s.secret_requests = os.environ.get("PORTAL_SECRET_REQUESTS", s.secret_requests)
    s.broker_socket = os.environ.get("PORTAL_BROKER_SOCKET", s.broker_socket)
    s.unsubscribe_url = os.environ.get("PORTAL_UNSUBSCRIBE_URL", s.unsubscribe_url)
    try:
        s.listen_port = int(os.environ.get("PORTAL_LISTEN_PORT", s.listen_port))
        s.public_port = int(os.environ.get("PORTAL_PORT", s.public_port))
    except ValueError:
        s.problems.append("PORTAL_PORT and PORTAL_LISTEN_PORT must be numbers")
    s.extra_hosts = tuple(h.strip().lower() for h in os.environ.get("PORTAL_HOSTS", "").split(",") if h.strip())
    # One variable decides both where compose publishes the port and whether
    # the portal speaks HTTPS, so the two can't disagree: anything but
    # loopback means the network can reach it, and then it's HTTPS only (P9).
    s.address = os.environ.get("PORTAL_ADDRESS", "127.0.0.1").strip() or "127.0.0.1"
    s.lan = s.address not in ("127.0.0.1", "::1", "localhost")
    try:
        ip = ipaddress.ip_address(s.address)
    except ValueError:
        ip = None
        if s.address != "localhost":
            s.problems.append(f"PORTAL_ADDRESS must be one of this computer's IP addresses, not {s.address!r}")
    if ip is not None and ip.is_unspecified:
        # Security review: one interface the user picked, never every interface.
        s.problems.append("PORTAL_ADDRESS can't be 0.0.0.0 or ::. Use the address of the network you want, "
                          "e.g. 192.168.1.20 (./bridgekeep portal network on picks it for you).")
    if s.lan:
        s.idle_timeout = 3600         # security lead: 1 hour idle while the network can reach it
    if s.lan and not s.extra_hosts:
        s.problems.append("PORTAL_ADDRESS opens the portal to your network, so PORTAL_HOSTS must list the "
                          "names and addresses you'll open it by, e.g. PORTAL_HOSTS=192.168.1.20,nas.local. "
                          "./bridgekeep portal network on sets both.")
    return s
