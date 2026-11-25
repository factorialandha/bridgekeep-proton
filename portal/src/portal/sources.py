"""Where each account's data comes from.

Today there is one Proton account on one host ("default"). Later a portal
may serve several accounts and nodes (multi-Bridge design), so pages read
through an Account rather than hard-coded paths, and anything the portal
stores is keyed by account id. Never put an email address in a URL or a
log line: use the id.
"""

from __future__ import annotations

from dataclasses import dataclass

from .settings import Settings

DEFAULT = "default"


@dataclass(frozen=True)
class Account:
    id: str
    analyzer_dir: str        # analyzer.db and health.json (read-only)
    host_status_dir: str     # bridge.env, storage.env, host.env from the host (read-only)
    config_dir: str          # portal.yaml, PAUSE: written by the portal, read by the analyzer
    curated_dir: str         # the owner's own curated.yaml (read-only)


def accounts(s: Settings) -> list[Account]:
    return [Account(DEFAULT, s.analyzer_data, s.host_status, s.portal_config, s.curated_lists)]


def get(s: Settings, account_id: str = DEFAULT) -> Account | None:
    return next((a for a in accounts(s) if a.id == account_id), None)
