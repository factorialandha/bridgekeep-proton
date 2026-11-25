"""One message through the whole pipeline: extract, pre-filter, classify, decide, log."""

from __future__ import annotations

import datetime as dt
import os
from dataclasses import dataclass, field

from . import alerts, decide, lists, prescan, providers, unsubscribe
from .feedback import Feedback
from .settings import Settings
from .classify import PROMPT_VERSION, Classification, ClassifyError, Classifier
from .config import Config
from .extract import Extracted, Limits, extract
from .store import Record, Store


@dataclass
class Result:
    record: Record
    extracted: Extracted
    injections: list[prescan.Injection] = field(default_factory=list)
    classification: Classification | None = None
    record_id: int | None = None
    # Live mode: why this message must stay where it is whatever the action
    # says (a code rule, security review of live mode item 8), or None.
    hold: str | None = None


class Analyzer:
    def __init__(self, cfg: Config, store: Store, classifier: Classifier | None) -> None:
        self.cfg = cfg
        self.store = store
        self.classifier = classifier
        self.key_missing = False   # set by the CLI when there is no API key file, or it is empty
        self.lists = lists.load(cfg.lists_dir, portal_dir=cfg.portal_dir)
        self.settings = Settings(cfg)
        self.settings.maybe_reload()
        self.feedback = Feedback(store, cfg.portal_dir)

    def refresh(self) -> None:
        """Once per poll: portal settings and corrections."""
        self.settings.maybe_reload()
        try:
            self.feedback.step()
        except Exception:  # noqa: BLE001 - corrections must never stop the inbox being watched
            import logging
            logging.getLogger(__name__).exception("could not read portal corrections")

    def model_on(self) -> bool:
        return (self.classifier is not None and self.cfg.model_enabled
                and providers.prices(self.cfg) is not None)

    def usage_model(self) -> str:
        """Spend is kept per provider and model, so estimates use the right price."""
        return f"{self.cfg.provider}/{self.cfg.model}"

    def maybe_reload_lists(self) -> None:
        """Hot reload: re-read the list files when any one changes."""
        current = {}
        for path, _ in lists.list_files(self.cfg.lists_dir, self.cfg.portal_dir):
            p = str(path)
            try:
                current[p] = lists.file_signature(os.lstat(p))
            except OSError:
                pass
        if current != self.lists.mtimes:
            self.lists = lists.load(self.cfg.lists_dir, portal_dir=self.cfg.portal_dir, previous=self.lists)

    def model_status(self) -> dict:
        """For health.json and the portal: is the model being used, and why not."""
        spend = round(self.store.spend_this_month(), 4)
        if self.classifier is None and self.key_missing:
            state = "no_key"
        elif self.classifier is not None and providers.prices(self.cfg) is None:
            state = "no_price"
        elif not self.model_on():
            state = "off"
        else:
            state = self._budget_block() or "on"
        return {"model": state, "provider": self.cfg.provider, "model_name": self.cfg.model,
                "spend_month_usd": spend, "budget_usd": self.cfg.monthly_budget_usd,
                "settings_problems": list(self.settings.problems) + (
                    ["model.enabled: no API key is set, so the model stays off"]
                    if self.cfg.model_enabled and self.key_missing else [])}

    def _alert_budget_once(self) -> None:
        """One budget_cap alert per month, remembered across restarts."""
        month = dt.datetime.now(dt.timezone.utc).strftime("%Y-%m")
        if self.store.get_state("alert:budget_cap") == month:
            return
        self.store.set_state("alert:budget_cap", month)
        alerts.send("budget_cap", f"monthly model budget {self.cfg.monthly_budget_usd:g} USD reached; "
                    "rules and lists only until the 1st", self.cfg.alert_dir)

    def _budget_block(self) -> str | None:
        if self.store.calls_since(3600) >= self.cfg.max_per_hour:
            return "rate_cap_hour"
        if self.store.calls_since(86400) >= self.cfg.max_per_day:
            return "rate_cap_day"
        if self.store.spend_this_month() >= self.cfg.monthly_budget_usd:
            return "budget_cap"
        return None

    def analyze(self, raw: bytes, message_key: str) -> Result:
        mode = self.cfg.effective_mode()
        ex = extract(raw, Limits(body_chars=self.cfg.body_chars), self.cfg.trusted_authserv)
        hits = lists.check(self.lists, ex.from_addr, ex.from_domain, ex.subject)
        injections = prescan.scan(ex.from_display, ex.subject, ex.body, ex.hidden_text)
        rec = Record(message_key=message_key, mode=mode, action=decide.KEEP, rule="", explain="",
                     from_addr=ex.from_addr, from_domain=ex.from_domain, subject=ex.subject,
                     verified=ex.auth.verified, injections=[i.pattern for i in injections],
                     prompt_version=PROMPT_VERSION)
        result = Result(rec, ex, injections)

        d = decide.pre_model(ex, hits)
        if d is None and not self.model_on():
            d = decide.Decision(decide.KEEP, "no_model", "Model disabled; not classified.")
        if d is None:
            blocked = self._budget_block()
            if blocked:
                if blocked == "budget_cap":
                    self._alert_budget_once()
                # A17: when a cap is hit, stop classifying and leave mail alone.
                d = decide.Decision(decide.KEEP, blocked, "Rate or budget cap reached; not classified.")
            else:
                rec.model = self.classifier.model
                hint = self.feedback.hint(ex.from_domain, ex.from_addr, ex.auth.verified and ex.from_count == 1)
                try:
                    c = self.classifier.classify(
                        ex.model_fields(), context=[hint.sentence()] if hint else None)
                except ClassifyError as e:
                    tokens = getattr(e, "tokens", None)
                    if tokens:
                        self.store.add_usage(*tokens, cost=providers.cost(self.cfg, *tokens),
                                             model=self.usage_model())
                    rec.error = str(e)[:200]
                    d = decide.Decision(decide.KEEP, "model_error", f"Model answer unusable ({e}); left in place.")
                else:
                    self.store.add_usage(c.input_tokens, c.output_tokens,
                                         providers.cost(self.cfg, c.input_tokens, c.output_tokens),
                                         model=self.usage_model())
                    result.classification = c
                    rec.label, rec.confidence, rec.reason = c.label, c.confidence, c.reason
                    d = decide.post_model(ex, hits, injections, c,
                                          self.cfg.quarantine_threshold, self.cfg.review_threshold,
                                          feedback_trusted=hint.sender if hint and hint.trusted else None)
        rec.action, rec.rule, rec.explain = d.action, d.rule, d.explain
        # Never moved, whatever the action: anything on the protect list
        # (also when it is on the block list too), or with a protected keyword.
        if hits.protected:
            result.hold = "protected"
        elif hits.keyword:
            # Codes, password resets, invoices: time-sensitive, so they stay
            # in INBOX even when the action says review (security review).
            result.hold = "protected keyword"
        # `applied` turns true only when the IMAP runner has really moved it.
        rec.applied = False
        result.record_id = self.store.add(rec)
        # Only recorded: the portal decides whether to show a button, and only
        # the separate unsubscribe service ever contacts the sender.
        o = unsubscribe.offer(ex, rec.label, rec.action, injections, bool(hits.lookalike_of))
        if o is not None:
            self.store.add_unsubscribe(result.record_id, o)
        return result

