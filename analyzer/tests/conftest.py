from pathlib import Path

import pytest

from analyzer.classify import Classification, ClassifyError
from analyzer.config import Config
from analyzer.pipeline import Analyzer
from analyzer.store import Store

FIXTURES = Path(__file__).parent / "fixtures"

PROTON_PASS = ("Authentication-Results: mailin021.protonmail.ch; dkim=pass header.d={d}; "
               "dmarc=pass (p=reject dis=none) header.from={d}; spf=pass smtp.mailfrom={d}\n")


def make_eml(frm="Alice <alice@example.com>", subject="Hello", body="Hi there", *, html=None,
             auth="pass", extra_headers="", domain=None) -> bytes:
    domain = domain or frm.rpartition("@")[2].strip(">")
    ar = PROTON_PASS.format(d=domain) if auth == "pass" else (auth or "")
    if html is not None:
        content = f"Content-Type: text/html; charset=utf-8\n\n{html}\n"
    else:
        content = f"Content-Type: text/plain; charset=utf-8\n\n{body}\n"
    return (f"{ar}{extra_headers}From: {frm}\nTo: me@example.org\nSubject: {subject}\n"
            f"Message-ID: <x@test>\nMIME-Version: 1.0\n{content}").encode()


class FakeClassifier:
    model = "fake"

    def __init__(self, label="legitimate", confidence=0.5, error=None):
        self.label, self.confidence, self.error = label, confidence, error
        self.calls = []

    def classify(self, fields, context=None):
        self.calls.append(fields)
        self.contexts = getattr(self, "contexts", []) + [context]
        if self.error:
            raise ClassifyError(self.error)
        return Classification(self.label, self.confidence, "fake reason", self.model, 100, 20)


@pytest.fixture
def lists_dir(tmp_path):
    d = tmp_path / "lists"
    d.mkdir()
    (d / "curated.yaml").write_text(
        """
protect:
  - address: billing@mybank.com
    reason: Bank statements
  - domain: employer.com
    subdomains: true
    reason: Work
keywords:
  - pattern: verification code
    reason: Security codes
block:
  - address: spammer@junk.example
    reason: Marked as junk twice
""")
    return d


@pytest.fixture
def make_analyzer(tmp_path, lists_dir):
    def _make(classifier=None, **cfg_kw):
        cfg = Config(lists_dir=str(lists_dir), db_path=":memory:", pause_file=str(tmp_path / "PAUSE"), **cfg_kw)
        return Analyzer(cfg, Store(":memory:"), classifier)
    return _make
