"""Who analyzes the mail: Anthropic (default), OpenAI, Google Gemini or the
admin's own local server (analyzer PR #49).

The portal only checks the form and leaves one request in the host's drop
box (secret_drop). Root's scripts/secret-requests.sh runs
scripts/analyzer-provider.sh with the key on stdin; that script checks
everything again, alerts Discord first, and rewrites analyzer.yaml. The
portal never writes analyzer.yaml or a key file.
"""

from __future__ import annotations

import re
from dataclasses import dataclass

# Kept word for word with analyzer/src/analyzer/providers.py DISCLOSURE (a
# test checks): security wants the same wording as the CLI.
DISCLOSURE = {
    "anthropic": "Anthropic receives the extracted fields of each analyzed message.",
    "openai": "OpenAI receives the extracted fields of each analyzed message. Check your plan's "
              "data-use terms; a paid plan with data sharing off, or zero retention, is recommended.",
    "gemini": "Google receives the extracted fields of each analyzed message. Check your plan's "
              "data-use terms: the free tier may use API data to improve Google's products, so a "
              "paid plan is recommended.",
    "local": "Your own server receives the extracted fields of each analyzed message; nothing leaves "
             "your network. Over plain http, mail content crosses your network unencrypted.",
}


@dataclass(frozen=True)
class Vendor:
    label: str
    key: re.Pattern
    key_hint: str
    key_placeholder: str
    needs_price: bool
    model_hint: str


VENDORS = {
    "anthropic": Vendor("Anthropic (Claude)", re.compile(r"sk-ant-[A-Za-z0-9_-]{20,200}"),
                        "That isn't a Claude API key. It starts with sk-ant-.", "sk-ant-…", False,
                        "claude-haiku-5-5 if left empty, which has a built-in price."),
    "openai": Vendor("OpenAI", re.compile(r"sk-[A-Za-z0-9_-]{20,200}"),
                     "That isn't an OpenAI API key. It starts with sk-.", "sk-…", True,
                     "Exactly as the OpenAI dashboard shows it, for example gpt-5-mini."),
    "gemini": Vendor("Google Gemini", re.compile(r"AIza[0-9A-Za-z_-]{35}"),
                     "That isn't a Gemini API key. It starts with AIza and is 39 characters long.", "AIza…", True,
                     "Exactly as Google AI Studio shows it, for example gemini-2.5-flash."),
    "local": Vendor("Your own server (Ollama, LM Studio, llama.cpp)", re.compile(r"[!-~]{1,200}"),
                    "That key has characters a server key can't have.", "optional", False,
                    "Exactly as your server lists it, for example llama3.1:8b."),
}
DEFAULT_MODEL = {"anthropic": "claude-haiku-5-5"}

MODEL = re.compile(r"[A-Za-z0-9][A-Za-z0-9._:/-]{0,99}")
ENDPOINT = re.compile(r"https?://([A-Za-z0-9.-]{1,253}|\[[0-9A-Fa-f:.]{2,45}\])(:[0-9]{1,5})?(/[A-Za-z0-9._~/-]{0,100})?")
PRICE = re.compile(r"[0-9]{1,4}(\.[0-9]{1,6})?")


class VendorError(Exception):
    """Shown to the admin as is."""


def check(form: dict) -> dict:
    """The non-secret fields, cleaned, or VendorError with what to fix."""
    provider = (form.get("provider") or "").strip()
    if provider not in VENDORS:
        raise VendorError("Choose who should analyze the mail.")
    model = (form.get("model") or "").strip() or DEFAULT_MODEL.get(provider, "")
    if not model:
        raise VendorError("Type the model name, exactly as your vendor's console or server shows it.")
    if not MODEL.fullmatch(model):
        raise VendorError("That model name has characters model names don't use. "
                          "Letters, digits and . _ : / - only, starting with a letter or digit.")
    endpoint = (form.get("endpoint") or "").strip()
    if provider == "local":
        if not endpoint:
            raise VendorError("Type your server's address, for example http://192.168.1.20:11434/v1.")
        if not ENDPOINT.fullmatch(endpoint):
            raise VendorError("That isn't a server address. It looks like http://192.168.1.20:11434/v1.")
    else:
        endpoint = ""
    price_in = (form.get("price_in") or "").strip()
    price_out = (form.get("price_out") or "").strip()
    if price_in or price_out:
        if not (PRICE.fullmatch(price_in) and PRICE.fullmatch(price_out)):
            raise VendorError("Prices are US$ per million tokens: both numbers, for example 0.25 and 2.")
    elif VENDORS[provider].needs_price:
        raise VendorError(f"Type {VENDORS[provider].label}'s prices for this model, from its pricing page. "
                          "The analyzer won't use a model it can't count the cost of.")
    return {"provider": provider, "model": model, "endpoint": endpoint,
            "price_in": price_in, "price_out": price_out}


def check_key(provider: str, key: str) -> str:
    """The key, stripped. Empty means: keep the one the host already has."""
    key = key.strip()
    if key and not VENDORS[provider].key.fullmatch(key):
        raise VendorError(VENDORS[provider].key_hint)
    return key


def label(provider: str) -> str:
    v = VENDORS.get(provider)
    return v.label if v else ""
