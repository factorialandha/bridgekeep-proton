"""Deterministic scan for text aimed at AI systems (scoping doc 6A.5a).

A match never makes a message safer. It is logged as an injection attempt,
it stops the sender from ever being learned as protected, and it means a
"legitimate" verdict from the model is not trusted (the message goes to
review instead).
"""

from __future__ import annotations

import base64
import re
from dataclasses import dataclass

_PATTERNS: list[tuple[str, re.Pattern]] = [
    (name, re.compile(rx, re.I))
    for name, rx in [
        ("ignore_instructions", r"\b(ignore|disregard|forget|override)\b.{0,40}\b(previous|prior|above|earlier|all|your|the)\b.{0,30}\b(instructions?|prompts?|rules|directions|guidelines)\b"),
        ("system_prompt", r"\b(system|developer)\s*(prompt|message|instructions?)\b|<\s*/?\s*(system|assistant|user)\s*>|\[/?(system|inst)\]|<\|im_(start|end)\|>"),
        ("role_play", r"\byou are (now )?(an? )?(ai|assistant|language model|classifier|spam filter)\b|\bas an ai (model|assistant)\b"),
        ("addressed_to_ai", r"\b(dear|attention|note to|message for|hey|hello)\s*,?\s*(the\s+)?(ai|llm|assistant|chatgpt|claude|gpt|gemini|model|classifier|spam filter|email filter|bot)\b"),
        ("classify_as", r"\b(classify|label|mark|categori[sz]e|treat|consider|rate)\b.{0,30}\b(this|the|it)\b.{0,30}\b(as )?(safe|legitimate|not spam|ham|important|trusted|whitelisted|allowlisted)\b"),
        ("pre_approved", r"\b(pre-?approved|already (been )?(verified|approved|whitelisted)|verified (safe|sender) by|this (email|message) is (safe|legitimate|not spam))\b"),
        ("output_format", r"\b(respond|reply|output|answer|return)\b.{0,30}\b(json|\{\s*\"label\"|confidence\s*[:=])"),
        ("fake_delimiter", r"(-{3,}|={3,}|#{3,})\s*(end|begin|start)\s*(of\s*)?(email|message|untrusted|content|data)|untrusted[_ -]?(content|email)[_ -]?(end|begin)"),
        ("confidence_claim", r"\"?\b(label|confidence)\"?\s*[:=]\s*\"?(legitimate|0?\.\d+|1(\.0+)?)\b"),
    ]
]

_B64_BLOB = re.compile(r"[A-Za-z0-9+/]{40,}={0,2}")


@dataclass
class Injection:
    pattern: str
    snippet: str


def scan(*texts: str) -> list[Injection]:
    found: list[Injection] = []
    seen: set[str] = set()

    def check(text: str, suffix: str = "") -> None:
        for name, rx in _PATTERNS:
            if name in seen:
                continue
            m = rx.search(text)
            if m:
                seen.add(name)
                found.append(Injection(name + suffix, text[max(0, m.start() - 20): m.end() + 20][:120]))

    for text in texts:
        if not text:
            continue
        check(text)
        # Instructions hidden in base64 inside the visible text.
        for blob in _B64_BLOB.findall(text)[:5]:
            try:
                decoded = base64.b64decode(blob + "=" * (-len(blob) % 4), validate=False).decode("utf-8")
            except Exception:  # noqa: BLE001
                continue
            if decoded.isprintable():
                check(decoded, ":base64")
    return found
