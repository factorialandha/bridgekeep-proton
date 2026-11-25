"""Other AI vendors: OpenAI, Google Gemini, and a local OpenAI-compatible
server (Ollama, LM Studio, llama.cpp). Anthropic stays the default and keeps
its own client in classify.py.

Same prompt, same fields, same untrusted-email markers and the same
validate() for every vendor; only the wire format differs. No vendor SDKs:
one small HTTP client, so the rules are the same everywhere and easy to read
(security review of the vendor design):

* Always through the egress proxy with CONNECT, also for a plain-http local
  server, so the proxy's one-entry allowlist decides where mail goes.
* Each vendor has its own key file; a key is never sent to another vendor.
  Gemini's key goes in the x-goog-api-key header, never in the URL.
* Answers are untrusted (a local model most of all): at most 64 KB read,
  one total deadline, no redirects (http.client never follows them), TLS
  verified for https. Only validate()'s three fields come out.

Which vendor, model and endpoint are used is set by the host (setup or the
portal's host-side drop box, with step-up), never by settings.yaml.
"""

from __future__ import annotations

import http.client
import ipaddress
import json
import ssl
import time
from dataclasses import dataclass
from urllib.parse import urlsplit

from .classify import (SCHEMA, SYSTEM_PROMPT, Classification, ClassifyError, build_user_message,
                       validate)

PROVIDERS = ("anthropic", "openai", "gemini", "local")
# The one host each hosted vendor may be reached on (the egress allowlist).
HOSTS = {
    "anthropic": "api.anthropic.com:443",
    "openai": "api.openai.com:443",
    "gemini": "generativelanguage.googleapis.com:443",
}
# Who receives the mail, for setup and the portal's confirm screen.
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
MAX_RESPONSE = 64 * 1024
TOTAL_TIMEOUT = 45.0
MAX_OUTPUT_TOKENS = 1024
# Docker networks and ports a local endpoint must never point at (Bridge,
# its SMTP, the mail network). The host-side check also refuses the other
# Docker subnets and published ports, which only it can see.
REFUSED_PORTS = (1143, 1025)
REFUSED_NETS = tuple(ipaddress.ip_network(n) for n in (
    "127.0.0.0/8", "::1/128", "169.254.0.0/16", "fe80::/10", "0.0.0.0/8", "172.31.253.0/24"))


@dataclass
class Endpoint:
    scheme: str
    host: str          # IP literal for local, the vendor's name otherwise
    port: int
    path: str          # base path, e.g. /v1


def check_local_endpoint(url: str) -> Endpoint:
    """A local server URL we accept, or ValueError saying why not.

    Must be an IP literal (the host resolved names during its own check and
    pinned the address), not loopback, link-local or Bridge's network, not
    Bridge's ports. Plain http only for a private (RFC 1918 / ULA) address."""
    try:
        parts = urlsplit(url)
        port = parts.port
    except ValueError:
        raise ValueError("not a valid address") from None
    if parts.scheme not in ("http", "https") or parts.username or parts.password or parts.query:
        raise ValueError("use http(s)://IP:port/v1 with no user, password or query")
    try:
        ip = ipaddress.ip_address((parts.hostname or "").strip("[]"))
    except ValueError:
        raise ValueError("use the server's IP address, not a name") from None
    port = port or (443 if parts.scheme == "https" else 80)
    if any(ip in n for n in REFUSED_NETS) or ip.is_multicast or ip.is_unspecified:
        raise ValueError("that address is this machine, link-local or Bridge's own network")
    if port in REFUSED_PORTS:
        raise ValueError("that port is Bridge's")
    if parts.scheme == "http" and not ip.is_private:
        raise ValueError("plain http is only allowed on your own network; use https")
    return Endpoint(parts.scheme, str(ip), port, (parts.path or "/v1").rstrip("/") or "/v1")


# Built-in prices, USD per million tokens (input, output). Other vendors'
# prices change often and differ by plan, so they are entered by you in setup
# or the portal; until then the model is not used ("no_price").
BUILT_IN_PRICES = {
    ("anthropic", "claude-haiku-5-5"): (0.10, 0.50),
}


def prices(cfg) -> tuple[float, float] | None:
    if cfg.price_in_per_mtok is not None and cfg.price_out_per_mtok is not None:
        return cfg.price_in_per_mtok, cfg.price_out_per_mtok
    if cfg.provider == "local":
        return 0.0, 0.0
    return BUILT_IN_PRICES.get((cfg.provider, cfg.model))


def cost(cfg, input_tokens: int, output_tokens: int) -> float:
    p = prices(cfg) or (0.0, 0.0)
    return (input_tokens * p[0] + output_tokens * p[1]) / 1_000_000


def egress_entry(provider: str, endpoint: str = "") -> str:
    """The single host:port the egress proxy should allow for this choice."""
    if provider == "local":
        ep = check_local_endpoint(endpoint)
        return f"{ep.host}:{ep.port}"
    return HOSTS[provider]


def _proxy(proxy: str) -> tuple[str, int]:
    p = urlsplit(proxy)
    if p.scheme != "http" or not p.hostname:
        raise ValueError("model.proxy must be http://host:port")
    return p.hostname, p.port or 3128


class HTTPClassifier:
    """OpenAI, Gemini or a local OpenAI-compatible server."""

    def __init__(self, provider: str, model: str, api_key: str = "", proxy: str = "",
                 endpoint: str = "", timeout: float = TOTAL_TIMEOUT, connection=None) -> None:
        if provider not in ("openai", "gemini", "local"):
            raise ValueError(f"unknown provider {provider}")
        if provider != "local" and not api_key:
            raise ValueError("an API key is needed")
        self.provider, self.model, self._key, self.timeout = provider, model, api_key, timeout
        if provider == "local":
            self.ep = check_local_endpoint(endpoint)
        elif provider == "openai":
            self.ep = Endpoint("https", "api.openai.com", 443, "/v1")
        else:
            self.ep = Endpoint("https", "generativelanguage.googleapis.com", 443, "/v1beta")
        self._proxy = _proxy(proxy) if proxy else None
        self._connection = connection   # tests

    # -- wire formats -----------------------------------------------------
    def _request(self, fields: dict, context: list[str] | None) -> tuple[str, dict, dict]:
        user = build_user_message(fields, context=context)
        if self.provider == "gemini":
            path = f"{self.ep.path}/models/{self.model}:generateContent"
            body = {"systemInstruction": {"parts": [{"text": SYSTEM_PROMPT}]},
                    "contents": [{"role": "user", "parts": [{"text": user}]}],
                    "generationConfig": {"responseMimeType": "application/json",
                                         "maxOutputTokens": MAX_OUTPUT_TOKENS, "temperature": 0}}
            headers = {"x-goog-api-key": self._key}
        else:
            path = f"{self.ep.path}/chat/completions"
            body = {"model": self.model, "temperature": 0,
                    "messages": [{"role": "system", "content": SYSTEM_PROMPT},
                                 {"role": "user", "content": user}],
                    "response_format": {"type": "json_schema",
                                        "json_schema": {"name": "triage", "strict": True, "schema": SCHEMA}}}
            body["max_completion_tokens" if self.provider == "openai" else "max_tokens"] = MAX_OUTPUT_TOKENS
            headers = {"Authorization": f"Bearer {self._key}"} if self._key else {}
        return path, body, headers

    def _answer(self, data: dict) -> tuple[str, tuple[int, int], str]:
        """(text, (input tokens, output tokens), stop reason) from a vendor's JSON."""
        if self.provider == "gemini":
            cand = (data.get("candidates") or [{}])[0]
            parts = ((cand.get("content") or {}).get("parts") or [{}])
            usage = data.get("usageMetadata") or {}
            tokens = (int(usage.get("promptTokenCount") or 0), int(usage.get("candidatesTokenCount") or 0))
            stop = "end_turn" if cand.get("finishReason") == "STOP" else str(cand.get("finishReason"))
            return str(parts[0].get("text") or ""), tokens, stop
        choice = (data.get("choices") or [{}])[0]
        usage = data.get("usage") or {}
        tokens = (int(usage.get("prompt_tokens") or 0), int(usage.get("completion_tokens") or 0))
        stop = "end_turn" if choice.get("finish_reason") == "stop" else str(choice.get("finish_reason"))
        return str((choice.get("message") or {}).get("content") or ""), tokens, stop

    # -- transport --------------------------------------------------------
    def _connect(self):
        if self._connection is not None:
            return self._connection(self.ep)
        if self.ep.scheme == "https":
            ctx = ssl.create_default_context()
            if self._proxy:
                conn = http.client.HTTPSConnection(*self._proxy, timeout=self.timeout, context=ctx)
            else:
                conn = http.client.HTTPSConnection(self.ep.host, self.ep.port, timeout=self.timeout, context=ctx)
        else:
            conn = http.client.HTTPConnection(*(self._proxy or (self.ep.host, self.ep.port)), timeout=self.timeout)
        if self._proxy:
            conn.set_tunnel(self.ep.host, self.ep.port)   # CONNECT, even for plain http
        return conn

    def _post(self, path: str, body: dict, headers: dict) -> tuple[int, bytes]:
        deadline = time.monotonic() + self.timeout
        raw = json.dumps(body).encode()
        conn = self._connect()
        try:
            conn.request("POST", path, body=raw, headers={
                **headers, "Host": self.ep.host if self.ep.port in (80, 443) else f"{self.ep.host}:{self.ep.port}",
                "Content-Type": "application/json", "Accept": "application/json",
                "Content-Length": str(len(raw)), "Connection": "close"})
            resp = conn.getresponse()
            chunks, size = [], 0
            while True:
                if time.monotonic() > deadline:
                    raise ClassifyError("answer took too long")
                chunk = resp.read(8192)
                if not chunk:
                    break
                size += len(chunk)
                if size > MAX_RESPONSE:
                    raise ClassifyError("answer too large")
                chunks.append(chunk)
            return resp.status, b"".join(chunks)
        except (OSError, http.client.HTTPException, ssl.SSLError) as e:
            raise ClassifyError(f"{self.provider} unreachable ({type(e).__name__})") from None
        finally:
            conn.close()

    def classify(self, fields: dict, context: list[str] | None = None) -> Classification:
        path, body, headers = self._request(fields, context)
        status, raw = self._post(path, body, headers)
        if status in (429,):
            raise ClassifyError("rate limited")
        if not 200 <= status < 300:
            raise ClassifyError(f"API error {status}")      # never echo the body: it may quote the key
        try:
            data = json.loads(raw.decode("utf-8"))
            if not isinstance(data, dict):
                raise ValueError
            text, tokens, stop = self._answer(data)
        except (ValueError, UnicodeDecodeError, TypeError, AttributeError, IndexError):
            raise ClassifyError("answer is not the expected JSON") from None
        if stop != "end_turn":
            err = ClassifyError(f"stopped: {stop[:40]}")
            err.tokens = tokens  # type: ignore[attr-defined]
            raise err
        try:
            label, conf, reason = validate(text)
        except ClassifyError as e:
            e.tokens = tokens  # type: ignore[attr-defined]
            raise
        return Classification(label, conf, reason, self.model, *tokens)
