"""
AI client abstraction.

Plugins call `self.ctx.ai.complete(prompt, system=…)` without caring which
backend is configured. The runtime constructs the right adapter based on
config.

Adapters provided:
    OllamaClient   — talks to a local/remote Ollama server (default).
                     Includes availability probe so we can skip gracefully
                     when the host PC is off.
    OpenAICompatibleClient
                   — any OpenAI-style /v1 server (LM Studio, vLLM, llama.cpp,
                     OpenAI). Can be reached through an SSH tunnel that the
                     workstation plugin opens on demand.
    DisabledAI     — used when no AI is configured. complete() returns an
                     informative error string.

Future adapters: AnthropicClient, GeminiClient.

Reachability model
──────────────────
`is_available()` does a fast (~2s) probe before any real call. A plugin can
choose to:
  • Block the user with a helpful "AI is offline" message, OR
  • Queue the work (state_dir/queue.json) for the scheduler to retry later.

Plugins should NOT call `complete()` if `is_available()` returned False —
the network round-trip will time out and ruin UX.
"""

from __future__ import annotations

import json
import logging
import socket
import urllib.error
import urllib.parse
import urllib.request
from abc import ABC, abstractmethod
from typing import Any, Callable

log = logging.getLogger(__name__)


class AIClient(ABC):
    """Abstract LLM client."""

    name: str = "abstract"

    @abstractmethod
    def complete(self, prompt: str, *, system: str | None = None,
                 max_tokens: int = 2048, temperature: float = 0.2) -> str:
        """Return the assistant's text reply. Raise on failure."""

    @abstractmethod
    def is_available(self) -> bool:
        """Fast probe (~1-2s). True if the backend is reachable & responsive."""


# ─── Ollama ────────────────────────────────────────────────────────────

class OllamaClient(AIClient):
    """
    Ollama HTTP client. Default endpoint http://localhost:11434.

    For the typical NetSentry deployment, this points to the user's
    workstation reachable via LAN or Tailscale, NOT the Pi itself
    (Ollama is too heavy for a Pi 4).

    Set `host` to the user's Tailscale IP (e.g. 100.x.y.z) for
    works-from-anywhere AI.
    """

    name = "ollama"

    def __init__(self, host: str = "localhost", port: int = 11434,
                 model: str = "llama3.1", *, probe_timeout: float = 2.0,
                 request_timeout: float = 120.0):
        self.host = host
        self.port = port
        self.model = model
        self.base = f"http://{host}:{port}"
        self._probe_timeout = probe_timeout
        self._request_timeout = request_timeout

    # ─── availability ────────────────────────────────────────────

    def is_available(self) -> bool:
        """Quick TCP probe + /api/tags ping."""
        try:
            with socket.create_connection((self.host, self.port),
                                           timeout=self._probe_timeout):
                pass
        except (socket.timeout, OSError):
            log.debug("Ollama at %s:%s — TCP unreachable", self.host, self.port)
            return False
        # TCP open. Verify it's actually Ollama (cheap GET).
        try:
            with urllib.request.urlopen(  # nosec B310
                f"{self.base}/api/tags", timeout=self._probe_timeout
            ) as r:
                return r.status == 200
        except (urllib.error.URLError, socket.timeout) as e:
            log.debug("Ollama at %s/api/tags failed: %s", self.base, e)
            return False

    # ─── completion ──────────────────────────────────────────────

    def complete(self, prompt: str, *, system: str | None = None,
                 max_tokens: int = 2048, temperature: float = 0.2) -> str:
        body: dict[str, Any] = {
            "model": self.model,
            "prompt": prompt,
            "stream": False,
            "options": {
                "num_predict": max_tokens,
                "temperature": temperature,
            },
        }
        if system:
            body["system"] = system

        req = urllib.request.Request(
            f"{self.base}/api/generate",
            data=json.dumps(body).encode("utf-8"),
            headers={"Content-Type": "application/json"},
        )
        try:
            with urllib.request.urlopen(req, timeout=self._request_timeout) as r:  # nosec B310
                payload = json.load(r)
        except (urllib.error.URLError, socket.timeout) as e:
            raise RuntimeError(f"Ollama request failed: {e}") from e
        # Ollama returns {"response": "...", "done": true, ...}
        text = (payload.get("response") or "").strip()
        if not text:
            raise RuntimeError(f"Ollama returned empty response: {payload}")
        return text

    def __repr__(self) -> str:
        return f"<OllamaClient host={self.host}:{self.port} model={self.model}>"


# ─── OpenAI-compatible (LM Studio, llama.cpp server, vLLM, OpenAI…) ──────

class OpenAICompatibleClient(AIClient):
    """
    Any server that speaks the OpenAI ``/v1`` API: ``GET /models`` and
    ``POST /chat/completions``. LM Studio is the first user; vLLM, llama.cpp's
    server, LiteLLM and OpenAI itself work the same way.

    A server that only listens on another machine's loopback is reached
    through an SSH tunnel (``core/tunnel.py``): whoever owns the tunnel calls
    :meth:`attach_tunnel`, and every availability probe then makes sure it is
    up first — so the AI becomes available when that PC is on, with no manual
    step, and stays a fast "no" when it is off.
    """

    name = "openai"

    def __init__(self, base_url: str = "http://127.0.0.1:1234/v1", model: str = "",
                 *, api_key: str | None = None, probe_timeout: float = 3.0,
                 request_timeout: float = 180.0,
                 opener: Callable[..., Any] = urllib.request.urlopen):
        base = str(base_url or "").strip().rstrip("/")
        if urllib.parse.urlsplit(base).scheme not in ("http", "https"):
            raise ValueError(f"base_url must be an http(s) URL, not {base_url!r}")
        self.base = base
        self.model = str(model or "")
        self._key = str(api_key or "")
        self._probe_timeout = probe_timeout
        self._request_timeout = request_timeout
        self._open = opener
        self._ensure: Callable[[], bool] | None = None

    def attach_tunnel(self, ensure: Callable[[], bool]) -> None:
        """Call ``ensure()`` before talking to the server (it returns False
        when the way there cannot be opened right now)."""
        self._ensure = ensure

    def endpoint(self) -> tuple[str, int]:
        """``(host, port)`` of the server, for checking where a tunnel must lead."""
        parts = urllib.parse.urlsplit(self.base)
        return (parts.hostname or "",
                parts.port or (443 if parts.scheme == "https" else 80))

    def _headers(self) -> dict[str, str]:
        headers = {"Content-Type": "application/json", "Accept": "application/json"}
        if self._key:
            headers["Authorization"] = f"Bearer {self._key}"
        return headers

    def _path_open(self) -> bool:
        if self._ensure is None:
            return True
        try:
            return bool(self._ensure())
        except Exception:
            log.exception("AI tunnel could not be checked")
            return False

    # ─── availability ────────────────────────────────────────────

    def is_available(self) -> bool:
        """The way there is open and the server lists its models."""
        if not self._path_open():
            return False
        return self.models() is not None

    def models(self) -> list[str] | None:
        """Model ids the server offers, or None when it does not answer."""
        req = urllib.request.Request(f"{self.base}/models", headers=self._headers())
        try:
            with self._open(req, timeout=self._probe_timeout) as r:  # nosec B310 - http(s) only, checked in __init__
                payload = json.load(r)
        except (urllib.error.URLError, socket.timeout, OSError, ValueError) as e:
            log.debug("AI server at %s/models did not answer: %s", self.base, e)
            return None
        data = payload.get("data") if isinstance(payload, dict) else None
        if not isinstance(data, list):
            return None
        return [str(m.get("id")) for m in data if isinstance(m, dict) and m.get("id")]

    # ─── completion ──────────────────────────────────────────────

    def complete(self, prompt: str, *, system: str | None = None,
                 max_tokens: int = 2048, temperature: float = 0.2) -> str:
        messages = ([{"role": "system", "content": system}] if system else []) + \
            [{"role": "user", "content": prompt}]
        return self.chat(messages, max_tokens=max_tokens, temperature=temperature)

    def chat(self, messages: list[dict[str, str]], *, max_tokens: int = 2048,
             temperature: float = 0.2) -> str:
        if not self._path_open():
            raise RuntimeError("AI server is not reachable right now")
        body: dict[str, Any] = {"messages": messages, "max_tokens": max_tokens,
                                "temperature": temperature, "stream": False}
        if self.model:
            body["model"] = self.model
        req = urllib.request.Request(f"{self.base}/chat/completions",
                                     data=json.dumps(body).encode("utf-8"),
                                     headers=self._headers(), method="POST")
        try:
            with self._open(req, timeout=self._request_timeout) as r:  # nosec B310 - http(s) only, checked in __init__
                payload = json.load(r)
        except urllib.error.HTTPError as e:
            # The reason only: the request (and its key) stays out of the message.
            raise RuntimeError(f"AI server answered HTTP {e.code}") from e
        except (urllib.error.URLError, socket.timeout, OSError) as e:
            raise RuntimeError(f"AI request failed: {getattr(e, 'reason', e)}") from e
        except ValueError as e:
            raise RuntimeError("AI server's answer was not JSON") from e
        try:
            text = payload["choices"][0]["message"]["content"] or ""
        except (KeyError, IndexError, TypeError):
            text = ""
        text = str(text).strip()
        if not text:
            raise RuntimeError("AI server returned an empty answer")
        return text

    def __repr__(self) -> str:
        tunnel = " via tunnel" if self._ensure else ""
        return f"<OpenAICompatibleClient {self.base} model={self.model or 'default'}{tunnel}>"


# ─── Disabled (no-op) ──────────────────────────────────────────────────

class DisabledAI(AIClient):
    """Stand-in when no AI is configured. Always reports unavailable."""

    name = "disabled"

    def is_available(self) -> bool:
        return False

    def complete(self, prompt: str, **_) -> str:
        raise RuntimeError(
            "AI is disabled in config. Set ai.provider in config.yaml."
        )


# ─── builder ───────────────────────────────────────────────────────────

def build_ai(cfg: dict | None) -> AIClient:
    """Build an AIClient from config dict. Returns DisabledAI if absent."""
    if not cfg or not cfg.get("provider"):
        return DisabledAI()

    provider = cfg["provider"].lower()
    params = cfg.get("config", {})

    if provider == "ollama":
        return OllamaClient(
            host=params.get("host", "localhost"),
            port=int(params.get("port", 11434)),
            model=params.get("model", "llama3.1"),
            probe_timeout=float(params.get("probe_timeout", 2.0)),
            request_timeout=float(params.get("request_timeout", 120.0)),
        )

    if provider in ("openai", "openai-compatible", "lmstudio"):
        try:
            return OpenAICompatibleClient(
                base_url=params.get("base_url", "http://127.0.0.1:1234/v1"),
                model=params.get("model", ""),
                api_key=params.get("api_key") or None,
                probe_timeout=float(params.get("probe_timeout", 3.0)),
                request_timeout=float(params.get("request_timeout", 180.0)),
            )
        except ValueError as e:
            log.error("AI provider %s: %s — using DisabledAI", provider, e)
            return DisabledAI()

    # Future: anthropic / google.
    log.warning("Unknown AI provider %r — using DisabledAI", provider)
    return DisabledAI()
