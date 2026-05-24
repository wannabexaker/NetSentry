"""
AI client abstraction.

Plugins call `self.ctx.ai.complete(prompt, system=…)` without caring which
backend is configured. The runtime constructs the right adapter based on
config.

Adapters provided:
    OllamaClient   — talks to a local/remote Ollama server (default).
                     Includes availability probe so we can skip gracefully
                     when the host PC is off.
    DisabledAI     — used when no AI is configured. complete() returns an
                     informative error string.

Future adapters: AnthropicClient, OpenAIClient, GeminiClient.

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
from typing import Any

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
            with urllib.request.urlopen(
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
            with urllib.request.urlopen(req, timeout=self._request_timeout) as r:
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

    # Future: anthropic / openai / google.
    log.warning("Unknown AI provider %r — using DisabledAI", provider)
    return DisabledAI()
