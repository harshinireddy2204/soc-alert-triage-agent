"""Chat backends for the triage agent. Standard library only, no SDKs.

Two real backends are provided:

* ``OllamaBackend`` talks to a local Ollama server, so the whole project can run
  for free on a desktop GPU.
* ``OpenAICompatibleBackend`` talks to any server that implements the OpenAI chat
  completions API (hosted or self-hosted).

``ScriptedBackend`` replays canned replies and exists for the tests.
"""

from __future__ import annotations

import json
import os
import time
import urllib.error
import urllib.request
from collections.abc import Callable
from dataclasses import dataclass
from typing import Protocol


@dataclass
class Reply:
    text: str
    input_tokens: int = 0
    output_tokens: int = 0


class Backend(Protocol):
    name: str

    def chat(self, messages: list[dict]) -> Reply: ...


class BackendError(Exception):
    pass


def _post(url: str, payload: dict, headers: dict[str, str], timeout: float, retries: int = 3) -> dict:
    body = json.dumps(payload).encode("utf-8")
    last: Exception | None = None
    for attempt in range(retries):
        request = urllib.request.Request(url, data=body, headers={"Content-Type": "application/json", **headers})
        try:
            with urllib.request.urlopen(request, timeout=timeout) as response:
                return json.loads(response.read().decode("utf-8"))
        except urllib.error.HTTPError as error:
            detail = error.read().decode("utf-8", errors="replace")[:300]
            last = BackendError(f"HTTP {error.code} from {url}: {detail}")
            if error.code not in (408, 409, 429, 500, 502, 503, 504):
                break
        except (urllib.error.URLError, TimeoutError, ConnectionError) as error:
            last = BackendError(f"cannot reach {url}: {error}")
        time.sleep(2.0 * (attempt + 1))
    assert last is not None
    raise last


class OllamaBackend:
    """Local models through Ollama's native chat API (https://ollama.com)."""

    def __init__(self, model: str, host: str | None = None, context_tokens: int = 8192, timeout: float = 600.0):
        self.model = model
        self.host = (host or os.environ.get("OLLAMA_HOST") or "http://localhost:11434").rstrip("/")
        if not self.host.startswith("http"):
            self.host = "http://" + self.host
        self.context_tokens = context_tokens
        self.timeout = timeout
        self.name = f"ollama:{model}"

    def chat(self, messages: list[dict]) -> Reply:
        data = _post(
            f"{self.host}/api/chat",
            {
                "model": self.model,
                "messages": messages,
                "stream": False,
                "format": "json",
                # Ollama silently truncates prompts longer than num_ctx, so it is set explicitly.
                "options": {"temperature": 0, "seed": 7, "num_ctx": self.context_tokens},
            },
            {},
            self.timeout,
        )
        return Reply(
            text=(data.get("message") or {}).get("content", ""),
            input_tokens=int(data.get("prompt_eval_count") or 0),
            output_tokens=int(data.get("eval_count") or 0),
        )


class OpenAICompatibleBackend:
    """Any endpoint that implements ``POST /chat/completions`` in the OpenAI format."""

    def __init__(
        self, model: str, base_url: str | None = None, api_key_env: str = "OPENAI_API_KEY", json_mode: bool = True, timeout: float = 300.0
    ):
        self.model = model
        self.base_url = (base_url or os.environ.get("OPENAI_BASE_URL") or "https://api.openai.com/v1").rstrip("/")
        self.api_key = os.environ.get(api_key_env, "")
        self.json_mode = json_mode
        self.timeout = timeout
        self.name = f"openai-compatible:{model}"

    def chat(self, messages: list[dict]) -> Reply:
        payload: dict = {"model": self.model, "messages": messages, "temperature": 0}
        if self.json_mode:
            payload["response_format"] = {"type": "json_object"}
        headers = {"Authorization": f"Bearer {self.api_key}"} if self.api_key else {}
        data = _post(f"{self.base_url}/chat/completions", payload, headers, self.timeout)
        try:
            text = data["choices"][0]["message"]["content"] or ""
        except (KeyError, IndexError, TypeError) as error:
            raise BackendError(f"unexpected response shape: {str(data)[:300]}") from error
        usage = data.get("usage") or {}
        return Reply(text=text, input_tokens=int(usage.get("prompt_tokens") or 0), output_tokens=int(usage.get("completion_tokens") or 0))


class ScriptedBackend:
    """Replays fixed replies, or computes them from the conversation. For tests."""

    def __init__(self, replies: list[str] | Callable[[list[dict]], str], name: str = "scripted"):
        self._replies = replies
        self._index = 0
        self.name = name
        self.seen: list[list[dict]] = []

    def chat(self, messages: list[dict]) -> Reply:
        self.seen.append([dict(m) for m in messages])
        if callable(self._replies):
            text = self._replies(messages)
        else:
            if self._index >= len(self._replies):
                raise BackendError("scripted backend ran out of replies")
            text = self._replies[self._index]
            self._index += 1
        return Reply(text=text, input_tokens=sum(len(m["content"]) for m in messages) // 4, output_tokens=len(text) // 4)


def make_backend(
    kind: str, model: str, base_url: str | None = None, api_key_env: str = "OPENAI_API_KEY", context_tokens: int = 8192
) -> Backend:
    if kind == "ollama":
        return OllamaBackend(model, host=base_url, context_tokens=context_tokens)
    if kind == "openai":
        return OpenAICompatibleBackend(model, base_url=base_url, api_key_env=api_key_env)
    raise ValueError(f"unknown backend {kind!r}; use 'ollama' or 'openai'")
