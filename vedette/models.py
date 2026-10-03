"""Model backend abstraction for Vedette.

Supported providers:
  - ollama:    local model via the Ollama /api/chat endpoint (no API key).
  - openai:    any OpenAI-compatible API via base_url + /chat/completions.
               When talking to api.openai.com with web_search=True, the
               Responses API (/v1/responses) is used with the server-side
               web_search tool.
  - anthropic: native Claude Messages API; web_search=True attaches the
               server-side web_search tool (results come back inline).

Data-boundary discipline: hosted backends receive only the research task
content. API key values are never logged, printed, or written to the audit
trail -- only backend kind, model id, and token counts are recorded.
"""

from __future__ import annotations

import os

import requests

VALID_PROVIDERS = ("ollama", "openai", "anthropic")

# Default env var holding the API key for each hosted provider.
PROVIDER_KEY_ENV = {
    "openai": "OPENAI_API_KEY",
    "anthropic": "ANTHROPIC_API_KEY",
}

DEFAULT_BASE_URLS = {
    "ollama": "http://localhost:11434",
    "openai": "https://api.openai.com/v1",
}

DEFAULT_MODELS = {
    "ollama": "llama3.1",
    "openai": "gpt-5",
    "anthropic": "claude-sonnet-4-5",
}


class ConfigError(Exception):
    """Raised for configuration problems (missing keys, unknown provider)."""


class ChatResult:
    """Result of one chat call: text plus normalized token usage."""

    def __init__(self, text, backend, model, input_tokens=0, output_tokens=0):
        self.text = text or ""
        self.backend = backend
        self.model = model
        self.input_tokens = input_tokens or 0
        self.output_tokens = output_tokens or 0

    def usage(self):
        return {
            "backend": self.backend,
            "model": self.model,
            "input_tokens": self.input_tokens,
            "output_tokens": self.output_tokens,
        }


def _require_env(name):
    """Return the env var value, or fail fast naming the missing variable."""
    value = os.environ.get(name)
    if not value:
        raise ConfigError(
            "Missing required API key: set %s in the environment "
            "(keys are read from env only, never from config files)." % name
        )
    return value


def _post_json(url, payload, headers=None, timeout=600):
    resp = requests.post(url, json=payload, headers=headers or {}, timeout=timeout)
    resp.raise_for_status()
    return resp.json()


class Backend:
    """Common chat(messages) -> ChatResult interface."""

    kind = "base"

    def __init__(self, model):
        self.model = model

    def chat(self, messages, system=None, web_search=False):
        raise NotImplementedError


class OllamaBackend(Backend):
    kind = "ollama"

    def __init__(self, model, base_url=None):
        super().__init__(model)
        self.base_url = (base_url or DEFAULT_BASE_URLS["ollama"]).rstrip("/")

    def chat(self, messages, system=None, web_search=False):
        # Local backend: web_search is not supported, silently ignored.
        msgs = ([{"role": "system", "content": system}] if system else []) + list(messages)
        data = _post_json(
            self.base_url + "/api/chat",
            {"model": self.model, "messages": msgs, "stream": False},
        )
        text = (data.get("message") or {}).get("content", "")
        return ChatResult(
            text,
            backend="ollama",
            model=self.model,
            input_tokens=data.get("prompt_eval_count", 0),
            output_tokens=data.get("eval_count", 0),
        )


class OpenAIBackend(Backend):
    kind = "openai"

    def __init__(self, model, api_key=None, base_url=None, api_key_env=None):
        super().__init__(model)
        env_name = api_key_env or PROVIDER_KEY_ENV["openai"]
        self.api_key = api_key if api_key is not None else _require_env(env_name)
        self.base_url = (base_url or DEFAULT_BASE_URLS["openai"]).rstrip("/")

    def _headers(self):
        return {"Authorization": "Bearer " + self.api_key}

    def _uses_responses_search(self):
        # The Responses API with web_search is an OpenAI-platform feature.
        return "api.openai.com" in self.base_url

    def chat(self, messages, system=None, web_search=False):
        if web_search and self._uses_responses_search():
            return self._responses_with_search(messages, system)
        return self._chat_completions(messages, system)

    def _chat_completions(self, messages, system):
        msgs = ([{"role": "system", "content": system}] if system else []) + list(messages)
        data = _post_json(
            self.base_url + "/chat/completions",
            {"model": self.model, "messages": msgs},
            headers=self._headers(),
        )
        text = (data.get("choices") or [{}])[0].get("message", {}).get("content", "")
        usage = data.get("usage") or {}
        return ChatResult(
            text,
            backend="openai",
            model=self.model,
            input_tokens=usage.get("prompt_tokens", 0),
            output_tokens=usage.get("completion_tokens", 0),
        )

    def _responses_with_search(self, messages, system):
        # Server-side web search: results come back inline, no tool loop needed.
        input_items = []
        if system:
            input_items.append({"role": "developer", "content": system})
        input_items.extend(messages)
        data = _post_json(
            self.base_url + "/responses",
            {
                "model": self.model,
                "input": input_items,
                "tools": [{"type": "web_search"}],
                "tool_choice": "auto",
            },
            headers=self._headers(),
        )
        text = self._extract_responses_text(data)
        usage = data.get("usage") or {}
        return ChatResult(
            text,
            backend="openai",
            model=self.model,
            input_tokens=usage.get("input_tokens", 0),
            output_tokens=usage.get("output_tokens", 0),
        )

    @staticmethod
    def _extract_responses_text(data):
        chunks = []
        for item in data.get("output") or []:
            if item.get("type") == "message":
                for part in item.get("content") or []:
                    if part.get("type") in ("output_text", "text") and part.get("text"):
                        chunks.append(part["text"])
        return "\n".join(chunks)


class AnthropicBackend(Backend):
    kind = "anthropic"

    WEB_SEARCH_TOOL = {"type": "web_search_20260205", "name": "web_search"}

    def __init__(self, model, api_key=None, api_key_env=None, api_version="2023-06-01"):
        super().__init__(model)
        env_name = api_key_env or PROVIDER_KEY_ENV["anthropic"]
        self.api_key = api_key if api_key is not None else _require_env(env_name)
        self.api_version = api_version

    def chat(self, messages, system=None, web_search=False):
        body = {
            "model": self.model,
            "max_tokens": 4096,
            "messages": list(messages),
        }
        if system:
            body["system"] = system
        if web_search:
            # Server-side tool: Anthropic executes the search and returns
            # the results inline as tool_result blocks.
            body["tools"] = [dict(self.WEB_SEARCH_TOOL)]
        data = _post_json(
            "https://api.anthropic.com/v1/messages",
            body,
            headers={
                "x-api-key": self.api_key,
                "anthropic-version": self.api_version,
                "content-type": "application/json",
            },
        )
        text = self._extract_text(data.get("content") or [])
        usage = data.get("usage") or {}
        return ChatResult(
            text,
            backend="anthropic",
            model=self.model,
            input_tokens=usage.get("input_tokens", 0),
            output_tokens=usage.get("output_tokens", 0),
        )

    @staticmethod
    def _extract_text(blocks):
        chunks = []

        def walk(node):
            if isinstance(node, dict):
                if node.get("type") == "text" and node.get("text"):
                    chunks.append(node["text"])
                for value in node.values():
                    walk(value)
            elif isinstance(node, list):
                for value in node:
                    walk(value)

        walk(blocks)
        return "\n".join(chunks)


def make_backend(provider, cfg):
    """Build a backend from a config section; fail fast on missing keys."""
    provider = (provider or "").lower()
    if provider not in VALID_PROVIDERS:
        raise ConfigError(
            "Unknown model provider %r (expected one of: %s)."
            % (provider, ", ".join(VALID_PROVIDERS))
        )
    model = cfg.get("model") or DEFAULT_MODELS[provider]
    if provider == "ollama":
        return OllamaBackend(model, base_url=cfg.get("base_url"))
    if provider == "openai":
        return OpenAIBackend(
            model,
            base_url=cfg.get("base_url"),
            api_key_env=cfg.get("api_key_env"),
        )
    return AnthropicBackend(model, api_key_env=cfg.get("api_key_env"))


def select_backends(cfg):
    """Return (research_backend, synthesis_backend) from the config."""
    research_cfg = cfg.get("research_backend") or {}
    synth_cfg = cfg.get("synthesis_backend") or {}
    research = make_backend(research_cfg.get("provider", "anthropic"), research_cfg)
    synthesis = make_backend(synth_cfg.get("provider", "ollama"), synth_cfg)
    return research, synthesis
