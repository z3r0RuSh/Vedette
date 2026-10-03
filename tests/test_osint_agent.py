"""Tests for the Vedette: prompts, config, backends (mocked), reports."""

import json
import os

import pytest
import yaml

from vedette import models, orchestrator, prompts, report as report_mod


# ---------------------------------------------------------------------------
# Prompt assembly
# ---------------------------------------------------------------------------

def test_axis_prompts_cover_all_axes():
    all_axes = [a for t in prompts.TARGET_TYPES for a in prompts.axes_for_type(t)]
    assert set(all_axes) == set(prompts.AXIS_PROMPTS)
    assert set(all_axes) == set(prompts.AXIS_TITLES)
    # company axes keep their historic names
    assert set(prompts.AXES) == {"jurisdiction", "contractual", "compliance",
                                 "incidents", "posture"}


def test_axes_for_type_rejects_unknown():
    with pytest.raises(ValueError):
        prompts.axes_for_type("planet")


def test_build_axis_prompt_includes_identity():
    text = prompts.build_axis_prompt("jurisdiction", "IDENTITY-JSON-HERE")
    assert "IDENTITY-JSON-HERE" in text


def test_build_axis_prompt_unknown_axis():
    with pytest.raises(ValueError):
        prompts.build_axis_prompt("nope", "{}")


def test_system_research_demands_sources_and_not_found():
    assert "NOT FOUND" in prompts.SYSTEM_RESEARCH
    assert "## Sources" in prompts.SYSTEM_RESEARCH


def test_identity_prompt_is_json_only():
    text = prompts.build_identity_prompt("Acme", "https://acme.example")
    assert "Acme" in text and "https://acme.example" in text
    assert "JSON" in text


def test_synthesis_prompt_includes_all_axes():
    axis_texts = {a: "text-%s" % a for a in prompts.AXES}
    text = prompts.build_synthesis_prompt("IDENT", axis_texts)
    for a in prompts.AXES:
        assert prompts.AXIS_TITLES[a] in text
        assert "text-%s" % a in text


# ---------------------------------------------------------------------------
# Config parsing
# ---------------------------------------------------------------------------

def test_load_config_defaults():
    cfg = orchestrator.load_config("/nonexistent/path.yaml")
    assert cfg["research_backend"]["provider"] == "anthropic"
    assert cfg["synthesis_backend"]["provider"] == "ollama"
    assert cfg["web_search"] is True
    # ollama_url propagated into the ollama backend section
    assert cfg["synthesis_backend"]["base_url"] == "http://localhost:11434"


def test_load_config_overrides(tmp_path):
    p = tmp_path / "config.yaml"
    p.write_text(yaml.safe_dump({
        "research_backend": {"provider": "openai", "model": "gpt-5"},
        "web_search": False,
    }))
    cfg = orchestrator.load_config(str(p))
    assert cfg["research_backend"]["provider"] == "openai"
    assert cfg["research_backend"]["model"] == "gpt-5"
    assert cfg["web_search"] is False
    assert cfg["synthesis_backend"]["provider"] == "ollama"  # default kept


def test_load_config_rejects_unknown_provider(tmp_path):
    p = tmp_path / "config.yaml"
    p.write_text(yaml.safe_dump({"research_backend": {"provider": "watson"}}))
    with pytest.raises(orchestrator.ConfigError):
        orchestrator.load_config(str(p))


# ---------------------------------------------------------------------------
# Backend selection (fail fast, names the env var)
# ---------------------------------------------------------------------------

def test_select_backend_missing_key_names_env_var(monkeypatch):
    monkeypatch.delenv("ANTHROPIC_API_KEY", raising=False)
    cfg = {"research_backend": {"provider": "anthropic"},
           "synthesis_backend": {"provider": "ollama"}}
    with pytest.raises(models.ConfigError) as exc:
        models.select_backends(cfg)
    assert "ANTHROPIC_API_KEY" in str(exc.value)


def test_select_backend_ollama_needs_no_key(monkeypatch):
    monkeypatch.delenv("OPENAI_API_KEY", raising=False)
    monkeypatch.delenv("ANTHROPIC_API_KEY", raising=False)
    cfg = {"research_backend": {"provider": "ollama"},
           "synthesis_backend": {"provider": "ollama"}}
    research, synth = models.select_backends(cfg)
    assert research.kind == "ollama" and synth.kind == "ollama"


def test_make_backend_unknown_provider():
    with pytest.raises(models.ConfigError):
        models.make_backend("watson", {})


# ---------------------------------------------------------------------------
# Backends with mocked HTTP
# ---------------------------------------------------------------------------

class FakeResp:
    def __init__(self, payload):
        self._payload = payload

    def raise_for_status(self):
        pass

    def json(self):
        return self._payload


def test_ollama_chat(monkeypatch):
    def fake_post(url, json=None, headers=None, timeout=None):
        assert url.endswith("/api/chat")
        return FakeResp({"message": {"content": "hello"},
                         "prompt_eval_count": 5, "eval_count": 7})
    monkeypatch.setattr("requests.post", fake_post)
    b = models.OllamaBackend("llama3.1")
    res = b.chat([{"role": "user", "content": "hi"}], web_search=True)  # ignored
    assert res.text == "hello"
    assert res.input_tokens == 5 and res.output_tokens == 7
    assert res.backend == "ollama"


def test_openai_chat_completions_custom_base(monkeypatch):
    seen = {}

    def fake_post(url, json=None, headers=None, timeout=None):
        seen["url"] = url
        seen["auth"] = headers.get("Authorization")
        return FakeResp({"choices": [{"message": {"content": "hi"}}],
                         "usage": {"prompt_tokens": 3, "completion_tokens": 4}})
    monkeypatch.setattr("requests.post", fake_post)
    b = models.OpenAIBackend("x", api_key="k",
                             base_url="https://example.com/v1")
    res = b.chat([{"role": "user", "content": "hi"}], web_search=True)
    assert seen["url"].endswith("/chat/completions")  # no /responses off-platform
    assert seen["auth"] == "Bearer k"
    assert res.text == "hi"
    assert res.input_tokens == 3 and res.output_tokens == 4


def test_openai_responses_web_search(monkeypatch):
    seen = {}

    def fake_post(url, json=None, headers=None, timeout=None):
        seen["url"] = url
        seen["body"] = json
        return FakeResp({
            "output": [{"type": "message",
                        "content": [{"type": "output_text", "text": "found stuff"}]},
                       {"type": "web_search_call", "status": "completed"}],
            "usage": {"input_tokens": 10, "output_tokens": 20},
        })
    monkeypatch.setattr("requests.post", fake_post)
    b = models.OpenAIBackend("gpt-5", api_key="k")  # default base -> Responses API
    res = b.chat([{"role": "user", "content": "research X"}],
                 system="sys", web_search=True)
    assert seen["url"].endswith("/responses")
    assert {"type": "web_search"} in seen["body"]["tools"]
    assert res.text == "found stuff"
    assert res.input_tokens == 10 and res.output_tokens == 20


def test_anthropic_chat_with_web_search(monkeypatch):
    seen = {}

    def fake_post(url, json=None, headers=None, timeout=None):
        seen["url"] = url
        seen["body"] = json
        seen["key"] = headers.get("x-api-key")
        return FakeResp({
            "content": [
                {"type": "text", "text": "result"},
                {"type": "tool_result",
                 "content": [{"type": "text", "text": "search hit"}]},
            ],
            "usage": {"input_tokens": 8, "output_tokens": 9},
        })
    monkeypatch.setattr("requests.post", fake_post)
    b = models.AnthropicBackend("claude-x", api_key="sek")
    res = b.chat([{"role": "user", "content": "research X"}], web_search=True)
    assert seen["url"].endswith("/v1/messages")
    assert seen["key"] == "sek"
    assert seen["body"]["tools"] == [{"type": "web_search_20260205",
                                      "name": "web_search"}]
    assert "result" in res.text and "search hit" in res.text
    assert res.input_tokens == 8 and res.output_tokens == 9


# ---------------------------------------------------------------------------
# Report rendering
# ---------------------------------------------------------------------------

def test_extract_sources_dedupes():
    text = "see https://a.example/x and https://b.example/y, also https://a.example/x."
    assert report_mod.extract_sources(text) == [
        "https://a.example/x", "https://b.example/y"]


def test_write_report(tmp_path):
    p = str(tmp_path / "report.md")
    axis_texts = {a: "body %s\nhttps://src.example/%s" % (a, a)
                  for a in prompts.AXES}
    report_mod.write_report(p, "Acme", '{"name": "Acme"}', axis_texts,
                            "VERDICT TEXT", {"research_backend": "x/y"})
    content = open(p, encoding="utf-8").read()
    assert "# Vedette Assessment: Acme" in content
    assert "VERDICT TEXT" in content
    for a in prompts.AXES:
        assert prompts.AXIS_TITLES[a] in content
    assert "## Source register" in content
    assert "https://src.example/jurisdiction" in content
    assert "research_backend: x/y" in content


def test_write_comparison(tmp_path):
    p = str(tmp_path / "comparison.md")
    report_mod.write_comparison(p, "A beats B https://c.example", ["A", "B"], {})
    content = open(p, encoding="utf-8").read()
    assert "# Provider Comparison: A, B" in content
    assert "https://c.example" in content


def test_slugify():
    assert orchestrator.slugify("GreenNode!") == "greennode"
    assert orchestrator.slugify("Core Weave") == "core-weave"
