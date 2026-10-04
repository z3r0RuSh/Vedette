"""Tests for multi-target, typed assessments: CLI parsing, orchestration,
per-type axes, comparison synthesis, scope guard, and GUI form parsing."""

import json
import os
import sys

import pytest

sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))

from vedette import models, orchestrator, prompts, report as report_mod
from vedette import scope, search as search_mod
from vedette.server import parse_gui_targets
from vedette.scope import ScopeError
import run_assessment


# ---------------------------------------------------------------------------
# CLI target parsing
# ---------------------------------------------------------------------------

def test_parse_target_plain_company():
    assert run_assessment.parse_target("Acme Corp") == {
        "name": "Acme Corp", "url": "", "type": "company"}


def test_parse_target_name_equals_url():
    assert run_assessment.parse_target("Acme=https://acme.com") == {
        "name": "Acme", "url": "https://acme.com", "type": "company"}


def test_parse_target_type_suffix():
    assert run_assessment.parse_target("nginx|software") == {
        "name": "nginx", "url": "", "type": "software"}
    assert run_assessment.parse_target("Acme=https://acme.com|domain") == {
        "name": "Acme", "url": "https://acme.com", "type": "domain"}


def test_parse_target_bare_url_becomes_domain():
    t = run_assessment.parse_target("https://example.com")
    assert t["type"] == "domain"
    assert t["url"] == "https://example.com"
    t = run_assessment.parse_target("example.com")
    assert t["type"] == "domain"
    assert t["url"] == "https://example.com"


def test_parse_target_explicit_type_not_overridden_by_url_shape():
    t = run_assessment.parse_target("https://example.com|software")
    assert t["type"] == "software"


def test_parse_target_default_type_applies():
    t = run_assessment.parse_target("nginx", "software")
    assert t == {"name": "nginx", "url": "", "type": "software"}


# ---------------------------------------------------------------------------
# Target normalization + scope guard
# ---------------------------------------------------------------------------

def test_normalize_target_dict_and_tuple():
    assert orchestrator.normalize_target(
        {"name": "Acme", "url": "https://a.co", "type": "company"}) == {
            "name": "Acme", "url": "https://a.co", "type": "company"}
    assert orchestrator.normalize_target(("nginx", "", "software")) == {
        "name": "nginx", "url": "", "type": "software"}
    assert orchestrator.normalize_target(("Acme", "https://a.co"))["type"] == "company"


def test_normalize_target_rejects_unknown_type():
    with pytest.raises(orchestrator.ConfigError):
        orchestrator.normalize_target({"name": "x", "type": "planet"})


def test_scope_refuses_non_security_target():
    with pytest.raises(ScopeError) as exc:
        scope.check_target("best pizza recipe")
    assert "Out of scope" in str(exc.value)


def test_scope_accepts_security_targets():
    scope.check_target("Acme Corp", "https://acme.com")
    scope.check_target("nginx")
    scope.check_target("example.com")


def test_assess_many_refuses_out_of_scope():
    cfg = orchestrator.load_config("/nonexistent/path.yaml")
    with pytest.raises(ScopeError):
        orchestrator.assess_many(cfg, [{"name": "pizza recipe"}], "/tmp/x")


# ---------------------------------------------------------------------------
# Prompt builders per type
# ---------------------------------------------------------------------------

def test_identity_prompts_per_type():
    assert "Organization name" in prompts.build_identity_prompt("Acme", "")
    sw = prompts.build_identity_prompt("nginx", "", "software")
    assert "Software name" in sw and "repository" in sw
    dom = prompts.build_identity_prompt("example.com", "https://example.com",
                                         "domain")
    assert "Domain or URL" in dom


def test_synthesis_prompt_uses_given_axes():
    axes = prompts.axes_for_type("software")
    axis_texts = {a: "body" for a in axes}
    text = prompts.build_synthesis_prompt("IDENT", axis_texts, axes=axes)
    assert "Supply chain & provenance" in text
    assert "Jurisdiction" not in text


def test_comparison_prompt_criteria_per_type():
    assert "supply-chain" in prompts.build_comparison_prompt("s", "software")
    assert "TLS" in prompts.build_comparison_prompt("s", "domain")
    assert "jurisdictional" in prompts.build_comparison_prompt("s", "company")
    assert "mixed" not in prompts.build_comparison_prompt("s", "mixed").lower() \
        or "each target's type" in prompts.build_comparison_prompt("s", "mixed")


# ---------------------------------------------------------------------------
# Batch orchestration with mocked backends
# ---------------------------------------------------------------------------

class FakeBackend:
    kind = "fake"

    def __init__(self, model="fake", store=None):
        self.model = model
        self.store = store if store is not None else []

    def chat(self, messages, system=None, web_search=False):
        self.store.append(messages[0]["content"])
        return models.ChatResult("CANNED", backend="fake", model="fake")


def _cfg_no_search():
    cfg = orchestrator.load_config("/nonexistent/path.yaml")
    cfg["tool_search"] = False
    return cfg


def _patch_backends(monkeypatch, store=None):
    monkeypatch.setattr(
        models, "select_backends",
        lambda cfg: (FakeBackend("r", store), FakeBackend("s", store)))


def _read_audit_lines(out_dir):
    with open(os.path.join(out_dir, "audit.jsonl"), encoding="utf-8") as fh:
        return [json.loads(line) for line in fh if line.strip()]


def test_assess_many_batch_two_types(monkeypatch, tmp_path):
    store = []
    _patch_backends(monkeypatch, store)
    events = []
    targets = [{"name": "Acme", "type": "company"},
               {"name": "nginx", "type": "software"}]
    results, comparison = orchestrator.assess_many(
        _cfg_no_search(), targets, str(tmp_path),
        progress_cb=lambda p, d, target=None: events.append((p, target)),
        no_cache=True)
    assert len(results) == 2
    assert results[0]["type"] == "company"
    assert results[1]["type"] == "software"
    assert results[0]["dir"] != results[1]["dir"]
    for r in results:
        assert os.path.exists(os.path.join(r["dir"], "report.md"))
    comp_path = os.path.join(str(tmp_path), "comparison.md")
    assert os.path.exists(comp_path)
    assert "CANNED" in comparison
    # per-target progress events fired
    seen_targets = {t for _, t in events}
    assert {"Acme", "nginx"} <= seen_targets
    # axis sections match the target type
    nginx_report = open(os.path.join(results[1]["dir"], "report.md"),
                        encoding="utf-8").read()
    assert "Supply chain & provenance" in nginx_report
    assert "Target type: software" in nginx_report
    acme_report = open(os.path.join(results[0]["dir"], "report.md"),
                       encoding="utf-8").read()
    assert "Jurisdiction, legal exposure" in acme_report
    # audit trail records the type
    started = [l for l in _read_audit_lines(results[1]["dir"])
               if l["event"] == "assessment_started"]
    assert started and started[0]["type"] == "software"


def test_assess_many_single_target_no_comparison(monkeypatch, tmp_path):
    _patch_backends(monkeypatch)
    results, comparison = orchestrator.assess_many(
        _cfg_no_search(), [{"name": "Acme", "type": "company"}], str(tmp_path),
        no_cache=True)
    assert len(results) == 1
    assert comparison is None
    assert not os.path.exists(os.path.join(str(tmp_path), "comparison.md"))


def test_assess_many_dedupes_same_name_dirs(monkeypatch, tmp_path):
    _patch_backends(monkeypatch)
    results, _ = orchestrator.assess_many(
        _cfg_no_search(),
        [{"name": "Acme", "type": "company"},
         {"name": "Acme", "type": "software"}],
        str(tmp_path), no_cache=True)
    assert results[0]["dir"] != results[1]["dir"]
    assert results[1]["dir"].endswith("-2")


def test_compare_targets_mixed_title(monkeypatch, tmp_path):
    _patch_backends(monkeypatch)
    results = [
        {"name": "Acme", "type": "company", "identity": {},
         "synthesis": "S1"},
        {"name": "example.com", "type": "domain", "identity": {},
         "synthesis": "S2"},
    ]
    orchestrator.compare_targets(_cfg_no_search(), results, str(tmp_path))
    content = open(os.path.join(str(tmp_path), "comparison.md"),
                   encoding="utf-8").read()
    assert "# Target Comparison:" in content
    assert "example.com (domain)" in content or "Acme (company)" in content


def test_compare_targets_software_title(monkeypatch, tmp_path):
    _patch_backends(monkeypatch)
    results = [
        {"name": "nginx", "type": "software", "identity": {},
         "synthesis": "S1"},
        {"name": "openssl", "type": "software", "identity": {},
         "synthesis": "S2"},
    ]
    orchestrator.compare_targets(_cfg_no_search(), results, str(tmp_path))
    content = open(os.path.join(str(tmp_path), "comparison.md"),
                   encoding="utf-8").read()
    assert "# Software Comparison:" in content


def test_assess_org_back_compat(monkeypatch, tmp_path):
    _patch_backends(monkeypatch)
    seen = []
    r = orchestrator.assess_org(_cfg_no_search(), "Acme", "https://acme.com",
                                str(tmp_path), progress_cb=lambda p, d: seen.append(p))
    assert r["type"] == "company" and r["org"] == "Acme"
    assert seen  # old (phase, detail) callback shape still works


# ---------------------------------------------------------------------------
# Built-in search called by research legs
# ---------------------------------------------------------------------------

class FakeSearchClient:
    provider = "duckduckgo"

    def __init__(self, *args, **kwargs):
        pass

    def search(self, query):
        return [{"url": "https://r.example/1", "title": "Hit",
                 "snippet": "snip",
                 "fetched_at": "2026-01-01T00:00:00+00:00"}]


def test_research_legs_call_search_tool(monkeypatch, tmp_path):
    store = []
    _patch_backends(monkeypatch, store)
    monkeypatch.setattr(search_mod, "SearchClient", FakeSearchClient)
    cfg = orchestrator.load_config("/nonexistent/path.yaml")
    cfg["tool_search"] = True  # on; searches go through the fake client
    orchestrator.assess_target(
        cfg, {"name": "Acme", "type": "company"}, str(tmp_path))
    # The search context was injected into the axis prompts.
    assert any("Live web search" in p and "https://r.example/1" in p
               for p in store)
    # ... and audited with URL + timestamp, no key material.
    records = _read_audit_lines(str(tmp_path))
    searches = [r for r in records if r["event"] == "web_search"]
    assert len(searches) == len(prompts.axes_for_type("company")) * 2
    blob = json.dumps(records)
    assert "https://r.example/1" in blob
    assert "fetched_at" in blob
    assert "API_KEY" not in blob


def test_research_continues_when_search_fails(monkeypatch, tmp_path):
    _patch_backends(monkeypatch)
    cfg = orchestrator.load_config("/nonexistent/path.yaml")
    cfg["tool_search"] = True
    cfg["search"]["provider"] = "nope"  # SearchClient raises -> degraded path
    r = orchestrator.assess_target(
        cfg, {"name": "Acme", "type": "company"}, str(tmp_path))
    assert os.path.exists(os.path.join(r["dir"], "report.md"))
    records = _read_audit_lines(r["dir"])
    assert any(l["event"] == "web_search_error" for l in records)


# ---------------------------------------------------------------------------
# GUI form parsing (server.parse_gui_targets)
# ---------------------------------------------------------------------------

def test_parse_gui_targets_new_shape():
    body = {"targets": [{"name": "nginx|software"}, {"name": "Acme=https://acme.com"}],
            "default_type": "company"}
    targets = parse_gui_targets(body)
    assert targets == [
        {"name": "nginx", "url": "", "type": "software"},
        {"name": "Acme", "url": "https://acme.com", "type": "company"},
    ]


def test_parse_gui_targets_per_item_type():
    body = {"targets": [{"name": "example.com", "type": "domain"}],
            "default_type": "company"}
    assert parse_gui_targets(body) == [
        {"name": "example.com", "url": "", "type": "domain"}]


def test_parse_gui_targets_legacy_shape():
    body = {"org": "Acme", "url": "https://acme.com",
            "compare": [{"name": "Beta", "url": ""}, "Gamma=https://g.co"]}
    targets = parse_gui_targets(body)
    assert targets == [
        {"name": "Acme", "url": "https://acme.com", "type": "company"},
        {"name": "Beta", "url": "", "type": "company"},
        {"name": "Gamma", "url": "https://g.co", "type": "company"},
    ]


def test_parse_gui_targets_rejects_bad_type():
    with pytest.raises(ValueError):
        parse_gui_targets({"targets": [{"name": "x", "type": "planet"}]})
    with pytest.raises(ValueError):
        parse_gui_targets({"targets": [{"name": "x"}], "default_type": "planet"})


def test_parse_gui_targets_requires_at_least_one():
    with pytest.raises(ValueError):
        parse_gui_targets({"targets": []})
    with pytest.raises(ValueError):
        parse_gui_targets({})


# ---------------------------------------------------------------------------
# Report rendering per type
# ---------------------------------------------------------------------------

def test_write_report_software_axes(tmp_path):
    p = str(tmp_path / "report.md")
    axes = prompts.axes_for_type("software")
    axis_texts = {a: "body" for a in axes}
    report_mod.write_report(p, "nginx", "{}", axis_texts, "VERDICT", {},
                            target_type="software", axes=axes)
    content = open(p, encoding="utf-8").read()
    assert "Target type: software" in content
    assert "## Research: Supply chain & provenance" in content
    assert "## Research: Jurisdiction" not in content


def test_write_comparison_titles(tmp_path):
    p = str(tmp_path / "c.md")
    report_mod.write_comparison(p, "text", ["a", "b"], {},
                                target_type="software")
    assert "# Software Comparison: a, b" in open(p).read()
    report_mod.write_comparison(p, "text", ["a", "b"], {},
                                target_type="domain")
    assert "# Domain Comparison: a, b" in open(p).read()
    report_mod.write_comparison(p, "text", ["a", "b"], {},
                                target_type="mixed")
    assert "# Target Comparison: a, b" in open(p).read()
    report_mod.write_comparison(p, "text", ["a", "b"], {})
    assert "# Provider Comparison: a, b" in open(p).read()
