"""Tests for OSINT collection profiles and the person target type.

Covers: profile validation, per-profile axes, the person type's identity
and axes, intel-style synthesis, search-query coverage for new axes,
scope-guard wording, and profile threading through the orchestrator.
"""

import json
import os
import sys

import pytest

sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))

from vedette import models, orchestrator, prompts, report as report_mod
from vedette import scope
from vedette import search as search_mod
from vedette.scope import ScopeError


# ---------------------------------------------------------------------------
# Profile validation
# ---------------------------------------------------------------------------

def test_profiles_list():
    assert set(prompts.PROFILES) == {
        "security", "corporate", "financial", "reputation", "technology",
        "full"}


def test_check_profile_accepts_all():
    for p in prompts.PROFILES:
        assert prompts.check_profile(p) == p
        assert prompts.check_profile(p.upper()) == p  # normalized


def test_check_profile_rejects_unknown():
    with pytest.raises(ValueError):
        prompts.check_profile("nope")


def test_orchestrator_check_profile_raises_config_error():
    with pytest.raises(orchestrator.ConfigError):
        orchestrator.check_profile("nope")


# ---------------------------------------------------------------------------
# Axes per profile
# ---------------------------------------------------------------------------

def test_security_profile_preserves_historic_axes():
    assert tuple(prompts.axes_for_type("company", "security")) == prompts.AXES
    assert tuple(prompts.axes_for_type("software", "security")) == tuple(
        prompts.AXES_BY_TYPE["software"])
    assert tuple(prompts.axes_for_type("domain", "security")) == tuple(
        prompts.AXES_BY_TYPE["domain"])


def test_osint_profiles_override_company_axes():
    assert tuple(prompts.axes_for_type("company", "corporate")) == (
        "ownership", "leadership", "financials", "footprint", "partnerships")
    assert tuple(prompts.axes_for_type("company", "financial")) == (
        "funding", "investors", "revenue", "manda", "valuation")
    assert tuple(prompts.axes_for_type("company", "reputation")) == (
        "coverage", "controversies", "regulatory", "sentiment")
    assert tuple(prompts.axes_for_type("company", "technology")) == (
        "techstack", "engineering", "patents", "opensource")


def test_osint_profiles_keep_other_type_axes():
    for profile in ("corporate", "financial", "reputation", "technology"):
        for t in ("software", "domain", "person"):
            assert tuple(prompts.axes_for_type(t, profile)) == tuple(
                prompts.AXES_BY_TYPE[t])


def test_full_profile_company_axes():
    axes = prompts.axes_for_type("company", "full")
    assert len(axes) == 5 + 5 + 5 + 4 + 4  # security + 4 OSINT profiles
    assert len(set(axes)) == len(axes)  # no duplicates
    assert set(prompts.AXES) <= set(axes)


def test_axes_for_type_rejects_bad_profile():
    with pytest.raises(ValueError):
        prompts.axes_for_type("company", "nope")


def test_axes_for_type_rejects_bad_type_with_profile():
    with pytest.raises(ValueError):
        prompts.axes_for_type("planet", "corporate")


# ---------------------------------------------------------------------------
# Person target type
# ---------------------------------------------------------------------------

def test_person_in_target_types():
    assert "person" in prompts.TARGET_TYPES


def test_person_axes():
    assert tuple(prompts.axes_for_type("person")) == (
        "p_background", "p_career", "p_affiliations", "p_presence",
        "p_controversies", "p_social")


def test_person_identity_prompt_is_json_only():
    text = prompts.build_identity_prompt("Jane Doe", "", "person")
    assert "Jane Doe" in text and "JSON" in text
    assert "Person name" in text


def test_normalize_target_accepts_person():
    t = orchestrator.normalize_target({"name": "Jane Doe", "type": "person"})
    assert t["type"] == "person"


def test_person_axis_prompts_build():
    for axis in prompts.axes_for_type("person"):
        text = prompts.build_axis_prompt(axis, "IDENTITY")
        assert "IDENTITY" in text
        assert prompts.AXIS_TITLES[axis]


def test_person_background_prompt_has_privacy_guardrail():
    text = prompts.AXIS_PROMPTS["p_background"]
    assert "home addresses" in text


# ---------------------------------------------------------------------------
# Intel brief style
# ---------------------------------------------------------------------------

def test_is_intel_brief():
    assert not prompts.is_intel_brief("security", "company")
    assert not prompts.is_intel_brief("security", "software")
    for p in ("corporate", "financial", "reputation", "technology", "full"):
        assert prompts.is_intel_brief(p, "company")
    # person is always intel-style, even under the security profile
    assert prompts.is_intel_brief("security", "person")


def test_intel_synthesis_prompt_sections():
    axis_texts = {a: "text-%s" % a
                  for a in prompts.axes_for_type("company", "corporate")}
    text = prompts.build_synthesis_prompt(
        "IDENT", axis_texts,
        axes=prompts.axes_for_type("company", "corporate"), intel_style=True)
    assert "## Key Judgments" in text
    assert "[High/Medium/Low]" in text
    assert "## Collection gaps" in text
    assert "## Outlook" in text
    assert "## Verdict" not in text  # buyer brief, not intel brief


def test_buyer_synthesis_prompt_unchanged():
    axis_texts = {a: "text-%s" % a for a in prompts.AXES}
    text = prompts.build_synthesis_prompt("IDENT", axis_texts)
    assert "## Verdict" in text
    assert "## Key Judgments" not in text


def test_osint_system_prompt_has_privacy_rule():
    assert "NOT FOUND" in prompts.SYSTEM_RESEARCH_OSINT
    assert "## Sources" in prompts.SYSTEM_RESEARCH_OSINT
    assert "home addresses" in prompts.SYSTEM_RESEARCH_OSINT


# ---------------------------------------------------------------------------
# Search queries for new axes
# ---------------------------------------------------------------------------

def test_new_axes_have_search_queries():
    for p in prompts.PROFILES:
        for t in ("company", "person"):
            for axis in prompts.axes_for_type(t, p):
                qs = search_mod.AXIS_QUERIES[t][axis]
                assert len(qs) >= 1
                for q in qs:
                    q.format(name="N", domain="d.example")


# ---------------------------------------------------------------------------
# Scope guard wording
# ---------------------------------------------------------------------------

def test_scope_refusal_mentions_people():
    with pytest.raises(ScopeError) as exc:
        scope.check_target("best pizza recipe")
    assert "people" in str(exc.value)


def test_scope_still_accepts_targets():
    scope.check_target("Acme Corp", "https://acme.com")
    scope.check_target("Jane Doe")


# ---------------------------------------------------------------------------
# Orchestrator threading
# ---------------------------------------------------------------------------

class FakeBackend:
    kind = "fake"

    def __init__(self, model="fake", store=None):
        self.model = model
        self.store = store if store is not None else []

    def chat(self, messages, system=None, web_search=False):
        self.store.append((system, messages[0]["content"]))
        return models.ChatResult("CANNED", backend="fake", model="fake")


def _cfg_no_search():
    cfg = orchestrator.load_config("/nonexistent/path.yaml")
    cfg["tool_search"] = False
    return cfg


def _patch_backends(monkeypatch, store=None):
    monkeypatch.setattr(
        models, "select_backends",
        lambda cfg: (FakeBackend("r", store), FakeBackend("s", store)))


def test_assess_many_rejects_bad_profile(monkeypatch, tmp_path):
    _patch_backends(monkeypatch)
    with pytest.raises(orchestrator.ConfigError):
        orchestrator.assess_many(
            _cfg_no_search(), [{"name": "Acme", "type": "company"}],
            str(tmp_path), profile="nope", no_cache=True)


def test_assess_many_corporate_profile_uses_osint_axes(monkeypatch, tmp_path):
    store = []
    _patch_backends(monkeypatch, store)
    results, _ = orchestrator.assess_many(
        _cfg_no_search(), [{"name": "Acme", "type": "company"}],
        str(tmp_path), profile="corporate", no_cache=True)
    assert len(results) == 1
    report = open(os.path.join(results[0]["dir"], "report.md"),
                  encoding="utf-8").read()
    assert "Ownership & corporate structure" in report
    assert "Jurisdiction, legal exposure" not in report
    # intel brief style in the synthesis leg prompt
    synth_prompts = [c for s, c in store if "Key Judgments" in c]
    assert synth_prompts
    # OSINT system prompt used on the research legs
    assert any(s == prompts.SYSTEM_RESEARCH_OSINT for s, c in store)
    # profile recorded in audit + metadata
    started = [json.loads(line) for line in
               open(os.path.join(results[0]["dir"], "audit.jsonl"),
                    encoding="utf-8") if line.strip()]
    assert any(l.get("event") == "assessment_started"
               and l.get("profile") == "corporate" for l in started)


def test_assess_many_person_target(monkeypatch, tmp_path):
    store = []
    _patch_backends(monkeypatch, store)
    results, _ = orchestrator.assess_many(
        _cfg_no_search(), [{"name": "Jane Doe", "type": "person"}],
        str(tmp_path), no_cache=True)
    assert len(results) == 1
    assert results[0]["type"] == "person"
    report = open(os.path.join(results[0]["dir"], "report.md"),
                  encoding="utf-8").read()
    assert "Target type: person" in report
    assert "Background & biography" in report
    # intel brief even under the default security profile
    assert any("Key Judgments" in c for _, c in store)


def test_assess_many_security_profile_unchanged(monkeypatch, tmp_path):
    store = []
    _patch_backends(monkeypatch, store)
    results, _ = orchestrator.assess_many(
        _cfg_no_search(), [{"name": "Acme", "type": "company"}],
        str(tmp_path), no_cache=True)
    report = open(os.path.join(results[0]["dir"], "report.md"),
                  encoding="utf-8").read()
    assert "Jurisdiction, legal exposure" in report
    assert "Ownership & corporate structure" not in report
    assert any("## Verdict" in c for _, c in store)
    assert any(s == prompts.SYSTEM_RESEARCH for s, c in store)


def test_axis_cache_second_run_skips_research_backend(monkeypatch, tmp_path):
    """An identical second run serves research legs from the on-disk cache."""
    target = [{"name": "AcmeCache", "type": "company"}]
    store = []
    _patch_backends(monkeypatch, store)
    orchestrator.assess_many(_cfg_no_search(), target, str(tmp_path))
    first_research = [s for s, _ in store if s == prompts.SYSTEM_RESEARCH]
    assert first_research  # first run actually researched
    # Second run, fresh store: research legs come from runs/.cache/, so the
    # backend sees no research calls (identity + synthesis still run live).
    store2 = []
    _patch_backends(monkeypatch, store2)
    results, _ = orchestrator.assess_many(
        _cfg_no_search(), target, str(tmp_path))
    assert not [s for s, _ in store2 if s == prompts.SYSTEM_RESEARCH]
    assert os.path.exists(os.path.join(results[0]["dir"], "report.md"))
    # ...while no_cache=True forces a full fresh run.
    store3 = []
    _patch_backends(monkeypatch, store3)
    orchestrator.assess_many(_cfg_no_search(), target, str(tmp_path),
                             no_cache=True)
    assert [s for s, _ in store3 if s == prompts.SYSTEM_RESEARCH]


def test_compare_person_title(tmp_path):
    path = report_mod.write_comparison(
        os.path.join(str(tmp_path), "c.md"), "text", ["Jane"], {},
        target_type="person")
    content = open(path, encoding="utf-8").read()
    assert content.startswith("# People Comparison")


def test_comparison_criteria_person():
    text = prompts.build_comparison_prompt("summaries", "person")
    assert "career trajectory" in text
