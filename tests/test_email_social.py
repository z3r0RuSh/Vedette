"""Tests for email/social/threat-intel tooling and the email target type.

Covers: social handle enumeration (mocked HTTP), Gravatar, email parsing,
DoH MX lookup (mocked), HIBP breach check with/without key, VirusTotal/OTX
with/without keys, urlscan/crt.sh parsing, email prompts/axes, CLI email
auto-detect, and orchestrator tool-context wiring.
"""

import json
import os
import sys

import pytest

sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))

from vedette import emailintel, models, orchestrator, prompts
from vedette import report as report_mod
from vedette import scope, search as search_mod
from vedette import social, threatintel
from vedette.scope import ScopeError
import run_assessment


# ---------------------------------------------------------------------------
# Fakes
# ---------------------------------------------------------------------------

class FakeResponse:
    def __init__(self, status_code=200, json_data=None, text=""):
        self.status_code = status_code
        self._json = json_data
        self.text = text

    def json(self):
        return self._json

    def raise_for_status(self):
        if self.status_code >= 400:
            raise Exception("HTTP %d" % self.status_code)


def fake_get_factory(mapping):
    """Return a fake requests.get honoring {(method-part): FakeResponse}."""
    def fake_get(url, headers=None, params=None, timeout=None,
                 allow_redirects=True):
        for key, resp in mapping.items():
            if key in url:
                if isinstance(resp, Exception):
                    raise resp
                return resp
        return FakeResponse(status_code=404, text="not found")
    return fake_get


class FakeBackend:
    kind = "fake"

    def __init__(self, model="fake", store=None):
        self.model = model
        self.store = store if store is not None else []

    def chat(self, messages, system=None, web_search=False):
        self.store.append((system, messages[0]["content"]))
        return models.ChatResult("CANNED", backend="fake", model="fake")


def _cfg_no_tools():
    cfg = orchestrator.load_config("/nonexistent/path.yaml")
    cfg["tool_search"] = False
    cfg["identity_tools"] = False
    cfg["threat_intel"] = False
    return cfg


def _patch_backends(monkeypatch, store=None):
    monkeypatch.setattr(
        models, "select_backends",
        lambda cfg: (FakeBackend("r", store), FakeBackend("s", store)))


# ---------------------------------------------------------------------------
# social.py
# ---------------------------------------------------------------------------

def test_sanitize_handle():
    assert social.sanitize_handle("@janedoe") == "janedoe"
    assert social.sanitize_handle("jane.doe_99") == "jane.doe_99"
    assert social.sanitize_handle("not a handle!") is None
    assert social.sanitize_handle("") is None


def test_handles_for_name():
    handles = social.handles_for_name("Jane Doe")
    assert handles == ["janedoe", "jane.doe", "jane_doe", "jdoe"]
    assert social.handles_for_name("Madonna") == ["madonna"]
    assert social.handles_for_name("") == []


def test_handles_for_email_local():
    handles = social.handles_for_email_local("jane.doe")
    assert "jane.doe" in handles
    assert "janedoe" in handles
    assert len(handles) <= 4


def test_check_handle_hit_and_miss(monkeypatch):
    monkeypatch.setattr(
        "requests.get",
        fake_get_factory({"github.com/janedoe": FakeResponse(200)}))
    client = social.SocialClient(rate_limit_s=0)
    hit = client.check_handle(social.PLATFORMS[0], "janedoe")
    assert hit["outcome"] == "hit" and hit["confidence"] == "high"
    assert hit["http_status"] == 200
    miss = client.check_handle(social.PLATFORMS[0], "nosuchuser")
    assert miss["outcome"] == "miss"


def test_check_handle_content_marker(monkeypatch):
    hn = [p for p in social.PLATFORMS if p[0] == "hackernews"][0]
    monkeypatch.setattr(
        "requests.get",
        fake_get_factory({"ycombinator": FakeResponse(200, text="No such user.")}))
    client = social.SocialClient(rate_limit_s=0)
    r = client.check_handle(hn, "nosuchuser")
    assert r["outcome"] == "miss" and r["confidence"] == "medium"


def test_check_handle_network_error_becomes_unknown(monkeypatch):
    monkeypatch.setattr(
        "requests.get",
        fake_get_factory({"github.com": Exception("boom")}))
    client = social.SocialClient(rate_limit_s=0)
    r = client.check_handle(social.PLATFORMS[0], "janedoe")
    assert r["outcome"] == "unknown"


def test_enumerate_audits_each_probe(monkeypatch):
    monkeypatch.setattr("requests.get",
                        fake_get_factory({"github.com/janedoe":
                                          FakeResponse(200)}))
    records = []
    client = social.SocialClient(rate_limit_s=0)
    results = client.enumerate("janedoe", records.append)
    assert len(results) == len(social.PLATFORMS)
    assert len(records) == len(social.PLATFORMS)
    assert all(r["event"] == "social_probe" for r in records)
    assert any(r["outcome"] == "hit" for r in records)


def test_enumerate_rejects_bad_handle():
    assert social.SocialClient().enumerate("not a handle!", [].append) == []


def test_gravatar_hit(monkeypatch):
    monkeypatch.setattr("requests.get",
                        fake_get_factory({"gravatar.com": FakeResponse(200)}))
    assert social.SocialClient(rate_limit_s=0).gravatar_hit("a@b.com") is True


def test_gravatar_miss(monkeypatch):
    monkeypatch.setattr("requests.get",
                        fake_get_factory({"gravatar.com": FakeResponse(404)}))
    assert social.SocialClient(rate_limit_s=0).gravatar_hit("a@b.com") is False


def test_format_results_lists_hits():
    results = [
        {"platform": "github", "handle": "jd", "url": "https://github.com/jd",
         "outcome": "hit", "confidence": "high", "http_status": 200},
        {"platform": "x", "handle": "jd", "url": "https://x.com/jd",
         "outcome": "unknown", "confidence": "medium", "http_status": None},
    ]
    text = social.format_results(results)
    assert "github.com/jd" in text
    assert "Uncheckable" in text


# ---------------------------------------------------------------------------
# emailintel.py
# ---------------------------------------------------------------------------

def test_parse_email():
    p = emailintel.parse_email("Jane.Doe@Example.COM")
    assert p == {"email": "Jane.Doe@Example.COM", "local": "Jane.Doe",
                 "domain": "example.com"}
    assert emailintel.parse_email("not-an-email") is None
    assert emailintel.parse_email("") is None


def test_mx_records_parses_doh(monkeypatch):
    doh = {"Answer": [{"data": "10 mx1.example.com."},
                      {"data": "20 mx2.example.com."}]}
    monkeypatch.setattr("requests.get",
                        fake_get_factory({"dns-query": FakeResponse(
                            200, json_data=doh)}))
    recs = emailintel.mx_records("example.com")
    assert recs == [{"preference": 10, "exchange": "mx1.example.com"},
                    {"preference": 20, "exchange": "mx2.example.com"}]


def test_mx_records_empty_domain_raises():
    with pytest.raises(emailintel.EmailIntelError):
        emailintel.mx_records("")


def test_hibp_without_key_returns_none(monkeypatch):
    monkeypatch.delenv(emailintel.HIBP_KEY_ENV, raising=False)
    assert emailintel.hibp_breaches("a@b.com") is None


def test_hibp_with_key_parses_breaches(monkeypatch):
    monkeypatch.setenv(emailintel.HIBP_KEY_ENV, "k")
    payload = [{"Name": "BreachA", "BreachDate": "2021-01-01"}]
    monkeypatch.setattr("requests.get",
                        fake_get_factory({"haveibeenpwned": FakeResponse(
                            200, json_data=payload)}))
    assert emailintel.hibp_breaches("a@b.com") == [
        {"name": "BreachA", "date": "2021-01-01"}]


def test_hibp_404_means_no_breaches(monkeypatch):
    monkeypatch.setenv(emailintel.HIBP_KEY_ENV, "k")
    monkeypatch.setattr("requests.get",
                        fake_get_factory({"haveibeenpwned": FakeResponse(
                            404, text="not found")}))
    assert emailintel.hibp_breaches("a@b.com") == []


def test_format_breaches_skipped_mentions_key(monkeypatch):
    monkeypatch.delenv(emailintel.HIBP_KEY_ENV, raising=False)
    text = emailintel.format_breaches("a@b.com", None)
    assert "HIBP_API_KEY" in text and "NOT FOUND" in text


def test_format_deliverability_no_mx():
    text = emailintel.format_deliverability(
        {"email": "a@b.com", "local": "a", "domain": "b.com"}, [])
    assert "none found" in text


# ---------------------------------------------------------------------------
# threatintel.py
# ---------------------------------------------------------------------------

def test_vt_without_key_returns_none(monkeypatch):
    monkeypatch.delenv(threatintel.VT_KEY_ENV, raising=False)
    assert threatintel.vt_domain_report("example.com") is None


def test_vt_report_parses(monkeypatch):
    monkeypatch.setenv(threatintel.VT_KEY_ENV, "k")
    payload = {"data": {"attributes": {
        "last_analysis_stats": {"malicious": 2, "suspicious": 1,
                                "harmless": 80, "undetected": 5},
        "categories": {"alpha": "phishing"},
        "registrar": "Example Registrar",
        "creation_date": "2020-01-01",
        "last_dns_records": [{"type": "A", "value": "1.2.3.4"}],
    }}}
    monkeypatch.setattr("requests.get",
                        fake_get_factory({"virustotal": FakeResponse(
                            200, json_data=payload)}))
    rep = threatintel.vt_domain_report("example.com")
    assert rep["analysis_stats"]["malicious"] == 2
    assert rep["registrar"] == "Example Registrar"
    text = threatintel.format_vt_report("example.com", rep)
    assert "2 malicious" in text


def test_vt_format_skipped_mentions_key():
    assert "VT_API_KEY" in threatintel.format_vt_report("example.com", None)


def test_otx_without_key_returns_none(monkeypatch):
    monkeypatch.delenv(threatintel.OTX_KEY_ENV, raising=False)
    assert threatintel.otx_domain_intel("example.com") is None


def test_otx_parses_pulses(monkeypatch):
    monkeypatch.setenv(threatintel.OTX_KEY_ENV, "k")
    general = {"reputation": 0,
               "pulse_info": {"count": 1,
                              "pulses": [{"name": "EvilPulse"}]}}
    urls = {"url_list": [{"url": "http://example.com/bad"}]}
    monkeypatch.setattr("requests.get", fake_get_factory({
        "indicators/domain": FakeResponse(200, json_data=general),
        "url_list": FakeResponse(200, json_data=urls),
    }))
    intel = threatintel.otx_domain_intel("example.com")
    assert intel["pulse_count"] == 1
    assert intel["pulses"] == ["EvilPulse"]
    text = threatintel.format_otx_intel("example.com", intel)
    assert "EvilPulse" in text


def test_urlscan_parses_and_fails_soft(monkeypatch):
    payload = {"results": [
        {"task": {"time": "2024-01-01", "url": "http://example.com/"},
         "page": {}, "screenshot": "http://s/1.png"}]}
    monkeypatch.setattr("requests.get",
                        fake_get_factory({"urlscan.io": FakeResponse(
                            200, json_data=payload)}))
    scans = threatintel.urlscan_search("example.com")
    assert scans[0]["url"] == "http://example.com/"
    assert "2024-01-01" in threatintel.format_urlscan("example.com", scans)

    monkeypatch.setattr("requests.get",
                        fake_get_factory({"urlscan.io": Exception("down")}))
    assert threatintel.urlscan_search("example.com") == []


def test_crtsh_dedupes_subdomains(monkeypatch):
    payload = [{"name_value": "a.example.com\nwww.example.com"},
               {"name_value": "a.example.com"},
               {"name_value": "*.example.com"}]
    monkeypatch.setattr("requests.get",
                        fake_get_factory({"crt.sh": FakeResponse(
                            200, json_data=payload)}))
    subs = threatintel.crtsh_subdomains("example.com")
    assert subs == ["a.example.com", "www.example.com"]
    assert "a.example.com" in threatintel.format_crtsh("example.com", subs)


# ---------------------------------------------------------------------------
# Prompts: email type
# ---------------------------------------------------------------------------

def test_email_target_type():
    assert "email" in prompts.TARGET_TYPES
    assert tuple(prompts.axes_for_type("email")) == (
        "e_format", "e_deliverability", "e_breaches", "e_associations")


def test_email_identity_prompt():
    text = prompts.build_identity_prompt("jane@example.com", "", "email")
    assert "Email address" in text and "JSON" in text


def test_email_axis_prompts_build():
    for axis in prompts.axes_for_type("email"):
        text = prompts.build_axis_prompt(axis, "IDENTITY")
        assert "IDENTITY" in text
        assert prompts.AXIS_TITLES[axis]


def test_email_is_intel_brief():
    assert prompts.is_intel_brief("security", "email")


def test_email_search_queries_exist():
    for axis in prompts.axes_for_type("email"):
        qs = search_mod.AXIS_QUERIES["email"][axis]
        assert len(qs) >= 1
        for q in qs:
            q.format(name="jane@example.com", domain="example.com")


def test_email_comparison():
    assert "deliverability" in prompts.build_comparison_prompt("x", "email")
    path = report_mod.write_comparison(
        "/tmp/vedette-email-comp-test.md", "text", ["jane@example.com"], {},
        target_type="email")
    assert open(path, encoding="utf-8").read().startswith(
        "# Email Comparison")


def test_scope_refusal_mentions_emails():
    with pytest.raises(ScopeError) as exc:
        scope.check_target("best pizza recipe")
    assert "emails" in str(exc.value)


# ---------------------------------------------------------------------------
# CLI + orchestrator wiring
# ---------------------------------------------------------------------------

def test_parse_target_bare_email_becomes_email():
    t = run_assessment.parse_target("jane@example.com")
    assert t["type"] == "email"
    assert t["name"] == "jane@example.com"


def test_parse_target_explicit_type_not_overridden():
    t = run_assessment.parse_target("jane@example.com|person")
    assert t["type"] == "person"


def test_config_defaults_include_new_flags():
    cfg = orchestrator.load_config("/nonexistent/path.yaml")
    assert cfg["identity_tools"] is True
    assert cfg["threat_intel"] is True


def test_identity_tool_context_skipped_for_company(tmp_path):
    ctx = orchestrator._identity_tool_context(
        _cfg_no_tools(), {"name": "Acme", "type": "company"},
        "jurisdiction", {}, str(tmp_path))
    assert ctx == ""


def test_identity_tool_context_deliverability(monkeypatch, tmp_path):
    monkeypatch.setattr(emailintel, "mx_records",
                        lambda domain: [{"preference": 10,
                                         "exchange": "mx.example.com"}])
    cfg = _cfg_no_tools()
    cfg["identity_tools"] = True
    ctx = orchestrator._identity_tool_context(
        cfg, {"name": "jane@example.com", "type": "email"},
        "e_deliverability", {"email": "jane@example.com"}, str(tmp_path))
    assert "mx.example.com" in ctx


def test_identity_tool_context_breach_skipped_without_key(monkeypatch,
                                                          tmp_path):
    monkeypatch.delenv(emailintel.HIBP_KEY_ENV, raising=False)
    cfg = _cfg_no_tools()
    cfg["identity_tools"] = True
    out_dir = str(tmp_path)
    ctx = orchestrator._identity_tool_context(
        cfg, {"name": "jane@example.com", "type": "email"},
        "e_breaches", {"email": "jane@example.com"}, out_dir)
    assert "HIBP_API_KEY" in ctx
    lines = [json.loads(l) for l in
             open(os.path.join(out_dir, "audit.jsonl"), encoding="utf-8")]
    assert any(l["event"] == "hibp_lookup"
               and l["outcome"] == "skipped_no_key" for l in lines)


def test_identity_tool_context_person_social(monkeypatch, tmp_path):
    monkeypatch.setattr(social.SocialClient, "enumerate",
                        lambda self, h, audit: [])
    monkeypatch.setattr(social.SocialClient, "gravatar_hit",
                        lambda self, e: None)
    cfg = _cfg_no_tools()
    cfg["identity_tools"] = True
    ctx = orchestrator._identity_tool_context(
        cfg, {"name": "Jane Doe", "type": "person"}, "p_social",
        {"name": "Jane Doe", "handles": ["janedoe"]}, str(tmp_path))
    assert "janedoe" in ctx


def test_threat_tool_context_skipped_for_company(tmp_path):
    ctx = orchestrator._threat_tool_context(
        _cfg_no_tools(), {"name": "Acme", "type": "company"},
        "phishing", str(tmp_path))
    assert ctx == ""


def test_threat_tool_context_phishing(monkeypatch, tmp_path):
    monkeypatch.setattr(threatintel, "vt_domain_report",
                        lambda d, a=None: {"analysis_stats":
                                           {"malicious": 0, "suspicious": 0,
                                            "harmless": 1, "undetected": 0},
                                           "categories": {}, "registrar": "",
                                           "creation_date": "",
                                           "dns_records": []})
    monkeypatch.setattr(threatintel, "otx_domain_intel",
                        lambda d, a=None: {"reputation": 0, "pulse_count": 0,
                                           "pulses": [], "urls": []})
    monkeypatch.setattr(threatintel, "urlscan_search", lambda d: [])
    cfg = _cfg_no_tools()
    cfg["threat_intel"] = True
    ctx = orchestrator._threat_tool_context(
        cfg, {"name": "example.com", "type": "domain"},
        "phishing", str(tmp_path))
    assert "VirusTotal" in ctx and "AlienVault OTX" in ctx
    assert "urlscan.io" in ctx


def test_assess_many_email_target_no_tools(monkeypatch, tmp_path):
    store = []
    _patch_backends(monkeypatch, store)
    results, _ = orchestrator.assess_many(
        _cfg_no_tools(), [{"name": "jane@example.com", "type": "email"}],
        str(tmp_path))
    assert len(results) == 1
    assert results[0]["type"] == "email"
    report = open(os.path.join(results[0]["dir"], "report.md"),
                  encoding="utf-8").read()
    assert "Target type: email" in report
    assert "Address format & pattern analysis" in report
    # Email targets use the intel brief style: the synthesis prompt (not the
    # mocked output) carries the Key Judgments section.
    synth_prompts = [c for s, c in store if "Key Judgments" in c]
    assert len(synth_prompts) == 1
