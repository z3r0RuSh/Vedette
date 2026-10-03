"""Tests for the built-in web search (vedette/search.py).

HTTP is mocked throughout: no test hits the live network.
"""

import json
import urllib.parse

import pytest

from vedette import search as search_mod
from vedette.search import SearchClient, SearchError


DDG_HTML = """
<html><body>
<table>
<tr><td><a rel="nofollow" href="//duckduckgo.com/l/?uddg=https%3A%2F%2Fexample.com%2Fa&amp;rut=x">Example A</a></td>
<td class="result-snippet">First <b>snippet</b> here.</td></tr>
<tr><td><a rel="nofollow" href="https://example.com/b">Example B</a></td>
<td class='result-snippet'>Second snippet.</td></tr>
<tr><td><a href="#nav">nav link</a></td></tr>
<tr><td><a rel="nofollow" href="javascript:void(0)">js link</a></td></tr>
</table>
</body></html>
"""


class FakeResp:
    def __init__(self, text="", payload=None, headers=None):
        self.text = text
        self._payload = payload or {}
        self.headers = headers or {}

    def raise_for_status(self):
        pass

    def json(self):
        return self._payload


# ---------------------------------------------------------------------------
# DuckDuckGo lite parsing
# ---------------------------------------------------------------------------

def test_ddg_parse_results():
    results = SearchClient.parse_ddg_lite(DDG_HTML, 10)
    assert len(results) == 2
    assert results[0]["url"] == "https://example.com/a"
    assert results[0]["title"] == "Example A"
    assert results[0]["snippet"] == "First snippet here."
    assert results[1]["url"] == "https://example.com/b"
    assert results[1]["snippet"] == "Second snippet."


def test_ddg_parse_respects_max_results():
    assert len(SearchClient.parse_ddg_lite(DDG_HTML, 1)) == 1


def test_ddg_parse_empty_html():
    assert SearchClient.parse_ddg_lite("", 6) == []
    assert SearchClient.parse_ddg_lite(None, 6) == []


def test_ddg_search_posts_to_lite(monkeypatch):
    seen = {}

    def fake_post(url, data=None, headers=None, timeout=None):
        seen["url"] = url
        seen["data"] = data
        seen["ua"] = headers.get("User-Agent")
        return FakeResp(text=DDG_HTML)
    monkeypatch.setattr("requests.post", fake_post)
    client = SearchClient(provider="duckduckgo", rate_limit_s=0)
    results = client.search("acme breach")
    assert seen["url"] == SearchClient.DDG_URL
    assert seen["data"] == {"q": "acme breach"}
    assert seen["ua"]  # polite UA set
    assert results[0]["url"] == "https://example.com/a"
    assert "fetched_at" in results[0]  # timestamp attached


# ---------------------------------------------------------------------------
# Serper / Bing parsing
# ---------------------------------------------------------------------------

def test_serper_search(monkeypatch):
    seen = {}

    def fake_post(url, json=None, headers=None, timeout=None):
        seen["url"] = url
        seen["auth"] = headers.get("X-API-KEY")
        seen["body"] = json
        return FakeResp(payload={"organic": [
            {"title": "T1", "link": "https://s.example/1", "snippet": "S1"},
            {"title": "T2", "link": "", "snippet": "skipped"},
        ]})
    monkeypatch.setattr("requests.post", fake_post)
    monkeypatch.setenv("SERPER_API_KEY", "sekret")
    client = SearchClient(provider="serper", rate_limit_s=0)
    results = client.search("acme soc2")
    assert seen["url"].endswith("/search")
    assert seen["auth"] == "sekret"
    assert seen["body"]["q"] == "acme soc2"
    assert [r["url"] for r in results] == ["https://s.example/1"]
    assert results[0]["title"] == "T1" and results[0]["snippet"] == "S1"


def test_bing_search(monkeypatch):
    seen = {}

    def fake_get(url, params=None, headers=None, timeout=None):
        seen["url"] = url
        seen["key"] = headers.get("Ocp-Apim-Subscription-Key")
        seen["params"] = params
        return FakeResp(payload={"webPages": {"value": [
            {"name": "B1", "url": "https://b.example/1", "snippet": "BS1"},
        ]}})
    monkeypatch.setattr("requests.get", fake_get)
    monkeypatch.setenv("BING_API_KEY", "bsekret")
    client = SearchClient(provider="bing", rate_limit_s=0)
    results = client.search("acme tls")
    assert "bing.microsoft.com" in seen["url"]
    assert seen["key"] == "bsekret"
    assert seen["params"]["q"] == "acme tls"
    assert results == [{"title": "B1", "url": "https://b.example/1",
                        "snippet": "BS1", "fetched_at": results[0]["fetched_at"]}]


def test_explicit_provider_without_key_names_env_var(monkeypatch):
    monkeypatch.delenv("SERPER_API_KEY", raising=False)
    with pytest.raises(SearchError) as exc:
        SearchClient(provider="serper")
    assert "SERPER_API_KEY" in str(exc.value)
    monkeypatch.delenv("BING_API_KEY", raising=False)
    with pytest.raises(SearchError) as exc:
        SearchClient(provider="bing")
    assert "BING_API_KEY" in str(exc.value)


def test_unknown_provider_rejected():
    with pytest.raises(SearchError):
        SearchClient(provider="yahoo")


# ---------------------------------------------------------------------------
# Provider auto-selection
# ---------------------------------------------------------------------------

def test_auto_prefers_serper_then_bing_then_duckduckgo(monkeypatch):
    monkeypatch.delenv("SERPER_API_KEY", raising=False)
    monkeypatch.delenv("BING_API_KEY", raising=False)
    assert SearchClient(provider="auto", rate_limit_s=0).provider == "duckduckgo"
    monkeypatch.setenv("BING_API_KEY", "k")
    assert SearchClient(provider="auto", rate_limit_s=0).provider == "bing"
    monkeypatch.setenv("SERPER_API_KEY", "k")
    assert SearchClient(provider="auto", rate_limit_s=0).provider == "serper"


# ---------------------------------------------------------------------------
# Rate limiting
# ---------------------------------------------------------------------------

def test_rate_limit_sleeps_between_calls(monkeypatch):
    sleeps = []
    monkeypatch.setattr("time.sleep", lambda s: sleeps.append(s))
    monkeypatch.setattr("time.monotonic", lambda: 1000.0)
    monkeypatch.setattr("requests.post", lambda *a, **k: FakeResp(text=""))
    client = SearchClient(provider="duckduckgo", rate_limit_s=2.0)
    client.search("one")
    client.search("two")
    assert sleeps, "expected a throttle sleep between calls"
    assert sleeps[0] == pytest.approx(2.0)


# ---------------------------------------------------------------------------
# Axis search + audit
# ---------------------------------------------------------------------------

class FakeClient:
    provider = "duckduckgo"

    def __init__(self, fail=False):
        self.fail = fail
        self.queries = []

    def search(self, query):
        self.queries.append(query)
        if self.fail:
            raise RuntimeError("network down")
        return [{"url": "https://r.example/%d" % i, "title": "T%d" % i,
                 "snippet": "S%d" % i, "fetched_at": "2026-01-01T00:00:00+00:00"}
                for i in range(2)]


def test_search_for_axis_audits_queries_urls_timestamps():
    records = []
    client = FakeClient()
    block = search_mod.search_for_axis(
        "company", "incidents", "Acme", "https://acme.example",
        client, records.append)
    assert "Acme" in client.queries[0]
    assert len(records) == 2  # one per query
    rec = records[0]
    assert rec["event"] == "web_search"
    assert rec["provider"] == "duckduckgo"
    assert rec["query"] and rec["result_count"] == 2
    assert rec["results"][0]["url"] == "https://r.example/0"
    assert rec["results"][0]["fetched_at"] == "2026-01-01T00:00:00+00:00"
    # No key material anywhere in the audit records.
    blob = json.dumps(records)
    assert "sekret" not in blob and "API_KEY" not in blob
    # Context block is usable in a prompt.
    assert "https://r.example/0" in block
    assert "Live web search" in block


def test_search_for_axis_never_raises_and_audits_errors():
    records = []
    block = search_mod.search_for_axis(
        "software", "vulnerabilities", "nginx", "", FakeClient(fail=True),
        records.append)
    assert block == ""
    assert all(r["event"] == "web_search_error" for r in records)
    assert records[0]["error"] == "network down"


def test_search_for_axis_domain_queries_use_domain():
    records = []
    client = FakeClient()
    search_mod.search_for_axis("domain", "tls", "example.com",
                               "https://example.com", client, records.append)
    assert any("example.com" in q for q in client.queries)


def test_axis_queries_cover_all_axes():
    for t in ("company", "software", "domain"):
        from vedette import prompts
        for axis in prompts.axes_for_type(t):
            qs = search_mod.AXIS_QUERIES[t][axis]
            assert len(qs) >= 1
            for q in qs:
                q.format(name="N", domain="d.example")  # templates are valid


# ---------------------------------------------------------------------------
# fetch_text
# ---------------------------------------------------------------------------

def test_fetch_text_strips_tags_and_caps(monkeypatch):
    def fake_get(url, headers=None, timeout=None):
        assert headers.get("User-Agent")
        return FakeResp(
            text="<html><head><style>.x{}</style><script>evil()</script></head>"
                 "<body><h1>Hi</h1><p>" + "word " * 10000 + "</p></body></html>",
            headers={"content-type": "text/html"})
    monkeypatch.setattr("requests.get", fake_get)
    client = SearchClient(provider="duckduckgo", rate_limit_s=0)
    text = client.fetch_text("https://example.com", max_chars=500)
    assert "evil()" not in text
    assert "Hi" in text
    assert len(text) <= 500


def test_fetch_text_rejects_non_text(monkeypatch):
    monkeypatch.setattr(
        "requests.get",
        lambda *a, **k: FakeResp(text="", headers={"content-type": "image/png"}))
    client = SearchClient(provider="duckduckgo", rate_limit_s=0)
    with pytest.raises(SearchError):
        client.fetch_text("https://example.com/logo.png")
