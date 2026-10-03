"""Orchestrator: triage -> per-axis research -> synthesis -> report.

Pipeline for each target (company, software, or domain):
  1. Triage: resolve target identity from name/URL (local-capable backend).
  2. Research: run the type's axes. Before each axis leg, the built-in web
     search tool (keyless DuckDuckGo by default; Serper/Bing optional) runs
     targeted queries so name-search works even with the local Ollama backend.
     Hosted backends can additionally use their own server-side web search.
  3. Synthesis: local-capable backend turns axis research into the brief.
  4. Report: markdown brief with a source register.

Data boundary: hosted backends receive only the research task content (target
identity + axis questions). The audit trail records backend kind, model id,
token counts, task names, and web-search queries/URLs -- never API key values.
"""

from __future__ import annotations

import copy
import json
import os
import re
from datetime import datetime, timezone

import yaml

from . import models
from . import prompts
from . import report as report_mod
from . import scope
from . import search as search_mod


DEFAULT_CONFIG = {
    "research_backend": {"provider": "anthropic", "model": None},
    "synthesis_backend": {"provider": "ollama", "model": None},
    "ollama_url": "http://localhost:11434",
    # Use server-side web search on the research legs when the backend
    # supports it (OpenAI Responses API / Anthropic web_search tool).
    "web_search": True,
    # Built-in web search run by the research legs before each axis model
    # call. Works with every backend, including local Ollama.
    "tool_search": True,
    "search": {
        "provider": "auto",   # auto | duckduckgo | serper | bing
        "max_results": 6,
        "rate_limit_s": 1.0,
        "timeout": 30,
    },
}


class ConfigError(models.ConfigError):
    pass


def load_config(path):
    """Load config.yaml, apply defaults, validate provider names."""
    cfg = copy.deepcopy(DEFAULT_CONFIG)
    if path and os.path.exists(path):
        with open(path, "r", encoding="utf-8") as fh:
            user_cfg = yaml.safe_load(fh) or {}
        for section in ("research_backend", "synthesis_backend", "search"):
            if section in user_cfg and isinstance(user_cfg[section], dict):
                cfg[section].update(user_cfg[section])
        for key in ("ollama_url", "web_search", "tool_search"):
            if key in user_cfg:
                cfg[key] = user_cfg[key]
    # Propagate ollama_url into the ollama backend section(s).
    for section in ("research_backend", "synthesis_backend"):
        if cfg[section].get("provider") == "ollama" and "base_url" not in cfg[section]:
            cfg[section]["base_url"] = cfg["ollama_url"]
    for section in ("research_backend", "synthesis_backend"):
        provider = (cfg[section].get("provider") or "").lower()
        if provider not in models.VALID_PROVIDERS:
            raise ConfigError(
                "Unknown provider %r in %s (expected one of: %s)."
                % (provider, section, ", ".join(models.VALID_PROVIDERS))
            )
        cfg[section]["provider"] = provider
    return cfg


def slugify(name):
    slug = re.sub(r"[^a-z0-9]+", "-", (name or "org").lower()).strip("-")
    return slug or "org"


def append_audit(out_dir, record):
    """Append one JSONL audit record. Never include key material."""
    os.makedirs(out_dir, exist_ok=True)
    record = dict(record)
    record.setdefault("ts", datetime.now(timezone.utc).isoformat())
    with open(os.path.join(out_dir, "audit.jsonl"), "a", encoding="utf-8") as fh:
        fh.write(json.dumps(record) + "\n")


def _audit_call(out_dir, task, result, web_search):
    append_audit(out_dir, {
        "event": "model_call",
        "task": task,
        "backend": result.backend,
        "model": result.model,
        "web_search": bool(web_search),
        "input_tokens": result.input_tokens,
        "output_tokens": result.output_tokens,
    })


def _emit(progress_cb, phase, detail, target=None):
    """Call a progress callback, tolerating the old (phase, detail) shape."""
    if not progress_cb:
        return
    try:
        progress_cb(phase, detail, target=target)
    except TypeError:
        progress_cb(phase, detail)


def normalize_target(t):
    """Normalize a target to {"name", "url", "type"}.

    Accepts a dict or a (name, url[, type]) tuple. Raises ConfigError on an
    unknown target type.
    """
    if isinstance(t, dict):
        name = (t.get("name") or "").strip()
        url = (t.get("url") or "").strip()
        type_ = (t.get("type") or "company").strip().lower()
    else:
        parts = list(t)
        name = (parts[0] if len(parts) > 0 else "").strip()
        url = (parts[1] if len(parts) > 1 else "").strip()
        type_ = (parts[2] if len(parts) > 2 else "company").strip().lower()
    if type_ not in prompts.TARGET_TYPES:
        raise ConfigError(
            "Unknown target type %r (expected one of: %s)."
            % (type_, ", ".join(prompts.TARGET_TYPES)))
    return {"name": name, "url": url, "type": type_}


def check_scope(targets):
    """Refuse non-security targets with the short refusal message."""
    for t in targets:
        scope.check_target(t.get("name", ""), t.get("url", ""))


def resolve_identity(backend, name, url, out_dir, progress_cb=None,
                     target_type="company"):
    """Triage step: resolve target identity before any research leg runs."""
    _emit(progress_cb, "triage", "Resolving %s identity" % target_type,
          target=name)
    result = backend.chat(
        [{"role": "user",
          "content": prompts.build_identity_prompt(name, url, target_type)}],
        system=None,
        web_search=False,
    )
    _audit_call(out_dir, "triage_identity", result, web_search=False)
    text = result.text.strip()
    try:
        start = text.index("{")
        end = text.rindex("}") + 1
        return json.loads(text[start:end])
    except (ValueError, json.JSONDecodeError):
        return {"name": name, "url": url, "notes": "IDENTITY UNRESOLVED",
                "raw": text}


def _axis_search_context(cfg, target, axis, out_dir):
    """Run the built-in web search for one axis; never raises."""
    if not cfg.get("tool_search"):
        return ""
    scfg = cfg.get("search") or {}
    try:
        client = search_mod.SearchClient(
            provider=scfg.get("provider", "auto"),
            max_results=scfg.get("max_results", 6),
            rate_limit_s=scfg.get("rate_limit_s", 1.0),
            timeout=scfg.get("timeout", 30),
        )
    except Exception as exc:  # noqa: BLE001 - bad search config, keep going
        append_audit(out_dir, {"event": "web_search_error", "axis": axis,
                               "error": str(exc)})
        return ""

    def _audit(record):
        append_audit(out_dir, record)

    try:
        return search_mod.search_for_axis(
            target["type"], axis, target["name"], target.get("url", ""),
            client, _audit)
    except Exception as exc:  # noqa: BLE001 - search must not kill a run
        append_audit(out_dir, {"event": "web_search_error", "axis": axis,
                               "error": str(exc)})
        return ""


def run_axis(research_backend, axis, identity, out_dir, web_search,
             progress_cb=None, search_context="", target=None):
    _emit(progress_cb, "research",
          "Researching: %s" % prompts.AXIS_TITLES[axis], target=target)
    prompt = prompts.build_axis_prompt(axis, identity)
    if search_context:
        prompt += "\n\n" + search_context
    result = research_backend.chat(
        [{"role": "user", "content": prompt}],
        system=prompts.SYSTEM_RESEARCH,
        web_search=web_search,
    )
    _audit_call(out_dir, "research_" + axis, result, web_search=web_search)
    return result.text


def synthesize(synthesis_backend, identity, axis_texts, out_dir,
               progress_cb=None, target=None, axes=None):
    _emit(progress_cb, "synthesize", "Synthesizing assessment brief",
          target=target)
    result = synthesis_backend.chat(
        [{"role": "user",
          "content": prompts.build_synthesis_prompt(identity, axis_texts,
                                                     axes=axes)}],
        system=prompts.SYSTEM_SYNTHESIS,
        web_search=False,
    )
    _audit_call(out_dir, "synthesize", result, web_search=False)
    return result.text


def assess_target(cfg, target, out_dir, progress_cb=None):
    """Run the full pipeline for one target dict; returns a summary dict."""
    target = normalize_target(target)
    name, target_type = target["name"], target["type"]
    axes = prompts.axes_for_type(target_type)
    research_backend, synthesis_backend = models.select_backends(cfg)
    web_search = bool(cfg.get("web_search", True))
    os.makedirs(out_dir, exist_ok=True)
    append_audit(out_dir, {"event": "assessment_started", "target": name,
                           "url": target.get("url") or "",
                           "type": target_type})

    identity = resolve_identity(synthesis_backend, name, target.get("url", ""),
                                out_dir, progress_cb, target_type)
    axis_texts = {}
    for axis in axes:
        search_context = _axis_search_context(cfg, target, axis, out_dir)
        axis_texts[axis] = run_axis(
            research_backend, axis, json.dumps(identity), out_dir, web_search,
            progress_cb, search_context=search_context, target=name,
        )
    synthesis_text = synthesize(
        synthesis_backend, json.dumps(identity), axis_texts, out_dir,
        progress_cb, target=name, axes=axes,
    )

    meta = {
        "target_type": target_type,
        "research_backend": "%s/%s" % (research_backend.kind,
                                       research_backend.model),
        "synthesis_backend": "%s/%s" % (synthesis_backend.kind,
                                        synthesis_backend.model),
        "web_search": web_search,
        "tool_search": bool(cfg.get("tool_search")),
    }
    report_path = os.path.join(out_dir, "report.md")
    report_mod.write_report(report_path, name, json.dumps(identity, indent=2),
                            axis_texts, synthesis_text, meta,
                            target_type=target_type, axes=axes)
    append_audit(out_dir, {"event": "assessment_done", "target": name,
                           "type": target_type, "report": report_path})
    return {
        "name": name,
        "org": name,  # back-compat alias
        "type": target_type,
        "identity": identity,
        "dir": out_dir,
        "synthesis": synthesis_text,
        "axis_texts": axis_texts,
    }


def assess_org(cfg, org, url, out_dir, progress_cb=None):
    """Back-compat wrapper: assess one company target."""
    return assess_target(cfg, {"name": org, "url": url, "type": "company"},
                         out_dir, progress_cb)


def compare_targets(cfg, results, out_dir, progress_cb=None):
    """Rank multiple assessed targets; writes comparison.md. Returns text."""
    _, synthesis_backend = models.select_backends(cfg)
    os.makedirs(out_dir, exist_ok=True)
    _emit(progress_cb, "compare", "Ranking targets")
    types = {r.get("type", "company") for r in results}
    target_type = types.pop() if len(types) == 1 else "mixed"
    summaries = []
    for r in results:
        summaries.append(
            "### %s (%s)\nIdentity: %s\n\nBrief:\n%s"
            % (r.get("name") or r.get("org"), r.get("type", "company"),
               json.dumps(r["identity"]), r["synthesis"])
        )
    result = synthesis_backend.chat(
        [{"role": "user",
          "content": prompts.build_comparison_prompt(
              "\n\n".join(summaries), target_type)}],
        system=prompts.SYSTEM_SYNTHESIS,
        web_search=False,
    )
    _audit_call(out_dir, "compare", result, web_search=False)
    meta = {
        "targets": ["%s (%s)" % (r.get("name") or r.get("org"),
                                 r.get("type", "company")) for r in results],
        "synthesis_backend": "%s/%s" % (synthesis_backend.kind,
                                        synthesis_backend.model),
    }
    comp_path = os.path.join(out_dir, "comparison.md")
    names = [r.get("name") or r.get("org") for r in results]
    report_mod.write_comparison(comp_path, result.text, names, meta,
                                target_type=target_type)
    return result.text


def compare_orgs(cfg, results, out_dir, progress_cb=None):
    """Back-compat wrapper for company comparisons."""
    return compare_targets(cfg, results, out_dir, progress_cb)


def _unique_dir(base_out_dir, name, used):
    slug = slugify(name)
    candidate = slug
    i = 2
    while candidate in used:
        candidate = "%s-%d" % (slug, i)
        i += 1
    used.add(candidate)
    return os.path.join(base_out_dir, candidate)


def assess_many(cfg, targets, base_out_dir, progress_cb=None):
    """Assess a list of targets (dicts or tuples); compare when > 1."""
    targets = [normalize_target(t) for t in targets]
    if not targets:
        raise ConfigError("No targets given.")
    check_scope(targets)
    results = []
    used_dirs = set()
    for target in targets:
        out_dir = _unique_dir(base_out_dir, target["name"], used_dirs)
        results.append(assess_target(cfg, target, out_dir, progress_cb))
    comparison = None
    if len(results) > 1:
        comparison = compare_targets(cfg, results, base_out_dir, progress_cb)
    _emit(progress_cb, "done", "Assessment complete")
    return results, comparison
