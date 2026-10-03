"""Markdown brief writer: per-org report plus a comparison report.

Each report ends with a numbered source register built from the URLs the
research legs cited, so claims stay traceable to their sources.
"""

from __future__ import annotations

import re
from datetime import datetime, timezone

from .prompts import AXES, AXIS_TITLES

URL_RE = re.compile(r"https?://[^\s\)>\]\"']+")


def extract_sources(text):
    """Pull unique URLs from research text, preserving first-seen order."""
    seen = []
    for match in URL_RE.finditer(text or ""):
        url = match.group(0).rstrip(".,;:")
        if url not in seen:
            seen.append(url)
    return seen


def _source_register(axis_texts, axes=None):
    axes = axes or AXES
    ordered = []
    for axis in axes:
        for url in extract_sources(axis_texts.get(axis, "")):
            if url not in ordered:
                ordered.append(url)
    lines = ["## Source register", ""]
    if not ordered:
        lines.append("No source URLs were cited by the research legs.")
    else:
        for i, url in enumerate(ordered, 1):
            lines.append("%d. %s" % (i, url))
    return "\n".join(lines)


def write_report(path, org, identity, axis_texts, synthesis_text, meta,
                 target_type="company", axes=None):
    """Write the full assessment brief for one target."""
    axes = axes or AXES
    generated = datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M UTC")
    lines = [
        "# Vedette Assessment: %s" % org,
        "",
        "Generated: %s" % generated,
        "Target type: %s" % (target_type or "company"),
        "",
        "## Target identity",
        "",
        "```",
        identity if isinstance(identity, str) else str(identity),
        "```",
        "",
        "## Brief",
        "",
        synthesis_text or "NOT FOUND",
        "",
    ]
    for axis in axes:
        lines.append("## Research: %s" % AXIS_TITLES[axis])
        lines.append("")
        lines.append(axis_texts.get(axis, "NOT FOUND") or "NOT FOUND")
        lines.append("")
    lines.append(_source_register(axis_texts, axes))
    lines.append("")
    if meta:
        lines.append("## Run metadata")
        lines.append("")
        for key in sorted(meta):
            lines.append("- %s: %s" % (key, meta[key]))
        lines.append("")
    with open(path, "w", encoding="utf-8") as fh:
        fh.write("\n".join(lines))
    return path


COMPARISON_TITLES = {
    "company": "Provider Comparison",
    "software": "Software Comparison",
    "domain": "Domain Comparison",
    "mixed": "Target Comparison",
}


def write_comparison(path, comparison_text, org_names, meta, target_type="company"):
    """Write the cross-target comparison report."""
    title = COMPARISON_TITLES.get((target_type or "company").lower(),
                                  COMPARISON_TITLES["mixed"])
    generated = datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M UTC")
    lines = [
        "# %s: %s" % (title, ", ".join(org_names)),
        "",
        "Generated: %s" % generated,
        "",
        comparison_text or "NOT FOUND",
        "",
        "## Source register",
        "",
    ]
    for url in extract_sources(comparison_text):
        lines.append("- %s" % url)
    lines.append("")
    if meta:
        lines.append("## Run metadata")
        lines.append("")
        for key in sorted(meta):
            lines.append("- %s: %s" % (key, meta[key]))
        lines.append("")
    with open(path, "w", encoding="utf-8") as fh:
        fh.write("\n".join(lines))
    return path
