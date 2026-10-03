#!/usr/bin/env python3
"""CLI for the OSINT assessment agent.

Target types: company (default), software, domain. Pass targets repeatably;
each is assessed on its type's security axes, and multiple targets get a
ranked comparison.

Examples:
  python run_assessment.py --target "GreenNode" --target "FPT Smart Cloud"
  python run_assessment.py --target "nginx|software" --target "openssl|software"
  python run_assessment.py --target "example.com|domain"
  python run_assessment.py --target "Acme=https://acme.com" --type company
  # back-compat:
  python run_assessment.py --org GreenNode --url https://greennode.ai
  python run_assessment.py --org GreenNode --url https://greennode.ai \\
      --compare "CoreWeave=https://coreweave.com,Nebius=https://nebius.com"
"""

import argparse
import logging
import os
import re
import sys

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from vedette import orchestrator
from vedette.dotenv import load_dotenv
from vedette.prompts import TARGET_TYPES
from vedette.scope import ScopeError
from vedette.server import log_secret_presence

URL_LIKE_RE = re.compile(r"^(https?://)?[a-z0-9]([a-z0-9.-]*[a-z0-9])?\.[a-z]{2,}(/.*)?$",
                         re.IGNORECASE)


def parse_target(spec, default_type="company"):
    """Parse one target spec into {"name", "url", "type"}.

    Accepted forms:
      "Name"                    -> company "Name"
      "Name=https://url"        -> company "Name" with URL
      "Name|software"           -> software "Name"
      "Name=https://url|domain" -> domain "Name" with URL
      "https://example.com"     -> domain (auto-detected from URL shape)
    """
    spec = (spec or "").strip()
    type_ = (default_type or "company").lower()
    if "|" in spec:
        spec, maybe_type = spec.rsplit("|", 1)
        maybe_type = maybe_type.strip().lower()
        if maybe_type in TARGET_TYPES:
            type_ = maybe_type
        else:
            spec = spec + "|" + maybe_type  # not a type suffix; keep it
        spec = spec.strip()
    name, url = spec, ""
    if "=" in spec and not spec.startswith("http"):
        name, url = spec.split("=", 1)
        name, url = name.strip(), url.strip()
    if type_ == (default_type or "company").lower() and URL_LIKE_RE.match(name):
        # Bare URL/domain with no explicit type -> treat as a domain target.
        type_ = "domain"
        if "://" not in name:
            url = "https://" + name
        else:
            url = name
    return {"name": name, "url": url, "type": type_}


def main():
    ap = argparse.ArgumentParser(description="OSINT assessment agent")
    ap.add_argument("--target", action="append", default=[],
                    help="Target to assess (repeatable): 'Name', "
                         "'Name=https://url', 'Name|software', "
                         "'https://example.com|domain'")
    ap.add_argument("--type", default="company", choices=list(TARGET_TYPES),
                    help="Default target type for --target/--org/--compare")
    ap.add_argument("--org", default=None,
                    help="Organization name (back-compat alias for --target)")
    ap.add_argument("--url", default="", help="Organization URL (back-compat)")
    ap.add_argument("--compare", default="",
                    help="Comma-separated extra targets, 'Name' or "
                         "'Name=https://url' (back-compat)")
    ap.add_argument("--backend", choices=["anthropic", "openai", "ollama"],
                    help="Override research backend provider")
    ap.add_argument("--model", default=None, help="Override research backend model id")
    ap.add_argument("--config", default="config.yaml", help="Path to config.yaml")
    ap.add_argument("--out", default="runs", help="Output directory for reports")
    args = ap.parse_args()

    load_dotenv()  # temp runs: .env fills secrets 1Password would provide

    logging.basicConfig(level=logging.INFO,
                        format="%(asctime)s %(name)s %(levelname)s %(message)s")
    log_secret_presence()  # names + set/not-set only, never values

    cfg = orchestrator.load_config(args.config)
    if args.backend:
        cfg["research_backend"]["provider"] = args.backend
    if args.model:
        cfg["research_backend"]["model"] = args.model

    targets = [parse_target(s, args.type) for s in args.target]
    if args.org:
        targets.append({"name": args.org, "url": args.url, "type": args.type})
    for item in args.compare.split(","):
        item = item.strip()
        if item:
            targets.append(parse_target(item, args.type))
    if not targets:
        ap.error("give at least one --target (or --org)")

    def _progress(phase, detail, target=None):
        label = ("[%s] " % target) if target else ""
        print("%s%s: %s" % (label, phase, detail), flush=True)

    try:
        results, comparison = orchestrator.assess_many(
            cfg, targets, args.out, progress_cb=_progress)
    except ScopeError as exc:
        print(str(exc), file=sys.stderr)
        sys.exit(2)
    for r in results:
        print("report: %s" % os.path.join(r["dir"], "report.md"))
    if comparison:
        print("comparison: %s" % os.path.join(args.out, "comparison.md"))


if __name__ == "__main__":
    main()
