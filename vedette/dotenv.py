"""Minimal .env file loader for temp runs without 1Password.

Reads KEY=VALUE lines from a `.env` file in the project root and injects
them into os.environ -- but only for names not already set, so a real
environment (or `op run`) always wins. Values are never logged.

This is intentionally dependency-free (no python-dotenv) and handles just
the common cases: blank lines, `#` comments, `export KEY=VALUE`, and
single/double-quoted values.
"""

from __future__ import annotations

import logging
import os

log = logging.getLogger("vedette.dotenv")


def parse_dotenv(text):
    """Parse .env text into an ordered dict of {name: value}."""
    values = {}
    for raw_line in text.splitlines():
        line = raw_line.strip()
        if not line or line.startswith("#"):
            continue
        if line.lower().startswith("export "):
            line = line[7:].strip()
        if "=" not in line:
            continue
        name, value = line.split("=", 1)
        name = name.strip()
        value = value.strip()
        if not name or not name.replace("_", "").isalnum():
            continue
        # Strip one layer of matching quotes.
        if len(value) >= 2 and value[0] == value[-1] and value[0] in ("'", '"'):
            value = value[1:-1]
        values[name] = value
    return values


def load_dotenv(path=None):
    """Load `.env` into os.environ (existing vars win). Returns names loaded.

    Looks for `.env` next to the project root when path is None. Missing file
    is a no-op -- this keeps 1Password/`op run` flows untouched.
    """
    if path is None:
        here = os.path.dirname(os.path.abspath(__file__))
        path = os.path.join(os.path.dirname(here), ".env")
    if not os.path.isfile(path):
        return []
    try:
        with open(path, encoding="utf-8") as fh:
            values = parse_dotenv(fh.read())
    except OSError as exc:
        log.warning("could not read .env file %s: %s", path, exc)
        return []
    loaded = []
    for name, value in values.items():
        if name not in os.environ:
            os.environ[name] = value
            loaded.append(name)
    if loaded:
        log.info(".env loaded %d secret(s): %s", len(loaded),
                 ", ".join(sorted(loaded)))
    return loaded
