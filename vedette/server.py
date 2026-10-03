"""Web GUI for the Vedette (FastAPI + no-build-step frontend in ui/).

Authenticated access only: Google OAuth (email allowlist) or generic OIDC.
Every route that triggers research or reads past assessments requires a valid
signed-cookie session. Secrets come from env vars only and are never logged.
"""

from __future__ import annotations

import copy
import json
import logging
import os
import threading
import time
from datetime import datetime, timezone

from fastapi import FastAPI, Request
from fastapi.responses import (
    FileResponse,
    HTMLResponse,
    JSONResponse,
    RedirectResponse,
)
from fastapi.staticfiles import StaticFiles

from urllib.parse import unquote_plus

from . import auth
from . import orchestrator

log = logging.getLogger("vedette.server")

HERE = os.path.dirname(os.path.abspath(__file__))
PROJECT_ROOT = os.path.dirname(HERE)
UI_DIR = os.path.join(PROJECT_ROOT, "ui")

# Secrets we track at startup: log names + set/not-set only, never values.
TRACKED_SECRETS = [
    "OPENAI_API_KEY",
    "ANTHROPIC_API_KEY",
    "SERPER_API_KEY",
    "BING_API_KEY",
    "OSINT_GOOGLE_CLIENT_ID",
    "OSINT_GOOGLE_CLIENT_SECRET",
    "OSINT_OIDC_CLIENT_ID",
    "OSINT_OIDC_CLIENT_SECRET",
    "OSINT_SESSION_SECRET",
    "OSINT_ALLOWED_GOOGLE_EMAILS",
    "OSINT_LOCAL_PASSWORD",
]


def log_secret_presence():
    """Log which secrets are set. Names only -- values are never printed."""
    for name in TRACKED_SECRETS:
        log.info("secret %s: %s", name, "set" if os.environ.get(name) else "not set")


def _runs_dir(cfg):
    d = cfg.get("runs_dir") or "runs"
    if not os.path.isabs(d):
        d = os.path.join(PROJECT_ROOT, d)
    os.makedirs(d, exist_ok=True)
    return d


def _session_timeout(cfg):
    return auth.session_timeout_seconds(cfg)


def _current_user(request, cfg):
    token = request.cookies.get(auth.SESSION_COOKIE)
    return auth.verify_session(token, _session_timeout(cfg))


def _callback_base(request):
    # Must match the redirect URI registered in the OAuth provider console.
    return str(request.base_url).rstrip("/")


def _split_type_suffix(spec):
    """Split an optional '|type' suffix off a target spec line."""
    from .prompts import TARGET_TYPES
    spec = (spec or "").strip()
    if "|" in spec:
        head, maybe = spec.rsplit("|", 1)
        if maybe.strip().lower() in TARGET_TYPES:
            return head.strip(), maybe.strip().lower()
    return spec, None


def parse_gui_targets(body):
    """Parse the new-assessment form body into [target dicts].

    Accepts the new shape {"targets": [{name, url, type}], "default_type"}
    and the legacy shape {"org", "url", "compare"}. Raises ValueError on
    empty or mistyped input.
    """
    from .prompts import TARGET_TYPES
    default_type = (body.get("default_type") or "company").lower()
    if default_type not in TARGET_TYPES:
        raise ValueError("unknown target type %r" % default_type)

    raw = body.get("targets")
    if raw is None:
        # Legacy shape.
        org = (body.get("org") or "").strip()
        raw = []
        if org:
            raw.append({"name": org, "url": (body.get("url") or "").strip()})
        for c in body.get("compare") or []:
            if isinstance(c, dict) and c.get("name"):
                raw.append({"name": c["name"].strip(),
                            "url": (c.get("url") or "").strip()})
            elif isinstance(c, str) and c.strip():
                raw.append({"name": c.strip()})

    targets = []
    for item in raw:
        if isinstance(item, str):
            name, url = item.strip(), ""
        elif isinstance(item, dict):
            name = (item.get("name") or "").strip()
            url = (item.get("url") or "").strip()
        else:
            continue
        if not url and "=" in name and not name.startswith("http"):
            name, url = (p.strip() for p in name.split("=", 1))
        if not name and not url:
            continue
        name, type_suffix = _split_type_suffix(name)
        if not name and url:
            name = url
        type_ = (item.get("type") if isinstance(item, dict) else None)
        type_ = (type_ or type_suffix or default_type).lower()
        if type_ not in TARGET_TYPES:
            raise ValueError("unknown target type %r" % type_)
        targets.append({"name": name, "url": url, "type": type_})
    if not targets:
        raise ValueError("at least one target is required")
    return targets


def create_app(cfg=None):
    cfg = cfg or {}
    app = FastAPI(title="Vedette", docs_url=None, redoc_url=None,
                  openapi_url=None)

    runs = {}
    runs_lock = threading.Lock()

    # -- public-path predicate -------------------------------------------------
    def _is_public(path):
        if path in ("/health", "/login"):
            return True
        if path.startswith(("/auth/", "/ui/")):
            return True
        return False

    @app.middleware("http")
    async def auth_gate(request: Request, call_next):
        if _is_public(request.url.path):
            return await call_next(request)
        user = _current_user(request, cfg)
        if not user:
            if request.url.path.startswith("/api/"):
                return JSONResponse({"error": "unauthorized"}, status_code=401)
            return RedirectResponse("/login", status_code=302)
        request.state.user = user
        return await call_next(request)

    # -- static UI -------------------------------------------------------------
    if os.path.isdir(UI_DIR):
        app.mount("/ui", StaticFiles(directory=UI_DIR), name="ui")

    @app.get("/health")
    def health():
        return {"ok": True}

    @app.get("/", response_class=HTMLResponse)
    def index(request: Request):
        user = _current_user(request, cfg)
        if not user:
            return RedirectResponse("/login", status_code=302)
        return FileResponse(os.path.join(UI_DIR, "index.html"))

    @app.get("/login", response_class=HTMLResponse)
    def login_page():
        g = auth.google_cfg(cfg)
        o = auth.oidc_cfg(cfg)
        buttons = ""
        if g["enabled"]:
            buttons += '<a class="btn" href="/auth/google/login">Sign in with Google</a>'
        if o["enabled"]:
            buttons += '<a class="btn" href="/auth/oidc/login">Sign in with SSO</a>'
        if not buttons:
            if auth.local_auth_active(cfg):
                buttons = (
                    '<form method="post" action="/auth/local/login">'
                    '<input type="password" name="password" '
                    'placeholder="Local password" autocomplete="current-password" '
                    'required autofocus>'
                    '<button class="btn primary" type="submit">Sign in locally</button>'
                    '</form>'
                    '<p style="font-size:0.85rem;opacity:0.75">Local failover is active '
                    'because no OAuth/OIDC provider is configured. Set up Google '
                    'OAuth or OIDC to switch to single sign-on.</p>'
                )
            else:
                buttons = ('<p class="error">No login provider is configured. '
                           'Set OSINT_LOCAL_PASSWORD for local sign-in, or set up '
                           'Google OAuth or OIDC (see README).</p>')
        return HTMLResponse(
            "<!doctype html><html><head><meta charset='utf-8'>"
            "<meta name='viewport' content='width=device-width,initial-scale=1'>"
            "<title>Vedette - Sign in</title>"
            "<link rel='stylesheet' href='/ui/styles.css'></head>"
            "<body><main class='login'><h1>Vedette</h1>"
            "<p>Sign in with an approved account to continue.</p>"
            + buttons + "</main></body></html>"
        )

    # -- OAuth -----------------------------------------------------------------
    def _finish_login(email, name, provider, allowed):
        if not allowed:
            log.warning("login rejected for %s via %s: not on allowlist", email, provider)
            return HTMLResponse(
                "<h1>Access denied</h1><p>This account is not approved for "
                "the Vedette.</p>", status_code=403)
        token = auth.create_session(email, name)
        resp = RedirectResponse("/", status_code=302)
        resp.set_cookie(auth.SESSION_COOKIE, token,
                        max_age=_session_timeout(cfg),
                        httponly=True, samesite="lax")
        log.info("login accepted for %s via %s", email, provider)
        return resp

    @app.get("/auth/google/login")
    def google_login(request: Request):
        try:
            url = auth.google_login_url(
                cfg, _callback_base(request) + "/auth/google/callback")
        except auth.AuthError as exc:
            return HTMLResponse("<h1>Login unavailable</h1><p>%s</p>" % exc,
                                status_code=500)
        return RedirectResponse(url, status_code=302)

    @app.get("/auth/google/callback")
    def google_callback(request: Request):
        code = request.query_params.get("code")
        state = request.query_params.get("state")
        err = request.query_params.get("error")
        if err or not code:
            return HTMLResponse("<h1>Sign-in failed</h1><p>%s</p>"
                                % (err or "missing code"), status_code=400)
        try:
            auth.verify_oauth_state(state)
            email, name = auth.google_exchange_code(
                cfg, code, _callback_base(request) + "/auth/google/callback")
        except auth.AuthError as exc:
            return HTMLResponse("<h1>Sign-in failed</h1><p>%s</p>" % exc,
                                status_code=400)
        allowed = auth.is_email_allowed(email, auth.google_allowed_emails(cfg))
        return _finish_login(email, name, "google", allowed)

    @app.get("/auth/oidc/login")
    def oidc_login(request: Request):
        try:
            url = auth.oidc_login_url(
                cfg, _callback_base(request) + "/auth/oidc/callback")
        except auth.AuthError as exc:
            return HTMLResponse("<h1>Login unavailable</h1><p>%s</p>" % exc,
                                status_code=500)
        return RedirectResponse(url, status_code=302)

    @app.get("/auth/oidc/callback")
    def oidc_callback(request: Request):
        code = request.query_params.get("code")
        state = request.query_params.get("state")
        err = request.query_params.get("error")
        if err or not code:
            return HTMLResponse("<h1>Sign-in failed</h1><p>%s</p>"
                                % (err or "missing code"), status_code=400)
        try:
            auth.verify_oauth_state(state)
            email, name = auth.oidc_exchange_code(
                cfg, code, _callback_base(request) + "/auth/oidc/callback")
        except auth.AuthError as exc:
            return HTMLResponse("<h1>Sign-in failed</h1><p>%s</p>" % exc,
                                status_code=400)
        allowed = auth.is_oidc_allowed(email, auth.oidc_cfg(cfg))
        return _finish_login(email, name, "oidc", allowed)

    @app.post("/auth/local/login")
    async def local_login(request: Request):
        # Local password failover: only reachable when no OAuth/OIDC provider
        # is configured and OSINT_LOCAL_PASSWORD is set. Form body is parsed
        # manually to avoid a python-multipart dependency.
        if not auth.local_auth_active(cfg):
            return HTMLResponse("<h1>Login unavailable</h1><p>Local sign-in is "
                                "not configured.</p>", status_code=403)
        try:
            raw = (await request.body()).decode("utf-8", "replace")
        except Exception:  # noqa: BLE001 - malformed body means no password
            raw = ""
        password = ""
        for part in raw.split("&"):
            if "=" not in part:
                continue
            k, v = part.split("=", 1)
            if k == "password":
                password = unquote_plus(v)
                break
        try:
            auth.verify_local_password(password)
        except auth.AuthError:
            time.sleep(1)  # slow down password guessing
            log.warning("local login failed: incorrect password")
            return HTMLResponse(
                "<h1>Sign-in failed</h1><p>Incorrect password.</p>"
                '<p><a href="/login">Try again</a></p>', status_code=401)
        return _finish_login("local", "Local operator", "local", True)

    @app.post("/auth/logout")
    def logout():
        resp = JSONResponse({"ok": True})
        resp.delete_cookie(auth.SESSION_COOKIE)
        return resp

    # -- API -------------------------------------------------------------------
    @app.get("/api/me")
    def me(request: Request):
        user = request.state.user
        return {"email": user["email"], "name": user.get("name", "")}

    def _read_run_meta(run_dir):
        meta_path = os.path.join(run_dir, "run.json")
        if os.path.exists(meta_path):
            with open(meta_path, encoding="utf-8") as fh:
                return json.load(fh)
        return None

    @app.get("/api/runs")
    def list_runs():
        items = []
        base = _runs_dir(cfg)
        for entry in sorted(os.listdir(base), reverse=True):
            run_dir = os.path.join(base, entry)
            meta = _read_run_meta(run_dir) if os.path.isdir(run_dir) else None
            if meta:
                items.append(meta)
        with runs_lock:
            for run_id, r in runs.items():
                if not any(i["id"] == run_id for i in items):
                    items.append({"id": run_id, "org": r["org"],
                                  "status": r["status"], "created": r["created"]})
        return {"runs": items}

    @app.post("/api/runs")
    async def start_run(request: Request):
        body = await request.json()
        try:
            targets = parse_gui_targets(body)
        except ValueError as exc:
            return JSONResponse({"error": str(exc)}, status_code=400)
        try:
            orchestrator.check_scope(targets)
        except orchestrator.scope.ScopeError as exc:
            return JSONResponse({"error": str(exc)}, status_code=400)
        provider = body.get("research_provider")
        model = body.get("research_model")

        run_cfg = copy.deepcopy(cfg)
        if provider:
            if provider not in ("anthropic", "openai", "ollama"):
                return JSONResponse({"error": "unknown provider"}, status_code=400)
            run_cfg["research_backend"]["provider"] = provider
        if model:
            run_cfg["research_backend"]["model"] = model

        # Fail fast on missing API key before spawning the thread.
        try:
            orchestrator.models.select_backends(run_cfg)
        except orchestrator.models.ConfigError as exc:
            return JSONResponse({"error": str(exc)}, status_code=400)

        stamp = datetime.now(timezone.utc).strftime("%Y%m%d-%H%M%S")
        first = targets[0]
        run_id = "run-%s-%s" % (stamp, orchestrator.slugify(first["name"]))
        run_dir = os.path.join(_runs_dir(cfg), run_id)
        os.makedirs(run_dir, exist_ok=True)
        created = datetime.now(timezone.utc).isoformat()
        display = first["name"] + (" (+%d)" % (len(targets) - 1)
                                   if len(targets) > 1 else "")
        meta = {"id": run_id, "org": display, "url": first["url"],
                "status": "running", "created": created,
                "targets": [{"name": t["name"], "type": t["type"],
                             "url": t["url"]} for t in targets]}
        with open(os.path.join(run_dir, "run.json"), "w", encoding="utf-8") as fh:
            json.dump(meta, fh)

        def _progress(phase, detail, target=None):
            with runs_lock:
                if run_id in runs:
                    runs[run_id]["phase"] = phase
                    runs[run_id]["detail"] = detail
                    if target:
                        tgt = runs[run_id].setdefault("targets", {})
                        tgt[target] = {"phase": phase, "detail": detail}

        def _worker():
            target_state = {t["name"]: {"phase": "queued", "detail": ""}
                            for t in targets}
            with runs_lock:
                runs[run_id] = {"org": display, "status": "running",
                                "phase": "starting", "detail": "",
                                "created": created, "targets": target_state}
            try:
                results, _ = orchestrator.assess_many(
                    run_cfg, targets, run_dir, progress_cb=_progress)
                final = "done"
                err = ""
            except Exception as exc:  # noqa: BLE001 - surfaced to the UI
                log.exception("run %s failed", run_id)
                final = "failed"
                err = str(exc)
                results = []
            with runs_lock:
                runs[run_id]["status"] = final
                runs[run_id]["error"] = err
            meta = _read_run_meta(run_dir) or {}
            meta.update({"id": run_id, "org": display, "url": first["url"],
                         "status": final, "created": created, "error": err,
                         "orgs": [r["name"] for r in results],
                         "targets": [{"name": r["name"], "type": r["type"],
                                      "dir": os.path.basename(r["dir"])}
                                     for r in results] or meta.get("targets")})
            with open(os.path.join(run_dir, "run.json"), "w", encoding="utf-8") as fh:
                json.dump(meta, fh)

        with runs_lock:
            runs[run_id] = {"org": display, "status": "running",
                            "phase": "starting", "detail": "",
                            "created": created,
                            "targets": {t["name"]: {"phase": "queued",
                                                   "detail": ""}
                                        for t in targets}}
        threading.Thread(target=_worker, daemon=True).start()
        return {"id": run_id, "status": "running"}

    @app.get("/api/runs/{run_id}")
    def run_status(run_id: str):
        with runs_lock:
            r = runs.get(run_id)
        if r:
            return {"id": run_id, **r}
        meta = _read_run_meta(os.path.join(_runs_dir(cfg), run_id))
        if meta:
            return meta
        return JSONResponse({"error": "unknown run"}, status_code=404)

    @app.get("/api/runs/{run_id}/report")
    def run_report(run_id: str):
        run_dir = os.path.join(_runs_dir(cfg), run_id)
        meta = _read_run_meta(run_dir) or {}
        dir_to_name = {}
        for t in meta.get("targets") or []:
            if t.get("dir") and t.get("name"):
                dir_to_name[t["dir"]] = "%s (%s)" % (t["name"],
                                                     t.get("type", ""))
        # Single-target runs keep report.md at the run root; multi-target
        # runs keep per-target reports in subdirs plus comparison.md.
        reports = {}
        root_report = os.path.join(run_dir, "report.md")
        if os.path.exists(root_report):
            with open(root_report, encoding="utf-8") as fh:
                reports["report"] = fh.read()
        for entry in sorted(os.listdir(run_dir)) if os.path.isdir(run_dir) else []:
            sub = os.path.join(run_dir, entry)
            rp = os.path.join(sub, "report.md")
            if os.path.isdir(sub) and os.path.exists(rp):
                with open(rp, encoding="utf-8") as fh:
                    reports[dir_to_name.get(entry, entry)] = fh.read()
        comp = os.path.join(run_dir, "comparison.md")
        comparison = None
        if os.path.exists(comp):
            with open(comp, encoding="utf-8") as fh:
                comparison = fh.read()
        if not reports and comparison is None:
            return JSONResponse({"error": "report not ready"}, status_code=404)
        return {"reports": reports, "comparison": comparison}

    return app


def main():
    import argparse
    import uvicorn

    logging.basicConfig(level=logging.INFO,
                        format="%(asctime)s %(name)s %(levelname)s %(message)s")
    ap = argparse.ArgumentParser(description="Vedette web GUI")
    ap.add_argument("--config", default=os.path.join(PROJECT_ROOT, "config.yaml"))
    ap.add_argument("--host", default=None)
    ap.add_argument("--port", type=int, default=None)
    args = ap.parse_args()

    from .dotenv import load_dotenv
    load_dotenv()  # temp runs: .env fills secrets 1Password would provide

    cfg = orchestrator.load_config(args.config)
    log_secret_presence()
    g = auth.google_cfg(cfg)
    o = auth.oidc_cfg(cfg)
    log.info("google login: %s", "enabled" if g["enabled"] else "disabled")
    log.info("oidc login: %s", "enabled" if o["enabled"] else "disabled")
    if auth.local_auth_active(cfg):
        log.warning("local password failover is ACTIVE "
                    "(no OAuth/OIDC configured); set up SSO to disable it")
    elif not g["enabled"] and not o["enabled"]:
        log.warning("no login provider configured; sign-in will be unavailable "
                    "(set OSINT_LOCAL_PASSWORD for local failover)")
    if not auth.google_allowed_emails(cfg) and not (
            o["enabled"] and (o["allowed_emails"] or o["allowed_domains"])):
        log.warning("no auth allowlist configured; all logins will be rejected")

    server_cfg = cfg.get("server") or {}
    host = args.host or server_cfg.get("host", "127.0.0.1")
    port = args.port or server_cfg.get("port", 8790)
    app = create_app(cfg)
    uvicorn.run(app, host=host, port=port, log_level="info")


if __name__ == "__main__":
    main()
