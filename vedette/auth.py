"""Authentication for the Vedette web GUI.

- Google OAuth (authorization code flow), restricted to an allowlist of
  approved Google account emails.
- Generic OIDC SSO provider as an alternative, restricted to an email
  allowlist and/or allowed email domains.
- Local password login: when OSINT_LOCAL_PASSWORD is set, the login page
  offers a password form. Failover by default: only when no OAuth/OIDC
  provider is configured. With auth.local.allow_with_provider: true in
  config.yaml it is also offered alongside a configured provider, so other
  testers can sign in with the shared password. Never active without a
  password (fail closed).
- Sessions are signed cookies (itsdangerous) with a configurable timeout.
- No anonymous access: every route that triggers research or reads past
  assessments requires a valid session.
- Secrets (OAuth client secrets, session secret, local password) come from
  env vars only and are never logged or written anywhere.
"""

from __future__ import annotations

import hmac
import os
import secrets as pysecrets
import time
from urllib.parse import urlencode

import requests
from itsdangerous import URLSafeTimedSerializer, BadSignature, SignatureExpired

GOOGLE_AUTH_URL = "https://accounts.google.com/o/oauth2/v2/auth"
GOOGLE_TOKEN_URL = "https://oauth2.googleapis.com/token"
GOOGLE_USERINFO_URL = "https://openidconnect.googleapis.com/v1/userinfo"

SESSION_COOKIE = "vedette_session"
SESSION_SALT = "vedette-session"
STATE_SALT = "vedette-oauth-state"


class AuthError(Exception):
    """Authentication/authorization failure (message is safe to show)."""


def _env(name, default=None):
    return os.environ.get(name, default)


def _email_list(value):
    """Normalize a comma-separated string or list into a set of lowercase emails."""
    if not value:
        return set()
    if isinstance(value, str):
        value = value.split(",")
    return {str(e).strip().lower() for e in value if str(e).strip()}


def _domain_list(value):
    if not value:
        return set()
    if isinstance(value, str):
        value = value.split(",")
    return {str(d).strip().lower().lstrip("@") for d in value if str(d).strip()}


def _require_env(name):
    value = os.environ.get(name)
    if not value:
        raise AuthError(
            "Server misconfigured: environment variable %s is not set." % name
        )
    return value


# ---------------------------------------------------------------------------
# Config readers
# ---------------------------------------------------------------------------

def auth_cfg(cfg):
    return (cfg.get("auth") or {})


def google_cfg(cfg):
    g = auth_cfg(cfg).get("google") or {}
    return {
        "client_id": _env("OSINT_GOOGLE_CLIENT_ID") or g.get("client_id"),
        "client_secret_env": g.get("client_secret_env") or "OSINT_GOOGLE_CLIENT_SECRET",
        "enabled": bool(_env("OSINT_GOOGLE_CLIENT_ID") or g.get("client_id")),
    }


def google_allowed_emails(cfg):
    """Allowlist for Google login. Env var overrides the config file list."""
    env = os.environ.get("OSINT_ALLOWED_GOOGLE_EMAILS")
    if env is not None:
        return _email_list(env)
    return _email_list(auth_cfg(cfg).get("allowed_google_emails"))


def oidc_cfg(cfg):
    o = auth_cfg(cfg).get("oidc") or {}
    allowed_emails = os.environ.get("OSINT_ALLOWED_EMAILS")
    allowed_domains = os.environ.get("OSINT_ALLOWED_DOMAINS")
    return {
        "enabled": bool(o.get("enabled")),
        "issuer": (o.get("issuer") or "").rstrip("/"),
        "client_id": _env("OSINT_OIDC_CLIENT_ID") or o.get("client_id"),
        "client_secret_env": o.get("client_secret_env") or "OSINT_OIDC_CLIENT_SECRET",
        "allowed_emails": _email_list(allowed_emails) if allowed_emails is not None
                          else _email_list(o.get("allowed_emails")),
        "allowed_domains": _domain_list(allowed_domains) if allowed_domains is not None
                           else _domain_list(o.get("allowed_domains")),
    }


def session_timeout_seconds(cfg):
    minutes = auth_cfg(cfg).get("session_timeout_minutes", 720)
    try:
        minutes = int(minutes)
    except (TypeError, ValueError):
        minutes = 720
    return max(60, minutes * 60)


# ---------------------------------------------------------------------------
# Local password login
# ---------------------------------------------------------------------------
# Offered on the login page when a local password is set. Failover by
# default (only when no OAuth/OIDC provider is configured); with
# auth.local.allow_with_provider: true it is also offered alongside a
# configured provider so other testers can sign in with the shared
# password. Never active without a password (fail closed).

def local_cfg(cfg):
    l = auth_cfg(cfg).get("local") or {}
    return {
        "enabled": bool(l.get("enabled", True)),
        "password_env": l.get("password_env") or "OSINT_LOCAL_PASSWORD",
        "allow_with_provider": bool(l.get("allow_with_provider", False)),
    }


def local_auth_active(cfg):
    """True when local password login should be offered.

    Failover by default: not offered alongside a configured OAuth/OIDC
    provider unless auth.local.allow_with_provider is true. Never active
    without a password set (fail closed).
    """
    l = local_cfg(cfg)
    if not l["enabled"]:
        return False
    if not _env(l["password_env"]):
        return False
    if google_cfg(cfg)["enabled"] or oidc_cfg(cfg)["enabled"]:
        return l["allow_with_provider"]
    return True


def verify_local_password(provided, password_env="OSINT_LOCAL_PASSWORD"):
    """Constant-time password check. Raises AuthError on mismatch/misconfig.

    The password value itself is never logged; only pass/fail is recorded.
    """
    expected = _env(password_env)
    if not expected:
        raise AuthError("Local login is not configured.")
    if not hmac.compare_digest(str(provided or ""), expected):
        raise AuthError("Incorrect password.")
    return True


# ---------------------------------------------------------------------------
# Allowlist checks (pure logic -- unit tested)
# ---------------------------------------------------------------------------

def is_email_allowed(email, allowed_emails):
    """Exact email allowlist check (case-insensitive)."""
    if not email or not allowed_emails:
        return False
    return email.strip().lower() in allowed_emails


def is_oidc_allowed(email, o_cfg):
    """OIDC access: allowed if the email is allowlisted OR its domain is."""
    email = (email or "").strip().lower()
    if not email or "@" not in email:
        return False
    if email in o_cfg.get("allowed_emails", set()):
        return True
    domain = email.rsplit("@", 1)[1]
    return domain in o_cfg.get("allowed_domains", set())


# ---------------------------------------------------------------------------
# Signed cookie sessions
# ---------------------------------------------------------------------------

def _session_serializer():
    secret = _require_env("OSINT_SESSION_SECRET")
    return URLSafeTimedSerializer(secret, salt=SESSION_SALT)


def _state_serializer():
    secret = _require_env("OSINT_SESSION_SECRET")
    return URLSafeTimedSerializer(secret, salt=STATE_SALT)


def create_session(email, name=""):
    """Mint a signed session cookie value for an authenticated email."""
    return _session_serializer().dumps(
        {"email": email, "name": name or "", "iat": int(time.time())}
    )


def verify_session(token, max_age_seconds):
    """Return the session payload dict, or None if invalid/expired."""
    if not token:
        return None
    try:
        data = _session_serializer().loads(token, max_age=max_age_seconds)
    except (BadSignature, SignatureExpired):
        return None
    if not isinstance(data, dict) or not data.get("email"):
        return None
    return data


def mint_oauth_state(provider):
    return _state_serializer().dumps(
        {"provider": provider, "nonce": pysecrets.token_urlsafe(16),
         "ts": int(time.time())}
    )


def verify_oauth_state(state, max_age_seconds=600):
    try:
        data = _state_serializer().loads(state, max_age=max_age_seconds)
    except (BadSignature, SignatureExpired):
        raise AuthError("Invalid or expired OAuth state (possible CSRF).")
    return data


# ---------------------------------------------------------------------------
# Google OAuth
# ---------------------------------------------------------------------------

def google_login_url(cfg, redirect_uri):
    g = google_cfg(cfg)
    if not g["enabled"]:
        raise AuthError("Google login is not configured.")
    state = mint_oauth_state("google")
    params = {
        "client_id": g["client_id"],
        "redirect_uri": redirect_uri,
        "response_type": "code",
        "scope": "openid email profile",
        "state": state,
        "access_type": "online",
        "prompt": "select_account",
    }
    return GOOGLE_AUTH_URL + "?" + urlencode(params)


def google_exchange_code(cfg, code, redirect_uri):
    """Exchange the auth code for the user's email/name. Raises AuthError."""
    g = google_cfg(cfg)
    client_secret = _require_env(g["client_secret_env"])
    try:
        tok = requests.post(
            GOOGLE_TOKEN_URL,
            data={
                "code": code,
                "client_id": g["client_id"],
                "client_secret": client_secret,
                "redirect_uri": redirect_uri,
                "grant_type": "authorization_code",
            },
            timeout=30,
        )
        tok.raise_for_status()
        access_token = tok.json().get("access_token")
        if not access_token:
            raise AuthError("Google token exchange failed.")
        ui = requests.get(
            GOOGLE_USERINFO_URL,
            headers={"Authorization": "Bearer " + access_token},
            timeout=30,
        )
        ui.raise_for_status()
        info = ui.json()
    except requests.RequestException as exc:
        raise AuthError("Google sign-in failed: %s" % exc)
    email = info.get("email") or ""
    if not email:
        raise AuthError("Google did not return an email address.")
    return email, info.get("name") or ""


# ---------------------------------------------------------------------------
# Generic OIDC
# ---------------------------------------------------------------------------

_discovery_cache = {}


def oidc_discovery(issuer):
    """Fetch (and cache) the provider's .well-known configuration."""
    if issuer not in _discovery_cache:
        try:
            resp = requests.get(
                issuer + "/.well-known/openid-configuration", timeout=30
            )
            resp.raise_for_status()
            _discovery_cache[issuer] = resp.json()
        except requests.RequestException as exc:
            raise AuthError("OIDC discovery failed for %s: %s" % (issuer, exc))
    return _discovery_cache[issuer]


def oidc_login_url(cfg, redirect_uri):
    o = oidc_cfg(cfg)
    if not (o["enabled"] and o["issuer"] and o["client_id"]):
        raise AuthError("OIDC login is not configured.")
    disc = oidc_discovery(o["issuer"])
    auth_endpoint = disc.get("authorization_endpoint")
    if not auth_endpoint:
        raise AuthError("OIDC provider has no authorization_endpoint.")
    state = mint_oauth_state("oidc")
    params = {
        "client_id": o["client_id"],
        "redirect_uri": redirect_uri,
        "response_type": "code",
        "scope": "openid email profile",
        "state": state,
    }
    return auth_endpoint + "?" + urlencode(params)


def oidc_exchange_code(cfg, code, redirect_uri):
    """Exchange the auth code; return (email, name). Raises AuthError."""
    o = oidc_cfg(cfg)
    client_secret = _require_env(o["client_secret_env"])
    disc = oidc_discovery(o["issuer"])
    token_endpoint = disc.get("token_endpoint")
    userinfo_endpoint = disc.get("userinfo_endpoint")
    if not token_endpoint:
        raise AuthError("OIDC provider has no token_endpoint.")
    try:
        tok = requests.post(
            token_endpoint,
            data={
                "code": code,
                "client_id": o["client_id"],
                "client_secret": client_secret,
                "redirect_uri": redirect_uri,
                "grant_type": "authorization_code",
            },
            timeout=30,
        )
        tok.raise_for_status()
        access_token = tok.json().get("access_token")
        if not access_token:
            raise AuthError("OIDC token exchange failed.")
        if userinfo_endpoint:
            ui = requests.get(
                userinfo_endpoint,
                headers={"Authorization": "Bearer " + access_token},
                timeout=30,
            )
            ui.raise_for_status()
            info = ui.json()
        else:
            info = {}
    except requests.RequestException as exc:
        raise AuthError("OIDC sign-in failed: %s" % exc)
    email = info.get("email") or ""
    if not email:
        raise AuthError("OIDC provider did not return an email address.")
    return email, info.get("name") or ""
