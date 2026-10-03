"""Tests for auth: allowlist logic, OIDC domain checks, signed sessions.

OAuth HTTP exchanges are not exercised here (no network); only the
allowlist/session logic the server depends on for access control.
"""

import pytest

from vedette import auth


# ---------------------------------------------------------------------------
# Email allowlist
# ---------------------------------------------------------------------------

def test_is_email_allowed_exact_case_insensitive():
    allowed = {"alice@example.com"}
    assert auth.is_email_allowed("Alice@Example.COM", allowed)
    assert auth.is_email_allowed("alice@example.com", allowed)


def test_is_email_allowed_rejects_unknown():
    assert not auth.is_email_allowed("mallory@evil.com", {"alice@example.com"})


def test_is_email_allowed_empty_list_rejects_all():
    assert not auth.is_email_allowed("alice@example.com", set())
    assert not auth.is_email_allowed("", {"alice@example.com"})
    assert not auth.is_email_allowed(None, {"alice@example.com"})


def test_google_allowed_emails_env_overrides_config(monkeypatch):
    cfg = {"auth": {"allowed_google_emails": ["config@example.com"]}}
    monkeypatch.setenv("OSINT_ALLOWED_GOOGLE_EMAILS",
                       "env1@example.com, Env2@Example.com ")
    allowed = auth.google_allowed_emails(cfg)
    assert allowed == {"env1@example.com", "env2@example.com"}


def test_google_allowed_emails_from_config():
    cfg = {"auth": {"allowed_google_emails": ["A@x.com", "b@x.com"]}}
    assert auth.google_allowed_emails(cfg) == {"a@x.com", "b@x.com"}


# ---------------------------------------------------------------------------
# OIDC allowlist: email list OR domain list
# ---------------------------------------------------------------------------

def _oidc(allowed_emails=None, allowed_domains=None):
    return {
        "allowed_emails": {e.lower() for e in (allowed_emails or [])},
        "allowed_domains": {d.lower().lstrip("@") for d in (allowed_domains or [])},
    }


def test_oidc_allowed_by_email():
    assert auth.is_oidc_allowed("Alice@Example.com", _oidc(["alice@example.com"]))


def test_oidc_allowed_by_domain():
    assert auth.is_oidc_allowed("anyone@example.com", _oidc(allowed_domains=["example.com"]))


def test_oidc_rejects_unlisted():
    assert not auth.is_oidc_allowed("mallory@evil.com",
                                    _oidc(["alice@example.com"], ["example.com"]))


def test_oidc_rejects_malformed():
    assert not auth.is_oidc_allowed("not-an-email", _oidc(allowed_domains=["x.com"]))
    assert not auth.is_oidc_allowed("", _oidc(allowed_domains=["x.com"]))
    assert not auth.is_oidc_allowed(None, _oidc(allowed_domains=["x.com"]))


def test_oidc_subdomain_not_implicitly_allowed():
    # sub.example.com is NOT example.com; domains must be listed explicitly
    assert not auth.is_oidc_allowed("u@sub.example.com",
                                    _oidc(allowed_domains=["example.com"]))


# ---------------------------------------------------------------------------
# Signed cookie sessions
# ---------------------------------------------------------------------------

def test_session_roundtrip(monkeypatch):
    monkeypatch.setenv("OSINT_SESSION_SECRET", "test-secret")
    token = auth.create_session("alice@example.com", "Alice")
    data = auth.verify_session(token, 3600)
    assert data["email"] == "alice@example.com"
    assert data["name"] == "Alice"


def test_session_tampered_rejected(monkeypatch):
    monkeypatch.setenv("OSINT_SESSION_SECRET", "test-secret")
    token = auth.create_session("alice@example.com")
    assert auth.verify_session(token + "tampered", 3600) is None


def test_session_wrong_secret_rejected(monkeypatch):
    monkeypatch.setenv("OSINT_SESSION_SECRET", "secret-one")
    token = auth.create_session("alice@example.com")
    monkeypatch.setenv("OSINT_SESSION_SECRET", "secret-two")
    assert auth.verify_session(token, 3600) is None


def test_session_expired_rejected(monkeypatch):
    monkeypatch.setenv("OSINT_SESSION_SECRET", "test-secret")
    token = auth.create_session("alice@example.com")
    assert auth.verify_session(token, -1) is None


def test_session_missing_rejected(monkeypatch):
    monkeypatch.setenv("OSINT_SESSION_SECRET", "test-secret")
    assert auth.verify_session("", 3600) is None
    assert auth.verify_session(None, 3600) is None


def test_session_requires_secret_env(monkeypatch):
    monkeypatch.delenv("OSINT_SESSION_SECRET", raising=False)
    with pytest.raises(auth.AuthError):
        auth.create_session("alice@example.com")


# ---------------------------------------------------------------------------
# OAuth state tokens
# ---------------------------------------------------------------------------

def test_oauth_state_roundtrip(monkeypatch):
    monkeypatch.setenv("OSINT_SESSION_SECRET", "test-secret")
    state = auth.mint_oauth_state("google")
    data = auth.verify_oauth_state(state)
    assert data["provider"] == "google"


def test_oauth_state_tampered_rejected(monkeypatch):
    monkeypatch.setenv("OSINT_SESSION_SECRET", "test-secret")
    with pytest.raises(auth.AuthError):
        auth.verify_oauth_state("bogus-state")


# ---------------------------------------------------------------------------
# Local password failover
# ---------------------------------------------------------------------------

def _bare_cfg():
    # No google client id, OIDC disabled: no provider configured.
    return {"auth": {"google": {"client_id": None},
                     "oidc": {"enabled": False},
                     "local": {"enabled": True}}}


def test_local_active_when_no_provider_and_password_set(monkeypatch):
    monkeypatch.setenv("OSINT_LOCAL_PASSWORD", "s3cret")
    monkeypatch.delenv("OSINT_GOOGLE_CLIENT_ID", raising=False)
    assert auth.local_auth_active(_bare_cfg())


def test_local_inactive_without_password(monkeypatch):
    monkeypatch.delenv("OSINT_LOCAL_PASSWORD", raising=False)
    monkeypatch.delenv("OSINT_GOOGLE_CLIENT_ID", raising=False)
    assert not auth.local_auth_active(_bare_cfg())


def test_local_inactive_when_google_configured(monkeypatch):
    # Failover only: never offered alongside a configured provider.
    monkeypatch.setenv("OSINT_LOCAL_PASSWORD", "s3cret")
    monkeypatch.setenv("OSINT_GOOGLE_CLIENT_ID", "some-client-id")
    assert not auth.local_auth_active(_bare_cfg())


def test_local_inactive_when_oidc_enabled(monkeypatch):
    monkeypatch.setenv("OSINT_LOCAL_PASSWORD", "s3cret")
    monkeypatch.delenv("OSINT_GOOGLE_CLIENT_ID", raising=False)
    cfg = _bare_cfg()
    cfg["auth"]["oidc"] = {"enabled": True, "issuer": "https://x.example.com",
                           "client_id": "id"}
    assert not auth.local_auth_active(cfg)


def test_local_inactive_when_disabled_in_config(monkeypatch):
    monkeypatch.setenv("OSINT_LOCAL_PASSWORD", "s3cret")
    monkeypatch.delenv("OSINT_GOOGLE_CLIENT_ID", raising=False)
    cfg = _bare_cfg()
    cfg["auth"]["local"] = {"enabled": False}
    assert not auth.local_auth_active(cfg)


def test_verify_local_password_accepts_correct(monkeypatch):
    monkeypatch.setenv("OSINT_LOCAL_PASSWORD", "s3cret")
    assert auth.verify_local_password("s3cret") is True


def test_verify_local_password_rejects_wrong(monkeypatch):
    monkeypatch.setenv("OSINT_LOCAL_PASSWORD", "s3cret")
    with pytest.raises(auth.AuthError):
        auth.verify_local_password("wrong")
    with pytest.raises(auth.AuthError):
        auth.verify_local_password("")
    with pytest.raises(auth.AuthError):
        auth.verify_local_password(None)


def test_verify_local_password_rejects_when_unset(monkeypatch):
    monkeypatch.delenv("OSINT_LOCAL_PASSWORD", raising=False)
    with pytest.raises(auth.AuthError):
        auth.verify_local_password("anything")
