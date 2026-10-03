# Vedette

Standalone agent: give it targets -- companies, software, domains -- and it
runs a structured OSINT security playbook, then produces source-linked
assessment briefs (and a ranked comparison when given multiple targets).

Pipeline per target: **triage** (resolve target identity) -> **research**
(type-specific security axes) -> **synthesis** (brief) -> **report.md** with a
source register. Before each research leg, the agent's **built-in web search**
runs targeted queries (keyless DuckDuckGo by default; Serper/Bing optional),
so name-search works with every model backend, including local Ollama. A web
GUI mirrors the CLI: multi-target form, per-target live progress, rendered
briefs, run history -- behind Google OAuth (email allowlist) or OIDC SSO. No
anonymous access.

## Target types and research axes

| Type | Axes |
|---|---|
| `company` | jurisdiction/legal exposure & state access; contractual data protections; compliance/assurance; incident/breach history; security-posture signals |
| `software` | supply chain/provenance (repo, maintainers, signing, SBOM); vulnerability history (CVEs, advisories); update cadence & support; data handling/telemetry & licensing; assurance (audits, bug bounty) |
| `domain` | WHOIS/registration; DNS/hosting & jurisdiction; TLS posture; incident/phishing history; related infrastructure |

All axes are OSINT + security focused. Non-security requests (e.g. using the
tool as a general Q&A or trivia engine) are refused with a short message.

Every research prompt demands source URLs with dates and requires `NOT FOUND`
for anything unverifiable -- no guessing.

## Setup

```bash
cd ~/Vedette
pip install -r requirements.txt
```

## Secrets: 1Password flow

All secrets live in 1Password. Nothing secret is committed, defaulted, or
logged -- the app reads everything from the environment, and on startup it logs
only secret *names* plus whether each is set.

`.env.template` lists every variable. Two ways to inject:

```bash
# Option A: op run resolves 1Password references from the template
op run --env-file=.env.template -- python run_assessment.py --org GreenNode --url https://greennode.ai

# Option B: op inject renders a concrete .env (keep it out of git), then source it
op inject -i .env.template -o .env
set -a && source .env && set +a
python -m vedette.server
```

### Env var -> 1Password field mapping

| Env var | 1Password field | Used for |
|---|---|---|
| `OPENAI_API_KEY` | API credential: OpenAI API key | research backend (`openai` provider) |
| `ANTHROPIC_API_KEY` | API credential: Anthropic API key | research backend (`anthropic` provider) |
| `OSINT_GOOGLE_CLIENT_ID` | (not secret) OAuth client ID | Google sign-in |
| `OSINT_GOOGLE_CLIENT_SECRET` | API credential: Google OAuth client secret | Google sign-in |
| `OSINT_OIDC_CLIENT_ID` | (not secret) OIDC client ID | SSO sign-in |
| `OSINT_OIDC_CLIENT_SECRET` | API credential: OIDC client secret | SSO sign-in |
| `OSINT_SESSION_SECRET` | Password: random 32+ chars | signed session cookies |
| `OSINT_ALLOWED_GOOGLE_EMAILS` | Text: comma-separated emails | Google login allowlist (overrides config) |
| `SERPER_API_KEY` | API credential: Serper API key | built-in web search (`serper` provider; optional) |
| `BING_API_KEY` | API credential: Bing API key | built-in web search (`bing` provider; optional) |
| `OSINT_ALLOWED_EMAILS` | Text: comma-separated emails | OIDC email allowlist (overrides config) |
| `OSINT_ALLOWED_DOMAINS` | Text: comma-separated domains | OIDC domain allowlist (overrides config) |
| `OSINT_LOCAL_PASSWORD` | Password: GUI sign-in | local password failover (see below) |

Ollama (local synthesis backend) needs no key.

## Google Cloud console setup (OAuth client)

1. Go to Google Cloud console -> APIs & Services -> Credentials.
2. Create Credentials -> OAuth client ID -> application type **Web application**.
3. Under **Authorized redirect URIs**, add:
   - `http://127.0.0.1:8790/auth/google/callback` (local dev; use your port)
   - `https://<your-host>/auth/google/callback` (production)
4. Copy the **Client ID** -> `OSINT_GOOGLE_CLIENT_ID` in 1Password.
5. Copy the **Client secret** -> `OSINT_GOOGLE_CLIENT_SECRET` in 1Password.
6. Put your email in `allowed_google_emails` (config.yaml) or
   `OSINT_ALLOWED_GOOGLE_EMAILS`. Anyone not on the list is rejected at login.

For OIDC instead, set `auth.oidc.enabled: true` with the issuer, client ID,
and `OSINT_OIDC_CLIENT_SECRET`, plus `allowed_emails` and/or
`allowed_domains`.

### Local password failover

When no OAuth/OIDC provider is configured, the GUI is still usable: set
`OSINT_LOCAL_PASSWORD` and the login page offers a password form instead of
an error. The failover is strictly a fallback -- it is never offered
alongside a configured provider, and without the password set the login page
stays fail-closed. Passwords are compared in constant time, failed attempts
are delayed, and setting up Google OAuth or OIDC later automatically
disables the failover.

## CLI usage

```bash
# Multiple companies in one run (ranked comparison included)
python run_assessment.py --target GreenNode --target "FPT Smart Cloud"

# Software targets: supply-chain, CVE, and maintenance axes
python run_assessment.py --target "nginx|software" --target "openssl|software"

# Domain targets
python run_assessment.py --target "example.com|domain"

# Target spec forms: "Name", "Name=https://url", "Name|software",
# "Name=https://url|domain". Bare URLs auto-detect as domains.
# --type sets the default type for all targets.

# Back-compat: --org/--url and --compare still work
python run_assessment.py --org GreenNode --url https://greennode.ai \
  --compare "CoreWeave=https://coreweave.com,Nebius=https://nebius.com"

# Pick the research backend / model
python run_assessment.py --target "Example Corp" --backend openai --model gpt-5

# Research fully local (no hosted key needed; built-in search still runs)
python run_assessment.py --target "Example Corp" --backend ollama
```

Output: `runs/<target-slug>/report.md` + `audit.jsonl` per target; multiple
targets add `runs/comparison.md`. The audit trail records backend, model,
token counts, and web-search queries/URLs -- never key values.

## Web search providers

Research legs call the agent's built-in search tool directly (works with
every backend, including local Ollama). Config in `config.yaml`:

```yaml
tool_search: true
search:
  provider: auto        # auto | duckduckgo | serper | bing
  max_results: 6
  rate_limit_s: 1.0
```

| Provider | Key | Notes |
|---|---|---|
| `duckduckgo` | none | default; polite UA + rate limit |
| `serper` | `SERPER_API_KEY` | Google results, higher quality |
| `bing` | `BING_API_KEY` | Bing Web Search API |

`auto` picks Serper if `SERPER_API_KEY` is set, else Bing if `BING_API_KEY`
is set, else DuckDuckGo. Keys are env-only (1Password pattern above);
search failures are audited and never kill a run.

## Web GUI

```bash
op run --env-file=.env.template -- python -m vedette.server
# -> http://127.0.0.1:8790  (sign in with an allowlisted account)
```

### Temp run without 1Password

Both the GUI and CLI load a plain `.env` file from the project root when
one exists (real environment variables always win, so `op run` is
unaffected). For a quick local run without 1Password:

```bash
cp .env.template .env   # then replace the op:// references with real values
python -m vedette.server
```

`.env` is gitignored -- never commit it. The minimum for the GUI with local
password failover is `OSINT_SESSION_SECRET` and `OSINT_LOCAL_PASSWORD`.

Flags: `--config`, `--host`, `--port`. The GUI mirrors the CLI: new-assessment
form (targets textarea, one per line; default type picker; backend/model pick),
per-target live progress bars, rendered source-linked briefs per target plus a
comparison tab, run history. Sessions are signed cookies with a
configurable timeout (`auth.session_timeout_minutes`); `/auth/logout` ends them.

## What needs a real key vs what runs without one

| Task | Needs |
|---|---|
| Research legs (`anthropic` provider) | `ANTHROPIC_API_KEY` |
| Research legs (`openai` provider) | `OPENAI_API_KEY` |
| Research legs (`ollama` provider) | nothing (local Ollama running; built-in web search still runs) |
| Triage + synthesis (default: local Ollama) | nothing |
| Web search on research legs | built-in tool: keyless DuckDuckGo by default; `SERPER_API_KEY`/`BING_API_KEY` optional upgrades. Hosted backends can *also* use their own server-side search (`web_search: true`) |
| GUI sign-in | `OSINT_SESSION_SECRET` always; OAuth/OIDC secrets per provider |
| Prompts, config parsing, report rendering, auth allowlist | nothing -- covered by the test suite with mocks |

Without any hosted key you can still run the full pipeline on `--backend ollama`
(research quality depends on the local model; no web search).

## Data boundary

Hosted backends receive only the research task content (org identity + axis
questions). The audit trail records backend kind, model id, task name, and
token counts -- never key values, never prompts beyond the task.

## Tests

```bash
python -m pytest tests/ -q
```

## License

MIT — see LICENSE.
