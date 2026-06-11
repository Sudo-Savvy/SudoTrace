# SudoTrace — CLAUDE.md

AI-powered SOC analyst workbench for Microsoft Defender for Endpoint Plan 2.
Scope document `SudoTrace-Full-Scope-v7-FINAL.txt` (gitignored) — local
reference only; read it before making non-obvious decisions.

## Quick start

```bash
docker compose up --build      # first run
docker compose up -d           # subsequent runs
docker compose down            # stop (data persists)
docker compose down -v         # WARNING: destroys all data
```

Visit https://localhost — accept the self-signed cert warning.
Default login: root / root — force password change on first login.

## Project structure

```
backend/        Python + FastAPI
  app/
    main.py     FastAPI app, lifespan, routers
    database.py SQLite init, get_db()
    security.py bcrypt, sessions, lockout logic
    models.py   Pydantic request models
    routers/
      health.py GET /api/health
      auth.py   login, logout, me, change-password
  Dockerfile    Multi-stage, python:3.12-slim-bookworm
  requirements.in  Direct dependencies (pip-tools source)

frontend/       React + TypeScript + Vite
  src/
    App.tsx     Auth state machine + routing
    api/auth.ts Fetch-based API client
    pages/      LoginPage, ChangePasswordPage, HomePage
    types/      TypeScript interfaces
  nginx.conf    HTTPS on 443, proxies /api/ to backend
  Dockerfile    Multi-stage, node:20-slim + nginx:1.27-alpine
```

## Key engineering rules

- **API**: Microsoft Graph Security API only for all MDE queries.
  Use `POST graph.microsoft.com/v1.0/security/runHuntingQuery` for all KQL.
- **AI models**: claude-haiku-4-5-20251001 is the default for ALL Claude calls,
  analyst-facing and background. Cost-driven decision — a deliberate departure
  from the original scope doc, which specified Sonnet for analyst-facing work.
  Override per-deployment via the `CLAUDE_ANALYSIS_MODEL` env var if a feature
  ever genuinely needs the stronger model.
- **Docker**: 127.0.0.1 binding only — never 0.0.0.0 on exposed ports.
- **Credentials**: UI text boxes only — no .env files, no config files.
- **Errors**: Plain English to analyst, full detail in audit log only.
- **Token tracking**: Every Claude API call logged to token_usage table from v0.6.

## Development notes

- Backend venv: `source backend/venv/bin/activate`
- Backend deps: edit `requirements.in`, run `pip-compile` then `pip install -r requirements.txt`
- Frontend deps: `cd frontend && npm install <package>`
- SQLite lives in Docker volume `sudotrace_data` — survives `docker compose down`
- TLS cert lives in Docker volume `sudotrace_certs` — auto-generated on first start
