# AGENTS.md

Guidance for OpenCode sessions working in this repo.

## Commands

```bash
# Install (editable). Use the [dev] extra for tests -- README only shows
# `pip install -e .`, which leaves pytest/httpx missing so tests fail.
pip install -e ".[dev]"

# Dev server (entry point is the `app` object in app.py)
uvicorn app:app --reload   # or: python app.py

# Tests (pytest; testpaths=".", files match test_*.py at repo root)
pytest
pytest test_oidc.py                    # one file
pytest test_oidc.py::test_token_pkce   # one test
```

There is **no lint / typecheck / formatter / CI** configured (no ruff, mypy, black, tox, pre-commit, `.github`). Do not invent those steps -- verification is `pytest` only.

## Architecture

Flat single-package layout: `pyproject.toml` sets `packages = []`, so modules are top-level files imported by bare name (`from config import settings`). There is no `src/` and no package directory.

- `app.py` -- FastAPI entry point (`app:app`). `lifespan` runs `init_db()` then `seed_admin()` on startup. `SessionMiddleware` (signed-cookie sessions) + security-headers middleware; defines `/health` and `/` (redirects to admin based on session). Includes `oidc_router` and `admin_router`.
- `oidc.py` -- `APIRouter` with the 4 OIDC endpoints (`/.well-known/openid-configuration`, `/authorize` GET+POST, `/token`, `/userinfo`), PKCE S256, JWT id_token. All protocol logic lives here.
- `admin.py` -- `APIRouter(prefix="/admin")` with the admin backend: login/logout, user list, create/edit/delete users, reset password, change own password. Auth via `SessionMiddleware` (cookie session `{uid, username, is_admin, csrf_token}`). CSRF token stored in session, validated on all POSTs. Lock-out guards: cannot delete/demote self, cannot remove last admin. Password change/reset revokes the user's access tokens. Audit table written on every mutating action.
- `db.py` -- SQLite persistence, raw SQL, **per-call connections** (`get_conn()` opens and closes a connection each call; no pooling, no async, no shared session). Tables: `users`, `codes`, `access_tokens`, `audit`. `consume_code` is one-shot (select then delete). WAL mode, `foreign_keys=ON`.
- `auth.py` -- bcrypt via passlib, `seed_admin()`, `user_to_claims()`.
- `config.py` -- pydantic-settings singleton (`settings`), env prefix `SSO_`, reads `.env`.
- `templates/` -- Jinja2 forms: `login.html` (OIDC authorize), `login_admin.html` (admin login), `admin_index.html` (user management), `account.html` (change password). All use inline CSS, `.card` centered layout.

## Token model (non-obvious)

The `access_token` is an **opaque random string stored in the DB** -- it is not a JWT. `/userinfo` validates it by DB lookup. Only the `id_token` is a JWT (HS256, signed with `settings.jwt_secret`). Do not try to JWT-decode the access token. (`refresh_token` is returned but never stored or validated -- there is no refresh endpoint.)

## Session model (admin backend)

The admin backend uses Starlette `SessionMiddleware` (signed cookies), **independent of OIDC**. The session stores `{uid, username, is_admin, csrf_token}` with `max_age=28800` (8h). Login writes the session after `session.clear()` (session-fixation protection). All admin POSTs validate a CSRF token stored in the session. Password change or reset calls `delete_tokens_by_user` to revoke the user's existing access tokens. The `audit` table records every mutating action (create_user, reset_password, edit_user, delete_user, change_password) -- write-only, no read API.

## Config & env

All config is `SSO_`-prefixed env vars (see `.env.example`). `settings` is a module-level singleton loaded at import time. Copy `.env.example` to `.env` before running. Production must override `SSO_JWT_SECRET` and `SSO_SESSION_SECRET` (both default `change-me`). `SSO_SESSION_MAX_AGE` defaults to `28800` (8h). Default seed admin: `admin` / `admin123`. `itsdangerous` is required (SessionMiddleware dependency).

## Testing conventions

- Tests are co-located at repo root: `test_app.py`, `test_auth.py`, `test_db.py`, `test_oidc.py`, `test_admin.py`.
- **DB isolation pattern**: tests redirect the DB to `tmp_path` by patching the singleton -- `monkeypatch.setattr(settings, "db_path", str(tmp_path / "test.db"))`. Never construct a new `Settings`; always patch `settings.db_path` on the existing singleton. `test_admin.py` also patches `settings.session_secret`.
- The `client` fixture wraps `TestClient(app)`, which triggers lifespan -> `init_db()` + `seed_admin()`, so the seed admin already exists in integration tests. (`test_oidc.py` calls both manually before building the client; `test_app.py` relies on the lifespan.)
- **CSRF in admin tests**: `test_admin.py` extracts `csrf_token` from GET response HTML (regex), passes it as a form field on POSTs. `follow_redirects=False` is used to assert 303 + Location header.

## Docker

`docker-compose.yml` mounts `./data` to `/app/data` and forces `SSO_DB_PATH=/app/data/sso.db` to persist the SQLite DB outside the container. `.dockerignore` excludes `test_*.py`, `*.md`, `.env`, and `data/` from the image.

## Reference

`OIDC_AUTH_SERVICE_SPEC.md` (289 lines) is the authoritative Outline-integration contract -- consult it for required OIDC endpoints, scopes, and claims when changing protocol behavior.
