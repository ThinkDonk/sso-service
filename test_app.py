import base64
import hashlib
import secrets
from urllib.parse import parse_qs, urlparse

import jwt
import pytest
from fastapi.testclient import TestClient

from config import settings
from app import app


def _make_pkce():
    verifier = secrets.token_urlsafe(48)
    challenge = base64.urlsafe_b64encode(hashlib.sha256(verifier.encode()).digest()).rstrip(b"=").decode()
    return verifier, challenge


@pytest.fixture
def client(tmp_path, monkeypatch):
    db_path = tmp_path / "test.db"
    monkeypatch.setattr(settings, "db_path", str(db_path))
    with TestClient(app) as c:
        yield c


def _full_authorize(client, code_challenge=None, code_challenge_method=None):
    data = {
        "client_id": settings.client_id,
        "redirect_uri": settings.redirect_uri_list[0],
        "state": "integration-state-xyz",
        "scope": "openid profile email",
        "username": settings.seed_username,
        "password": settings.seed_password,
    }
    if code_challenge:
        data["code_challenge"] = code_challenge
        data["code_challenge_method"] = code_challenge_method
    return client.post("/authorize", data=data, follow_redirects=False)


def _extract_code(location):
    q = parse_qs(urlparse(location).query)
    return q["code"][0]


def _exchange_token(client, code, code_verifier=None):
    data = {
        "grant_type": "authorization_code",
        "code": code,
        "redirect_uri": settings.redirect_uri_list[0],
        "client_id": settings.client_id,
        "client_secret": settings.client_secret,
    }
    if code_verifier:
        data["code_verifier"] = code_verifier
    return client.post("/token", data=data)


def test_health(client):
    resp = client.get("/health")
    assert resp.status_code == 200
    assert resp.json() == {"status": "ok"}


def test_security_headers(client):
    resp = client.get("/health")
    assert resp.headers["X-Content-Type-Options"] == "nosniff"
    assert resp.headers["X-Frame-Options"] == "DENY"
    assert "default-src 'self'" in resp.headers["Content-Security-Policy"]
    assert "style-src 'unsafe-inline'" in resp.headers["Content-Security-Policy"]


def test_lifespan_seeds_admin(client):
    resp = _full_authorize(client)
    assert resp.status_code == 302
    location = resp.headers["location"]
    assert "code=" in location


def test_full_oidc_flow(client):
    resp = _full_authorize(client)
    assert resp.status_code == 302
    location = resp.headers["location"]
    assert "code=" in location
    assert "state=integration-state-xyz" in location
    code = _extract_code(location)
    token_resp = _exchange_token(client, code)
    assert token_resp.status_code == 200
    data = token_resp.json()
    assert "access_token" in data
    assert "id_token" in data
    assert "refresh_token" in data
    assert data["token_type"] == "Bearer"
    access_token = data["access_token"]
    userinfo_resp = client.get("/userinfo", headers={"Authorization": f"Bearer {access_token}"})
    assert userinfo_resp.status_code == 200
    claims = userinfo_resp.json()
    assert claims["sub"]
    assert claims["email"] == settings.seed_email
    id_token = data["id_token"]
    payload = jwt.decode(id_token, settings.jwt_secret, algorithms=["HS256"], audience=settings.client_id)
    assert payload["sub"]
    assert payload["email"] == settings.seed_email


def test_full_oidc_flow_with_pkce(client):
    verifier, challenge = _make_pkce()
    resp = _full_authorize(client, code_challenge=challenge, code_challenge_method="S256")
    assert resp.status_code == 302
    location = resp.headers["location"]
    assert "state=integration-state-xyz" in location
    code = _extract_code(location)
    token_resp = _exchange_token(client, code, code_verifier=verifier)
    assert token_resp.status_code == 200
    data = token_resp.json()
    assert "access_token" in data
    assert "id_token" in data
    access_token = data["access_token"]
    userinfo_resp = client.get("/userinfo", headers={"Authorization": f"Bearer {access_token}"})
    assert userinfo_resp.status_code == 200
    claims = userinfo_resp.json()
    assert claims["email"] == settings.seed_email
    id_token = data["id_token"]
    payload = jwt.decode(id_token, settings.jwt_secret, algorithms=["HS256"], audience=settings.client_id)
    assert payload["sub"]
    assert payload["email"] == settings.seed_email


def test_docs_available(client):
    resp = client.get("/docs")
    assert resp.status_code == 200