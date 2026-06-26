import base64
import hashlib
import secrets
from urllib.parse import parse_qs, urlparse

import pytest
from fastapi.testclient import TestClient

from config import settings
import db
import auth

def _make_pkce():
    verifier = secrets.token_urlsafe(48)
    challenge = base64.urlsafe_b64encode(hashlib.sha256(verifier.encode()).digest()).rstrip(b"=").decode()
    return verifier, challenge

@pytest.fixture
def client(tmp_path, monkeypatch):
    db_path = tmp_path / "test.db"
    monkeypatch.setattr(settings, "db_path", str(db_path))
    db.init_db()
    auth.seed_admin()
    from app import app
    with TestClient(app) as c:
        yield c

def _do_authorize(client, code_challenge=None):
    params = {
        "client_id": settings.client_id,
        "redirect_uri": settings.redirect_uri_list[0],
        "state": "test-state-123",
        "scope": "openid profile email",
    }
    if code_challenge:
        params["code_challenge"] = code_challenge
        params["code_challenge_method"] = "S256"
    resp = client.post("/authorize", data={**params, "username": settings.seed_username, "password": settings.seed_password}, follow_redirects=False)
    return resp


def _extract_code(location):
    q = parse_qs(urlparse(location).query)
    return q["code"][0]

def test_well_known(client):
    resp = client.get("/.well-known/openid-configuration")
    assert resp.status_code == 200
    data = resp.json()
    assert data["issuer"] == settings.issuer_url
    assert "authorization_endpoint" in data
    assert "token_endpoint" in data
    assert "userinfo_endpoint" in data
    assert "S256" in data["code_challenge_methods_supported"]


def test_authorize_get_renders_login(client):
    params = {
        "client_id": settings.client_id,
        "redirect_uri": settings.redirect_uri_list[0],
        "state": "test-state",
        "scope": "openid profile email",
    }
    resp = client.get("/authorize", params=params)
    assert resp.status_code == 200
    assert "username" in resp.text or "<form" in resp.text


def test_authorize_get_invalid_client(client):
    params = {
        "client_id": "wrong-client",
        "redirect_uri": settings.redirect_uri_list[0],
        "state": "test",
    }
    resp = client.get("/authorize", params=params)
    assert resp.status_code == 200
    assert "client_id" in resp.text


def test_authorize_get_invalid_redirect_uri(client):
    params = {
        "client_id": settings.client_id,
        "redirect_uri": "https://evil.example.com/callback",
        "state": "test",
    }
    resp = client.get("/authorize", params=params)
    assert resp.status_code == 200
    assert "redirect_uri" in resp.text

def test_authorize_post_success(client):
    resp = _do_authorize(client)
    assert resp.status_code == 302
    location = resp.headers["location"]
    assert "code=" in location
    assert "state=test-state-123" in location


def test_authorize_post_wrong_password(client):
    params = {
        "client_id": settings.client_id,
        "redirect_uri": settings.redirect_uri_list[0],
        "state": "test-state",
        "scope": "openid profile email",
    }
    resp = client.post("/authorize", data={**params, "username": settings.seed_username, "password": "wrong-password"}, follow_redirects=False)
    assert resp.status_code == 200
    assert "error" in resp.text

def test_token_success(client):
    resp = _do_authorize(client)
    code = _extract_code(resp.headers["location"])
    token_resp = client.post("/token", data={
        "grant_type": "authorization_code",
        "code": code,
        "redirect_uri": settings.redirect_uri_list[0],
        "client_id": settings.client_id,
        "client_secret": settings.client_secret,
    })
    assert token_resp.status_code == 200
    data = token_resp.json()
    assert "access_token" in data
    assert "id_token" in data
    assert "refresh_token" in data
    assert data["token_type"] == "Bearer"


def test_token_invalid_code(client):
    token_resp = client.post("/token", data={
        "grant_type": "authorization_code",
        "code": "nonexistent-code",
        "redirect_uri": settings.redirect_uri_list[0],
        "client_id": settings.client_id,
        "client_secret": settings.client_secret,
    })
    assert token_resp.status_code == 400
    assert token_resp.json()["error"] == "invalid_grant"


def test_token_invalid_client(client):
    resp = _do_authorize(client)
    code = _extract_code(resp.headers["location"])
    token_resp = client.post("/token", data={
        "grant_type": "authorization_code",
        "code": code,
        "redirect_uri": settings.redirect_uri_list[0],
        "client_id": settings.client_id,
        "client_secret": "wrong-secret",
    })
    assert token_resp.status_code == 401
    assert token_resp.json()["error"] == "invalid_client"


def test_token_code_replay(client):
    resp = _do_authorize(client)
    code = _extract_code(resp.headers["location"])
    token_data = {
        "grant_type": "authorization_code",
        "code": code,
        "redirect_uri": settings.redirect_uri_list[0],
        "client_id": settings.client_id,
        "client_secret": settings.client_secret,
    }
    first = client.post("/token", data=token_data)
    assert first.status_code == 200
    second = client.post("/token", data=token_data)
    assert second.status_code == 400
    assert second.json()["error"] == "invalid_grant"


def test_token_pkce(client):
    verifier, challenge = _make_pkce()
    resp = _do_authorize(client, code_challenge=challenge)
    code = _extract_code(resp.headers["location"])
    token_resp = client.post("/token", data={
        "grant_type": "authorization_code",
        "code": code,
        "redirect_uri": settings.redirect_uri_list[0],
        "client_id": settings.client_id,
        "client_secret": settings.client_secret,
        "code_verifier": verifier,
    })
    assert token_resp.status_code == 200
    assert "access_token" in token_resp.json()


def test_token_pkce_wrong_verifier(client):
    verifier, challenge = _make_pkce()
    resp = _do_authorize(client, code_challenge=challenge)
    code = _extract_code(resp.headers["location"])
    token_resp = client.post("/token", data={
        "grant_type": "authorization_code",
        "code": code,
        "redirect_uri": settings.redirect_uri_list[0],
        "client_id": settings.client_id,
        "client_secret": settings.client_secret,
        "code_verifier": "wrong-verifier-value",
    })
    assert token_resp.status_code == 400
    assert token_resp.json()["error"] == "invalid_grant"

def test_userinfo_success(client):
    resp = _do_authorize(client)
    code = _extract_code(resp.headers["location"])
    token_resp = client.post("/token", data={
        "grant_type": "authorization_code",
        "code": code,
        "redirect_uri": settings.redirect_uri_list[0],
        "client_id": settings.client_id,
        "client_secret": settings.client_secret,
    })
    access_token = token_resp.json()["access_token"]
    userinfo_resp = client.get("/userinfo", headers={"Authorization": f"Bearer {access_token}"})
    assert userinfo_resp.status_code == 200
    data = userinfo_resp.json()
    assert "sub" in data
    assert "email" in data


def test_userinfo_invalid_token(client):
    resp = client.get("/userinfo", headers={"Authorization": "Bearer invalid-token-123"})
    assert resp.status_code == 401
    assert resp.json()["error"] == "invalid_token"


def test_userinfo_no_auth(client):
    resp = client.get("/userinfo")
    assert resp.status_code == 401
    assert resp.json()["error"] == "invalid_token"


def test_well_known_has_end_session_endpoint(client):
    resp = client.get("/.well-known/openid-configuration")
    assert resp.status_code == 200
    data = resp.json()
    assert "end_session_endpoint" in data
    assert data["end_session_endpoint"].endswith("/logout")


def test_logout_with_valid_referer_redirects(client):
    first_uri = settings.redirect_uri_list[0]
    parsed = urlparse(first_uri)
    origin = f"{parsed.scheme}://{parsed.netloc}"
    resp = client.get("/logout", headers={"Referer": first_uri}, follow_redirects=False)
    assert resp.status_code == 302
    assert resp.headers["location"] == origin + "/"


def test_logout_without_referer_shows_page(client):
    resp = client.get("/logout", follow_redirects=False)
    assert resp.status_code == 200
    assert "已登出" in resp.text


def test_logout_with_foreign_referer_shows_page(client):
    resp = client.get("/logout", headers={"Referer": "https://evil.example.com/home"}, follow_redirects=False)
    assert resp.status_code == 200
    assert "已登出" in resp.text
