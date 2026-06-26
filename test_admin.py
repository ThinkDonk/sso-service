import re
import time
import pytest
from fastapi.testclient import TestClient
from app import app
from config import settings
from db import (get_user_by_username, get_user_by_id, save_token,
                get_token, create_user)
from auth import hash_password


@pytest.fixture
def client(tmp_path, monkeypatch):
    monkeypatch.setattr(settings, "db_path", str(tmp_path / "test.db"))
    monkeypatch.setattr(settings, "session_secret", "test-secret-key-for-testing")
    with TestClient(app) as c:
        yield c


def extract_csrf(html: str) -> str:
    m = re.search(r'name="csrf_token" value="([^"]+)"', html)
    assert m, "csrf_token not found in HTML"
    return m.group(1)


def login(client, username="admin", password="admin123"):
    r = client.get("/admin/login")
    csrf = extract_csrf(r.text)
    return client.post("/admin/login", data={
        "username": username, "password": password, "csrf_token": csrf
    }, follow_redirects=False)


def get_csrf(client, path):
    r = client.get(path)
    return extract_csrf(r.text)


# ---------------------------------------------------------------------------
# Login & session
# ---------------------------------------------------------------------------

def test_index_redirect_anonymous(client):
    r = client.get("/", follow_redirects=False)
    assert r.status_code == 303
    assert "/admin/login" in r.headers["location"]


def test_admin_login_success(client):
    r = login(client)
    assert r.status_code == 303
    assert "/admin/" in r.headers["location"]


def test_normal_login_redirect_account(client):
    create_user(
        username="normal1", password_hash=hash_password("pass123"),
        email="n@e.com", name="Normal", is_admin=False,
    )
    r = login(client, username="normal1", password="pass123")
    assert r.status_code == 303
    assert "/admin/account" in r.headers["location"]


def test_login_wrong_password(client):
    r = login(client, password="wrong")
    assert r.status_code == 200
    assert "用户名或密码错误" in r.text


def test_login_no_csrf(client):
    r = client.post("/admin/login", data={
        "username": "admin", "password": "admin123",
    }, follow_redirects=False)
    assert r.status_code in (200, 422)


# ---------------------------------------------------------------------------
# Authorization
# ---------------------------------------------------------------------------

def test_admin_dashboard_requires_login(client):
    r = client.get("/admin/", follow_redirects=False)
    assert r.status_code == 303
    assert "/admin/login" in r.headers["location"]


def test_admin_dashboard_as_admin(client):
    login(client)
    r = client.get("/admin/")
    assert r.status_code == 200
    assert "用户管理" in r.text or "admin" in r.text


def test_normal_user_forbidden(client):
    create_user(
        username="forbid", password_hash=hash_password("pass123"),
        email="f@e.com", name="Forbid", is_admin=False,
    )
    login(client, username="forbid", password="pass123")
    r = client.get("/admin/", follow_redirects=False)
    assert r.status_code == 403


def test_normal_user_account_access(client):
    create_user(
        username="accuser", password_hash=hash_password("pass123"),
        email="a@e.com", name="AccUser", is_admin=False,
    )
    login(client, username="accuser", password="pass123")
    r = client.get("/admin/account")
    assert r.status_code == 200


# ---------------------------------------------------------------------------
# User management (admin)
# ---------------------------------------------------------------------------

def test_create_user(client):
    login(client)
    csrf = get_csrf(client, "/admin/")
    r = client.post("/admin/users", data={
        "username": "testuser", "password": "test123",
        "name": "Test", "email": "t@e.com",
        "is_admin": "1", "csrf_token": csrf,
    }, follow_redirects=False)
    assert r.status_code == 303
    assert "msg=created" in r.headers["location"]
    user = get_user_by_username("testuser")
    assert user is not None


def test_create_duplicate_user(client):
    login(client)
    csrf = get_csrf(client, "/admin/")
    client.post("/admin/users", data={
        "username": "dupuser", "password": "dup123",
        "name": "Dup", "email": "d@e.com",
        "csrf_token": csrf,
    }, follow_redirects=False)
    r = client.post("/admin/users", data={
        "username": "dupuser", "password": "dup123",
        "name": "Dup", "email": "d2@e.com",
        "csrf_token": csrf,
    }, follow_redirects=False)
    assert r.status_code == 303
    assert "err=user_exists" in r.headers["location"]


def test_create_user_no_csrf(client):
    login(client)
    r = client.post("/admin/users", data={
        "username": "x", "password": "x",
        "name": "x", "email": "x@x.com",
        "csrf_token": "invalid_token",
    }, follow_redirects=False)
    assert r.status_code in (400, 422)


def test_reset_password(client):
    login(client)
    uid = create_user(
        username="resetme", password_hash=hash_password("oldpass"),
        email="r@e.com", name="ResetMe", is_admin=False,
    )
    csrf = get_csrf(client, "/admin/")
    r = client.post(f"/admin/users/{uid}/password", data={
        "new_password": "newpass", "csrf_token": csrf,
    }, follow_redirects=False)
    assert r.status_code == 303
    assert "msg=password_reset" in r.headers["location"]


def test_reset_password_revokes_token(client):
    login(client)
    uid = create_user(
        username="revoke1", password_hash=hash_password("pw1"),
        email="rv1@e.com", name="Revoke1", is_admin=False,
    )
    token_val = "tok-reset-" + str(int(time.time()))
    save_token(token_val, uid, int(time.time()) + 3600)
    assert get_token(token_val) is not None
    csrf = get_csrf(client, "/admin/")
    client.post(f"/admin/users/{uid}/password", data={
        "new_password": "newpass2", "csrf_token": csrf,
    }, follow_redirects=False)
    assert get_token(token_val) is None


def test_edit_user(client):
    login(client)
    uid = create_user(
        username="editme", password_hash=hash_password("pw1"),
        email="old@e.com", name="OldName", is_admin=False,
    )
    csrf = get_csrf(client, "/admin/")
    r = client.post(f"/admin/users/{uid}/edit", data={
        "name": "NewName", "email": "new@e.com",
        "is_admin": "0", "csrf_token": csrf,
    }, follow_redirects=False)
    assert r.status_code == 303
    assert "msg=edited" in r.headers["location"]
    user = get_user_by_id(uid)
    assert user["name"] == "NewName"
    assert user["email"] == "new@e.com"


def test_edit_demote_self_rejected(client):
    login(client)
    admin_user = get_user_by_username("admin")
    csrf = get_csrf(client, "/admin/")
    r = client.post(f"/admin/users/{admin_user['id']}/edit", data={
        "name": admin_user["name"], "email": admin_user["email"],
        "is_admin": "0", "csrf_token": csrf,
    }, follow_redirects=False)
    assert r.status_code == 303
    assert "err=cannot_demote_self" in r.headers["location"]


def test_delete_user(client):
    login(client)
    uid = create_user(
        username="delme", password_hash=hash_password("pw1"),
        email="del@e.com", name="DelMe", is_admin=False,
    )
    csrf = get_csrf(client, "/admin/")
    r = client.post(f"/admin/users/{uid}/delete", data={
        "csrf_token": csrf,
    }, follow_redirects=False)
    assert r.status_code == 303
    assert "msg=deleted" in r.headers["location"]
    assert get_user_by_id(uid) is None


def test_delete_self_rejected(client):
    login(client)
    admin_user = get_user_by_username("admin")
    csrf = get_csrf(client, "/admin/")
    r = client.post(f"/admin/users/{admin_user['id']}/delete", data={
        "csrf_token": csrf,
    }, follow_redirects=False)
    assert r.status_code == 303
    assert "err=cannot_delete_self" in r.headers["location"]


def test_delete_revokes_token(client):
    login(client)
    uid = create_user(
        username="delrevoke", password_hash=hash_password("pw1"),
        email="dr@e.com", name="DelRevoke", is_admin=False,
    )
    token_val = "tok-del-" + str(int(time.time()))
    save_token(token_val, uid, int(time.time()) + 3600)
    assert get_token(token_val) is not None
    csrf = get_csrf(client, "/admin/")
    client.post(f"/admin/users/{uid}/delete", data={
        "csrf_token": csrf,
    }, follow_redirects=False)
    assert get_token(token_val) is None


# ---------------------------------------------------------------------------
# Change password (account page)
# ---------------------------------------------------------------------------

def test_change_password(client):
    create_user(
        username="chgpw", password_hash=hash_password("oldpass"),
        email="ch@e.com", name="ChgPw", is_admin=False,
    )
    login(client, username="chgpw", password="oldpass")
    csrf = get_csrf(client, "/admin/account")
    r = client.post("/admin/account", data={
        "current_password": "oldpass", "new_password": "newpass",
        "confirm_password": "newpass", "csrf_token": csrf,
    }, follow_redirects=False)
    assert r.status_code == 303
    assert "msg=password_changed" in r.headers["location"]

    client.post("/admin/logout", data={"csrf_token": csrf}, follow_redirects=False)
    r_old = login(client, username="chgpw", password="oldpass")
    assert r_old.status_code == 200
    assert "用户名或密码错误" in r_old.text

    r_new = login(client, username="chgpw", password="newpass")
    assert r_new.status_code == 303


def test_change_password_wrong_current(client):
    create_user(
        username="chgpw2", password_hash=hash_password("oldpass"),
        email="ch2@e.com", name="ChgPw2", is_admin=False,
    )
    login(client, username="chgpw2", password="oldpass")
    csrf = get_csrf(client, "/admin/account")
    r = client.post("/admin/account", data={
        "current_password": "wrongpass", "new_password": "newpass",
        "confirm_password": "newpass", "csrf_token": csrf,
    }, follow_redirects=False)
    assert r.status_code == 303
    assert "err=wrong_password" in r.headers["location"]


def test_change_password_mismatch(client):
    create_user(
        username="chgpw3", password_hash=hash_password("oldpass"),
        email="ch3@e.com", name="ChgPw3", is_admin=False,
    )
    login(client, username="chgpw3", password="oldpass")
    csrf = get_csrf(client, "/admin/account")
    r = client.post("/admin/account", data={
        "current_password": "oldpass", "new_password": "aaa",
        "confirm_password": "bbb", "csrf_token": csrf,
    }, follow_redirects=False)
    assert r.status_code == 303
    assert "err=password_mismatch" in r.headers["location"]


def test_change_password_revokes_token(client):
    create_user(
        username="chgpw4", password_hash=hash_password("oldpass"),
        email="ch4@e.com", name="ChgPw4", is_admin=False,
    )
    user = get_user_by_username("chgpw4")
    uid = user["id"]
    token_val = "tok-chgpw-" + str(int(time.time()))
    save_token(token_val, uid, int(time.time()) + 3600)
    assert get_token(token_val) is not None

    login(client, username="chgpw4", password="oldpass")
    csrf = get_csrf(client, "/admin/account")
    client.post("/admin/account", data={
        "current_password": "oldpass", "new_password": "newpass",
        "confirm_password": "newpass", "csrf_token": csrf,
    }, follow_redirects=False)
    assert get_token(token_val) is None


# ---------------------------------------------------------------------------
# Logout
# ---------------------------------------------------------------------------

def test_logout(client):
    login(client)
    csrf = get_csrf(client, "/admin/")
    r = client.post("/admin/logout", data={
        "csrf_token": csrf,
    }, follow_redirects=False)
    assert r.status_code == 303
    assert "/admin/login" in r.headers["location"]

    r2 = client.get("/admin/", follow_redirects=False)
    assert r2.status_code == 303
    assert "/admin/login" in r2.headers["location"]
