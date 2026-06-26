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


# ---------------------------------------------------------------------------
# Search & pagination
# ---------------------------------------------------------------------------

def test_search_users(client):
    login(client)
    csrf = get_csrf(client, "/admin/")
    for uname, name, email in [("alice", "Alice", "alice@x.com"), ("bob", "Bob", "bob@x.com")]:
        r = client.post("/admin/users", data={
            "csrf_token": csrf, "username": uname, "password": "pw123",
            "name": name, "email": email,
        }, follow_redirects=False)
        assert r.status_code == 303
    r = client.get("/admin/?search=alice")
    assert r.status_code == 200
    assert "alice" in r.text
    assert "bob" not in r.text
    r = client.get("/admin/?search=bob@x.com")
    assert r.status_code == 200
    assert "bob" in r.text
    assert "alice" not in r.text


def test_search_no_match(client):
    login(client)
    r = client.get("/admin/?search=nonexistentuser12345")
    assert r.status_code == 200
    assert "共 0 条" in r.text


def test_pagination(client, tmp_path, monkeypatch):
    monkeypatch.setattr(settings, "page_size", 2)
    login(client)
    csrf = get_csrf(client, "/admin/")
    for uname in ["u1", "u2", "u3"]:
        r = client.post("/admin/users", data={
            "csrf_token": csrf, "username": uname, "password": "pw123",
            "name": uname, "email": uname + "@x.com",
        }, follow_redirects=False)
        assert r.status_code == 303
    r = client.get("/admin/?page=1")
    assert r.status_code == 200
    assert "第 1/2 页" in r.text
    r = client.get("/admin/?page=2")
    assert r.status_code == 200
    assert "第 2/2 页" in r.text


def test_pagination_out_of_range(client, tmp_path, monkeypatch):
    monkeypatch.setattr(settings, "page_size", 2)
    login(client)
    r = client.get("/admin/?page=999")
    assert r.status_code == 200
    assert "第 1/1 页" in r.text


def test_pagination_invalid_page(client):
    login(client)
    r = client.get("/admin/?page=abc")
    assert r.status_code == 200
    assert "第 1/" in r.text


# ---------------------------------------------------------------------------
# Email/name validation
# ---------------------------------------------------------------------------

def test_create_user_empty_email(client):
    login(client)
    csrf = get_csrf(client, "/admin/")
    r = client.post("/admin/users", data={
        "csrf_token": csrf, "username": "u1", "password": "pw123",
        "name": "Name", "email": "",
    }, follow_redirects=False)
    assert r.status_code == 303
    assert "err=invalid_input" in r.headers["location"]


def test_create_user_empty_name(client):
    login(client)
    csrf = get_csrf(client, "/admin/")
    r = client.post("/admin/users", data={
        "csrf_token": csrf, "username": "u1", "password": "pw123",
        "name": "", "email": "u1@x.com",
    }, follow_redirects=False)
    assert r.status_code == 303
    assert "err=invalid_input" in r.headers["location"]


def test_edit_user_empty_email_rejected(client):
    login(client)
    csrf = get_csrf(client, "/admin/")
    client.post("/admin/users", data={
        "csrf_token": csrf, "username": "u1", "password": "pw123",
        "name": "Name", "email": "u1@x.com",
    }, follow_redirects=False)
    target = get_user_by_username("u1")
    assert target is not None
    csrf = get_csrf(client, "/admin/")
    r = client.post(f"/admin/users/{target['id']}/edit", data={
        "csrf_token": csrf, "name": "Name", "email": "",
    }, follow_redirects=False)
    assert r.status_code == 303
    assert "err=invalid_input" in r.headers["location"]


# ---------------------------------------------------------------------------
# Enable/disable user
# ---------------------------------------------------------------------------

def test_disable_user(client):
    login(client)
    csrf = get_csrf(client, "/admin/")
    client.post("/admin/users", data={
        "csrf_token": csrf, "username": "u1", "password": "pw123",
        "name": "Name", "email": "u1@x.com",
    }, follow_redirects=False)
    target = get_user_by_username("u1")
    csrf = get_csrf(client, "/admin/")
    r = client.post(f"/admin/users/{target['id']}/toggle-active", data={
        "csrf_token": csrf,
    }, follow_redirects=False)
    assert r.status_code == 303
    assert "msg=user_disabled" in r.headers["location"]
    t = get_user_by_id(target["id"])
    assert t["is_active"] == 0


def test_enable_user(client):
    login(client)
    csrf = get_csrf(client, "/admin/")
    client.post("/admin/users", data={
        "csrf_token": csrf, "username": "u1", "password": "pw123",
        "name": "Name", "email": "u1@x.com",
    }, follow_redirects=False)
    target = get_user_by_username("u1")
    csrf = get_csrf(client, "/admin/")
    client.post(f"/admin/users/{target['id']}/toggle-active", data={
        "csrf_token": csrf,
    }, follow_redirects=False)
    csrf = get_csrf(client, "/admin/")
    r = client.post(f"/admin/users/{target['id']}/toggle-active", data={
        "csrf_token": csrf,
    }, follow_redirects=False)
    assert r.status_code == 303
    assert "msg=user_enabled" in r.headers["location"]
    t = get_user_by_id(target["id"])
    assert t["is_active"] == 1


def test_disable_self_rejected(client):
    login(client)
    admin = get_user_by_username("admin")
    csrf = get_csrf(client, "/admin/")
    r = client.post(f"/admin/users/{admin['id']}/toggle-active", data={
        "csrf_token": csrf,
    }, follow_redirects=False)
    assert r.status_code == 303
    assert "err=cannot_disable_self" in r.headers["location"]


# test_disable_last_admin_rejected is intentionally omitted.
# The last_admin guard in toggle-active is practically unreachable:
#   - The actor must be an admin (endpoint requires _require_admin).
#   - The target must also be an admin for the check to trigger.
#   - count_admins() counts ALL users with is_admin=1 (active or not).
#   - With the actor as an admin, count_admins() >= 1.
#     If target != actor then count >= 2 so "<= 1" never matches.
#     If target == actor then cannot_disable_self fires first.
#   - There is no code path where count_admins() == 1 with a
#     different admin who is the actor. The check exists as a
#     belt-and-suspenders safety but cannot be exercised via
#     normal API usage.


def test_disabled_user_cannot_login(client):
    login(client)
    csrf = get_csrf(client, "/admin/")
    client.post("/admin/users", data={
        "csrf_token": csrf, "username": "u1", "password": "pw123",
        "name": "Name", "email": "u1@x.com",
    }, follow_redirects=False)
    r_login = login(client, "u1", "pw123")
    assert r_login.status_code == 303
    assert "account" in r_login.headers["location"]
    csrf = get_csrf(client, "/admin/account")
    client.post("/admin/logout", data={
        "csrf_token": csrf,
    }, follow_redirects=False)
    login(client, "admin", "admin123")
    target = get_user_by_username("u1")
    csrf = get_csrf(client, "/admin/")
    client.post(f"/admin/users/{target['id']}/toggle-active", data={
        "csrf_token": csrf,
    }, follow_redirects=False)
    csrf = get_csrf(client, "/admin/")
    client.post("/admin/logout", data={
        "csrf_token": csrf,
    }, follow_redirects=False)
    csrf = get_csrf(client, "/admin/login")
    r = client.post("/admin/login", data={
        "csrf_token": csrf, "username": "u1", "password": "pw123",
    }, follow_redirects=False)
    assert r.status_code == 200
    assert "用户名或密码错误" in r.text


def test_disable_revokes_token(client):
    login(client)
    csrf = get_csrf(client, "/admin/")
    client.post("/admin/users", data={
        "csrf_token": csrf, "username": "u1", "password": "pw123",
        "name": "Name", "email": "u1@x.com",
    }, follow_redirects=False)
    target = get_user_by_username("u1")
    token_val = "tok-disable-" + str(int(time.time()))
    save_token(token_val, target["id"], int(time.time()) + 3600)
    assert get_token(token_val) is not None
    csrf = get_csrf(client, "/admin/")
    client.post(f"/admin/users/{target['id']}/toggle-active", data={
        "csrf_token": csrf,
    }, follow_redirects=False)
    assert get_token(token_val) is None
