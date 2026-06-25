import pytest
from config import settings
import db
import auth


@pytest.fixture
def tmp_db(tmp_path, monkeypatch):
    db_path = tmp_path / "test.db"
    monkeypatch.setattr(settings, "db_path", str(db_path))
    db.init_db()
    return db_path


def test_hash_and_verify_password(tmp_db):
    pw = "correct-password"
    pw_hash = auth.hash_password(pw)
    assert pw_hash != pw
    assert auth.verify_password(pw, pw_hash) is True
    assert auth.verify_password("wrong-password", pw_hash) is False

def test_authenticate_success(tmp_db):
    pw_hash = auth.hash_password("mypassword")
    db.create_user("testuser", pw_hash, "test@test.com", "Test User")
    result = auth.authenticate("testuser", "mypassword")
    assert result is not None
    assert result["username"] == "testuser"
    assert result["email"] == "test@test.com"

def test_authenticate_wrong_password(tmp_db):
    pw_hash = auth.hash_password("mypassword")
    db.create_user("testuser2", pw_hash, "test2@test.com", "Test User 2")
    result = auth.authenticate("testuser2", "badpassword")
    assert result is None

def test_authenticate_user_not_found(tmp_db):
    result = auth.authenticate("nonexistent", "any-password")
    assert result is None

def test_seed_admin_creates(tmp_db):
    auth.seed_admin()
    user = db.get_user_by_username(settings.seed_username)
    assert user is not None
    assert user["username"] == settings.seed_username
    assert user["email"] == settings.seed_email
    assert user["name"] == settings.seed_name
    assert user["is_admin"] == 1

def test_seed_admin_idempotent(tmp_db):
    auth.seed_admin()
    auth.seed_admin()
    user = db.get_user_by_username(settings.seed_username)
    assert user is not None
    conn = db.get_conn()
    count = conn.execute(
        "SELECT COUNT(*) FROM users WHERE username=?",
        (settings.seed_username,),
    ).fetchone()[0]
    conn.close()
    assert count == 1

def test_user_to_claims(tmp_db):
    user = {
        "id": 42,
        "username": "alice",
        "email": "alice@example.com",
        "name": "Alice",
        "picture": None,
        "password_hash": "ignored",
        "is_admin": 0,
    }
    claims = auth.user_to_claims(user)
    assert claims["sub"] == "42"
    assert isinstance(claims["sub"], str)
    assert claims["email"] == "alice@example.com"
    assert claims["email_verified"] is True
    assert claims["preferred_username"] == "alice"
    assert claims["name"] == "Alice"
    assert "picture" not in claims
