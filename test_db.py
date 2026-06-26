import pytest
import time
from config import settings
import db


@pytest.fixture
def tmp_db(tmp_path, monkeypatch):
    db_path = tmp_path / "test.db"
    monkeypatch.setattr(settings, "db_path", str(db_path))
    db.init_db()
    return db_path


def test_init_db_creates_tables(tmp_db):
    conn = db.get_conn()
    tables = conn.execute(
        "SELECT name FROM sqlite_master WHERE type='table' ORDER BY name"
    ).fetchall()
    conn.close()
    table_names = [row["name"] for row in tables]
    assert "users" in table_names
    assert "codes" in table_names
    assert "access_tokens" in table_names


def test_init_db_idempotent(tmp_db):
    db.init_db()
    db.init_db()


def test_create_and_get_user(tmp_db):
    user_id = db.create_user("alice", "hash123", "alice@test.com", "Alice", is_admin=False)
    assert isinstance(user_id, int)
    assert user_id > 0

    user_by_name = db.get_user_by_username("alice")
    assert user_by_name is not None
    assert user_by_name["username"] == "alice"
    assert user_by_name["email"] == "alice@test.com"
    assert user_by_name["name"] == "Alice"
    assert user_by_name["is_admin"] == 0

    user_by_id = db.get_user_by_id(user_id)
    assert user_by_id is not None
    assert user_by_id["username"] == "alice"


def test_get_user_not_found(tmp_db):
    assert db.get_user_by_username("nobody") is None
    assert db.get_user_by_id(9999) is None


def test_save_and_consume_code(tmp_db):
    user_id = db.create_user("bob", "hash456", "bob@test.com", "Bob")
    expires = int(time.time()) + 600
    db.save_code("code123", user_id, "http://redirect", "challenge_abc", expires)

    code_row = db.consume_code("code123")
    assert code_row is not None
    assert code_row["code"] == "code123"
    assert code_row["user_id"] == user_id
    assert code_row["redirect_uri"] == "http://redirect"
    assert code_row["code_challenge"] == "challenge_abc"


def test_consume_code_one_time(tmp_db):
    user_id = db.create_user("carol", "hash789", "carol@test.com", "Carol")
    expires = int(time.time()) + 600
    db.save_code("code_one_shot", user_id, "http://redirect", None, expires)

    first = db.consume_code("code_one_shot")
    assert first is not None

    second = db.consume_code("code_one_shot")
    assert second is None


def test_consume_code_not_found(tmp_db):
    result = db.consume_code("nonexistent_code")
    assert result is None


def test_save_and_get_token(tmp_db):
    user_id = db.create_user("dave", "hash101", "dave@test.com", "Dave")
    expires = int(time.time()) + 3600
    db.save_token("token_abc", user_id, expires)

    token = db.get_token("token_abc")
    assert token is not None
    assert token["token"] == "token_abc"
    assert token["user_id"] == user_id


def test_delete_token(tmp_db):
    user_id = db.create_user("eve", "hash202", "eve@test.com", "Eve")
    expires = int(time.time()) + 3600
    db.save_token("token_del", user_id, expires)

    assert db.get_token("token_del") is not None

    db.delete_token("token_del")
    assert db.get_token("token_del") is None


def test_get_token_not_found(tmp_db):
    assert db.get_token("nonexistent_token") is None


def test_list_users(tmp_db):
    db.create_user("alice", "hash1", "alice@test.com", "Alice")
    db.create_user("bob", "hash2", "bob@test.com", "Bob")
    users = db.list_users()
    assert len(users) == 2
    assert users[0]["username"] == "alice"
    assert users[1]["username"] == "bob"


def test_update_user_password(tmp_db):
    user_id = db.create_user("alice", "hash_old", "alice@test.com", "Alice")
    db.update_user_password(user_id, "hash_new")
    user = db.get_user_by_id(user_id)
    assert user is not None
    assert user["password_hash"] == "hash_new"


def test_update_user_info(tmp_db):
    user_id = db.create_user("alice", "hash1", "alice@test.com", "Alice")
    db.update_user_info(user_id, "Alice Updated", "alice_new@test.com", True)
    user = db.get_user_by_id(user_id)
    assert user is not None
    assert user["name"] == "Alice Updated"
    assert user["email"] == "alice_new@test.com"
    assert user["is_admin"] == 1


def test_delete_user(tmp_db):
    user_id = db.create_user("alice", "hash1", "alice@test.com", "Alice")
    db.delete_user(user_id)
    assert db.get_user_by_id(user_id) is None


def test_delete_tokens_by_user(tmp_db):
    user_id = db.create_user("alice", "hash1", "alice@test.com", "Alice")
    expires = int(time.time()) + 3600
    db.save_token("token_a", user_id, expires)
    db.save_token("token_b", user_id, expires)
    db.delete_tokens_by_user(user_id)
    assert db.get_token("token_a") is None
    assert db.get_token("token_b") is None


def test_count_admins(tmp_db):
    db.create_user("normal", "hash1", "normal@test.com", "Normal", is_admin=False)
    db.create_user("admin", "hash2", "admin@test.com", "Admin", is_admin=True)
    assert db.count_admins() == 1


def test_record_audit(tmp_db):
    actor_id = db.create_user("admin", "hash1", "admin@test.com", "Admin")
    db.record_audit(actor_id, "create_user", None)
    conn = db.get_conn()
    rows = conn.execute("SELECT * FROM audit ORDER BY id").fetchall()
    conn.close()
    assert len(rows) == 1
    record = dict(rows[0])
    assert record["actor_id"] == actor_id
    assert record["action"] == "create_user"
    assert record["target_id"] is None
    assert isinstance(record["ts"], int)
