"""sqlite 持久化 - 连接管理、表结构、CRUD 封装。"""

import sqlite3
import time
from config import settings


def get_conn() -> sqlite3.Connection:
    conn = sqlite3.connect(settings.db_path)
    conn.execute("PRAGMA journal_mode=WAL")
    conn.execute("PRAGMA foreign_keys=ON")
    conn.row_factory = sqlite3.Row
    return conn


def init_db() -> None:
    conn = get_conn()
    conn.execute(
        "CREATE TABLE IF NOT EXISTS users("
        "id INTEGER PRIMARY KEY AUTOINCREMENT,"
        "username TEXT UNIQUE NOT NULL,"
        "password_hash TEXT NOT NULL,"
        "email TEXT NOT NULL,"
        "name TEXT NOT NULL,"
        "picture TEXT,"
        "is_admin INTEGER DEFAULT 0"
        ")"
    )
    conn.execute(
        "CREATE TABLE IF NOT EXISTS codes("
        "code TEXT PRIMARY KEY,"
        "user_id INTEGER NOT NULL,"
        "redirect_uri TEXT NOT NULL,"
        "code_challenge TEXT,"
        "expires_at INTEGER NOT NULL"
        ")"
    )
    conn.execute(
        "CREATE TABLE IF NOT EXISTS access_tokens("
        "token TEXT PRIMARY KEY,"
        "user_id INTEGER NOT NULL,"
        "expires_at INTEGER NOT NULL"
        ")"
    )
    conn.execute(
        "CREATE TABLE IF NOT EXISTS audit("
        "id INTEGER PRIMARY KEY AUTOINCREMENT,"
        "actor_id INTEGER NOT NULL,"
        "action TEXT NOT NULL,"
        "target_id INTEGER,"
        "ts INTEGER NOT NULL"
        ")"
    )
    conn.commit()
    conn.close()


# --- users ---

def get_user_by_username(username: str) -> dict | None:
    conn = get_conn()
    row = conn.execute("SELECT * FROM users WHERE username=?", (username,)).fetchone()
    conn.close()
    return dict(row) if row else None


def get_user_by_id(user_id: int) -> dict | None:
    conn = get_conn()
    row = conn.execute("SELECT * FROM users WHERE id=?", (user_id,)).fetchone()
    conn.close()
    return dict(row) if row else None


def create_user(username: str, password_hash: str, email: str, name: str, is_admin: bool = False) -> int:
    conn = get_conn()
    cur = conn.execute(
        "INSERT INTO users(username, password_hash, email, name, is_admin) VALUES(?,?,?,?,?)",
        (username, password_hash, email, name, int(is_admin)),
    )
    conn.commit()
    user_id = cur.lastrowid
    assert user_id is not None
    conn.close()
    return user_id


# --- codes ---

def save_code(code: str, user_id: int, redirect_uri: str, code_challenge: str | None, expires_at: int) -> None:
    conn = get_conn()
    conn.execute(
        "INSERT INTO codes(code, user_id, redirect_uri, code_challenge, expires_at) VALUES(?,?,?,?,?)",
        (code, user_id, redirect_uri, code_challenge, expires_at),
    )
    conn.commit()
    conn.close()


def consume_code(code: str) -> dict | None:
    """查询并删除 code（一次性消费），返回 code 记录或 None。"""
    conn = get_conn()
    row = conn.execute("SELECT * FROM codes WHERE code=?", (code,)).fetchone()
    conn.execute("DELETE FROM codes WHERE code=?", (code,))
    conn.commit()
    conn.close()
    return dict(row) if row else None


# --- access_tokens ---

def save_token(token: str, user_id: int, expires_at: int) -> None:
    conn = get_conn()
    conn.execute(
        "INSERT INTO access_tokens(token, user_id, expires_at) VALUES(?,?,?)",
        (token, user_id, expires_at),
    )
    conn.commit()
    conn.close()


def get_token(token: str) -> dict | None:
    conn = get_conn()
    row = conn.execute("SELECT * FROM access_tokens WHERE token=?", (token,)).fetchone()
    conn.close()
    return dict(row) if row else None


def delete_token(token: str) -> None:
    conn = get_conn()
    conn.execute("DELETE FROM access_tokens WHERE token=?", (token,))
    conn.commit()
    conn.close()


def list_users() -> list[dict]:
    conn = get_conn()
    rows = conn.execute("SELECT * FROM users ORDER BY id").fetchall()
    conn.close()
    return [dict(row) for row in rows]


def update_user_password(user_id: int, password_hash: str) -> None:
    conn = get_conn()
    conn.execute(
        "UPDATE users SET password_hash=? WHERE id=?",
        (password_hash, user_id),
    )
    conn.commit()
    conn.close()


def update_user_info(user_id: int, name: str, email: str, is_admin: bool) -> None:
    conn = get_conn()
    conn.execute(
        "UPDATE users SET name=?, email=?, is_admin=? WHERE id=?",
        (name, email, int(is_admin), user_id),
    )
    conn.commit()
    conn.close()


def delete_user(user_id: int) -> None:
    conn = get_conn()
    conn.execute("DELETE FROM users WHERE id=?", (user_id,))
    conn.commit()
    conn.close()


def delete_tokens_by_user(user_id: int) -> None:
    conn = get_conn()
    conn.execute("DELETE FROM access_tokens WHERE user_id=?", (user_id,))
    conn.commit()
    conn.close()


def count_admins() -> int:
    conn = get_conn()
    row = conn.execute("SELECT COUNT(*) as cnt FROM users WHERE is_admin=1").fetchone()
    conn.close()
    return row["cnt"] if row else 0


def record_audit(actor_id: int, action: str, target_id: int | None) -> None:
    conn = get_conn()
    conn.execute(
        "INSERT INTO audit(actor_id, action, target_id, ts) VALUES(?,?,?,?)",
        (actor_id, action, target_id, int(time.time())),
    )
    conn.commit()
    conn.close()
