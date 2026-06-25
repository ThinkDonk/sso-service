"""sqlite 持久化 - 连接管理、表结构、CRUD 封装。"""

import sqlite3
import time
from config import settings


def get_conn() -> sqlite3.Connection:
    # TODO: P0 implement - enable WAL, set row_factory=sqlite3.Row
    pass


def init_db() -> None:
    # TODO: P0 implement - create users/codes/access_tokens tables
    pass


# --- users ---

def get_user_by_username(username: str) -> dict | None:
    # TODO: P0 implement
    pass


def get_user_by_id(user_id: int) -> dict | None:
    # TODO: P0 implement
    pass


def create_user(username: str, password_hash: str, email: str, name: str, is_admin: bool = False) -> int:
    # TODO: P0 implement
    pass


# --- codes ---

def save_code(code: str, user_id: int, redirect_uri: str, code_challenge: str | None, expires_at: int) -> None:
    # TODO: P0 implement
    pass


def consume_code(code: str) -> dict | None:
    """查询并删除 code（一次性消费），返回 code 记录或 None。"""
    # TODO: P0 implement
    pass


# --- access_tokens ---

def save_token(token: str, user_id: int, expires_at: int) -> None:
    # TODO: P0 implement
    pass


def get_token(token: str) -> dict | None:
    # TODO: P0 implement
    pass


def delete_token(token: str) -> None:
    # TODO: P0 implement
    pass
