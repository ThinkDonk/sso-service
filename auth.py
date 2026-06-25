"""User authentication - password hashing, seed admin, OIDC claims mapping."""
from passlib.context import CryptContext
from config import settings
from db import create_user, get_user_by_username

_pwd_ctx = CryptContext(schemes=["bcrypt"], deprecated="auto")


def hash_password(password: str) -> str:
    # TODO: P0 implement - hash password with bcrypt
    pass


def verify_password(password: str, password_hash: str) -> bool:
    # TODO: P0 implement - verify password against hash
    pass


def authenticate(username: str, password: str) -> dict | None:
    """Verify credentials, return user dict or None."""
    # TODO: P0 implement
    pass


def seed_admin() -> None:
    """Insert seed admin if users table is empty."""
    # TODO: P0 implement
    pass


def user_to_claims(user: dict) -> dict:
    """Convert user record to OIDC claims (sub/email/name/preferred_username/picture)."""
    # TODO: P0 implement
    pass
