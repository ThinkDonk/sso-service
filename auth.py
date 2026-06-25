"""User authentication - password hashing, seed admin, OIDC claims mapping."""
from passlib.context import CryptContext
from config import settings
from db import create_user, get_user_by_username

_pwd_ctx = CryptContext(schemes=["bcrypt"], deprecated="auto")


def hash_password(password: str) -> str:
    return _pwd_ctx.hash(password)


def verify_password(password: str, password_hash: str) -> bool:
    return _pwd_ctx.verify(password, password_hash)


def authenticate(username: str, password: str) -> dict | None:
    user = get_user_by_username(username)
    if user is None:
        return None
    if not verify_password(password, user["password_hash"]):
        return None
    return dict(user)


def seed_admin() -> None:
    if get_user_by_username(settings.seed_username) is not None:
        return
    create_user(
        username=settings.seed_username,
        password_hash=hash_password(settings.seed_password),
        email=settings.seed_email,
        name=settings.seed_name,
        is_admin=True,
    )


def user_to_claims(user: dict) -> dict:
    claims = {
        "sub": str(user["id"]),
        "email": user["email"],
        "email_verified": True,
        "preferred_username": user["username"],
        "name": user["name"],
    }
    picture = user.get("picture")
    if picture is not None:
        claims["picture"] = picture
    return claims
