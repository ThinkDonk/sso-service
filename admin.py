import secrets
from fastapi import APIRouter, Form, Request, HTTPException
from fastapi.responses import HTMLResponse, RedirectResponse
from fastapi.templating import Jinja2Templates
from auth import authenticate, hash_password
from config import settings
from db import (
    list_users, create_user, get_user_by_username, get_user_by_id,
    update_user_password, update_user_info, delete_user,
    delete_tokens_by_user, count_admins, record_audit,
)

router = APIRouter(prefix="/admin", tags=["admin"])
templates = Jinja2Templates(directory="templates")


def _current_user(request: Request) -> dict | None:
    uid = request.session.get("uid")
    if uid is None:
        return None
    return {
        "id": uid,
        "username": request.session.get("username"),
        "is_admin": bool(request.session.get("is_admin", False)),
    }


def _require_login(request: Request) -> dict:
    user = _current_user(request)
    if user is None:
        raise HTTPException(status_code=303, headers={"Location": "/admin/login"})
    return user


def _require_admin(request: Request) -> dict:
    user = _require_login(request)
    if not user["is_admin"]:
        raise HTTPException(status_code=403, detail="需要管理员权限")
    return user


def _ensure_csrf_token(request: Request) -> str:
    token = request.session.get("csrf_token")
    if not token:
        token = secrets.token_urlsafe(32)
        request.session["csrf_token"] = token
    return token


def _verify_csrf(request: Request, token: str) -> bool:
    expected = request.session.get("csrf_token")
    return bool(token) and token == expected


@router.get("/login", response_class=HTMLResponse)
def login_page(request: Request):
    user = _current_user(request)
    if user is not None:
        if user["is_admin"]:
            raise HTTPException(status_code=303, headers={"Location": "/admin/"})
        else:
            raise HTTPException(status_code=303, headers={"Location": "/admin/account"})
    return templates.TemplateResponse(request, "login_admin.html", {
        "csrf_token": _ensure_csrf_token(request),
        "error": None,
    })


@router.post("/login", response_class=HTMLResponse)
def login_action(request: Request, username: str = Form(), password: str = Form(), csrf_token: str = Form()):
    if not _verify_csrf(request, csrf_token):
        return templates.TemplateResponse(request, "login_admin.html", {
            "csrf_token": _ensure_csrf_token(request),
            "error": "CSRF 校验失败",
        })
    user = authenticate(username, password)
    if user is None:
        return templates.TemplateResponse(request, "login_admin.html", {
            "csrf_token": _ensure_csrf_token(request),
            "error": "用户名或密码错误",
        })
    request.session.clear()
    request.session["uid"] = user["id"]
    request.session["username"] = user["username"]
    request.session["is_admin"] = bool(user["is_admin"])
    _ensure_csrf_token(request)
    if bool(user["is_admin"]):
        return RedirectResponse("/admin/", status_code=303)
    return RedirectResponse("/admin/account", status_code=303)


@router.post("/logout")
def logout_action(request: Request, csrf_token: str = Form()):
    _require_login(request)
    if not _verify_csrf(request, csrf_token):
        raise HTTPException(status_code=400, detail="CSRF 校验失败")
    request.session.clear()
    return RedirectResponse("/admin/login", status_code=303)


@router.get("/", response_class=HTMLResponse)
def admin_index(request: Request):
    actor = _require_admin(request)
    users = list_users()
    return templates.TemplateResponse(request, "admin_index.html", {
        "users": users,
        "csrf_token": _ensure_csrf_token(request),
        "current_user": actor,
        "message": request.query_params.get("msg"),
        "error": request.query_params.get("err"),
    })


@router.post("/users")
def create_user_action(
    request: Request,
    username: str = Form(),
    password: str = Form(),
    name: str = Form(),
    email: str = Form(),
    is_admin: bool = Form(False),
    csrf_token: str = Form(),
):
    actor = _require_admin(request)
    if not _verify_csrf(request, csrf_token):
        raise HTTPException(status_code=400, detail="CSRF 校验失败")
    if not username or not password:
        return RedirectResponse("/admin/?err=invalid_input", status_code=303)
    if get_user_by_username(username) is not None:
        return RedirectResponse("/admin/?err=user_exists", status_code=303)
    new_id = create_user(
        username=username,
        password_hash=hash_password(password),
        email=email,
        name=name,
        is_admin=is_admin,
    )
    record_audit(actor["id"], "create_user", new_id)
    return RedirectResponse("/admin/?msg=created", status_code=303)


@router.post("/users/{user_id}/password")
def reset_password_action(
    request: Request,
    user_id: int,
    new_password: str = Form(),
    csrf_token: str = Form(),
):
    actor = _require_admin(request)
    if not _verify_csrf(request, csrf_token):
        raise HTTPException(status_code=400, detail="CSRF 校验失败")
    if not new_password:
        return RedirectResponse("/admin/?err=empty_password", status_code=303)
    update_user_password(user_id, hash_password(new_password))
    delete_tokens_by_user(user_id)
    record_audit(actor["id"], "reset_password", user_id)
    return RedirectResponse("/admin/?msg=password_reset", status_code=303)


@router.post("/users/{user_id}/edit")
def edit_user_action(
    request: Request,
    user_id: int,
    name: str = Form(),
    email: str = Form(),
    is_admin: bool = Form(False),
    csrf_token: str = Form(),
):
    actor = _require_admin(request)
    if not _verify_csrf(request, csrf_token):
        raise HTTPException(status_code=400, detail="CSRF 校验失败")
    target = get_user_by_id(user_id)
    if target is None:
        raise HTTPException(status_code=404, detail="用户不存在")
    if user_id == actor["id"] and bool(target["is_admin"]) and not is_admin:
        return RedirectResponse("/admin/?err=cannot_demote_self", status_code=303)
    if bool(target["is_admin"]) and not is_admin and count_admins() <= 1:
        return RedirectResponse("/admin/?err=last_admin", status_code=303)
    update_user_info(user_id, name, email, is_admin)
    record_audit(actor["id"], "edit_user", user_id)
    return RedirectResponse("/admin/?msg=edited", status_code=303)


@router.post("/users/{user_id}/delete")
def delete_user_action(
    request: Request,
    user_id: int,
    csrf_token: str = Form(),
):
    actor = _require_admin(request)
    if not _verify_csrf(request, csrf_token):
        raise HTTPException(status_code=400, detail="CSRF 校验失败")
    target = get_user_by_id(user_id)
    if target is None:
        raise HTTPException(status_code=404, detail="用户不存在")
    if user_id == actor["id"]:
        return RedirectResponse("/admin/?err=cannot_delete_self", status_code=303)
    if bool(target["is_admin"]) and count_admins() <= 1:
        return RedirectResponse("/admin/?err=last_admin", status_code=303)
    delete_tokens_by_user(user_id)
    delete_user(user_id)
    record_audit(actor["id"], "delete_user", user_id)
    return RedirectResponse("/admin/?msg=deleted", status_code=303)


@router.get("/account", response_class=HTMLResponse)
def account_page(request: Request):
    actor = _require_login(request)
    return templates.TemplateResponse(request, "account.html", {
        "csrf_token": _ensure_csrf_token(request),
        "current_user": actor,
        "message": request.query_params.get("msg"),
        "error": request.query_params.get("err"),
    })


@router.post("/account")
def change_password_action(
    request: Request,
    current_password: str = Form(),
    new_password: str = Form(),
    confirm_password: str = Form(),
    csrf_token: str = Form(),
):
    actor = _require_login(request)
    if not _verify_csrf(request, csrf_token):
        raise HTTPException(status_code=400, detail="CSRF 校验失败")
    if authenticate(actor["username"], current_password) is None:
        return RedirectResponse("/admin/account?err=wrong_password", status_code=303)
    if not new_password:
        return RedirectResponse("/admin/account?err=empty_password", status_code=303)
    if new_password != confirm_password:
        return RedirectResponse("/admin/account?err=password_mismatch", status_code=303)
    update_user_password(actor["id"], hash_password(new_password))
    delete_tokens_by_user(actor["id"])
    record_audit(actor["id"], "change_password", actor["id"])
    return RedirectResponse("/admin/account?msg=password_changed", status_code=303)
