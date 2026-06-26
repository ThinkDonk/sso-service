import secrets
from urllib.parse import urlencode, urlparse, urlunparse, parse_qsl
from fastapi import APIRouter, Form, Request, HTTPException
from fastapi.responses import HTMLResponse, RedirectResponse
from fastapi.templating import Jinja2Templates
from auth import authenticate, hash_password
from config import settings
from db import (
    list_users, count_users, create_user, get_user_by_username,
    get_user_by_id, update_user_password, update_user_info, delete_user,
    delete_tokens_by_user, count_admins, record_audit, set_user_active,
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


def _admin_redirect(base: str, search: str, page: int) -> RedirectResponse:
    parsed = urlparse(base)
    qs = dict(parse_qsl(parsed.query))
    if search:
        qs["search"] = search
    if page and page > 1:
        qs["page"] = str(page)
    query = urlencode(qs)
    location = urlunparse(("", "", parsed.path, parsed.params, query, ""))
    return RedirectResponse(location, status_code=303)


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
    search = request.query_params.get("search", "").strip()
    page = request.query_params.get("page", "1")
    try:
        page = max(1, int(page))
    except (TypeError, ValueError):
        page = 1
    page_size = settings.page_size
    total = count_users(search)
    total_pages = max(1, (total + page_size - 1) // page_size)
    if page > total_pages:
        page = total_pages
    offset = (page - 1) * page_size
    users = list_users(search, offset, page_size)
    return templates.TemplateResponse(request, "admin_index.html", {
        "users": users,
        "csrf_token": _ensure_csrf_token(request),
        "current_user": actor,
        "message": request.query_params.get("msg"),
        "error": request.query_params.get("err"),
        "search": search,
        "page": page,
        "page_size": page_size,
        "total": total,
        "total_pages": total_pages,
    })


@router.post("/users")
def create_user_action(
    request: Request,
    username: str = Form(),
    password: str = Form(),
    name: str = Form(""),
    email: str = Form(""),
    is_admin: bool = Form(False),
    csrf_token: str = Form(),
    search: str = Form(""),
    page: int = Form(1),
):
    actor = _require_admin(request)
    if not _verify_csrf(request, csrf_token):
        raise HTTPException(status_code=400, detail="CSRF 校验失败")
    if not username or not password:
        return _admin_redirect("/admin/?err=invalid_input", search, page)
    if not email or not name:
        return _admin_redirect("/admin/?err=invalid_input", search, page)
    if get_user_by_username(username) is not None:
        return _admin_redirect("/admin/?err=user_exists", search, page)
    new_id = create_user(
        username=username,
        password_hash=hash_password(password),
        email=email,
        name=name,
        is_admin=is_admin,
    )
    record_audit(actor["id"], "create_user", new_id)
    return _admin_redirect("/admin/?msg=created", search, page)


@router.post("/users/{user_id}/password")
def reset_password_action(
    request: Request,
    user_id: int,
    new_password: str = Form(),
    csrf_token: str = Form(),
    search: str = Form(""),
    page: int = Form(1),
):
    actor = _require_admin(request)
    if not _verify_csrf(request, csrf_token):
        raise HTTPException(status_code=400, detail="CSRF 校验失败")
    if not new_password:
        return _admin_redirect("/admin/?err=empty_password", search, page)
    update_user_password(user_id, hash_password(new_password))
    delete_tokens_by_user(user_id)
    record_audit(actor["id"], "reset_password", user_id)
    return _admin_redirect("/admin/?msg=password_reset", search, page)


@router.post("/users/{user_id}/edit")
def edit_user_action(
    request: Request,
    user_id: int,
    name: str = Form(""),
    email: str = Form(""),
    is_admin: bool = Form(False),
    csrf_token: str = Form(),
    search: str = Form(""),
    page: int = Form(1),
):
    actor = _require_admin(request)
    if not _verify_csrf(request, csrf_token):
        raise HTTPException(status_code=400, detail="CSRF 校验失败")
    target = get_user_by_id(user_id)
    if target is None:
        raise HTTPException(status_code=404, detail="用户不存在")
    if not email or not name:
        return _admin_redirect("/admin/?err=invalid_input", search, page)
    if user_id == actor["id"] and bool(target["is_admin"]) and not is_admin:
        return _admin_redirect("/admin/?err=cannot_demote_self", search, page)
    if bool(target["is_admin"]) and not is_admin and count_admins() <= 1:
        return _admin_redirect("/admin/?err=last_admin", search, page)
    update_user_info(user_id, name, email, is_admin)
    record_audit(actor["id"], "edit_user", user_id)
    return _admin_redirect("/admin/?msg=edited", search, page)


@router.post("/users/{user_id}/delete")
def delete_user_action(
    request: Request,
    user_id: int,
    csrf_token: str = Form(),
    search: str = Form(""),
    page: int = Form(1),
):
    actor = _require_admin(request)
    if not _verify_csrf(request, csrf_token):
        raise HTTPException(status_code=400, detail="CSRF 校验失败")
    target = get_user_by_id(user_id)
    if target is None:
        raise HTTPException(status_code=404, detail="用户不存在")
    if user_id == actor["id"]:
        return _admin_redirect("/admin/?err=cannot_delete_self", search, page)
    if bool(target["is_admin"]) and count_admins() <= 1:
        return _admin_redirect("/admin/?err=last_admin", search, page)
    delete_tokens_by_user(user_id)
    delete_user(user_id)
    record_audit(actor["id"], "delete_user", user_id)
    return _admin_redirect("/admin/?msg=deleted", search, page)


@router.post("/users/{user_id}/toggle-active")
def toggle_active_action(
    request: Request,
    user_id: int,
    csrf_token: str = Form(),
    search: str = Form(""),
    page: int = Form(1),
):
    actor = _require_admin(request)
    if not _verify_csrf(request, csrf_token):
        raise HTTPException(status_code=400, detail="CSRF 校验失败")
    target = get_user_by_id(user_id)
    if target is None:
        raise HTTPException(status_code=404, detail="用户不存在")
    current_active = bool(target["is_active"])
    if not current_active:
        set_user_active(user_id, 1)
        record_audit(actor["id"], "enable_user", user_id)
        return _admin_redirect("/admin/?msg=user_enabled", search, page)
    if user_id == actor["id"]:
        return _admin_redirect("/admin/?err=cannot_disable_self", search, page)
    if bool(target["is_admin"]) and count_admins() <= 1:
        return _admin_redirect("/admin/?err=last_admin", search, page)
    set_user_active(user_id, 0)
    delete_tokens_by_user(user_id)
    record_audit(actor["id"], "disable_user", user_id)
    return _admin_redirect("/admin/?msg=user_disabled", search, page)


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
