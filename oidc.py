"""OIDC protocol endpoints - 4 endpoints + PKCE + token lifecycle."""
import base64
import hashlib
import secrets
import time
from typing import Optional
from urllib.parse import urlparse

import jwt
from fastapi import APIRouter, Form, Query, Request
from fastapi.responses import HTMLResponse, JSONResponse, RedirectResponse
from fastapi.templating import Jinja2Templates

from auth import authenticate, user_to_claims
from config import settings
from db import consume_code, delete_token, get_token, get_user_by_id, save_code, save_token

router = APIRouter()
templates = Jinja2Templates(directory="templates")


def _verify_pkce(verifier: str, challenge: str) -> bool:
    digest = hashlib.sha256(verifier.encode()).digest()
    computed = base64.urlsafe_b64encode(digest).rstrip(b"=").decode()
    return computed == challenge


def _make_access_token() -> str:
    return secrets.token_urlsafe(32)


def _make_id_token(user: dict) -> str:
    now = int(time.time())
    payload = {
        "iss": settings.issuer_url,
        "sub": str(user["id"]),
        "aud": settings.client_id,
        "exp": now + settings.access_token_expires,
        "iat": now,
        "email": user["email"],
    }
    return jwt.encode(payload, settings.jwt_secret, algorithm="HS256")


@router.get("/.well-known/openid-configuration")
def well_known():
    return JSONResponse({
        "issuer": settings.issuer_url,
        "authorization_endpoint": f"{settings.issuer_url}/authorize",
        "token_endpoint": f"{settings.issuer_url}/token",
        "userinfo_endpoint": f"{settings.issuer_url}/userinfo",
        "end_session_endpoint": f"{settings.issuer_url}/logout",
        "jwks_uri": f"{settings.issuer_url}/.well-known/jwks.json",
        "scopes_supported": ["openid", "profile", "email"],
        "response_types_supported": ["code"],
        "grant_types_supported": ["authorization_code"],
        "code_challenge_methods_supported": ["S256"],
    })


@router.get("/authorize", response_class=HTMLResponse)
def authorize_get(
    request: Request,
    client_id: str = Query(...),
    redirect_uri: str = Query(...),
    state: str = Query(""),
    scope: str = Query("openid profile email"),
    code_challenge: Optional[str] = Query(None),
    code_challenge_method: Optional[str] = Query(None),
):
    if client_id != settings.client_id:
        return HTMLResponse("<html><body><h1>Error</h1><p>无效的 client_id</p></body></html>")
    if redirect_uri not in settings.redirect_uri_list:
        return HTMLResponse("<html><body><h1>Error</h1><p>无效的 redirect_uri</p></body></html>")
    context = {
        "client_id": client_id,
        "redirect_uri": redirect_uri,
        "state": state,
        "scope": scope,
        "code_challenge": code_challenge,
        "code_challenge_method": code_challenge_method,
    }
    return templates.TemplateResponse(request, "login.html", context)


@router.post("/authorize", response_class=HTMLResponse)
def authorize_post(
    request: Request,
    client_id: str = Form(...),
    redirect_uri: str = Form(...),
    state: str = Form(""),
    scope: str = Form("openid profile email"),
    code_challenge: Optional[str] = Form(None),
    code_challenge_method: Optional[str] = Form(None),
    username: str = Form(...),
    password: str = Form(...),
):
    if client_id != settings.client_id:
        return HTMLResponse("<html><body><h1>Error</h1><p>无效的 client_id</p></body></html>")
    if redirect_uri not in settings.redirect_uri_list:
        return HTMLResponse("<html><body><h1>Error</h1><p>无效的 redirect_uri</p></body></html>")
    user = authenticate(username, password)
    if user is None:
        context = {
            "client_id": client_id,
            "redirect_uri": redirect_uri,
            "state": state,
            "scope": scope,
            "code_challenge": code_challenge,
            "code_challenge_method": code_challenge_method,
            "error": "用户名或密码错误",
        }
        return templates.TemplateResponse(request, "login.html", context)
    code = secrets.token_urlsafe(32)
    expires_at = int(time.time()) + settings.code_expires
    save_code(code, user["id"], redirect_uri, code_challenge, expires_at)
    callback_url = f"{redirect_uri}?code={code}&state={state}"
    return RedirectResponse(url=callback_url, status_code=302)


@router.post("/token")
def token(
    grant_type: str = Form(...),
    code: Optional[str] = Form(None),
    redirect_uri: Optional[str] = Form(None),
    client_id: str = Form(...),
    client_secret: str = Form(...),
    code_verifier: Optional[str] = Form(None),
):
    if grant_type != "authorization_code":
        return JSONResponse({"error": "unsupported_grant_type"}, status_code=400)
    if client_id != settings.client_id or client_secret != settings.client_secret:
        return JSONResponse({"error": "invalid_client"}, status_code=401)
    if code is None:
        return JSONResponse({"error": "invalid_grant", "error_description": "code not found or already used"}, status_code=400)
    code_record = consume_code(code)
    if code_record is None:
        return JSONResponse({"error": "invalid_grant", "error_description": "code not found or already used"}, status_code=400)
    if redirect_uri != code_record["redirect_uri"]:
        return JSONResponse({"error": "invalid_grant", "error_description": "redirect_uri mismatch"}, status_code=400)
    if int(time.time()) > code_record["expires_at"]:
        return JSONResponse({"error": "invalid_grant", "error_description": "code expired"}, status_code=400)
    if code_record["code_challenge"] is not None:
        if code_verifier is None:
            return JSONResponse({"error": "invalid_grant", "error_description": "code_verifier required"}, status_code=400)
        if not _verify_pkce(code_verifier, code_record["code_challenge"]):
            return JSONResponse({"error": "invalid_grant", "error_description": "PKCE verification failed"}, status_code=400)
    user = get_user_by_id(code_record["user_id"])
    access_token = _make_access_token()
    save_token(access_token, user["id"], int(time.time()) + settings.access_token_expires)
    id_token = _make_id_token(user)
    refresh_token = secrets.token_urlsafe(32)
    return JSONResponse({
        "access_token": access_token,
        "token_type": "Bearer",
        "expires_in": settings.access_token_expires,
        "id_token": id_token,
        "refresh_token": refresh_token,
    })


@router.get("/userinfo")
def userinfo(request: Request):
    auth_header = request.headers.get("authorization")
    if auth_header is None or not auth_header.startswith("Bearer "):
        return JSONResponse({"error": "invalid_token", "error_description": "missing or malformed Authorization header"}, status_code=401, headers={"WWW-Authenticate": "Bearer"})
    token_str = auth_header[7:]
    token_record = get_token(token_str)
    if token_record is None:
        return JSONResponse({"error": "invalid_token", "error_description": "token not found"}, status_code=401, headers={"WWW-Authenticate": "Bearer"})
    if int(time.time()) > token_record["expires_at"]:
        delete_token(token_str)
        return JSONResponse({"error": "invalid_token", "error_description": "token expired"}, status_code=401, headers={"WWW-Authenticate": "Bearer"})
    user = get_user_by_id(token_record["user_id"])
    claims = user_to_claims(user)
    return JSONResponse(claims)


@router.get("/logout")
def logout(request: Request):
    allowed_origins = set()
    for uri in settings.redirect_uri_list:
        parsed = urlparse(uri)
        if parsed.scheme and parsed.netloc:
            allowed_origins.add(f"{parsed.scheme}://{parsed.netloc}")
    referer = request.headers.get("referer")
    target = None
    if referer:
        rp = urlparse(referer)
        if rp.scheme and rp.netloc:
            origin = f"{rp.scheme}://{rp.netloc}"
            if origin in allowed_origins:
                target = origin + "/"
    if target:
        return RedirectResponse(target, status_code=302)
    return HTMLResponse("""<!DOCTYPE html>
<html lang="zh-CN">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width, initial-scale=1.0">
<title>已登出</title>
<style>
* { box-sizing: border-box; margin: 0; padding: 0; }
body { font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", sans-serif; background: #f5f5f5; display: flex; justify-content: center; align-items: center; min-height: 100vh; }
.card { background: #fff; padding: 2rem 2.5rem; border-radius: 8px; box-shadow: 0 2px 10px rgba(0,0,0,0.1); max-width: 360px; width: 100%; text-align: center; }
h1 { font-size: 1.25rem; margin-bottom: 1rem; color: #333; }
p { color: #6b7280; font-size: 0.9rem; line-height: 1.6; }
</style>
</head>
<body>
<div class="card">
<h1>已登出</h1>
<p>您已成功退出登录。您可以关闭此页面，或重新登录。</p>
</div>
</body>
</html>""")
