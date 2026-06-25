"""OIDC protocol endpoints - 4 endpoints + PKCE + token lifecycle."""
import base64
import hashlib
import secrets
import time
from typing import Optional

import jwt
from fastapi import APIRouter, Form, Query, Request
from fastapi.responses import HTMLResponse, JSONResponse, RedirectResponse
from fastapi.templating import Jinja2Templates

from auth import authenticate, user_to_claims
from config import settings
from db import consume_code, get_token, get_user_by_id, save_code, save_token

router = APIRouter()
templates = Jinja2Templates(directory="templates")


def _verify_pkce(verifier: str, challenge: str) -> bool:
    # TODO: P0 implement - S256: base64url(sha256(verifier)) == challenge
    pass


def _make_access_token() -> str:
    # TODO: P0 implement
    pass


def _make_id_token(user: dict) -> str:
    # TODO: P0 implement - HS256 sign id_token JWT
    pass


@router.get("/.well-known/openid-configuration")
def well_known():
    # TODO: P0 implement - OIDC discovery metadata
    pass


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
    # TODO: P0 implement - validate client_id/redirect_uri -> render login page
    pass


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
    # TODO: P0 implement - verify password -> generate code -> 302 redirect
    pass


@router.post("/token")
def token(
    grant_type: str = Form(...),
    code: Optional[str] = Form(None),
    redirect_uri: Optional[str] = Form(None),
    client_id: str = Form(...),
    client_secret: str = Form(...),
    code_verifier: Optional[str] = Form(None),
):
    # TODO: P0 implement - code exchange for token
    pass


@router.get("/userinfo")
def userinfo(request: Request):
    # TODO: P0 implement - Bearer validation -> return user info
    pass
