from typing import Dict
from urllib.parse import urlencode, parse_qsl

import httpx
from fastapi import APIRouter, Depends
from sqlalchemy.orm import Session

from back.app.settings import settings
from back.app.database import get_db

from back.app.auth.schemas import Url, AuthorizationResponse, GithubUser, User, Token
from back.app.auth.helpers import generate_token, create_access_token
from back.app.auth.crud import get_user_by_login, create_user, get_user
from back.app.auth.dependencies import get_user_from_header
from back.app.auth.models import User as DbUser

LOGIN_URL = "https://github.com/login/oauth/authorize"
REDIRECT_URL = f"{settings.app_url}/auth/github"
TOKEN_URL = "https://github.com/login/oauth/access_token"
USER_URL = "https://api.github.com/user"

router = APIRouter()


@router.get("/login")
def get_login_url() -> Url:
    params = {
        "client_id": settings.github_client_id,
        "redirect_uri": REDIRECT_URL,
        "state": generate_token(),
    }
    return Url(url=f"{LOGIN_URL}?{urlencode(params)}")


@router.post("/authorize")
async def verify_authorization(
    body: AuthorizationResponse, db: Session = Depends(get_db)
) -> Token:
    params = {
        "client_id": settings.github_client_id,
        "client_secret": settings.github_client_secret,
        "code": body.code,
        "state": body.state,
    }

    async with httpx.AsyncClient() as client:
        token_request = await client.post(TOKEN_URL, params=params)
        response: Dict[bytes, bytes] = dict(parse_qsl(token_request.content))
        github_token = response[b"access_token"].decode("utf-8")
        github_header = {"Authorization": f"token {github_token}"}
        user_request = await client.get(USER_URL, headers=github_header)
        github_user = GithubUser(**user_request.json())

    db_user = get_user_by_login(db, github_user.login)
    if db_user is None:
        db_user = create_user(db, github_user)

    verified_user = User.from_orm(db_user)
    access_token = create_access_token(data=verified_user)

    return Token(access_token=access_token, token_type="bearer", user=db_user)


@router.get("/me", response_model=User)
def read_profile(
    user: User = Depends(get_user_from_header),
    db: Session = Depends(get_db),
) -> DbUser:
    db_user = get_user(db, user.id)
    if db_user is None:
        raise HTTPException(status_code=404, detail="User not found")
    return db_user
