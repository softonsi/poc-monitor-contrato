import time
import uuid
from hmac import compare_digest

import bcrypt
from fastapi import Depends, HTTPException, status
from fastapi.security import HTTPAuthorizationCredentials, HTTPBearer
from pydantic import BaseModel
from sqlalchemy import text
from sqlalchemy.orm import Session

from src.config import Config
from src.db.session import get_db

security = HTTPBearer(auto_error=False)

TOKEN_EXPIRY_SECONDS = 7200  # 2 horas

# Armazenamento em memória: {token: {"username": str, "created": float}}
_active_tokens: dict[str, dict] = {}


class LoginRequest(BaseModel):
    username: str
    password: str


class LoginResponse(BaseModel):
    access_token: str
    token_type: str = "bearer"


def _clean_expired():
    now = time.time()
    expired = [k for k, v in _active_tokens.items() if now - v["created"] > TOKEN_EXPIRY_SECONDS]
    for k in expired:
        del _active_tokens[k]


def _password_matches(plain_password: str, stored_password: str) -> bool:
    if stored_password.startswith(("$2a$", "$2b$", "$2y$")):
        return bcrypt.checkpw(plain_password.encode(), stored_password.encode())
    return compare_digest(plain_password, stored_password)


def login(data: LoginRequest, db: Session) -> LoginResponse:
    _clean_expired()

    result = db.execute(
        text("""
            SELECT COD_USUARIO, SENHA
            FROM TB_USUARIOS
            WHERE USUARIO = :user
              AND COD_INSTITUICAO = :cod
              AND STATUS = 1
        """),
        {"user": data.username, "cod": Config.WEB_AUTH_COD_INSTITUICAO},
    ).fetchone()

    if not result or not _password_matches(data.password, result.SENHA):
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Usuário ou senha inválidos",
        )

    token = str(uuid.uuid4())
    _active_tokens[token] = {
        "username": data.username,
        "created": time.time(),
    }
    return LoginResponse(access_token=token)


def require_auth(credentials: HTTPAuthorizationCredentials | None = Depends(security)):
    if not credentials:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Autenticação requerida",
        )

    session = _active_tokens.get(credentials.credentials)
    if not session:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Token inválido",
        )

    if time.time() - session["created"] > TOKEN_EXPIRY_SECONDS:
        del _active_tokens[credentials.credentials]
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Token expirado",
        )

    _active_tokens[credentials.credentials]["created"] = time.time()
    return True
