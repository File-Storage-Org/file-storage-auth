from datetime import datetime, timedelta
from typing import Union, Any

import jwt
from passlib.context import CryptContext

from .config import (
    ACCESS_TOKEN_EXPIRE_MINUTES,
    ALGORITHM,
    JWT_SECRET_KEY,
    REFRESH_TOKEN_EXPIRE_MINUTES,
    JWT_REFRESH_SECRET_KEY,
)

password_context = CryptContext(schemes=["bcrypt"], deprecated="auto")


def get_hashed_password(password: str) -> str:
    return password_context.hash(password)


def verify_password(password: str, hashed_pass: str) -> bool:
    return password_context.verify(password, hashed_pass)


def decode_access_token(token: str) -> int:
    decoded_jwt = jwt.decode(token, JWT_SECRET_KEY, ALGORITHM)
    return decoded_jwt.get("user_id")


def create_access_token(subject: Union[str, Any], user_id: Union[str, Any]) -> str:
    expires_delta = datetime.utcnow() + timedelta(
        minutes=ACCESS_TOKEN_EXPIRE_MINUTES
    )

    to_encode = {"exp": expires_delta, "sub": str(subject), "user_id": str(user_id), "isAuth": True}
    encoded_jwt = jwt.encode(to_encode, JWT_SECRET_KEY, ALGORITHM)
    return encoded_jwt


def create_refresh_token(subject: Union[str, Any]) -> str:
    expires_delta = datetime.utcnow() + timedelta(
        minutes=REFRESH_TOKEN_EXPIRE_MINUTES
    )

    to_encode = {"exp": expires_delta, "sub": str(subject)}
    encoded_jwt = jwt.encode(to_encode, JWT_REFRESH_SECRET_KEY, ALGORITHM)
    return encoded_jwt


def refresh_access_token(refresh_token: str):
    encoded_jwt = jwt.decode(refresh_token, JWT_REFRESH_SECRET_KEY, ALGORITHM)
    return encoded_jwt
