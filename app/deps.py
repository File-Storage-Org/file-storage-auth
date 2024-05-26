import jwt

from datetime import datetime
from .config import (
    JWT_SECRET_KEY,
    JWT_REFRESH_SECRET_KEY,
    ALGORITHM,
)


async def is_token_expired(token: str, jwt_refresh: bool = False) -> bool:
    # Here's options verify_exp parameter
    # It is False because jwt decode func is checking exp by itself
    # As we need to check token exp by ourselves, then it must equal False
    # if jwt_refresh is True then you pass refresh token else access token
    if jwt_refresh:
        payload = jwt.decode(
            token, JWT_REFRESH_SECRET_KEY, algorithms=[ALGORITHM], options={"verify_exp": False}
        )
    else:
        payload = jwt.decode(
            token, JWT_SECRET_KEY, algorithms=[ALGORITHM], options={"verify_exp": False}
        )
    exp = payload.get("exp")
    if exp:
        now = datetime.utcnow()
        expiration_datetime = datetime.utcfromtimestamp(exp)
        return now > expiration_datetime
    else:
        # If 'exp' claim is not present, consider token as expired
        return True
