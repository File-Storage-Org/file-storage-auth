from typing import Annotated

from fastapi import status, HTTPException, Depends, APIRouter, Cookie, Response, Header
from fastapi.security import OAuth2PasswordRequestForm
from sqlalchemy.orm import Session

from app.database import SessionLocal
from app import models
from app.deps import is_token_expired
from app.schemas import UserOut, UserAuth, TokenSchema, TokenUserSchema, TokenAccessSchema
from app.utils import (
    get_hashed_password,
    create_access_token,
    create_refresh_token,
    verify_password,
    refresh_access_token,
    decode_access_token,
)

router = APIRouter()


# Dependency
def get_db():
    db = SessionLocal()
    try:
        yield db
    finally:
        db.close()


@router.get("/connection")
async def connection():
    return "OK"


@router.post("/signup", summary="Create new user", response_model=UserOut)
async def create_user(data: UserAuth, db: Session = Depends(get_db)):
    user = db.query(models.User).filter_by(email=data.email).first()
    if user:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="User with this email already exist",
        )
    user = models.User(
        username=data.username,
        email=data.email,
        hashed_password=get_hashed_password(data.password),
    )
    db.add(user)
    db.commit()
    db.refresh(user)

    return user


@router.post(
    "/login",
    summary="Create access and refresh tokens for user",
    response_model=TokenUserSchema,
)
async def login(
        response: Response, form_data: OAuth2PasswordRequestForm = Depends(), db: Session = Depends(get_db)
):
    user = db.query(models.User).filter_by(username=form_data.username).first()
    if user is None:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="Incorrect username or password",
        )

    if not verify_password(form_data.password, str(user.hashed_password)):
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="Incorrect username or password",
        )

    refresh_token = create_refresh_token(user.email)
    instance = models.Token(refresh=refresh_token, user_id=user.id)
    db.add(instance)
    db.commit()

    response.set_cookie(key="refresh_token", value=refresh_token, httponly=True)
    return {
        "user": UserOut(id=user.id, username=user.username, email=user.email),
        "access_token": create_access_token(user.email, user.id),
        "refresh_token": refresh_token,
    }


@router.get(
    "/user",
    summary="Get auth user",
    response_model=UserOut,
)
async def get_user(authorization: Annotated[str | None, Header()] = None, db: Session = Depends(get_db)):
    token = authorization.split(" ")[1]
    is_expired = await is_token_expired(token)

    if is_expired:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Token was expired",
        )

    user_id = decode_access_token(token)
    user = db.query(models.User).filter_by(id=user_id).first()

    return UserOut(id=user.id, username=user.username, email=user.email)


@router.get(
    "/refresh",
    summary="Refresh access token",
    response_model=TokenSchema,
)
async def refresh(
        response: Response,
        refresh_token: Annotated[str | None, Cookie()] = None,
        db: Session = Depends(get_db)):
    is_expired = await is_token_expired(refresh_token, jwt_refresh=True)

    if is_expired:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Refresh token was expired",
        )

    token_data = refresh_access_token(refresh_token)
    token = db.query(models.Token).filter_by(refresh=refresh_token).first()

    if not token_data or not token:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Refresh token not found",
        )

    user = db.query(models.User).filter_by(id=token.user_id).first()

    refresh_token = create_refresh_token(user.email)
    token.refresh = refresh_token
    db.commit()

    response.set_cookie(key="refresh_token", value=refresh_token)
    return {
        "access_token": create_access_token(user.email, user.id),
        "refresh_token": refresh_token,
    }


@router.post(
    "/logout",
    summary="Log out user"
)
async def logout(
        response: Response, data: TokenAccessSchema,
        refresh_token: Annotated[str | None, Cookie()] = None,
        db: Session = Depends(get_db)
):
    is_expired = await is_token_expired(data.access_token)

    if is_expired:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Token was expired",
        )

    user_id = decode_access_token(data.access_token)

    user = db.query(models.User).filter_by(id=user_id).first()

    if user is None:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="User does not exist",
        )

    instance = db.query(models.Token).filter_by(refresh=refresh_token).first()
    db.delete(instance)
    db.commit()

    response.delete_cookie(key="refresh_token", httponly=True)

    return {"message": "success"}
