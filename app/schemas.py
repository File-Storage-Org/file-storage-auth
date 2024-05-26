from pydantic import BaseModel, Field


class UserAuth(BaseModel):
    username: str = Field(..., description="username")
    email: str = Field(..., description="user email")
    password: str = Field(..., min_length=5, max_length=24, description="user password")


class UserOut(BaseModel):
    id: int
    username: str
    email: str


class TokenSchema(BaseModel):
    access_token: str
    refresh_token: str


class TokenAccessSchema(BaseModel):
    access_token: str


class TokenUserSchema(TokenSchema):
    user: UserOut
    access_token: str
    refresh_token: str


class TokenPayload(BaseModel):
    sub: str = None
    exp: int = None
