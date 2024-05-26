from datetime import datetime

from sqlalchemy import Column, Integer, String, DateTime, ForeignKey

from .database import Base


class User(Base):
    __tablename__ = "users"

    id = Column(Integer, primary_key=True)
    username = Column(String, unique=True, nullable=False)
    email = Column(String, unique=True, nullable=False)
    hashed_password = Column(String, nullable=False)
    created_at = Column(DateTime, default=datetime.utcnow)
    updated_at = Column(DateTime, default=datetime.utcnow, onupdate=datetime.utcnow)


class Token(Base):
    __tablename__ = "tokens"

    id = Column(Integer, primary_key=True)
    refresh = Column(String, nullable=False)
    user_id = Column(Integer, ForeignKey("users.id"), nullable=False)
