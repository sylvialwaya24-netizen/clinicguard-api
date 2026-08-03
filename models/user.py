from sqlmodel import SQLModel, Field
from datetime import datetime
from typing import Optional
from enum import Enum
from sqlalchemy import Column, Enum as SAEnum


class UserRole(str, Enum):
    ADMIN = "admin"
    DOCTOR = "doctor"
    PATIENT = "patient"


class User(SQLModel, table=True):
    id: Optional[int] = Field(
        default=None,
        primary_key=True
    )

    username: str = Field(
        unique=True,
        index=True,
        min_length=3,
        max_length=50
    )

    email: str = Field(
        unique=True,
        index=True
    )

    hashed_password: str

    full_name: str = Field(
        min_length=2,
        max_length=100
    )

    role: UserRole = Field(
        default=UserRole.DOCTOR,
        sa_column=Column(
            SAEnum(
                UserRole,
                values_callable=lambda enum_cls: [
                    role.value for role in enum_cls
                ],
                name="userrole"
            ),
            nullable=False
        )
    )

    is_active: bool = Field(
        default=True
    )

    created_at: datetime = Field(
        default_factory=datetime.utcnow
    )

    updated_at: datetime = Field(
        default_factory=datetime.utcnow
    )

    last_login: Optional[datetime] = None


class UserCreate(SQLModel):
    username: str = Field(
        min_length=3,
        max_length=50
    )

    email: str

    password: str = Field(
        min_length=8
    )

    full_name: str = Field(
        min_length=2,
        max_length=100
    )

    role: UserRole = Field(
        default=UserRole.DOCTOR
    )


class UserLogin(SQLModel):
    username: str
    password: str


class UserResponse(SQLModel):
    id: int
    username: str
    email: str
    full_name: str
    role: UserRole
    is_active: bool
    created_at: datetime

