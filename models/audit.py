from sqlmodel import SQLModel, Field
from datetime import datetime
from typing import Optional


class AuditLog(SQLModel, table=True):
    id: Optional[int] = Field(
        default=None,
        primary_key=True
    )

    user_id: int = Field(
        foreign_key="user.id"
    )

    action: str

    resource: str

    resource_id: Optional[int] = None

    details: Optional[str] = None

    created_at: datetime = Field(
        default_factory=datetime.utcnow
    )