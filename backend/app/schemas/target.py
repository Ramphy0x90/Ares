from datetime import datetime
from pydantic import BaseModel


class TargetCreate(BaseModel):
    name: str
    host: str
    target_type: str = "host"
    description: str | None = None
    tags: list[str] | None = None


class TargetUpdate(BaseModel):
    name: str | None = None
    host: str | None = None
    target_type: str | None = None
    description: str | None = None
    tags: list[str] | None = None


class TargetResponse(BaseModel):
    id: int
    name: str
    host: str
    target_type: str
    description: str | None
    tags: str | None
    created_at: datetime
    updated_at: datetime

    model_config = {"from_attributes": True}
