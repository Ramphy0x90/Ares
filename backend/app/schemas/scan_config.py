from datetime import datetime
from pydantic import BaseModel


class ScanConfigCreate(BaseModel):
    name: str
    scanners: list[str]
    options: dict | None = None


class ScanConfigUpdate(BaseModel):
    name: str | None = None
    scanners: list[str] | None = None
    options: dict | None = None


class ScanConfigResponse(BaseModel):
    id: int
    name: str
    scanners: str
    options: str | None
    created_at: datetime

    model_config = {"from_attributes": True}
