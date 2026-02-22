from datetime import datetime
from pydantic import BaseModel


class ScanCreate(BaseModel):
    target_id: int
    scan_config_id: int | None = None
    scanners: list[str] | None = None
    options: dict | None = None


class ScanResponse(BaseModel):
    id: int
    target_id: int
    scan_config_id: int | None
    status: str
    progress: float
    started_at: datetime | None
    completed_at: datetime | None
    error_message: str | None
    created_at: datetime

    model_config = {"from_attributes": True}
