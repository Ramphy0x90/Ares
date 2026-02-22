from datetime import datetime
from pydantic import BaseModel


class ReportCreate(BaseModel):
    scan_id: int
    title: str
    format: str = "html"


class ReportResponse(BaseModel):
    id: int
    scan_id: int
    title: str
    format: str
    file_path: str | None
    created_at: datetime

    model_config = {"from_attributes": True}
