from datetime import datetime
from sqlalchemy import String, Text, DateTime
from sqlalchemy.orm import Mapped, mapped_column, relationship

from app.database import Base


class ScanConfig(Base):
    __tablename__ = "scan_configs"

    id: Mapped[int] = mapped_column(primary_key=True, autoincrement=True)
    name: Mapped[str] = mapped_column(String(255), nullable=False)
    scanners: Mapped[str] = mapped_column(Text, nullable=False)  # JSON array
    options: Mapped[str | None] = mapped_column(Text, nullable=True)  # JSON dict
    created_at: Mapped[datetime] = mapped_column(DateTime, default=datetime.utcnow)

    scans: Mapped[list["Scan"]] = relationship("Scan", back_populates="scan_config")
