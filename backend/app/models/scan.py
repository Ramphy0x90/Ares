from datetime import datetime
from sqlalchemy import String, Float, DateTime, ForeignKey, Text
from sqlalchemy.orm import Mapped, mapped_column, relationship

from app.database import Base


class Scan(Base):
    __tablename__ = "scans"

    id: Mapped[int] = mapped_column(primary_key=True, autoincrement=True)
    target_id: Mapped[int] = mapped_column(ForeignKey("targets.id", ondelete="CASCADE"), nullable=False)
    scan_config_id: Mapped[int | None] = mapped_column(ForeignKey("scan_configs.id", ondelete="SET NULL"), nullable=True)
    status: Mapped[str] = mapped_column(String(50), nullable=False, default="pending")
    progress: Mapped[float] = mapped_column(Float, default=0.0)
    started_at: Mapped[datetime | None] = mapped_column(DateTime, nullable=True)
    completed_at: Mapped[datetime | None] = mapped_column(DateTime, nullable=True)
    error_message: Mapped[str | None] = mapped_column(Text, nullable=True)
    created_at: Mapped[datetime] = mapped_column(DateTime, default=datetime.utcnow)

    target: Mapped["Target"] = relationship("Target", back_populates="scans")
    scan_config: Mapped["ScanConfig | None"] = relationship("ScanConfig", back_populates="scans")
    vulnerabilities: Mapped[list["Vulnerability"]] = relationship("Vulnerability", back_populates="scan", cascade="all, delete-orphan")
    reports: Mapped[list["Report"]] = relationship("Report", back_populates="scan", cascade="all, delete-orphan")
