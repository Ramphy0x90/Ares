from fastapi import APIRouter, Depends
from sqlalchemy import select, func
from sqlalchemy.ext.asyncio import AsyncSession

from app.database import get_db
from app.models.target import Target
from app.models.scan import Scan
from app.models.vulnerability import Vulnerability
from app.schemas.vulnerability import VulnerabilityResponse

router = APIRouter()


@router.get("/stats")
async def get_stats(db: AsyncSession = Depends(get_db)):
    total_targets = (await db.execute(select(func.count(Target.id)))).scalar() or 0
    total_scans = (await db.execute(select(func.count(Scan.id)))).scalar() or 0
    active_scans = (await db.execute(select(func.count(Scan.id)).where(Scan.status == "running"))).scalar() or 0

    severity_counts = {}
    for sev in ["critical", "high", "medium", "low", "info"]:
        count = (await db.execute(select(func.count(Vulnerability.id)).where(Vulnerability.severity == sev))).scalar() or 0
        severity_counts[sev] = count

    return {
        "total_targets": total_targets,
        "total_scans": total_scans,
        "active_scans": active_scans,
        "vuln_counts_by_severity": severity_counts,
    }


@router.get("/recent-findings", response_model=list[VulnerabilityResponse])
async def recent_findings(db: AsyncSession = Depends(get_db)):
    result = await db.execute(select(Vulnerability).order_by(Vulnerability.created_at.desc()).limit(20))
    return result.scalars().all()
