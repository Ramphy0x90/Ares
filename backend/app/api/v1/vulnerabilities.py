from fastapi import APIRouter, Depends, HTTPException
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from app.database import get_db
from app.models.vulnerability import Vulnerability
from app.schemas.vulnerability import VulnerabilityResponse, VulnerabilityUpdate

router = APIRouter()


@router.get("", response_model=list[VulnerabilityResponse])
async def list_vulnerabilities(severity: str | None = None, status: str | None = None, scanner: str | None = None, scan_id: int | None = None, db: AsyncSession = Depends(get_db)):
    stmt = select(Vulnerability)
    if scan_id:
        stmt = stmt.where(Vulnerability.scan_id == scan_id)
    if severity:
        stmt = stmt.where(Vulnerability.severity == severity)
    if status:
        stmt = stmt.where(Vulnerability.status == status)
    if scanner:
        stmt = stmt.where(Vulnerability.scanner_name == scanner)
    result = await db.execute(stmt.order_by(Vulnerability.created_at.desc()))
    return result.scalars().all()


@router.get("/{vuln_id}", response_model=VulnerabilityResponse)
async def get_vulnerability(vuln_id: int, db: AsyncSession = Depends(get_db)):
    vuln = await db.get(Vulnerability, vuln_id)
    if not vuln:
        raise HTTPException(404, "Vulnerability not found")
    return vuln


@router.patch("/{vuln_id}", response_model=VulnerabilityResponse)
async def update_vulnerability(vuln_id: int, data: VulnerabilityUpdate, db: AsyncSession = Depends(get_db)):
    vuln = await db.get(Vulnerability, vuln_id)
    if not vuln:
        raise HTTPException(404, "Vulnerability not found")
    vuln.status = data.status
    await db.commit()
    await db.refresh(vuln)
    return vuln
