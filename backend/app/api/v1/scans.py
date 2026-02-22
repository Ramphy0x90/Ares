import json
from fastapi import APIRouter, Depends, HTTPException
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from app.database import get_db, async_session
from app.models.scan import Scan
from app.models.target import Target
from app.schemas.scan import ScanCreate, ScanResponse
from app.schemas.vulnerability import VulnerabilityResponse
from app.models.vulnerability import Vulnerability
from app.services.scan_service import scan_service

router = APIRouter()


@router.get("", response_model=list[ScanResponse])
async def list_scans(target_id: int | None = None, status: str | None = None, db: AsyncSession = Depends(get_db)):
    stmt = select(Scan)
    if target_id:
        stmt = stmt.where(Scan.target_id == target_id)
    if status:
        stmt = stmt.where(Scan.status == status)
    result = await db.execute(stmt.order_by(Scan.created_at.desc()))
    return result.scalars().all()


@router.post("", response_model=ScanResponse, status_code=201)
async def create_scan(data: ScanCreate, db: AsyncSession = Depends(get_db)):
    target = await db.get(Target, data.target_id)
    if not target:
        raise HTTPException(404, "Target not found")
    scan = Scan(target_id=data.target_id, scan_config_id=data.scan_config_id)
    db.add(scan)
    await db.commit()
    await db.refresh(scan)
    scanner_names = data.scanners or ["network"]
    config = data.options or {}
    scan_service.start_scan(scan.id, target.host, scanner_names, config, async_session)
    return scan


@router.get("/{scan_id}", response_model=ScanResponse)
async def get_scan(scan_id: int, db: AsyncSession = Depends(get_db)):
    scan = await db.get(Scan, scan_id)
    if not scan:
        raise HTTPException(404, "Scan not found")
    return scan


@router.post("/{scan_id}/stop", response_model=ScanResponse)
async def stop_scan(scan_id: int, db: AsyncSession = Depends(get_db)):
    scan = await db.get(Scan, scan_id)
    if not scan:
        raise HTTPException(404, "Scan not found")
    await scan_service.stop_scan(scan_id)
    await db.refresh(scan)
    return scan


@router.delete("/{scan_id}", status_code=204)
async def delete_scan(scan_id: int, db: AsyncSession = Depends(get_db)):
    scan = await db.get(Scan, scan_id)
    if not scan:
        raise HTTPException(404, "Scan not found")
    if scan.status == "running":
        await scan_service.stop_scan(scan_id)
    await db.delete(scan)
    await db.commit()


@router.get("/{scan_id}/vulnerabilities", response_model=list[VulnerabilityResponse])
async def get_scan_vulnerabilities(scan_id: int, db: AsyncSession = Depends(get_db)):
    result = await db.execute(select(Vulnerability).where(Vulnerability.scan_id == scan_id))
    return result.scalars().all()
