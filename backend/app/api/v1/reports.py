from fastapi import APIRouter, Depends, HTTPException
from fastapi.responses import FileResponse
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from app.database import get_db
from app.models.report import Report
from app.schemas.report import ReportCreate, ReportResponse
from app.services.report_service import generate_report

router = APIRouter()


@router.get("", response_model=list[ReportResponse])
async def list_reports(db: AsyncSession = Depends(get_db)):
    result = await db.execute(select(Report).order_by(Report.created_at.desc()))
    return result.scalars().all()


@router.post("", response_model=ReportResponse, status_code=201)
async def create_report(data: ReportCreate, db: AsyncSession = Depends(get_db)):
    report = await generate_report(db, data.scan_id, data.title, data.format)
    return report


@router.get("/{report_id}", response_model=ReportResponse)
async def get_report(report_id: int, db: AsyncSession = Depends(get_db)):
    report = await db.get(Report, report_id)
    if not report:
        raise HTTPException(404, "Report not found")
    return report


@router.get("/{report_id}/download")
async def download_report(report_id: int, db: AsyncSession = Depends(get_db)):
    report = await db.get(Report, report_id)
    if not report or not report.file_path:
        raise HTTPException(404, "Report file not found")
    return FileResponse(report.file_path, filename=f"{report.title}.{report.format}")
