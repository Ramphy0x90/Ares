import json
from fastapi import APIRouter, Depends, HTTPException
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from app.database import get_db
from app.models.scan_config import ScanConfig
from app.schemas.scan_config import ScanConfigCreate, ScanConfigUpdate, ScanConfigResponse

router = APIRouter()


@router.get("", response_model=list[ScanConfigResponse])
async def list_scan_configs(db: AsyncSession = Depends(get_db)):
    result = await db.execute(select(ScanConfig))
    return result.scalars().all()


@router.post("", response_model=ScanConfigResponse, status_code=201)
async def create_scan_config(data: ScanConfigCreate, db: AsyncSession = Depends(get_db)):
    config = ScanConfig(
        name=data.name,
        scanners=json.dumps(data.scanners),
        options=json.dumps(data.options) if data.options else None,
    )
    db.add(config)
    await db.commit()
    await db.refresh(config)
    return config


@router.get("/{config_id}", response_model=ScanConfigResponse)
async def get_scan_config(config_id: int, db: AsyncSession = Depends(get_db)):
    config = await db.get(ScanConfig, config_id)
    if not config:
        raise HTTPException(404, "Scan config not found")
    return config


@router.put("/{config_id}", response_model=ScanConfigResponse)
async def update_scan_config(config_id: int, data: ScanConfigUpdate, db: AsyncSession = Depends(get_db)):
    config = await db.get(ScanConfig, config_id)
    if not config:
        raise HTTPException(404, "Scan config not found")
    update = data.model_dump(exclude_unset=True)
    if "scanners" in update:
        update["scanners"] = json.dumps(update["scanners"])
    if "options" in update and update["options"] is not None:
        update["options"] = json.dumps(update["options"])
    for k, v in update.items():
        setattr(config, k, v)
    await db.commit()
    await db.refresh(config)
    return config


@router.delete("/{config_id}", status_code=204)
async def delete_scan_config(config_id: int, db: AsyncSession = Depends(get_db)):
    config = await db.get(ScanConfig, config_id)
    if not config:
        raise HTTPException(404, "Scan config not found")
    await db.delete(config)
    await db.commit()
