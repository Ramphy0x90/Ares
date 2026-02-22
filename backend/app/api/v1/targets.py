import json
from fastapi import APIRouter, Depends, HTTPException
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from app.database import get_db
from app.models.target import Target
from app.schemas.target import TargetCreate, TargetUpdate, TargetResponse

router = APIRouter()


@router.get("", response_model=list[TargetResponse])
async def list_targets(search: str | None = None, type: str | None = None, db: AsyncSession = Depends(get_db)):
    stmt = select(Target)
    if search:
        stmt = stmt.where(Target.name.ilike(f"%{search}%"))
    if type:
        stmt = stmt.where(Target.target_type == type)
    result = await db.execute(stmt)
    return result.scalars().all()


@router.post("", response_model=TargetResponse, status_code=201)
async def create_target(data: TargetCreate, db: AsyncSession = Depends(get_db)):
    target = Target(
        name=data.name, host=data.host, target_type=data.target_type,
        description=data.description, tags=json.dumps(data.tags) if data.tags else None,
    )
    db.add(target)
    await db.commit()
    await db.refresh(target)
    return target


@router.get("/{target_id}", response_model=TargetResponse)
async def get_target(target_id: int, db: AsyncSession = Depends(get_db)):
    target = await db.get(Target, target_id)
    if not target:
        raise HTTPException(404, "Target not found")
    return target


@router.put("/{target_id}", response_model=TargetResponse)
async def update_target(target_id: int, data: TargetUpdate, db: AsyncSession = Depends(get_db)):
    target = await db.get(Target, target_id)
    if not target:
        raise HTTPException(404, "Target not found")
    for field, value in data.model_dump(exclude_unset=True).items():
        if field == "tags" and value is not None:
            value = json.dumps(value)
        setattr(target, field, value)
    await db.commit()
    await db.refresh(target)
    return target


@router.delete("/{target_id}", status_code=204)
async def delete_target(target_id: int, db: AsyncSession = Depends(get_db)):
    target = await db.get(Target, target_id)
    if not target:
        raise HTTPException(404, "Target not found")
    await db.delete(target)
    await db.commit()
