from fastapi import APIRouter, Depends

from app.api.v1 import targets, scans, vulnerabilities, reports, scan_configs, dashboard, ws, exploits
from app.auth import get_current_user

v1_router = APIRouter()

_auth = [Depends(get_current_user)]

v1_router.include_router(targets.router, prefix="/targets", tags=["targets"], dependencies=_auth)
v1_router.include_router(scans.router, prefix="/scans", tags=["scans"], dependencies=_auth)
v1_router.include_router(vulnerabilities.router, prefix="/vulnerabilities", tags=["vulnerabilities"], dependencies=_auth)
v1_router.include_router(reports.router, prefix="/reports", tags=["reports"], dependencies=_auth)
v1_router.include_router(scan_configs.router, prefix="/scan-configs", tags=["scan-configs"], dependencies=_auth)
v1_router.include_router(dashboard.router, prefix="/dashboard", tags=["dashboard"], dependencies=_auth)
v1_router.include_router(exploits.router, prefix="/exploits", tags=["exploits"], dependencies=_auth)
v1_router.include_router(ws.router, tags=["websocket"])
