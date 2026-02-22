import asyncio
from datetime import datetime

from sqlalchemy.ext.asyncio import AsyncSession

from app.models.scan import Scan
from app.models.vulnerability import Vulnerability
from app.scanners.base import BaseScannerPlugin, Finding
from app.services.ws_manager import ws_manager


class ScanService:
    def __init__(self):
        self._tasks: dict[int, asyncio.Task] = {}

    def _get_scanner(self, name: str) -> BaseScannerPlugin | None:
        from app.scanners.registry import scanner_registry
        return scanner_registry.get(name)

    async def execute_scan(self, scan_id: int, target: str, scanner_names: list[str], config: dict, session_factory):
        async with session_factory() as db:
            scan = await db.get(Scan, scan_id)
            scan.status = "running"
            scan.started_at = datetime.utcnow()
            await db.commit()

            try:
                total = len(scanner_names)
                for idx, name in enumerate(scanner_names):
                    scanner = self._get_scanner(name)
                    if not scanner:
                        continue
                    await ws_manager.broadcast(scan_id, {"type": "scanner_start", "scanner": name, "progress": idx / total})
                    async for finding in scanner.run(target, config):
                        vuln = Vulnerability(
                            scan_id=scan_id,
                            title=finding.title,
                            severity=finding.severity.value,
                            description=finding.description,
                            evidence=finding.evidence,
                            remediation=finding.remediation,
                            cwe_id=finding.cwe_id,
                            cvss_score=finding.cvss_score,
                            affected_component=finding.affected_component,
                            scanner_name=name,
                        )
                        db.add(vuln)
                        await db.commit()
                        await db.refresh(vuln)
                        await ws_manager.broadcast(scan_id, {"type": "finding", "data": {"id": vuln.id, "title": vuln.title, "severity": vuln.severity}})
                    await ws_manager.broadcast(scan_id, {"type": "scanner_complete", "scanner": name, "progress": (idx + 1) / total})

                scan.status = "completed"
                scan.progress = 1.0
            except asyncio.CancelledError:
                scan.status = "cancelled"
            except Exception as e:
                scan.status = "failed"
                scan.error_message = str(e)
            finally:
                scan.completed_at = datetime.utcnow()
                await db.commit()
                await ws_manager.broadcast(scan_id, {"type": "scan_complete", "status": scan.status})

    def start_scan(self, scan_id: int, target: str, scanner_names: list[str], config: dict, session_factory):
        task = asyncio.create_task(self.execute_scan(scan_id, target, scanner_names, config, session_factory))
        self._tasks[scan_id] = task
        return task

    async def stop_scan(self, scan_id: int):
        task = self._tasks.get(scan_id)
        if task and not task.done():
            task.cancel()


scan_service = ScanService()
