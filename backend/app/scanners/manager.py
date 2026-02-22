from app.scanners.base import BaseScannerPlugin, Finding
from app.scanners.registry import scanner_registry
from typing import AsyncIterator


class ScanManager:
    """Orchestrates running scanners against targets."""

    async def run_scanners(self, target: str, scanner_names: list[str], config: dict) -> AsyncIterator[Finding]:
        for name in scanner_names:
            scanner = scanner_registry.get(name)
            if scanner is None:
                continue
            if not await scanner.validate_target(target):
                continue
            async for finding in scanner.run(target, config):
                yield finding
