from app.scanners.base import BaseScannerPlugin


class ScannerRegistry:
    def __init__(self):
        self._scanners: dict[str, BaseScannerPlugin] = {}

    def register(self, scanner: BaseScannerPlugin):
        self._scanners[scanner.name] = scanner

    def get(self, name: str) -> BaseScannerPlugin | None:
        return self._scanners.get(name)

    def list_scanners(self) -> list[BaseScannerPlugin]:
        return list(self._scanners.values())


scanner_registry = ScannerRegistry()
