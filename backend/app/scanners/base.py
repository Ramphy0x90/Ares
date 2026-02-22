from abc import ABC, abstractmethod
from dataclasses import dataclass
from enum import Enum
from typing import AsyncIterator


class Severity(str, Enum):
    CRITICAL = "critical"
    HIGH = "high"
    MEDIUM = "medium"
    LOW = "low"
    INFO = "info"


@dataclass
class Finding:
    title: str
    severity: Severity
    description: str
    evidence: str
    remediation: str
    cwe_id: str | None = None
    cvss_score: float | None = None
    affected_component: str | None = None


class BaseScannerPlugin(ABC):
    """All scanner modules must implement this interface."""

    @property
    @abstractmethod
    def name(self) -> str:
        """Unique scanner identifier."""

    @property
    @abstractmethod
    def description(self) -> str:
        """Human-readable description."""

    @abstractmethod
    async def run(self, target: str, config: dict) -> AsyncIterator[Finding]:
        """Execute scan against target. Yields findings as discovered."""
        yield  # type: ignore

    @abstractmethod
    async def validate_target(self, target: str) -> bool:
        """Check if this scanner can handle the given target."""
