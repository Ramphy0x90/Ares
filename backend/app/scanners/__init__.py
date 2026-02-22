from app.scanners.base import BaseScannerPlugin, Finding, Severity
from app.scanners.registry import scanner_registry
from app.scanners.network_scanner import NetworkScanner
from app.scanners.web_vuln_scanner import WebVulnScanner
from app.scanners.llm_security_scanner import LLMSecurityScanner
from app.scanners.api_security_scanner import APISecurityScanner
from app.scanners.ssl_analyzer import SSLAnalyzer
from app.scanners.credential_tester import CredentialTester


def register_all_scanners():
    """Register all built-in scanner plugins."""
    scanners = [
        NetworkScanner(),
        WebVulnScanner(),
        LLMSecurityScanner(),
        APISecurityScanner(),
        SSLAnalyzer(),
        CredentialTester(),
    ]
    for scanner in scanners:
        scanner_registry.register(scanner)


# Auto-register on import
register_all_scanners()

__all__ = [
    "BaseScannerPlugin",
    "Finding",
    "Severity",
    "scanner_registry",
    "register_all_scanners",
    "NetworkScanner",
    "WebVulnScanner",
    "LLMSecurityScanner",
    "APISecurityScanner",
    "SSLAnalyzer",
    "CredentialTester",
]
