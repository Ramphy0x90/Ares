import asyncio
import socket
import logging
from typing import AsyncIterator
from urllib.parse import urlparse

from app.scanners.base import BaseScannerPlugin, Finding, Severity

logger = logging.getLogger(__name__)

TOP_100_PORTS = [
    21, 22, 23, 25, 53, 80, 110, 111, 135, 139,
    143, 161, 162, 199, 389, 443, 445, 465, 514, 515,
    548, 554, 587, 631, 636, 993, 995, 1025, 1080, 1099,
    1433, 1434, 1521, 1720, 1723, 2049, 2121, 2222, 2375, 2376,
    3000, 3128, 3306, 3389, 3690, 4443, 4848, 5000, 5432, 5555,
    5672, 5900, 5901, 5984, 5985, 5986, 6000, 6379, 6443, 6666,
    7001, 7002, 7070, 7443, 8000, 8008, 8009, 8080, 8081, 8083,
    8088, 8180, 8443, 8500, 8834, 8888, 9000, 9001, 9042, 9090,
    9100, 9200, 9300, 9418, 9999, 10000, 10250, 10443, 11211, 15672,
    27017, 27018, 28017, 44818, 47001, 49152, 49153, 49154, 50000, 50070,
]

SERVICE_NAMES = {
    21: "FTP", 22: "SSH", 23: "Telnet", 25: "SMTP", 53: "DNS",
    80: "HTTP", 110: "POP3", 111: "RPCbind", 135: "MSRPC", 139: "NetBIOS",
    143: "IMAP", 161: "SNMP", 389: "LDAP", 443: "HTTPS", 445: "SMB",
    465: "SMTPS", 514: "Syslog", 587: "SMTP-Sub", 636: "LDAPS", 993: "IMAPS",
    995: "POP3S", 1433: "MSSQL", 1521: "Oracle", 2049: "NFS", 2375: "Docker",
    2376: "Docker-TLS", 3306: "MySQL", 3389: "RDP", 5432: "PostgreSQL",
    5672: "AMQP", 5900: "VNC", 5984: "CouchDB", 5985: "WinRM",
    6379: "Redis", 6443: "K8s-API", 7001: "WebLogic", 8080: "HTTP-Proxy",
    8443: "HTTPS-Alt", 8500: "Consul", 8834: "Nessus", 9000: "SonarQube",
    9090: "Prometheus", 9200: "Elasticsearch", 9418: "Git", 10250: "Kubelet",
    11211: "Memcached", 15672: "RabbitMQ-Mgmt", 27017: "MongoDB",
    50000: "Jenkins", 50070: "HDFS",
}

RISKY_PORTS = {
    21: ("FTP may allow anonymous access or transmit credentials in cleartext", Severity.MEDIUM),
    23: ("Telnet transmits all data including credentials in cleartext", Severity.HIGH),
    135: ("MSRPC can expose Windows services to remote exploitation", Severity.MEDIUM),
    139: ("NetBIOS may allow null session enumeration", Severity.MEDIUM),
    445: ("SMB is a common target for ransomware and lateral movement", Severity.HIGH),
    2375: ("Docker API without TLS allows unauthenticated container management", Severity.CRITICAL),
    3389: ("RDP is a frequent brute-force and exploit target", Severity.MEDIUM),
    5900: ("VNC often runs without authentication or with weak passwords", Severity.HIGH),
    6379: ("Redis default configuration has no authentication", Severity.HIGH),
    9200: ("Elasticsearch default installation has no authentication", Severity.HIGH),
    11211: ("Memcached with no auth can be abused for DDoS amplification", Severity.HIGH),
    27017: ("MongoDB default installation has no authentication", Severity.HIGH),
}


class NetworkScanner(BaseScannerPlugin):
    @property
    def name(self) -> str:
        return "network"

    @property
    def description(self) -> str:
        return "Port scanning, service detection, and banner grabbing"

    async def run(self, target: str, config: dict) -> AsyncIterator[Finding]:
        host = self._extract_host(target)
        ports = config.get("ports", TOP_100_PORTS)
        timeout = config.get("timeout", 2)
        concurrency = config.get("concurrency", 50)

        open_ports: list[tuple[int, str]] = []
        semaphore = asyncio.Semaphore(concurrency)

        async def check_port(port: int):
            async with semaphore:
                result = await self._scan_port(host, port, timeout)
                if result is not None:
                    open_ports.append((port, result))

        tasks = [check_port(p) for p in ports]
        await asyncio.gather(*tasks)
        open_ports.sort(key=lambda x: x[0])

        if not open_ports:
            yield Finding(
                title="No open ports detected",
                severity=Severity.INFO,
                description=f"No open ports found on {host} from the scanned range.",
                evidence=f"Scanned {len(ports)} ports on {host}",
                remediation="No action needed. Verify scan was not blocked by firewall.",
                affected_component=host,
            )
            return

        port_summary = ", ".join(f"{p}/{SERVICE_NAMES.get(p, 'unknown')}" for p, _ in open_ports)
        yield Finding(
            title=f"Open ports discovered on {host}",
            severity=Severity.INFO,
            description=f"Found {len(open_ports)} open ports on {host}.",
            evidence=f"Open ports: {port_summary}",
            remediation="Review open ports and close unnecessary services. Apply firewall rules.",
            affected_component=host,
        )

        for port, banner in open_ports:
            if port in RISKY_PORTS:
                risk_desc, severity = RISKY_PORTS[port]
                svc = SERVICE_NAMES.get(port, f"port {port}")
                yield Finding(
                    title=f"Risky service detected: {svc} on port {port}",
                    severity=severity,
                    description=risk_desc,
                    evidence=f"Port {port} is open on {host}. Banner: {banner or 'N/A'}",
                    remediation=f"Restrict access to port {port} via firewall rules. Consider disabling {svc} if not required.",
                    cwe_id="CWE-200",
                    affected_component=f"{host}:{port}",
                )

            if banner:
                vuln = self._check_banner_vulnerabilities(host, port, banner)
                if vuln:
                    yield vuln

    async def validate_target(self, target: str) -> bool:
        host = self._extract_host(target)
        return bool(host)

    def _extract_host(self, target: str) -> str:
        if "://" in target:
            parsed = urlparse(target)
            return parsed.hostname or ""
        if ":" in target and not target.startswith("["):
            return target.split(":")[0]
        return target

    async def _scan_port(self, host: str, port: int, timeout: float) -> str | None:
        try:
            _, writer = await asyncio.wait_for(
                asyncio.open_connection(host, port),
                timeout=timeout,
            )
            banner = await self._grab_banner(host, port, writer, timeout)
            writer.close()
            try:
                await writer.wait_closed()
            except Exception:
                pass
            return banner
        except (asyncio.TimeoutError, OSError, ConnectionRefusedError):
            return None

    async def _grab_banner(self, host: str, port: int, writer, timeout: float) -> str:
        try:
            reader_writer = await asyncio.wait_for(
                asyncio.open_connection(host, port),
                timeout=timeout,
            )
            reader, w2 = reader_writer
            # Some services send banner on connect
            try:
                data = await asyncio.wait_for(reader.read(1024), timeout=min(timeout, 2))
                banner = data.decode("utf-8", errors="replace").strip()
            except asyncio.TimeoutError:
                banner = ""
            w2.close()
            try:
                await w2.wait_closed()
            except Exception:
                pass
            return banner
        except Exception:
            return ""

    def _check_banner_vulnerabilities(self, host: str, port: int, banner: str) -> Finding | None:
        banner_lower = banner.lower()

        # Check for version disclosure
        version_keywords = ["openssh", "apache", "nginx", "microsoft", "proftpd", "vsftpd", "mysql", "postgresql"]
        for keyword in version_keywords:
            if keyword in banner_lower:
                return Finding(
                    title=f"Service version disclosed on port {port}",
                    severity=Severity.LOW,
                    description=f"The service on port {port} discloses its version in the banner, aiding attacker reconnaissance.",
                    evidence=f"Banner: {banner}",
                    remediation="Configure the service to suppress version information in banners.",
                    cwe_id="CWE-200",
                    affected_component=f"{host}:{port}",
                )

        # Check for known vulnerable patterns
        if "openssh" in banner_lower:
            # Check for old SSH versions
            for old_ver in ["openssh_6.", "openssh_5.", "openssh_4.", "openssh_7.0", "openssh_7.1", "openssh_7.2"]:
                if old_ver in banner_lower.replace(" ", "_"):
                    return Finding(
                        title=f"Outdated OpenSSH version on port {port}",
                        severity=Severity.HIGH,
                        description="An outdated OpenSSH version was detected which may be vulnerable to known exploits.",
                        evidence=f"Banner: {banner}",
                        remediation="Update OpenSSH to the latest stable version.",
                        cwe_id="CWE-1104",
                        cvss_score=7.5,
                        affected_component=f"{host}:{port}",
                    )
        return None
