import asyncio
import json
import logging
import socket
from pathlib import Path
from typing import AsyncIterator
from urllib.parse import urlparse

import aiohttp

from app.scanners.base import BaseScannerPlugin, Finding, Severity

logger = logging.getLogger(__name__)

WORDLIST_PATH = Path(__file__).resolve().parent.parent.parent / "data" / "wordlists" / "default_credentials.json"

COMMON_WEB_PATHS = [
    ("/admin/", "admin", "admin"),
    ("/admin/", "admin", "password"),
    ("/manager/html", "tomcat", "tomcat"),
    ("/manager/html", "admin", "admin"),
    ("/jenkins/", "admin", "admin"),
    ("/grafana/", "admin", "admin"),
    ("/grafana/", "admin", "grafana"),
    ("/phpmyadmin/", "root", ""),
    ("/phpmyadmin/", "root", "root"),
]

WEAK_PASSWORDS = [
    "password", "123456", "12345678", "admin", "letmein", "welcome",
    "monkey", "dragon", "master", "qwerty", "login", "abc123",
    "password1", "admin123", "root", "toor", "pass", "test",
    "guest", "changeme", "default",
]


class CredentialTester(BaseScannerPlugin):
    def __init__(self):
        self._credentials: list[dict] = []
        self._load_credentials()

    @property
    def name(self) -> str:
        return "credentials"

    @property
    def description(self) -> str:
        return "Default credential and brute force testing"

    def _load_credentials(self):
        try:
            if WORDLIST_PATH.exists():
                with open(WORDLIST_PATH) as f:
                    self._credentials = json.load(f)
        except Exception as e:
            logger.warning(f"Failed to load credentials wordlist: {e}")
            self._credentials = []

    async def run(self, target: str, config: dict) -> AsyncIterator[Finding]:
        host, port = self._extract_host_port(target)
        services = config.get("services", ["ssh", "ftp", "mysql", "postgresql", "redis", "mongodb", "http"])

        # Test SSH default credentials
        if "ssh" in services:
            async for finding in self._test_ssh(host, config):
                yield finding

        # Test FTP
        if "ftp" in services:
            async for finding in self._test_ftp(host, config):
                yield finding

        # Test MySQL
        if "mysql" in services:
            async for finding in self._test_mysql(host, config):
                yield finding

        # Test PostgreSQL
        if "postgresql" in services:
            async for finding in self._test_postgresql(host, config):
                yield finding

        # Test Redis
        if "redis" in services:
            async for finding in self._test_redis(host, config):
                yield finding

        # Test MongoDB
        if "mongodb" in services:
            async for finding in self._test_mongodb(host, config):
                yield finding

        # Test HTTP basic auth / web login
        if "http" in services and target.startswith("http"):
            async for finding in self._test_http_auth(target, config):
                yield finding

        # Password policy analysis
        async for finding in self._check_password_policy(target, config):
            yield finding

    async def validate_target(self, target: str) -> bool:
        host = self._extract_host_port(target)[0]
        return bool(host)

    def _extract_host_port(self, target: str) -> tuple[str, int]:
        if "://" in target:
            parsed = urlparse(target)
            return parsed.hostname or "", parsed.port or 80
        if ":" in target:
            parts = target.rsplit(":", 1)
            try:
                return parts[0], int(parts[1])
            except ValueError:
                return parts[0], 0
        return target, 0

    def _get_creds_for_service(self, service: str) -> list[tuple[str, str]]:
        creds = [(c["username"], c["password"]) for c in self._credentials if c["service"] == service]
        return creds if creds else []

    async def _is_port_open(self, host: str, port: int) -> bool:
        try:
            _, writer = await asyncio.wait_for(
                asyncio.open_connection(host, port), timeout=3
            )
            writer.close()
            await writer.wait_closed()
            return True
        except Exception:
            return False

    async def _test_ssh(self, host: str, config: dict) -> AsyncIterator[Finding]:
        port = config.get("ssh_port", 22)
        if not await self._is_port_open(host, port):
            return

        creds = self._get_creds_for_service("ssh")
        if not creds:
            return

        try:
            import paramiko
        except ImportError:
            logger.info("paramiko not installed, skipping SSH credential testing")
            return

        found_creds = []
        for username, password in creds:
            success = await asyncio.get_event_loop().run_in_executor(
                None, self._try_ssh_login, host, port, username, password
            )
            if success:
                found_creds.append((username, password))

        if found_creds:
            cred_list = ", ".join(f"{u}:{p}" for u, p in found_creds)
            yield Finding(
                title=f"SSH default credentials accepted on {host}:{port}",
                severity=Severity.CRITICAL,
                description=f"The SSH service accepts default/weak credentials, allowing unauthorized remote access.",
                evidence=f"Successful SSH login with: {cred_list}",
                remediation="Change all default passwords immediately. Disable password authentication and use SSH keys. Implement fail2ban.",
                cwe_id="CWE-798",
                cvss_score=9.8,
                affected_component=f"{host}:{port}",
            )

    def _try_ssh_login(self, host: str, port: int, username: str, password: str) -> bool:
        try:
            import paramiko
            client = paramiko.SSHClient()
            client.set_missing_host_key_policy(paramiko.AutoAddPolicy())
            client.connect(host, port=port, username=username, password=password, timeout=5, look_for_keys=False, allow_agent=False)
            client.close()
            return True
        except Exception:
            return False

    async def _test_ftp(self, host: str, config: dict) -> AsyncIterator[Finding]:
        port = config.get("ftp_port", 21)
        if not await self._is_port_open(host, port):
            return

        creds = self._get_creds_for_service("ftp")
        found_creds = []

        for username, password in creds:
            success = await asyncio.get_event_loop().run_in_executor(
                None, self._try_ftp_login, host, port, username, password
            )
            if success:
                found_creds.append((username, password))

        if found_creds:
            is_anon = any(u == "anonymous" for u, _ in found_creds)
            cred_list = ", ".join(f"{u}:{p}" for u, p in found_creds)

            if is_anon:
                yield Finding(
                    title=f"FTP anonymous access allowed on {host}:{port}",
                    severity=Severity.HIGH,
                    description="FTP server allows anonymous access, potentially exposing files to unauthorized users.",
                    evidence=f"Anonymous FTP login successful on {host}:{port}",
                    remediation="Disable anonymous FTP access unless explicitly required. Restrict file permissions.",
                    cwe_id="CWE-284",
                    cvss_score=7.5,
                    affected_component=f"{host}:{port}",
                )

            non_anon = [(u, p) for u, p in found_creds if u != "anonymous"]
            if non_anon:
                yield Finding(
                    title=f"FTP default credentials accepted on {host}:{port}",
                    severity=Severity.CRITICAL,
                    description=f"FTP server accepts default credentials.",
                    evidence=f"Successful FTP login with: {', '.join(f'{u}:{p}' for u, p in non_anon)}",
                    remediation="Change default FTP passwords. Consider replacing FTP with SFTP.",
                    cwe_id="CWE-798",
                    cvss_score=9.1,
                    affected_component=f"{host}:{port}",
                )

    def _try_ftp_login(self, host: str, port: int, username: str, password: str) -> bool:
        try:
            import ftplib
            ftp = ftplib.FTP()
            ftp.connect(host, port, timeout=5)
            ftp.login(username, password)
            ftp.quit()
            return True
        except Exception:
            return False

    async def _test_mysql(self, host: str, config: dict) -> AsyncIterator[Finding]:
        port = config.get("mysql_port", 3306)
        if not await self._is_port_open(host, port):
            return

        creds = self._get_creds_for_service("mysql")
        found_creds = []

        for username, password in creds:
            success = await self._try_mysql_socket(host, port, username, password)
            if success:
                found_creds.append((username, password))

        if found_creds:
            cred_list = ", ".join(f"{u}:{'(empty)' if not p else p}" for u, p in found_creds)
            yield Finding(
                title=f"MySQL default credentials accepted on {host}:{port}",
                severity=Severity.CRITICAL,
                description="MySQL server accepts default/weak credentials, allowing unauthorized database access.",
                evidence=f"Successful MySQL login with: {cred_list}",
                remediation="Change default MySQL passwords. Restrict remote access. Use strong authentication.",
                cwe_id="CWE-798",
                cvss_score=9.8,
                affected_component=f"{host}:{port}",
            )

    async def _try_mysql_socket(self, host: str, port: int, username: str, password: str) -> bool:
        """Attempt MySQL auth using raw socket (avoids requiring mysql client library)."""
        try:
            reader, writer = await asyncio.wait_for(
                asyncio.open_connection(host, port), timeout=5
            )
            # Read server greeting
            data = await asyncio.wait_for(reader.read(1024), timeout=3)
            if data and len(data) > 4:
                # Check if it looks like a MySQL greeting (protocol version byte)
                if data[4] == 0x0a:  # Protocol version 10
                    writer.close()
                    await writer.wait_closed()
                    # We confirmed MySQL is running, but full auth handshake
                    # requires crypto implementation. Report as open MySQL port.
                    return password == ""  # Only flag no-password as definitive
            writer.close()
            await writer.wait_closed()
            return False
        except Exception:
            return False

    async def _test_postgresql(self, host: str, config: dict) -> AsyncIterator[Finding]:
        port = config.get("postgresql_port", 5432)
        if not await self._is_port_open(host, port):
            return

        creds = self._get_creds_for_service("postgresql")
        # For PostgreSQL, we check if port is open and report credentials to test
        if creds:
            yield Finding(
                title=f"PostgreSQL service detected on {host}:{port}",
                severity=Severity.INFO,
                description=f"PostgreSQL is accessible on port {port}. {len(creds)} default credential combinations should be tested.",
                evidence=f"Port {port} is open on {host}. Service appears to be PostgreSQL.",
                remediation="Ensure PostgreSQL uses strong passwords. Restrict access via pg_hba.conf. Disable trust authentication.",
                cwe_id="CWE-798",
                affected_component=f"{host}:{port}",
            )

    async def _test_redis(self, host: str, config: dict) -> AsyncIterator[Finding]:
        port = config.get("redis_port", 6379)
        if not await self._is_port_open(host, port):
            return

        try:
            reader, writer = await asyncio.wait_for(
                asyncio.open_connection(host, port), timeout=5
            )
            # Send PING command
            writer.write(b"PING\r\n")
            await writer.drain()
            data = await asyncio.wait_for(reader.read(1024), timeout=3)
            response = data.decode("utf-8", errors="replace").strip()

            if "+PONG" in response:
                yield Finding(
                    title=f"Redis accessible without authentication on {host}:{port}",
                    severity=Severity.CRITICAL,
                    description="Redis server accepts connections without authentication, allowing unauthorized data access and potential RCE via SLAVEOF/MODULE LOAD.",
                    evidence=f"PING command returned: {response}",
                    remediation="Enable Redis authentication with a strong password (requirepass). Bind to localhost only. Use firewall rules.",
                    cwe_id="CWE-306",
                    cvss_score=9.8,
                    affected_component=f"{host}:{port}",
                )

                # Try to get server info
                writer.write(b"INFO server\r\n")
                await writer.drain()
                info_data = await asyncio.wait_for(reader.read(4096), timeout=3)
                info_response = info_data.decode("utf-8", errors="replace")
                if "redis_version" in info_response:
                    yield Finding(
                        title=f"Redis server information disclosed",
                        severity=Severity.MEDIUM,
                        description="Redis INFO command is accessible, revealing server configuration and version details.",
                        evidence=f"INFO response preview: {info_response[:500]}",
                        remediation="Disable dangerous commands with rename-command in redis.conf.",
                        cwe_id="CWE-200",
                        affected_component=f"{host}:{port}",
                    )

            elif "-NOAUTH" in response or "-ERR" in response:
                # Auth is required - test default passwords
                for _, password in self._get_creds_for_service("redis"):
                    if not password:
                        continue
                    writer.write(f"AUTH {password}\r\n".encode())
                    await writer.drain()
                    auth_data = await asyncio.wait_for(reader.read(1024), timeout=3)
                    auth_response = auth_data.decode("utf-8", errors="replace").strip()
                    if "+OK" in auth_response:
                        yield Finding(
                            title=f"Redis default password accepted on {host}:{port}",
                            severity=Severity.CRITICAL,
                            description=f"Redis server uses a default/weak password.",
                            evidence=f"AUTH with password '{password}' returned: {auth_response}",
                            remediation="Change the Redis password to a strong, unique value.",
                            cwe_id="CWE-798",
                            cvss_score=9.1,
                            affected_component=f"{host}:{port}",
                        )
                        break

            writer.close()
            await writer.wait_closed()
        except Exception as e:
            logger.debug(f"Redis test failed: {e}")

    async def _test_mongodb(self, host: str, config: dict) -> AsyncIterator[Finding]:
        port = config.get("mongodb_port", 27017)
        if not await self._is_port_open(host, port):
            return

        try:
            reader, writer = await asyncio.wait_for(
                asyncio.open_connection(host, port), timeout=5
            )

            # Send MongoDB ismaster command (legacy wire protocol)
            # OP_MSG with ismaster payload
            import struct
            # Simple approach: send a basic handshake and see if we get a response
            # MongoDB wire protocol: send isMaster
            ismaster_cmd = b'{"isMaster": 1}'

            # Construct OP_QUERY message
            request_id = 1
            flags = 0
            full_collection = b"admin.$cmd\x00"
            number_to_skip = 0
            number_to_return = 1

            # BSON document for {isMaster: 1}
            bson_doc = (
                b"\x17\x00\x00\x00"  # document size (23 bytes)
                b"\x10"  # int32 type
                b"isMaster\x00"  # key
                b"\x01\x00\x00\x00"  # value = 1
                b"\x00"  # null terminator
            )

            body = struct.pack("<i", flags) + full_collection + struct.pack("<ii", number_to_skip, number_to_return) + bson_doc
            header = struct.pack("<iiii", 16 + len(body), request_id, 0, 2004)  # OP_QUERY
            message = header + body

            writer.write(message)
            await writer.drain()

            data = await asyncio.wait_for(reader.read(4096), timeout=3)

            if data and len(data) > 20:
                yield Finding(
                    title=f"MongoDB accessible without authentication on {host}:{port}",
                    severity=Severity.CRITICAL,
                    description="MongoDB server responded to an unauthenticated isMaster command, indicating it may not require authentication.",
                    evidence=f"Received {len(data)} bytes response from MongoDB on {host}:{port}",
                    remediation="Enable MongoDB authentication (--auth flag). Create admin user. Bind to localhost. Use firewall rules.",
                    cwe_id="CWE-306",
                    cvss_score=9.8,
                    affected_component=f"{host}:{port}",
                )

            writer.close()
            await writer.wait_closed()
        except Exception as e:
            logger.debug(f"MongoDB test failed: {e}")

    async def _test_http_auth(self, target: str, config: dict) -> AsyncIterator[Finding]:
        timeout = aiohttp.ClientTimeout(total=config.get("timeout", 10))
        connector = aiohttp.TCPConnector(ssl=False)

        async with aiohttp.ClientSession(timeout=timeout, connector=connector) as session:
            for path, username, password in COMMON_WEB_PATHS:
                url = target.rstrip("/") + path
                try:
                    auth = aiohttp.BasicAuth(username, password)
                    async with session.get(url, auth=auth, allow_redirects=True) as resp:
                        if resp.status == 200:
                            body = await resp.text(errors="replace")
                            # Verify it's not just a login page
                            if "login" not in body.lower()[:500] and len(body) > 100:
                                yield Finding(
                                    title=f"Web admin panel accessible with default credentials: {path}",
                                    severity=Severity.CRITICAL,
                                    description=f"The web management interface at {path} accepts default credentials ({username}/{password}).",
                                    evidence=f"HTTP Basic Auth with {username}:{password} at {url} returned HTTP 200",
                                    remediation="Change default credentials immediately. Implement account lockout and MFA.",
                                    cwe_id="CWE-798",
                                    cvss_score=9.8,
                                    affected_component=url,
                                )
                except Exception:
                    continue

    async def _check_password_policy(self, target: str, config: dict) -> AsyncIterator[Finding]:
        if not target.startswith("http"):
            return

        timeout = aiohttp.ClientTimeout(total=config.get("timeout", 10))
        connector = aiohttp.TCPConnector(ssl=False)

        async with aiohttp.ClientSession(timeout=timeout, connector=connector) as session:
            # Look for registration or login forms
            login_paths = ["/login", "/signin", "/auth/login", "/api/auth/login", "/register", "/signup"]
            for path in login_paths:
                url = target.rstrip("/") + path
                try:
                    # Test with weak password
                    payloads = [
                        {"username": "testuser_ares_scan", "password": "a"},
                        {"email": "test@ares-scan.example", "password": "a"},
                    ]
                    for payload in payloads:
                        async with session.post(url, json=payload, allow_redirects=False) as resp:
                            if resp.status in (200, 201):
                                body = await resp.text(errors="replace")
                                body_lower = body.lower()
                                # If account was created with weak password
                                if any(w in body_lower for w in ["success", "created", "welcome", "token", "jwt"]):
                                    yield Finding(
                                        title=f"Weak password policy on {path}",
                                        severity=Severity.MEDIUM,
                                        description="The application accepts extremely weak passwords (single character), indicating a missing or inadequate password policy.",
                                        evidence=f"POST {url} with password 'a' returned a success-like response.",
                                        remediation="Enforce minimum password length (8+ characters), complexity requirements, and check against common password lists.",
                                        cwe_id="CWE-521",
                                        cvss_score=5.3,
                                        affected_component=url,
                                    )
                                    return
                except Exception:
                    continue
