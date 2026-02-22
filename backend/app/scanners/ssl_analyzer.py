import asyncio
import datetime
import logging
import ssl
import socket
from typing import AsyncIterator
from urllib.parse import urlparse

import aiohttp

from app.scanners.base import BaseScannerPlugin, Finding, Severity

logger = logging.getLogger(__name__)

WEAK_CIPHERS = [
    "RC4", "DES", "3DES", "MD5", "NULL", "EXPORT", "anon",
    "RC2", "IDEA", "SEED", "CAMELLIA128",
]

DEPRECATED_PROTOCOLS = {
    ssl.PROTOCOL_TLSv1: "TLSv1.0",
    ssl.PROTOCOL_TLSv1_1: "TLSv1.1",
} if hasattr(ssl, "PROTOCOL_TLSv1") else {}

TLS_PROTOCOL_CHECKS = [
    ("TLSv1.0", ssl.TLSVersion.TLSv1 if hasattr(ssl.TLSVersion, "TLSv1") else None, Severity.HIGH),
    ("TLSv1.1", ssl.TLSVersion.TLSv1_1 if hasattr(ssl.TLSVersion, "TLSv1_1") else None, Severity.MEDIUM),
]


class SSLAnalyzer(BaseScannerPlugin):
    @property
    def name(self) -> str:
        return "ssl"

    @property
    def description(self) -> str:
        return "TLS/SSL certificate and cipher analysis"

    async def run(self, target: str, config: dict) -> AsyncIterator[Finding]:
        host, port = self._extract_host_port(target)
        if not host:
            return

        # Certificate checks
        async for finding in self._check_certificate(host, port):
            yield finding

        # TLS version checks
        async for finding in self._check_tls_versions(host, port):
            yield finding

        # Cipher suite analysis
        async for finding in self._check_ciphers(host, port):
            yield finding

        # HSTS check (if HTTP target)
        if target.startswith("http"):
            async for finding in self._check_hsts(target):
                yield finding

    async def validate_target(self, target: str) -> bool:
        host = self._extract_host_port(target)[0]
        return bool(host)

    def _extract_host_port(self, target: str) -> tuple[str, int]:
        if "://" in target:
            parsed = urlparse(target)
            host = parsed.hostname or ""
            port = parsed.port or (443 if parsed.scheme == "https" else 443)
            return host, port
        if ":" in target:
            parts = target.rsplit(":", 1)
            try:
                return parts[0], int(parts[1])
            except ValueError:
                return parts[0], 443
        return target, 443

    async def _check_certificate(self, host: str, port: int) -> AsyncIterator[Finding]:
        try:
            cert_info = await asyncio.get_event_loop().run_in_executor(
                None, self._get_cert_info, host, port
            )
            if cert_info is None:
                yield Finding(
                    title=f"Cannot retrieve SSL certificate from {host}:{port}",
                    severity=Severity.HIGH,
                    description="Failed to establish TLS connection or retrieve certificate.",
                    evidence=f"Connection to {host}:{port} failed during TLS handshake.",
                    remediation="Ensure TLS is properly configured on the server.",
                    cwe_id="CWE-295",
                    affected_component=f"{host}:{port}",
                )
                return

            # Check expiry
            not_after = cert_info.get("notAfter", "")
            if not_after:
                try:
                    expiry = datetime.datetime.strptime(not_after, "%b %d %H:%M:%S %Y %Z")
                    now = datetime.datetime.utcnow()
                    days_left = (expiry - now).days

                    if days_left < 0:
                        yield Finding(
                            title=f"SSL certificate expired",
                            severity=Severity.CRITICAL,
                            description=f"The certificate for {host} expired {abs(days_left)} days ago on {not_after}.",
                            evidence=f"Certificate notAfter: {not_after}\nExpired {abs(days_left)} days ago.",
                            remediation="Renew the SSL certificate immediately.",
                            cwe_id="CWE-298",
                            cvss_score=9.0,
                            affected_component=f"{host}:{port}",
                        )
                    elif days_left < 30:
                        yield Finding(
                            title=f"SSL certificate expiring soon ({days_left} days)",
                            severity=Severity.MEDIUM,
                            description=f"The certificate for {host} expires in {days_left} days on {not_after}.",
                            evidence=f"Certificate notAfter: {not_after}\n{days_left} days remaining.",
                            remediation="Renew the SSL certificate before expiry. Consider using automated renewal (e.g., Let's Encrypt with certbot).",
                            cwe_id="CWE-298",
                            affected_component=f"{host}:{port}",
                        )
                    elif days_left < 90:
                        yield Finding(
                            title=f"SSL certificate expires in {days_left} days",
                            severity=Severity.LOW,
                            description=f"The certificate for {host} expires on {not_after} ({days_left} days remaining).",
                            evidence=f"Certificate notAfter: {not_after}",
                            remediation="Plan certificate renewal. Enable automated renewal.",
                            cwe_id="CWE-298",
                            affected_component=f"{host}:{port}",
                        )
                except ValueError:
                    pass

            # Check subject/SAN mismatch
            subject = dict(x[0] for x in cert_info.get("subject", ()))
            cn = subject.get("commonName", "")
            san_list = [entry[1] for entry in cert_info.get("subjectAltName", ())]

            if host != cn and host not in san_list:
                # Check wildcard
                wildcard_match = any(
                    s.startswith("*.") and host.endswith(s[1:]) for s in [cn] + san_list
                )
                if not wildcard_match:
                    yield Finding(
                        title="SSL certificate hostname mismatch",
                        severity=Severity.HIGH,
                        description=f"The certificate CN '{cn}' and SANs do not match the host '{host}'.",
                        evidence=f"Host: {host}\nCN: {cn}\nSANs: {', '.join(san_list)}",
                        remediation="Obtain a certificate that includes the correct hostname.",
                        cwe_id="CWE-295",
                        cvss_score=7.4,
                        affected_component=f"{host}:{port}",
                    )

            # Check self-signed
            issuer = dict(x[0] for x in cert_info.get("issuer", ()))
            issuer_cn = issuer.get("commonName", "")
            if issuer_cn == cn:
                yield Finding(
                    title="Self-signed SSL certificate detected",
                    severity=Severity.MEDIUM,
                    description=f"The certificate for {host} appears to be self-signed (issuer CN matches subject CN).",
                    evidence=f"Subject CN: {cn}\nIssuer CN: {issuer_cn}",
                    remediation="Use a certificate signed by a trusted Certificate Authority.",
                    cwe_id="CWE-295",
                    cvss_score=5.9,
                    affected_component=f"{host}:{port}",
                )

            # Check weak signature algorithm
            sig_alg = cert_info.get("signatureAlgorithm", "")
            if sig_alg and any(weak in sig_alg.lower() for weak in ["sha1", "md5", "md2"]):
                yield Finding(
                    title=f"Weak certificate signature algorithm: {sig_alg}",
                    severity=Severity.HIGH,
                    description=f"The certificate uses a weak signature algorithm ({sig_alg}) which is vulnerable to collision attacks.",
                    evidence=f"Signature algorithm: {sig_alg}",
                    remediation="Reissue the certificate with SHA-256 or stronger signature algorithm.",
                    cwe_id="CWE-328",
                    cvss_score=7.4,
                    affected_component=f"{host}:{port}",
                )

        except Exception as e:
            logger.warning(f"Certificate check failed for {host}:{port}: {e}")

    def _get_cert_info(self, host: str, port: int) -> dict | None:
        try:
            ctx = ssl.create_default_context()
            with socket.create_connection((host, port), timeout=10) as sock:
                with ctx.wrap_socket(sock, server_hostname=host) as ssock:
                    cert = ssock.getpeercert()
                    return cert
        except ssl.SSLCertVerificationError:
            # Try again without verification to still get cert info
            try:
                ctx = ssl.create_default_context()
                ctx.check_hostname = False
                ctx.verify_mode = ssl.CERT_NONE
                with socket.create_connection((host, port), timeout=10) as sock:
                    with ctx.wrap_socket(sock, server_hostname=host) as ssock:
                        # With CERT_NONE, getpeercert() returns empty dict
                        # Use getpeercert(binary_form=True) and parse
                        return ssock.getpeercert(binary_form=False) or {"_verification_failed": True}
            except Exception:
                return None
        except Exception:
            return None

    async def _check_tls_versions(self, host: str, port: int) -> AsyncIterator[Finding]:
        for protocol_name, tls_version, severity in TLS_PROTOCOL_CHECKS:
            if tls_version is None:
                continue
            supported = await asyncio.get_event_loop().run_in_executor(
                None, self._test_tls_version, host, port, tls_version
            )
            if supported:
                yield Finding(
                    title=f"Deprecated TLS version supported: {protocol_name}",
                    severity=severity,
                    description=f"The server supports {protocol_name}, which is deprecated and has known vulnerabilities.",
                    evidence=f"Successfully connected to {host}:{port} using {protocol_name}.",
                    remediation=f"Disable {protocol_name} on the server. Only allow TLS 1.2 and TLS 1.3.",
                    cwe_id="CWE-326",
                    cvss_score=7.4 if severity == Severity.HIGH else 5.3,
                    affected_component=f"{host}:{port}",
                )

    def _test_tls_version(self, host: str, port: int, tls_version) -> bool:
        try:
            ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
            ctx.check_hostname = False
            ctx.verify_mode = ssl.CERT_NONE
            ctx.minimum_version = tls_version
            ctx.maximum_version = tls_version
            with socket.create_connection((host, port), timeout=5) as sock:
                with ctx.wrap_socket(sock, server_hostname=host) as ssock:
                    return True
        except Exception:
            return False

    async def _check_ciphers(self, host: str, port: int) -> AsyncIterator[Finding]:
        try:
            weak_found = await asyncio.get_event_loop().run_in_executor(
                None, self._get_weak_ciphers, host, port
            )
            if weak_found:
                yield Finding(
                    title="Weak cipher suites supported",
                    severity=Severity.MEDIUM,
                    description=f"The server supports weak cipher suites: {', '.join(weak_found)}",
                    evidence=f"Weak ciphers detected on {host}:{port}: {', '.join(weak_found)}",
                    remediation="Disable weak cipher suites. Use only AEAD ciphers (AES-GCM, ChaCha20-Poly1305). Configure cipher preference order.",
                    cwe_id="CWE-326",
                    cvss_score=5.3,
                    affected_component=f"{host}:{port}",
                )
        except Exception as e:
            logger.debug(f"Cipher check failed: {e}")

    def _get_weak_ciphers(self, host: str, port: int) -> list[str]:
        weak = []
        try:
            ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
            ctx.check_hostname = False
            ctx.verify_mode = ssl.CERT_NONE
            with socket.create_connection((host, port), timeout=5) as sock:
                with ctx.wrap_socket(sock, server_hostname=host) as ssock:
                    cipher = ssock.cipher()
                    if cipher:
                        cipher_name = cipher[0]
                        for weak_pattern in WEAK_CIPHERS:
                            if weak_pattern.upper() in cipher_name.upper():
                                weak.append(cipher_name)
                                break
        except Exception:
            pass
        return weak

    async def _check_hsts(self, target: str) -> AsyncIterator[Finding]:
        try:
            timeout = aiohttp.ClientTimeout(total=10)
            connector = aiohttp.TCPConnector(ssl=False)
            async with aiohttp.ClientSession(timeout=timeout, connector=connector) as session:
                # Check HTTPS version
                https_target = target.replace("http://", "https://") if target.startswith("http://") else target
                async with session.get(https_target, allow_redirects=True) as resp:
                    hsts = resp.headers.get("Strict-Transport-Security", "")
                    if not hsts:
                        yield Finding(
                            title="HSTS header missing",
                            severity=Severity.MEDIUM,
                            description="The HTTPS response does not include a Strict-Transport-Security header, leaving users vulnerable to SSL stripping attacks.",
                            evidence=f"No Strict-Transport-Security header in response from {https_target}",
                            remediation="Add 'Strict-Transport-Security: max-age=31536000; includeSubDomains; preload' header.",
                            cwe_id="CWE-319",
                            cvss_score=5.4,
                            affected_component=https_target,
                        )
                    else:
                        # Check max-age value
                        import re
                        max_age_match = re.search(r"max-age=(\d+)", hsts)
                        if max_age_match:
                            max_age = int(max_age_match.group(1))
                            if max_age < 31536000:  # Less than 1 year
                                yield Finding(
                                    title=f"HSTS max-age is short ({max_age} seconds)",
                                    severity=Severity.LOW,
                                    description=f"HSTS max-age is set to {max_age} seconds ({max_age // 86400} days). Recommended minimum is 1 year (31536000 seconds).",
                                    evidence=f"Strict-Transport-Security: {hsts}",
                                    remediation="Increase max-age to at least 31536000 (1 year). Consider adding includeSubDomains and preload directives.",
                                    cwe_id="CWE-319",
                                    affected_component=https_target,
                                )

                        if "includesubdomains" not in hsts.lower():
                            yield Finding(
                                title="HSTS missing includeSubDomains directive",
                                severity=Severity.LOW,
                                description="HSTS header does not include the includeSubDomains directive, leaving subdomains vulnerable to downgrade attacks.",
                                evidence=f"Strict-Transport-Security: {hsts}",
                                remediation="Add includeSubDomains to the HSTS header.",
                                cwe_id="CWE-319",
                                affected_component=https_target,
                            )

                # Check HTTP -> HTTPS redirect
                if target.startswith("https://"):
                    http_target = target.replace("https://", "http://")
                    try:
                        async with session.get(http_target, allow_redirects=False) as resp:
                            if resp.status not in (301, 302, 307, 308):
                                yield Finding(
                                    title="HTTP does not redirect to HTTPS",
                                    severity=Severity.MEDIUM,
                                    description="The HTTP version of the site does not redirect to HTTPS, allowing unencrypted connections.",
                                    evidence=f"GET {http_target} returned HTTP {resp.status} instead of a redirect.",
                                    remediation="Configure the web server to redirect all HTTP requests to HTTPS.",
                                    cwe_id="CWE-319",
                                    affected_component=http_target,
                                )
                    except Exception:
                        pass
        except Exception as e:
            logger.warning(f"HSTS check failed: {e}")
