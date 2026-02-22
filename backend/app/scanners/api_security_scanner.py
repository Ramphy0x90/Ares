import asyncio
import json
import logging
import re
from typing import AsyncIterator
from urllib.parse import urljoin, urlparse

import aiohttp

from app.scanners.base import BaseScannerPlugin, Finding, Severity

logger = logging.getLogger(__name__)

COMMON_API_PATHS = [
    "swagger.json", "swagger/v1/swagger.json", "api-docs", "api-docs/",
    "openapi.json", "openapi.yaml", "v1/openapi.json", "v2/openapi.json",
    "docs", "docs/", "redoc", "redoc/",
    ".well-known/openapi.json", "api/swagger.json",
    "api/", "api/v1/", "api/v2/", "api/v3/",
    "graphql", "graphiql", "playground",
    "api/health", "api/status", "api/version", "api/info",
    "actuator", "actuator/health", "actuator/env", "actuator/beans",
    "debug", "debug/", "console", "console/",
    "admin/api", "internal/api", "private/api",
    "_catalog", "api/users", "api/admin",
    "wp-json/", "wp-json/wp/v2/users",
]

HTTP_METHODS = ["GET", "POST", "PUT", "DELETE", "PATCH", "OPTIONS", "HEAD"]


class APISecurityScanner(BaseScannerPlugin):
    @property
    def name(self) -> str:
        return "api_security"

    @property
    def description(self) -> str:
        return "API endpoint security testing"

    async def run(self, target: str, config: dict) -> AsyncIterator[Finding]:
        timeout = aiohttp.ClientTimeout(total=config.get("timeout", 10))
        connector = aiohttp.TCPConnector(ssl=False)

        async with aiohttp.ClientSession(timeout=timeout, connector=connector) as session:
            # Endpoint discovery
            async for finding in self._discover_endpoints(session, target, config):
                yield finding

            # CORS misconfiguration
            async for finding in self._check_cors(session, target):
                yield finding

            # HTTP method tampering
            async for finding in self._test_method_tampering(session, target, config):
                yield finding

            # Authentication bypass
            async for finding in self._test_auth_bypass(session, target, config):
                yield finding

            # Rate limit detection
            async for finding in self._test_rate_limiting(session, target, config):
                yield finding

            # Parameter pollution
            async for finding in self._test_parameter_pollution(session, target, config):
                yield finding

    async def validate_target(self, target: str) -> bool:
        return target.startswith("http://") or target.startswith("https://")

    async def _discover_endpoints(self, session: aiohttp.ClientSession, target: str, config: dict) -> AsyncIterator[Finding]:
        paths = config.get("api_paths", COMMON_API_PATHS)
        semaphore = asyncio.Semaphore(config.get("concurrency", 10))
        discovered = []

        async def check_path(path: str) -> tuple[str, int, str] | None:
            async with semaphore:
                url = urljoin(target.rstrip("/") + "/", path)
                try:
                    async with session.get(url, allow_redirects=False) as resp:
                        if resp.status in (200, 201, 301, 302):
                            body = ""
                            if resp.status == 200:
                                body = await resp.text(errors="replace")
                            return (path, resp.status, body[:500])
                except Exception:
                    pass
            return None

        tasks = [check_path(p) for p in paths]
        results = await asyncio.gather(*tasks)

        for result in results:
            if result:
                path, status, body = result
                discovered.append(path)

                # Check for Swagger/OpenAPI exposure
                if any(kw in path.lower() for kw in ["swagger", "openapi", "api-docs"]):
                    severity = Severity.MEDIUM
                    if body and ("paths" in body or "swagger" in body.lower() or "openapi" in body.lower()):
                        severity = Severity.HIGH
                        yield Finding(
                            title=f"API documentation endpoint exposed: /{path}",
                            severity=severity,
                            description="API documentation (Swagger/OpenAPI) is publicly accessible, revealing API structure, endpoints, and potentially sensitive schemas.",
                            evidence=f"GET {urljoin(target, path)} returned HTTP {status}\nBody preview: {body[:300]}",
                            remediation="Restrict API documentation to authenticated users or internal networks only.",
                            cwe_id="CWE-200",
                            cvss_score=5.3,
                            affected_component=urljoin(target, path),
                        )
                    continue

                # Check for Spring Boot Actuator
                if "actuator" in path.lower():
                    yield Finding(
                        title=f"Spring Boot Actuator endpoint exposed: /{path}",
                        severity=Severity.HIGH,
                        description="Spring Boot Actuator endpoints are accessible, potentially exposing environment variables, configuration, and health information.",
                        evidence=f"GET {urljoin(target, path)} returned HTTP {status}\nBody preview: {body[:300]}",
                        remediation="Restrict Actuator endpoints to management port only or require authentication.",
                        cwe_id="CWE-200",
                        cvss_score=7.5,
                        affected_component=urljoin(target, path),
                    )
                    continue

                # Check for GraphQL
                if "graphql" in path.lower() or "graphiql" in path.lower():
                    yield Finding(
                        title=f"GraphQL endpoint discovered: /{path}",
                        severity=Severity.MEDIUM,
                        description="A GraphQL endpoint was found. If introspection is enabled, the full API schema can be extracted.",
                        evidence=f"GET {urljoin(target, path)} returned HTTP {status}",
                        remediation="Disable introspection in production. Implement query depth limiting and cost analysis.",
                        cwe_id="CWE-200",
                        affected_component=urljoin(target, path),
                    )
                    continue

                # Check for user data endpoints
                if "users" in path.lower() and body and ('"email"' in body or '"username"' in body):
                    yield Finding(
                        title=f"User data endpoint accessible without auth: /{path}",
                        severity=Severity.HIGH,
                        description="A user data API endpoint is accessible without authentication, potentially leaking user information.",
                        evidence=f"GET {urljoin(target, path)} returned HTTP {status}\nBody preview: {body[:300]}",
                        remediation="Require authentication for all user data endpoints. Implement proper access controls.",
                        cwe_id="CWE-284",
                        cvss_score=7.5,
                        affected_component=urljoin(target, path),
                    )
                    continue

        if discovered:
            yield Finding(
                title=f"Discovered {len(discovered)} API endpoints",
                severity=Severity.INFO,
                description=f"Found {len(discovered)} accessible API paths during enumeration.",
                evidence="Paths: " + ", ".join(f"/{p}" for p in discovered),
                remediation="Review all discovered endpoints and ensure proper authentication and authorization.",
                affected_component=target,
            )

    async def _check_cors(self, session: aiohttp.ClientSession, target: str) -> AsyncIterator[Finding]:
        test_origins = [
            "https://evil.com",
            "https://attacker.example.com",
            "null",
        ]

        for origin in test_origins:
            try:
                headers = {"Origin": origin}
                async with session.get(target, headers=headers) as resp:
                    acao = resp.headers.get("Access-Control-Allow-Origin", "")
                    acac = resp.headers.get("Access-Control-Allow-Credentials", "")

                    if acao == "*":
                        yield Finding(
                            title="CORS wildcard origin allowed",
                            severity=Severity.MEDIUM,
                            description="The API allows requests from any origin (Access-Control-Allow-Origin: *). While this alone may be acceptable for public APIs, it can be problematic if combined with credential-based access.",
                            evidence=f"Origin: {origin}\nAccess-Control-Allow-Origin: {acao}\nAccess-Control-Allow-Credentials: {acac}",
                            remediation="Restrict CORS to trusted domains. Never use wildcard with Allow-Credentials.",
                            cwe_id="CWE-942",
                            cvss_score=5.3,
                            affected_component=target,
                        )
                        return

                    if acao == origin and origin != "null":
                        severity = Severity.HIGH if acac.lower() == "true" else Severity.MEDIUM
                        yield Finding(
                            title="CORS reflects arbitrary origin",
                            severity=severity,
                            description=f"The API reflects the Origin header as Access-Control-Allow-Origin, allowing any website to make cross-origin requests.{' Credentials are also allowed, enabling full CSRF-style attacks.' if acac.lower() == 'true' else ''}",
                            evidence=f"Origin: {origin}\nAccess-Control-Allow-Origin: {acao}\nAccess-Control-Allow-Credentials: {acac}",
                            remediation="Validate the Origin header against an allow-list of trusted domains.",
                            cwe_id="CWE-942",
                            cvss_score=8.0 if acac.lower() == "true" else 5.3,
                            affected_component=target,
                        )
                        return

                    if acao == "null":
                        yield Finding(
                            title="CORS allows null origin",
                            severity=Severity.MEDIUM,
                            description="The API allows the 'null' origin, which can be triggered from sandboxed iframes or local files.",
                            evidence=f"Origin: null\nAccess-Control-Allow-Origin: null",
                            remediation="Do not allow 'null' as a valid origin in CORS configuration.",
                            cwe_id="CWE-942",
                            cvss_score=5.3,
                            affected_component=target,
                        )
                        return
            except Exception:
                continue

    async def _test_method_tampering(self, session: aiohttp.ClientSession, target: str, config: dict) -> AsyncIterator[Finding]:
        test_url = config.get("method_test_url", target)

        try:
            # First get baseline with GET
            async with session.get(test_url) as get_resp:
                get_status = get_resp.status

            # Try other methods
            unexpected_methods = []
            for method in ["PUT", "DELETE", "PATCH"]:
                try:
                    async with session.request(method, test_url) as resp:
                        if resp.status not in (404, 405, 401, 403, 501):
                            unexpected_methods.append((method, resp.status))
                except Exception:
                    continue

            if unexpected_methods:
                methods_str = ", ".join(f"{m} ({s})" for m, s in unexpected_methods)
                yield Finding(
                    title="Unexpected HTTP methods accepted",
                    severity=Severity.MEDIUM,
                    description=f"The endpoint accepts HTTP methods beyond GET: {methods_str}. This may indicate insufficient method filtering.",
                    evidence=f"URL: {test_url}\nAccepted methods: {methods_str}",
                    remediation="Restrict HTTP methods to only those required. Return 405 Method Not Allowed for unsupported methods.",
                    cwe_id="CWE-749",
                    affected_component=test_url,
                )

            # Check OPTIONS for allowed methods
            try:
                async with session.options(test_url) as resp:
                    allow = resp.headers.get("Allow", "")
                    if allow and any(m in allow.upper() for m in ["DELETE", "PUT", "TRACE"]):
                        yield Finding(
                            title="Potentially dangerous methods listed in OPTIONS response",
                            severity=Severity.LOW,
                            description=f"The OPTIONS response advertises methods that may be dangerous if not properly secured.",
                            evidence=f"Allow: {allow}",
                            remediation="Review and restrict advertised methods. Ensure all methods require proper authorization.",
                            cwe_id="CWE-749",
                            affected_component=test_url,
                        )
            except Exception:
                pass
        except Exception as e:
            logger.warning(f"Method tampering test failed: {e}")

    async def _test_auth_bypass(self, session: aiohttp.ClientSession, target: str, config: dict) -> AsyncIterator[Finding]:
        protected_paths = config.get("protected_paths", [
            "api/admin", "api/users", "api/v1/admin", "admin",
            "api/v1/users/me", "api/profile", "api/settings",
        ])

        bypass_headers = [
            {"X-Forwarded-For": "127.0.0.1"},
            {"X-Originating-IP": "127.0.0.1"},
            {"X-Real-IP": "127.0.0.1"},
            {"X-Custom-IP-Authorization": "127.0.0.1"},
            {"X-Forwarded-Host": "localhost"},
        ]

        for path in protected_paths:
            url = urljoin(target.rstrip("/") + "/", path)

            # Test without auth
            try:
                async with session.get(url) as resp:
                    if resp.status == 200:
                        body = await resp.text(errors="replace")
                        if len(body) > 50 and "login" not in body.lower()[:200]:
                            yield Finding(
                                title=f"Authentication bypass: /{path} accessible without auth",
                                severity=Severity.HIGH,
                                description=f"The protected endpoint /{path} is accessible without authentication.",
                                evidence=f"GET {url} returned HTTP 200\nBody preview: {body[:200]}",
                                remediation="Require authentication for all protected endpoints. Implement middleware-level auth checks.",
                                cwe_id="CWE-306",
                                cvss_score=7.5,
                                affected_component=url,
                            )
                            continue
            except Exception:
                continue

            # Test with IP spoofing headers
            for headers in bypass_headers:
                try:
                    async with session.get(url, headers=headers) as resp:
                        if resp.status == 200:
                            body = await resp.text(errors="replace")
                            if len(body) > 50 and "login" not in body.lower()[:200]:
                                header_name = list(headers.keys())[0]
                                yield Finding(
                                    title=f"Auth bypass via {header_name} header on /{path}",
                                    severity=Severity.CRITICAL,
                                    description=f"The protected endpoint /{path} can be accessed by setting {header_name}: 127.0.0.1, bypassing authentication.",
                                    evidence=f"GET {url} with {headers} returned HTTP 200",
                                    remediation=f"Do not trust {header_name} for access control decisions. Implement proper authentication.",
                                    cwe_id="CWE-290",
                                    cvss_score=9.8,
                                    affected_component=url,
                                )
                                break
                except Exception:
                    continue

    async def _test_rate_limiting(self, session: aiohttp.ClientSession, target: str, config: dict) -> AsyncIterator[Finding]:
        rate_limit_url = config.get("rate_limit_url", target)
        num_requests = config.get("rate_limit_requests", 50)

        try:
            statuses = []
            for _ in range(num_requests):
                try:
                    async with session.get(rate_limit_url) as resp:
                        statuses.append(resp.status)
                        if resp.status == 429:
                            break
                except Exception:
                    break

            rate_limited = 429 in statuses
            if not rate_limited and len(statuses) >= num_requests:
                yield Finding(
                    title="No rate limiting detected",
                    severity=Severity.MEDIUM,
                    description=f"Sent {num_requests} requests without receiving a 429 Too Many Requests response. The API may be vulnerable to brute force and DoS attacks.",
                    evidence=f"Sent {num_requests} GET requests to {rate_limit_url}. All returned non-429 status codes. Status distribution: {dict((s, statuses.count(s)) for s in set(statuses))}",
                    remediation="Implement rate limiting (e.g., 100 requests/minute per IP). Use API gateway or middleware like express-rate-limit, FastAPI SlowAPI.",
                    cwe_id="CWE-770",
                    cvss_score=5.3,
                    affected_component=rate_limit_url,
                )
            elif rate_limited:
                idx = statuses.index(429)
                yield Finding(
                    title="Rate limiting is active",
                    severity=Severity.INFO,
                    description=f"Rate limiting triggered after {idx + 1} requests.",
                    evidence=f"Received 429 after {idx + 1} requests to {rate_limit_url}.",
                    remediation="Verify rate limits are appropriately configured for all endpoints.",
                    affected_component=rate_limit_url,
                )
        except Exception as e:
            logger.warning(f"Rate limit test failed: {e}")

    async def _test_parameter_pollution(self, session: aiohttp.ClientSession, target: str, config: dict) -> AsyncIterator[Finding]:
        test_url = config.get("param_pollution_url", target)
        parsed = urlparse(test_url)

        # Test HTTP Parameter Pollution
        test_cases = [
            ("id", "1&id=2", "Parameter pollution with duplicate 'id'"),
            ("role", "user&role=admin", "Privilege escalation via parameter pollution"),
            ("price", "100&price=0", "Price manipulation via parameter pollution"),
        ]

        for param, value, description in test_cases:
            try:
                separator = "&" if "?" in test_url else "?"
                polluted_url = f"{test_url}{separator}{param}={value}"

                async with session.get(polluted_url) as resp:
                    if resp.status == 200:
                        body = await resp.text(errors="replace")
                        # Check if server-side processing accepted the duplicated param
                        if "admin" in body.lower() and "role" in param:
                            yield Finding(
                                title=f"HTTP parameter pollution: {description}",
                                severity=Severity.HIGH,
                                description=f"The server appears to process duplicate parameters in a way that could be exploited. {description}.",
                                evidence=f"URL: {polluted_url}\nHTTP {resp.status}\nBody preview: {body[:300]}",
                                remediation="Validate and deduplicate HTTP parameters server-side. Use the first or last parameter value consistently.",
                                cwe_id="CWE-235",
                                cvss_score=6.5,
                                affected_component=test_url,
                            )
            except Exception:
                continue
