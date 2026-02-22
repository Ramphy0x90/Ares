import asyncio
import logging
import re
from typing import AsyncIterator
from urllib.parse import urlparse, urljoin, quote

import aiohttp

from app.scanners.base import BaseScannerPlugin, Finding, Severity

logger = logging.getLogger(__name__)

XSS_PAYLOADS = [
    '<script>alert("XSS")</script>',
    '"><img src=x onerror=alert(1)>',
    "'-alert(1)-'",
    "<svg/onload=alert(1)>",
    "javascript:alert(1)",
    '"><svg/onload=alert(String.fromCharCode(88,83,83))>',
    "{{7*7}}",
    "${7*7}",
    "<img src=x onerror=prompt(1)>",
    "'-confirm(1)-'",
    '<details open ontoggle=alert(1)>',
    '<body onload=alert(1)>',
]

SQLI_PAYLOADS = [
    "' OR '1'='1",
    "' OR '1'='1' --",
    "' OR '1'='1' /*",
    "1' ORDER BY 1--",
    "1' UNION SELECT NULL--",
    "1; DROP TABLE users--",
    "' AND 1=1--",
    "' AND 1=2--",
    "admin'--",
    "1' WAITFOR DELAY '0:0:5'--",
    "1' AND SLEEP(5)--",
    "') OR ('1'='1",
]

SQLI_ERROR_PATTERNS = [
    r"sql syntax",
    r"mysql_fetch",
    r"mysqli_",
    r"pg_query",
    r"sqlite3?\.OperationalError",
    r"ORA-\d{5}",
    r"Microsoft OLE DB Provider",
    r"ODBC SQL Server Driver",
    r"unclosed quotation mark",
    r"quoted string not properly terminated",
    r"SQL command not properly ended",
    r"PostgreSQL.*ERROR",
    r"Warning.*mysql_",
    r"valid MySQL result",
    r"MySqlClient",
    r"com\.mysql\.jdbc",
]

TRAVERSAL_PAYLOADS = [
    "../../../../etc/passwd",
    "..\\..\\..\\..\\windows\\system32\\drivers\\etc\\hosts",
    "....//....//....//etc/passwd",
    "..%2f..%2f..%2fetc%2fpasswd",
    "%2e%2e/%2e%2e/%2e%2e/etc/passwd",
    "..%252f..%252f..%252fetc/passwd",
]

TRAVERSAL_SUCCESS_PATTERNS = [
    r"root:.*:0:0:",
    r"\[extensions\]",
    r"\[boot loader\]",
]

COMMON_DIRS = [
    ".git/HEAD", ".env", ".svn/entries", "wp-admin/", "wp-login.php",
    "admin/", "administrator/", "phpmyadmin/", "server-status", "server-info",
    ".htaccess", "robots.txt", "sitemap.xml", "crossdomain.xml",
    "backup/", "backups/", "db/", "database/", "dump/", "sql/",
    "api/", "api/v1/", "swagger.json", "openapi.json", "api-docs/",
    ".well-known/security.txt", "config.php.bak", "web.config",
]

SECURITY_HEADERS = {
    "Strict-Transport-Security": {
        "severity": Severity.MEDIUM,
        "description": "HTTP Strict Transport Security (HSTS) header is missing. This allows downgrade attacks and cookie hijacking.",
        "remediation": "Add 'Strict-Transport-Security: max-age=31536000; includeSubDomains' header.",
        "cwe_id": "CWE-319",
    },
    "Content-Security-Policy": {
        "severity": Severity.MEDIUM,
        "description": "Content Security Policy (CSP) header is missing. This increases the risk of XSS attacks.",
        "remediation": "Implement a Content-Security-Policy header to restrict resource loading sources.",
        "cwe_id": "CWE-79",
    },
    "X-Frame-Options": {
        "severity": Severity.LOW,
        "description": "X-Frame-Options header is missing. The page may be vulnerable to clickjacking attacks.",
        "remediation": "Add 'X-Frame-Options: DENY' or 'X-Frame-Options: SAMEORIGIN' header.",
        "cwe_id": "CWE-1021",
    },
    "X-Content-Type-Options": {
        "severity": Severity.LOW,
        "description": "X-Content-Type-Options header is missing. Browsers may MIME-sniff responses, leading to XSS.",
        "remediation": "Add 'X-Content-Type-Options: nosniff' header.",
        "cwe_id": "CWE-16",
    },
    "X-XSS-Protection": {
        "severity": Severity.INFO,
        "description": "X-XSS-Protection header is not set. While deprecated in modern browsers, it provides defense-in-depth for older browsers.",
        "remediation": "Add 'X-XSS-Protection: 1; mode=block' header.",
        "cwe_id": "CWE-79",
    },
    "Referrer-Policy": {
        "severity": Severity.LOW,
        "description": "Referrer-Policy header is missing. Sensitive URLs may leak via the Referer header.",
        "remediation": "Add 'Referrer-Policy: strict-origin-when-cross-origin' header.",
        "cwe_id": "CWE-200",
    },
    "Permissions-Policy": {
        "severity": Severity.LOW,
        "description": "Permissions-Policy header is missing. Browser features like camera, microphone, geolocation are not restricted.",
        "remediation": "Add Permissions-Policy header to restrict browser feature access.",
        "cwe_id": "CWE-16",
    },
}

OPEN_REDIRECT_PAYLOADS = [
    "https://evil.com",
    "//evil.com",
    "/\\evil.com",
    "https:evil.com",
    "///evil.com",
]

REDIRECT_PARAMS = ["url", "redirect", "next", "return", "returnUrl", "redirect_uri", "go", "target", "rurl", "dest"]


class WebVulnScanner(BaseScannerPlugin):
    @property
    def name(self) -> str:
        return "web_vuln"

    @property
    def description(self) -> str:
        return "OWASP Top 10 web vulnerability checks"

    async def run(self, target: str, config: dict) -> AsyncIterator[Finding]:
        timeout = aiohttp.ClientTimeout(total=config.get("timeout", 10))
        connector = aiohttp.TCPConnector(ssl=False)

        async with aiohttp.ClientSession(timeout=timeout, connector=connector) as session:
            # Security headers
            async for finding in self._check_security_headers(session, target):
                yield finding

            # Cookie security
            async for finding in self._check_cookie_security(session, target):
                yield finding

            # Directory/file discovery
            async for finding in self._check_sensitive_files(session, target, config):
                yield finding

            # XSS detection
            async for finding in self._test_xss(session, target, config):
                yield finding

            # SQL injection
            async for finding in self._test_sqli(session, target, config):
                yield finding

            # Directory traversal
            async for finding in self._test_traversal(session, target, config):
                yield finding

            # Open redirect
            async for finding in self._test_open_redirect(session, target):
                yield finding

            # CSRF token check
            async for finding in self._check_csrf(session, target):
                yield finding

    async def validate_target(self, target: str) -> bool:
        return target.startswith("http://") or target.startswith("https://")

    async def _check_security_headers(self, session: aiohttp.ClientSession, target: str) -> AsyncIterator[Finding]:
        try:
            async with session.get(target, allow_redirects=True) as resp:
                headers = resp.headers
                for header_name, info in SECURITY_HEADERS.items():
                    if header_name.lower() not in {k.lower() for k in headers.keys()}:
                        yield Finding(
                            title=f"Missing security header: {header_name}",
                            severity=info["severity"],
                            description=info["description"],
                            evidence=f"Response from {target} does not include {header_name} header.",
                            remediation=info["remediation"],
                            cwe_id=info["cwe_id"],
                            affected_component=target,
                        )

                # Check for dangerous headers
                server = headers.get("Server", "")
                if server:
                    yield Finding(
                        title="Server header reveals technology",
                        severity=Severity.LOW,
                        description="The Server header discloses backend technology, aiding attacker fingerprinting.",
                        evidence=f"Server: {server}",
                        remediation="Remove or obfuscate the Server header.",
                        cwe_id="CWE-200",
                        affected_component=target,
                    )

                x_powered = headers.get("X-Powered-By", "")
                if x_powered:
                    yield Finding(
                        title="X-Powered-By header reveals technology",
                        severity=Severity.LOW,
                        description="The X-Powered-By header discloses backend technology.",
                        evidence=f"X-Powered-By: {x_powered}",
                        remediation="Remove the X-Powered-By header.",
                        cwe_id="CWE-200",
                        affected_component=target,
                    )
        except Exception as e:
            logger.warning(f"Header check failed for {target}: {e}")

    async def _check_cookie_security(self, session: aiohttp.ClientSession, target: str) -> AsyncIterator[Finding]:
        try:
            async with session.get(target, allow_redirects=True) as resp:
                for cookie_header in resp.headers.getall("Set-Cookie", []):
                    cookie_lower = cookie_header.lower()
                    cookie_name = cookie_header.split("=")[0].strip()

                    if "secure" not in cookie_lower and target.startswith("https"):
                        yield Finding(
                            title=f"Cookie '{cookie_name}' missing Secure flag",
                            severity=Severity.MEDIUM,
                            description="Cookie can be transmitted over unencrypted HTTP, risking interception.",
                            evidence=f"Set-Cookie: {cookie_header}",
                            remediation="Add the Secure flag to all cookies on HTTPS sites.",
                            cwe_id="CWE-614",
                            affected_component=target,
                        )

                    if "httponly" not in cookie_lower:
                        yield Finding(
                            title=f"Cookie '{cookie_name}' missing HttpOnly flag",
                            severity=Severity.LOW,
                            description="Cookie is accessible via JavaScript, increasing XSS impact.",
                            evidence=f"Set-Cookie: {cookie_header}",
                            remediation="Add the HttpOnly flag to cookies that don't need JavaScript access.",
                            cwe_id="CWE-1004",
                            affected_component=target,
                        )

                    if "samesite" not in cookie_lower:
                        yield Finding(
                            title=f"Cookie '{cookie_name}' missing SameSite attribute",
                            severity=Severity.LOW,
                            description="Cookie may be sent in cross-site requests, enabling CSRF.",
                            evidence=f"Set-Cookie: {cookie_header}",
                            remediation="Add 'SameSite=Lax' or 'SameSite=Strict' attribute.",
                            cwe_id="CWE-1275",
                            affected_component=target,
                        )
        except Exception as e:
            logger.warning(f"Cookie check failed for {target}: {e}")

    async def _check_sensitive_files(self, session: aiohttp.ClientSession, target: str, config: dict) -> AsyncIterator[Finding]:
        dirs = config.get("directories", COMMON_DIRS)
        semaphore = asyncio.Semaphore(config.get("concurrency", 10))

        async def check_path(path: str) -> Finding | None:
            async with semaphore:
                url = urljoin(target.rstrip("/") + "/", path)
                try:
                    async with session.get(url, allow_redirects=False) as resp:
                        if resp.status == 200:
                            body = await resp.text(errors="replace")
                            # Verify it's not a generic 404 page
                            if len(body) > 0 and "not found" not in body.lower()[:200]:
                                severity = Severity.HIGH if path.startswith(".git") or path == ".env" else Severity.MEDIUM
                                return Finding(
                                    title=f"Sensitive file/directory accessible: {path}",
                                    severity=severity,
                                    description=f"The path /{path} is publicly accessible and may expose sensitive information.",
                                    evidence=f"GET {url} returned HTTP {resp.status}. Body preview: {body[:200]}",
                                    remediation=f"Restrict access to /{path} via web server configuration or remove it from the web root.",
                                    cwe_id="CWE-538",
                                    affected_component=url,
                                )
                except Exception:
                    pass
            return None

        tasks = [check_path(d) for d in dirs]
        results = await asyncio.gather(*tasks)
        for r in results:
            if r:
                yield r

    async def _test_xss(self, session: aiohttp.ClientSession, target: str, config: dict) -> AsyncIterator[Finding]:
        test_params = config.get("xss_params", ["q", "search", "query", "s", "keyword", "name", "input", "value"])
        max_payloads = config.get("max_xss_payloads", 5)

        for param in test_params:
            for payload in XSS_PAYLOADS[:max_payloads]:
                url = f"{target.rstrip('/')}?{param}={quote(payload)}"
                try:
                    async with session.get(url, allow_redirects=True) as resp:
                        body = await resp.text(errors="replace")
                        if payload in body:
                            yield Finding(
                                title=f"Reflected XSS via parameter '{param}'",
                                severity=Severity.HIGH,
                                description=f"The parameter '{param}' reflects user input without sanitization, enabling cross-site scripting.",
                                evidence=f"Payload: {payload}\nURL: {url}\nPayload found reflected in response body.",
                                remediation="Sanitize and encode all user input before reflecting it in HTML. Implement Content-Security-Policy.",
                                cwe_id="CWE-79",
                                cvss_score=6.1,
                                affected_component=url,
                            )
                            break  # One finding per param is enough
                except Exception:
                    continue

    async def _test_sqli(self, session: aiohttp.ClientSession, target: str, config: dict) -> AsyncIterator[Finding]:
        test_params = config.get("sqli_params", ["id", "user", "name", "query", "search", "page", "category"])
        max_payloads = config.get("max_sqli_payloads", 5)

        for param in test_params:
            for payload in SQLI_PAYLOADS[:max_payloads]:
                url = f"{target.rstrip('/')}?{param}={quote(payload)}"
                try:
                    async with session.get(url, allow_redirects=True) as resp:
                        body = await resp.text(errors="replace")
                        for pattern in SQLI_ERROR_PATTERNS:
                            if re.search(pattern, body, re.IGNORECASE):
                                yield Finding(
                                    title=f"SQL injection detected via parameter '{param}'",
                                    severity=Severity.CRITICAL,
                                    description=f"The parameter '{param}' appears vulnerable to SQL injection. Database error messages were returned.",
                                    evidence=f"Payload: {payload}\nURL: {url}\nMatched pattern: {pattern}",
                                    remediation="Use parameterized queries / prepared statements. Never concatenate user input into SQL.",
                                    cwe_id="CWE-89",
                                    cvss_score=9.8,
                                    affected_component=url,
                                )
                                break
                        else:
                            continue
                        break  # Found SQLi for this param
                except Exception:
                    continue

    async def _test_traversal(self, session: aiohttp.ClientSession, target: str, config: dict) -> AsyncIterator[Finding]:
        test_params = config.get("traversal_params", ["file", "path", "page", "doc", "template", "include", "dir"])

        for param in test_params:
            for payload in TRAVERSAL_PAYLOADS:
                url = f"{target.rstrip('/')}?{param}={quote(payload)}"
                try:
                    async with session.get(url, allow_redirects=True) as resp:
                        body = await resp.text(errors="replace")
                        for pattern in TRAVERSAL_SUCCESS_PATTERNS:
                            if re.search(pattern, body):
                                yield Finding(
                                    title=f"Directory traversal via parameter '{param}'",
                                    severity=Severity.CRITICAL,
                                    description=f"The parameter '{param}' is vulnerable to path traversal, allowing reading of arbitrary files.",
                                    evidence=f"Payload: {payload}\nURL: {url}\nFile contents found in response.",
                                    remediation="Validate and sanitize file paths. Use an allow-list of permitted files. Avoid user input in file paths.",
                                    cwe_id="CWE-22",
                                    cvss_score=9.1,
                                    affected_component=url,
                                )
                                break
                        else:
                            continue
                        break
                except Exception:
                    continue

    async def _test_open_redirect(self, session: aiohttp.ClientSession, target: str) -> AsyncIterator[Finding]:
        for param in REDIRECT_PARAMS:
            for payload in OPEN_REDIRECT_PAYLOADS:
                url = f"{target.rstrip('/')}?{param}={quote(payload)}"
                try:
                    async with session.get(url, allow_redirects=False) as resp:
                        if resp.status in (301, 302, 303, 307, 308):
                            location = resp.headers.get("Location", "")
                            if "evil.com" in location:
                                yield Finding(
                                    title=f"Open redirect via parameter '{param}'",
                                    severity=Severity.MEDIUM,
                                    description=f"The parameter '{param}' allows redirecting users to arbitrary external URLs.",
                                    evidence=f"URL: {url}\nRedirected to: {location}",
                                    remediation="Validate redirect URLs against an allow-list of permitted domains. Use relative paths.",
                                    cwe_id="CWE-601",
                                    cvss_score=4.7,
                                    affected_component=url,
                                )
                                break
                except Exception:
                    continue

    async def _check_csrf(self, session: aiohttp.ClientSession, target: str) -> AsyncIterator[Finding]:
        try:
            async with session.get(target, allow_redirects=True) as resp:
                body = await resp.text(errors="replace")
                # Look for forms without CSRF tokens
                forms = re.findall(r"<form[^>]*>.*?</form>", body, re.DOTALL | re.IGNORECASE)
                for form in forms:
                    form_lower = form.lower()
                    if "method=\"post\"" in form_lower or "method='post'" in form_lower:
                        has_csrf = any(
                            tok in form_lower
                            for tok in ["csrf", "_token", "authenticity_token", "__requestverificationtoken", "antiforgery"]
                        )
                        if not has_csrf:
                            yield Finding(
                                title="POST form without CSRF token",
                                severity=Severity.MEDIUM,
                                description="A form using POST method was found without a CSRF token, making it vulnerable to cross-site request forgery.",
                                evidence=f"Form found at {target}: {form[:300]}...",
                                remediation="Add CSRF tokens to all state-changing forms. Use SameSite cookie attributes.",
                                cwe_id="CWE-352",
                                cvss_score=5.4,
                                affected_component=target,
                            )
                            break  # One CSRF finding per page
        except Exception as e:
            logger.warning(f"CSRF check failed: {e}")
