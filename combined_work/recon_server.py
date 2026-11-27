
import ftplib
import socket
import subprocess
import json
import requests

from mcp.server.fastmcp import FastMCP


# ============================================================
# 1. SERVER CONFIGURATION AND AUTHORIZED SCOPE
# ============================================================

ALLOWED_TARGETS = {"127.0.0.1"}
ALLOWED_WEB_PORTS = {3000}

mcp = FastMCP("ReconServer")


def _check_service_scope(target: str) -> str | None:
    """Validate the target for service-side reconnaissance."""

    normalized = target.strip() if isinstance(target, str) else ""

    if normalized not in ALLOWED_TARGETS:
        return (
            f"REFUSED: Target '{target}' is outside the authorized "
            f"allowlist {sorted(ALLOWED_TARGETS)}."
        )

    return None


def _check_web_scope(target: str, port: int) -> str | None:
    """Validate the target and port for web-side reconnaissance."""

    normalized = target.strip() if isinstance(target, str) else ""

    if normalized not in ALLOWED_TARGETS or port not in ALLOWED_WEB_PORTS:
        return "REFUSED: Target or port is outside the authorized web lab scope."

    return None


# ============================================================
# 2. SERVICE-SIDE RECONNAISSANCE TOOLS
# ============================================================

@mcp.tool()
def banner_grab(target: str, port: int, timeout: float = 2.0) -> str:
    """Connect to an allowlisted TCP target and read its initial service banner."""

    denied = _check_service_scope(target)
    if denied:
        return denied

    host = target.strip()

    try:
        with socket.create_connection(
            (host, int(port)), timeout=timeout
        ) as sock:
            sock.settimeout(timeout)

            try:
                data = sock.recv(1024)
                banner = data.decode("utf-8", errors="replace").strip()
            except TimeoutError:
                banner = "<connected, no immediate banner sent>"

        return f"target={host} port={port} state=open banner={banner!r}"

    except Exception as exc:
        return f"target={host} port={port} error={exc}"


@mcp.tool()
def anonymous_ftp_check(
    target: str, port: int = 2121, timeout: float = 3.0
) -> str:
    """Check whether an allowlisted FTP service permits anonymous login."""

    denied = _check_service_scope(target)
    if denied:
        return denied

    host = target.strip()
    ftp = ftplib.FTP()

    try:
        ftp.connect(host, int(port), timeout=timeout)
        welcome = ftp.getwelcome()
        login_resp = ftp.login()

        try:
            listing = ftp.nlst()[:10]
        except Exception:
            listing = []

        return (
            f"target={host} port={port} anonymous_login=ALLOWED "
            f"welcome={welcome!r} response={login_resp!r} "
            f"sample_entries={listing}"
        )

    except ftplib.error_perm as exc:
        return (
            f"target={host} port={port} "
            f"anonymous_login=DENIED detail={exc}"
        )

    except Exception as exc:
        return f"target={host} port={port} error={exc}"

    finally:
        try:
            ftp.quit()
        except Exception:
            pass


@mcp.tool()
def http_probe(
    target: str, port: int = 8080,
    path: str = "/", timeout: float = 3.0
) -> str:
    """Send a read-only HTTP GET request and inspect response information."""

    denied = _check_service_scope(target)
    if denied:
        return denied

    host = target.strip()
    clean_path = path if path.startswith("/") else f"/{path}"
    url = f"http://{host}:{int(port)}{clean_path}"

    try:
        response = requests.get(
            url,
            headers={"User-Agent": "MCP-Recon-Lab/1.0"},
            timeout=timeout,
            allow_redirects=False
        )

        headers = response.headers
        body = response.text[:512].strip()

        return (
            f"url={url} status={response.status_code} "
            f"server={headers.get('Server', '<none>')} "
            f"x_powered_by={headers.get('X-Powered-By', '<none>')} "
            f"body_preview={body!r}"
        )

    except requests.RequestException as exc:
        return f"url={url} error={exc}"


@mcp.tool()
def nmap_service_scan(
    target: str, ports: str = "2121,8080"
) -> str:
    """Run a read-only Nmap service/version scan against an allowlisted target."""

    denied = _check_service_scope(target)
    if denied:
        return denied

    host = target.strip()

    try:
        proc = subprocess.run(
            ["nmap", "-sV", "-Pn", "-p", str(ports), host],
            capture_output=True,
            text=True,
            timeout=60
        )

        return proc.stdout.strip() or proc.stderr.strip()

    except FileNotFoundError:
        return "ERROR: 'nmap' binary not found in PATH."

    except Exception as exc:
        return f"ERROR running nmap: {exc}"


# ============================================================
# 3. WEB-SIDE RECONNAISSANCE TOOLS
# ============================================================

@mcp.tool()
def scan_http_headers(
    target: str = "127.0.0.1",
    port: int = 3000
) -> str:
    """Inspect HTTP responses for common security headers."""

    denied = _check_web_scope(target, port)
    if denied:
        return denied

    target = target.strip()
    url = f"http://{target}:{port}/"

    try:
        response = requests.get(
            url,
            timeout=5,
            allow_redirects=False
        )

        headers = response.headers

        expected_headers = {
            "Content-Security-Policy": None,
            "X-Frame-Options": None,
            "X-Content-Type-Options": "nosniff",
            "Referrer-Policy": None,
            "Permissions-Policy": None
        }

        findings = []

        for header, expected_value in expected_headers.items():
            actual_value = headers.get(header)

            if actual_value is None:
                findings.append({
                    "header": header,
                    "status": "MISSING",
                    "observed_value": None,
                    "finding": f"{header} was not present in the response."
                })

            elif expected_value and actual_value.lower() != expected_value.lower():
                findings.append({
                    "header": header,
                    "status": "MISCONFIGURED",
                    "observed_value": actual_value,
                    "finding": (
                        f"{header} was present but did not have "
                        f"the expected value '{expected_value}'."
                    )
                })

            else:
                findings.append({
                    "header": header,
                    "status": "PRESENT",
                    "observed_value": actual_value,
                    "finding": f"{header} was present."
                })

        return json.dumps({
            "scanner": "HTTP Security Header Scanner",
            "target": url,
            "http_status": response.status_code,
            "findings": findings
        }, indent=2)

    except requests.RequestException as exc:
        return json.dumps({
            "scanner": "HTTP Security Header Scanner",
            "target": url,
            "error": str(exc)
        }, indent=2)


@mcp.tool()
def enumerate_http_methods(
    target: str = "127.0.0.1",
    port: int = 3000
) -> str:
    """Identify HTTP methods advertised by the target using OPTIONS."""

    denied = _check_web_scope(target, port)
    if denied:
        return denied

    target = target.strip()
    url = f"http://{target}:{port}/"

    try:
        response = requests.options(
            url,
            timeout=5,
            allow_redirects=False
        )

        allow_header = response.headers.get("Allow")

        if allow_header:
            methods = [
                method.strip().upper()
                for method in allow_header.split(",")
                if method.strip()
            ]
            status = "ADVERTISED"
        else:
            methods = []
            status = "NOT_ADVERTISED"

        return json.dumps({
            "scanner": "HTTP Method Enumeration",
            "target": url,
            "http_status": response.status_code,
            "allow_header": allow_header,
            "advertised_methods": methods,
            "status": status
        }, indent=2)

    except requests.RequestException as exc:
        return json.dumps({
            "scanner": "HTTP Method Enumeration",
            "target": url,
            "error": str(exc)
        }, indent=2)


@mcp.tool()
def analyze_cookie_security(
    target: str = "127.0.0.1",
    port: int = 3000
) -> str:
    """Inspect cookies returned by the target for security attributes."""

    denied = _check_web_scope(target, port)
    if denied:
        return denied

    target = target.strip()
    url = f"http://{target}:{port}/"

    try:
        response = requests.get(
            url,
            timeout=5,
            allow_redirects=False
        )

        set_cookie_headers = response.raw.headers.getlist("Set-Cookie")

        cookies = []

        for cookie_header in set_cookie_headers:
            parts = [
                part.strip() for part in cookie_header.split(";")
            ]

            name_value = parts[0]
            cookie_name = name_value.split("=", 1)[0]

            attributes = {}

            for part in parts[1:]:
                if "=" in part:
                    key, value = part.split("=", 1)
                    attributes[key.strip().lower()] = value.strip()
                else:
                    attributes[part.lower()] = True

            http_only = "httponly" in attributes
            secure = "secure" in attributes
            same_site = attributes.get("samesite")

            cookies.append({
                "cookie_name": cookie_name,
                "httponly": http_only,
                "secure": secure,
                "samesite": same_site,
                "findings": [
                    finding
                    for finding, condition in [
                        ("HttpOnly attribute is missing", not http_only),
                        ("Secure attribute is missing", not secure),
                        ("SameSite attribute is missing", same_site is None)
                    ]
                    if condition
                ]
            })

        return json.dumps({
            "scanner": "Cookie Security Analyzer",
            "target": url,
            "http_status": response.status_code,
            "cookies_found": len(cookies),
            "cookies": cookies
        }, indent=2)

    except requests.RequestException as exc:
        return json.dumps({
            "scanner": "Cookie Security Analyzer",
            "target": url,
            "error": str(exc)
        }, indent=2)


# ============================================================
# 4. START COMBINED MCP SERVER
# ============================================================

if __name__ == "__main__":
    mcp.run(transport="stdio")