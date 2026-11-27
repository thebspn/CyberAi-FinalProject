import requests
import json
from mcp.server.fastmcp import FastMCP

# 1. Configuration and scope validation
ALLOWED_TARGETS = {"127.0.0.1"}
ALLOWED_PORTS = {3000}

mcp = FastMCP("WebReconServer")


def _check_scope(target: str, port: int) -> str | None:
    """Ensure the target is within the authorized lab scope."""
    if target not in ALLOWED_TARGETS or port not in ALLOWED_PORTS:
        return "REFUSED: Target is outside the authorized lab scope."
    return None



@mcp.tool()
def scan_http_headers(
    target: str = "127.0.0.1",
    port: int = 3000
) -> str:
    """ Inspect HTTP responses for common security headers.
        Returns observed headers and potential security findings.
    """

    # Verify that the target is within the authorized scope
    denied = _check_scope(target, port)
    if denied:
        return denied

    url = f"http://{target}:{port}/"

    try:
        # Send a read-only GET request
        response = requests.get(
            url,
            timeout=5,
            allow_redirects=False
        )

        headers = response.headers

        # Headers to inspect
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


# 3. Scanner 2: HTTP method enumeration
@mcp.tool()
def enumerate_http_methods(
    target: str = "127.0.0.1",
    port: int = 3000
) -> str:
    """ Identify HTTP methods advertised by the target using an OPTIONS request.
        Returns the HTTP status and advertised methods.
    """

    # Verify that the target is within the authorized scope
    denied = _check_scope(target, port)
    if denied:
        return denied

    url = f"http://{target}:{port}/"

    try:
        # Send a read-only OPTIONS request
        response = requests.options(
            url,
            timeout=5,
            allow_redirects=False
        )

        # Retrieve the Allow header
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



# 4. Scanner 3: Cookie security analysis
@mcp.tool()
def analyze_cookie_security(
    target: str = "127.0.0.1",
    port: int = 3000
) -> str:
    """Inspect cookies returned by the target for HttpOnly, Secure, and SameSite security attributes."""

    # Verify that the target is within the authorized scope
    denied = _check_scope(target, port)
    if denied:
        return denied

    url = f"http://{target}:{port}/"

    try:
        # Send a read-only GET request
        response = requests.get(
            url,
            timeout=5,
            allow_redirects=False
        )

        # Retrieve individual Set-Cookie headers
        set_cookie_headers = response.raw.headers.getlist("Set-Cookie")

        cookies = []

        for cookie_header in set_cookie_headers:

            # Separate the cookie name/value from its attributes
            parts = [part.strip() for part in cookie_header.split(";")]

            name_value = parts[0]
            cookie_name = name_value.split("=", 1)[0]

            attributes = {}

            for part in parts[1:]:
                if "=" in part:
                    key, value = part.split("=", 1)
                    attributes[key.strip().lower()] = value.strip()
                else:
                    attributes[part.lower()] = True

            # Check security attributes
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


# 5. Start MCP server
if __name__ == "__main__":
    mcp.run(transport="stdio")