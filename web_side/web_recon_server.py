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
    """
    Inspect HTTP responses for common security headers.
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
def enumerate_http_methods(target: str = "127.0.0.1",
                           port: int = 3000) -> str:
    """Identify HTTP methods advertised by the target."""
    # Scanner implementation goes here


# 4. Scanner 3: Cookie security analysis
@mcp.tool()
def analyze_cookie_security(target: str = "127.0.0.1",
                            port: int = 3000) -> str:
    """Inspect cookies for HttpOnly, Secure, and SameSite attributes."""
    # Scanner implementation goes here


# 5. Start MCP server
if __name__ == "__main__":
    mcp.run(transport="stdio")