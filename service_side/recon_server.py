import ftplib
import socket
import subprocess
import urllib.error
import urllib.request
from mcp.server.fastmcp import FastMCP

ALLOWED_TARGETS = {"127.0.0.1"}

mcp = FastMCP("ServiceReconServer")


def _check_scope(target: str) -> str | None:
    """Fail-closed allowlist check. Returns an error string if out of scope."""
    normalized = target.strip() if isinstance(target, str) else ""
    if normalized not in ALLOWED_TARGETS:
        return (
            f"REFUSED: Target '{target}' is outside the authorized allowlist "
            f"{sorted(ALLOWED_TARGETS)}."
        )
    return None


@mcp.tool()
def banner_grab(target: str, port: int, timeout: float = 2.0) -> str:
    """Connect to a TCP port on an allowlisted target and read any initial service banner."""
    denied = _check_scope(target)
    if denied:
        return denied

    host = target.strip()
    try:
        with socket.create_connection((host, int(port)), timeout=timeout) as sock:
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
def anonymous_ftp_check(target: str, port: int = 2121, timeout: float = 3.0) -> str:
    """Check whether an FTP service on an allowlisted target allows anonymous login (read-only check)."""
    denied = _check_scope(target)
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
            f"welcome={welcome!r} response={login_resp!r} sample_entries={listing}"
        )
    except ftplib.error_perm as exc:
        return f"target={host} port={port} anonymous_login=DENIED detail={exc}"
    except Exception as exc:
        return f"target={host} port={port} error={exc}"
    finally:
        try:
            ftp.quit()
        except Exception:
            pass


@mcp.tool()
def http_probe(target: str, port: int = 8080, path: str = "/", timeout: float = 3.0) -> str:
    """Send a read-only HTTP GET request to an allowlisted target and inspect status, Server header, and body preview."""
    denied = _check_scope(target)
    if denied:
        return denied

    host = target.strip()
    clean_path = path if path.startswith("/") else f"/{path}"
    url = f"http://{host}:{int(port)}{clean_path}"
    req = urllib.request.Request(url, headers={"User-Agent": "MCP-Recon-Lab/1.0"}, method="GET")
    try:
        with urllib.request.urlopen(req, timeout=timeout) as resp:
            headers = dict(resp.headers)
            body = resp.read(512).decode("utf-8", errors="replace").strip()
            return (
                f"url={url} status={resp.status} "
                f"server={headers.get('Server', '<none>')} "
                f"x_powered_by={headers.get('X-Powered-By', '<none>')} "
                f"body_preview={body!r}"
            )
    except urllib.error.HTTPError as exc:
        return f"url={url} http_status={exc.code} reason={exc.reason!r}"
    except Exception as exc:
        return f"url={url} error={exc}"


@mcp.tool()
def nmap_service_scan(target: str, ports: str = "2121,8080") -> str:
    """Run a read-only nmap service/version scan (-sV) on specific ports of an allowlisted target."""
    denied = _check_scope(target)
    if denied:
        return denied

    host = target.strip()
    try:
        proc = subprocess.run(
            ["nmap", "-sV", "-Pn", "-p", str(ports), host],
            capture_output=True,
            text=True,
            timeout=60,
        )
        return proc.stdout.strip() or proc.stderr.strip()
    except FileNotFoundError:
        return "ERROR: 'nmap' binary not found in PATH."
    except Exception as exc:
        return f"ERROR running nmap: {exc}"


if __name__ == "__main__":
    mcp.run(transport="stdio")