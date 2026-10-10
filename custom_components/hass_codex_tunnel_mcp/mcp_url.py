"""HA-MCP URL validation and probing helpers."""

from __future__ import annotations

import asyncio
from dataclasses import dataclass
from http.client import HTTPResponse
import ipaddress
import socket
from urllib.error import HTTPError, URLError
from urllib.parse import ParseResult, urlsplit, urlunsplit, unquote
from urllib.request import HTTPRedirectHandler, Request, build_opener


class MCPUrlError(ValueError):
    """Raised when an HA-MCP URL is invalid or unreachable."""


@dataclass(frozen=True)
class MCPUrlAssessment:
    """Security assessment for a configured HA-MCP URL."""

    url: str
    redacted_url: str
    is_local_or_private: bool
    warning: str | None = None


_LOCAL_HOSTNAMES = {"localhost", "homeassistant", "homeassistant.local"}


def normalize_mcp_url(value: str) -> str:
    """Normalize and validate the HA-MCP server URL."""
    raw = value.strip()
    parsed = urlsplit(raw)
    if parsed.scheme not in {"http", "https"}:
        raise MCPUrlError("invalid_mcp_url")
    if not parsed.hostname:
        raise MCPUrlError("invalid_mcp_url")
    if parsed.username or parsed.password:
        raise MCPUrlError("invalid_mcp_url")
    path = parsed.path.rstrip("/")
    if not path or path == "/":
        raise MCPUrlError("missing_mcp_path")
    if path == "/mcp":
        raise MCPUrlError("default_mcp_path")
    return urlunsplit(
        (
            parsed.scheme,
            parsed.netloc,
            path,
            parsed.query,
            "",
        )
    )


def redact_mcp_url(value: str) -> str:
    """Redact the secret path of an HA-MCP URL."""
    try:
        parsed = urlsplit(value)
    except ValueError:
        return "**REDACTED**"
    if not parsed.scheme or not parsed.netloc:
        return "**REDACTED**"
    # A legacy/malformed saved URL might still contain userinfo even though
    # normalize_mcp_url rejects new userinfo configurations.
    host = parsed.hostname
    if not host:
        return "**REDACTED**"
    safe_host = f"[{host}]" if ":" in host else host
    try:
        port = parsed.port
    except ValueError:
        return "**REDACTED**"
    authority = safe_host + (f":{port}" if port is not None else "")
    return urlunsplit((parsed.scheme, authority, "/**REDACTED**", "", ""))


def assess_mcp_url(value: str) -> MCPUrlAssessment:
    """Return a security assessment for the HA-MCP URL."""
    normalized = normalize_mcp_url(value)
    parsed = urlsplit(normalized)
    private = _is_private_or_local(parsed)
    warning = None
    if not private and parsed.scheme == "http":
        raise MCPUrlError("insecure_public_mcp_url")
    if not private:
        warning = "public_mcp_url"
    elif parsed.scheme == "https" and parsed.hostname not in _LOCAL_HOSTNAMES:
        warning = "https_mcp_url"
    return MCPUrlAssessment(
        url=normalized,
        redacted_url=redact_mcp_url(normalized),
        is_local_or_private=private,
        warning=warning,
    )


async def async_probe_mcp_url(
    value: str, timeout: float = 5.0, bearer_token: str = ""
) -> None:
    """Probe the configured HA-MCP URL for basic reachability."""
    validate_admin_auth_mode(value, bool(bearer_token))
    validate_connector_credential(value, bearer_token)
    await asyncio.to_thread(_probe_mcp_url, value, timeout, bearer_token)


def validate_admin_auth_mode(value: str, injected_bearer: bool) -> None:
    """Native administrator identity must be the actual caller's HA session."""
    path = urlsplit(value).path
    for _ in range(3):
        decoded = unquote(path)
        if decoded == path:
            break
        path = decoded
    if path.rstrip("/") == "/api/mcp/hass_codex_admin" and injected_bearer:
        raise MCPUrlError("native_admin_requires_caller_oauth")


def validate_connector_credential(value: str, bearer_token: str) -> None:
    """The administrator accepts only its narrow connection capabilities."""
    if urlsplit(value).path == "/api/hass_codex_admin/mcp" and bearer_token and (not bearer_token.startswith("hca_") or len(bearer_token) != 47):
        raise MCPUrlError("scoped_connector_credential_required")


class _NoRedirects(HTTPRedirectHandler):
    """Never forward backend bearer credentials to redirect destinations."""

    def redirect_request(self, req, fp, code, msg, headers, newurl):
        return None


def _probe_mcp_url(value: str, timeout: float, bearer_token: str = "") -> None:
    headers = {"User-Agent": "hass-codex-tunnel-mcp"}
    if bearer_token:
        headers["Authorization"] = f"Bearer {bearer_token}"
    request = Request(value, method="GET", headers=headers)
    # urllib's default redirect handler can follow the configured endpoint
    # to an untrusted origin.  Never forward the backend Authorization header.
    opener = build_opener(_NoRedirects())
    try:
        with opener.open(request, timeout=timeout) as response:
            _validate_probe_response(response)
    except HTTPError as err:
        if 300 <= err.code < 400:
            raise MCPUrlError("mcp_probe_redirect_rejected") from err
        if bearer_token and err.code in (401, 403):
            raise MCPUrlError("mcp_auth_rejected") from err
        if err.code == 404 or err.code >= 500:
            raise MCPUrlError("mcp_probe_failed") from err
        # Without a bearer token, a 401 can be a valid challenge in the
        # interactive OAuth setup.  For a GET probe, 400/405/406 can indicate
        # an MCP endpoint that expects POST.  These are NOT proof of auth.
        # Successful credential validation needs a separate MCP POST test.
    except (TimeoutError, OSError, URLError) as err:
        raise MCPUrlError("mcp_probe_failed") from err


def _validate_probe_response(response: HTTPResponse) -> None:
    if response.status >= 500:
        raise MCPUrlError("mcp_probe_failed")


def _is_private_or_local(parsed: ParseResult) -> bool:
    hostname = parsed.hostname or ""
    lower = hostname.lower()
    if lower in _LOCAL_HOSTNAMES or lower.endswith(".local"):
        return True
    try:
        ip = ipaddress.ip_address(lower)
        return ip.is_private or ip.is_loopback
    except ValueError:
        pass

    try:
        infos = socket.getaddrinfo(hostname, parsed.port or _default_port(parsed.scheme))
    except OSError:
        return False
    for info in infos:
        address = info[4][0]
        try:
            ip = ipaddress.ip_address(address)
        except ValueError:
            return False
        if not (ip.is_private or ip.is_loopback):
            return False
    return bool(infos)


def _default_port(scheme: str) -> int:
    return 443 if scheme == "https" else 80
