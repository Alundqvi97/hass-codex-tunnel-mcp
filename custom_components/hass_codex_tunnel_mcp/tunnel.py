"""Supervise tunnel-client for OpenAI Tunnel for HA-MCP."""

from __future__ import annotations

import asyncio
from collections.abc import Callable, Mapping
from dataclasses import dataclass
import logging
import os
from pathlib import Path

from .const import (
    CONF_API_KEY,
    CONF_CONTROL_PLANE_BASE_URL,
    CONF_CONTROL_PLANE_PATH,
    CONF_HA_MCP_BEARER_TOKEN,
    CONF_HA_MCP_URL,
    CONF_TUNNEL_ID,
    TUNNEL_CLIENT_VERSION,
)
from .binary import is_clean_version
from .mcp_url import validate_admin_auth_mode

_LOGGER = logging.getLogger(__name__)


@dataclass(frozen=True)
class TunnelCommandConfig:
    """Inputs required to build a tunnel-client command."""

    tunnel_id: str
    mcp_server_url: str
    run_dir: Path
    control_plane_base_url: str = ""
    control_plane_url_path: str = ""
    use_ha_mcp_bearer_token: bool = False


def build_mcp_server_url(url: str) -> str:
    """Build the channel-mapped local MCP server URL."""
    return f"channel=main,url={url}"


def build_tunnel_command(executable: Path, config: TunnelCommandConfig) -> list[str]:
    """Build the tunnel-client command line."""
    validate_admin_auth_mode(config.mcp_server_url, config.use_ha_mcp_bearer_token)
    health_file = config.run_dir / "health.url"
    command = [
        str(executable),
        "run",
        "--control-plane.tunnel-id",
        config.tunnel_id,
        "--control-plane.api-key",
        "env:CONTROL_PLANE_API_KEY",
        "--mcp.server-url",
        build_mcp_server_url(config.mcp_server_url),
        "--health.listen-addr",
        "127.0.0.1:0",
        "--health.url-file",
        str(health_file),
    ]
    if config.control_plane_base_url:
        command.extend(["--control-plane.base-url", config.control_plane_base_url])
    if config.control_plane_url_path:
        command.extend(["--control-plane.url-path", config.control_plane_url_path])
    if config.use_ha_mcp_bearer_token:
        command.extend(
            [
                "--mcp.extra-headers",
                "Authorization: env:HA_MCP_AUTH_HEADER",
                "--mcp.discovery-extra-headers",
                "Authorization: env:HA_MCP_AUTH_HEADER",
            ]
        )
    return command


@dataclass
class TunnelStatus:
    """Current tunnel process state."""

    state: str = "stopped"
    healthy: bool = False
    version: str = TUNNEL_CLIENT_VERSION
    health_url: str | None = None
    returncode: int | None = None
    last_error: str | None = None


class TunnelManager:
    """One owner, one child and bounded recovery using the selected binary.

    Explicit starts are serialized; recovery never downloads an update. A child
    holds the ownership lease too, and Linux parent-death notification ends it
    if Core dies abruptly. No PID scans or signals to unrelated processes.
    """

    def __init__(self, executable_provider, run_dir, notify=None, *, retry_delays=(1, 2, 4, 8), poll_interval=2, stable_window=300, terminate_timeout=10, credential_provider=None):
        self._executable_provider = executable_provider
        self._run_dir = run_dir
        self._notify = notify or (lambda: None)
        self._process = None
        self._watch_task = None
        self._cleanup_task = None
        self._log_tasks = []
        self._lock = asyncio.Lock()
        self._lease = None
        self._entry_data = None
        self._requested_data = None
        self.epoch = 0
        self._closed = False
        self._retry_delays, self._poll_interval, self._stable_window = retry_delays, poll_interval, stable_window
        self._terminate_timeout, self._credential_provider = terminate_timeout, credential_provider
        self.status = TunnelStatus()

    @property
    def process(self):
        return self._process

    async def start(self, entry_data, *, force_download=False, executable_override=None, _replace=False, expected_epoch=None):
        async with self._lock:
            if self._closed:
                raise RuntimeError("tunnel_lifecycle_closed")
            if expected_epoch is not None and expected_epoch != self.epoch:
                raise RuntimeError("tunnel_lifecycle_superseded")
            if not _replace and not force_download and executable_override is None and self._requested_data == dict(entry_data) and self._watch_task and not self._watch_task.done():
                return
            await self._stop_locked()
            self.epoch += 1
            self._entry_data = dict(entry_data)
            self._requested_data = dict(entry_data)
            try:
                await asyncio.to_thread(self._run_dir.mkdir, parents=True, exist_ok=True)
                self._lease = _acquire_lease(self._run_dir / "owner.lock")
                executable = Path(executable_override) if executable_override is not None else Path(await self._maybe_await(self._executable_provider(force_download)))
                token = self._credential_provider(entry_data) if self._credential_provider else str(entry_data.get(CONF_HA_MCP_BEARER_TOKEN) or "").strip()
                from .mcp_url import validate_connector_credential
                validate_connector_credential(str(entry_data[CONF_HA_MCP_URL]), token)
                config = TunnelCommandConfig(str(entry_data[CONF_TUNNEL_ID]), str(entry_data[CONF_HA_MCP_URL]), self._run_dir,
                    str(entry_data.get(CONF_CONTROL_PLANE_BASE_URL) or ""), str(entry_data.get(CONF_CONTROL_PLANE_PATH) or ""), bool(token))
                command = build_tunnel_command(executable, config)
                env = os.environ.copy()
                env["CONTROL_PLANE_API_KEY"] = str(entry_data[CONF_API_KEY])
                env.pop("HA_MCP_AUTH_HEADER", None)
                if token:
                    env["HA_MCP_AUTH_HEADER"] = "Bearer "+token
                self._entry_data[CONF_HA_MCP_BEARER_TOKEN] = token
                self.status = TunnelStatus(state="starting", version=_version_from_executable(executable))
                await self._spawn(command, env)
                self._watch_task = asyncio.create_task(self._supervise(command, env))
                self._notify()
            except BaseException as error:
                if isinstance(error, Exception):
                    error.tunnel_activation_epoch = self.epoch
                await self._stop_locked()
                self.status.state, self.status.last_error = "error", "configuration_binary_or_ownership_error"
                self._notify()
                raise

    async def _spawn(self, command, env):
        self._poll_observations = {}
        health_file = self._run_dir / "health.url"
        await asyncio.to_thread(_prepare_run_dir, self._run_dir, health_file)
        import sys
        wrapped = [sys.executable, str(Path(__file__).with_name("process_owner.py")), str(os.getpid()), *command]
        creation = asyncio.create_task(asyncio.create_subprocess_exec(*wrapped, env=env, pass_fds=(self._lease,),
            stdout=asyncio.subprocess.PIPE, stderr=asyncio.subprocess.PIPE))
        try:
            await _finish_owned(creation)
        finally:
            if creation.done() and not creation.cancelled():
                self._process = creation.result()
        self._log_tasks = [asyncio.create_task(self._log_stream(stream, level)) for stream, level in
            ((self._process.stdout, logging.INFO), (self._process.stderr, logging.WARNING))]

    async def stop(self):
        await _finish_owned(asyncio.create_task(self._stop_serialized()))

    async def _stop_serialized(self):
        async with self._lock:
            self.epoch += 1
            self._entry_data = None
            self._requested_data = None
            self.status.state, self.status.healthy = "stopping", False
            self._notify()
            try:
                await self._stop_locked()
            finally:
                if self._process is None:
                    self.status = TunnelStatus(state="stopped", version=self.status.version)
                    self._notify()

    async def close(self):
        """Unload/shutdown irreversibly removes this manager's start authority."""
        self._closed = True
        await self.stop()

    async def _stop_locked(self):
        if self._cleanup_task is None or self._cleanup_task.done():
            self._cleanup_task = asyncio.create_task(self._cleanup_owned())
        await _finish_owned(self._cleanup_task)

    async def _cleanup_owned(self):
        task = self._watch_task
        if task:
            task.cancel()
            await asyncio.gather(task, return_exceptions=True)
        process = self._process
        await self._terminate_owned(process)
        await self._stop_log_tasks()
        self._watch_task = self._process = None
        if self._lease is not None:
            os.close(self._lease)
            self._lease = None

    async def _terminate_owned(self, process):
        if process and process.returncode is None:
            try:
                process.terminate()
            except ProcessLookupError:
                pass
            try:
                await asyncio.wait_for(process.wait(), self._terminate_timeout)
            except TimeoutError:
                try:
                    process.kill()
                except ProcessLookupError:
                    pass
                try:
                    await asyncio.wait_for(process.wait(), self._terminate_timeout)
                except TimeoutError:
                    self.status.state, self.status.healthy = "cleanup_incomplete", False
                    self.status.last_error = "owned_child_reaping_incomplete"
                    self._notify()
                    # Preserve ownership and prevent a replacement while uncertain.
                    raise RuntimeError("owned_child_reaping_incomplete") from None

    async def restart(self, entry_data):
        await self.start(entry_data, _replace=True)

    async def redownload(self, entry_data):
        await self.start(entry_data, force_download=True, _replace=True)

    async def wait_until_healthy(self, timeout):
        task = self._watch_task
        deadline = asyncio.get_running_loop().time()+timeout
        while asyncio.get_running_loop().time() < deadline and task is self._watch_task:
            if self.status.healthy and self._process and self._process.returncode is None:
                return True
            if task is None or task.done():
                return False
            await asyncio.sleep(min(.1, self._poll_interval))
        return False

    async def _supervise(self, command, env):
        failures = 0
        try:
            while True:
                process = self._process
                started = asyncio.get_running_loop().time()
                while process.returncode is None:
                    category, url = await asyncio.to_thread(_observe_health, self._run_dir / "health.url", self._entry_data, self._poll_observations)
                    if category == "authentication_denied":
                        self.status.state, self.status.last_error = "authentication_denied", category
                        self.status.healthy = False
                        await self._terminate_owned(process)
                        await self._stop_log_tasks()
                        self._notify()
                        return
                    self.status.healthy = category == "ready"
                    self.status.state = "healthy" if self.status.healthy else "degraded"
                    self.status.health_url, self.status.last_error = url, None if self.status.healthy else category
                    self._notify()
                    await asyncio.sleep(self._poll_interval)
                await process.wait()
                self.status.healthy, self.status.health_url = False, None
                self.status.returncode = process.returncode
                await self._stop_log_tasks()
                if process.returncode == 2:
                    self.status.state, self.status.last_error = "configuration_error", "client_configuration_rejected"
                    self._notify()
                    return
                if asyncio.get_running_loop().time()-started >= self._stable_window:
                    failures = 0
                if failures >= len(self._retry_delays):
                    self.status.state, self.status.last_error = "exhausted", "local_process_recovery_exhausted"
                    self._notify()
                    return
                self.status.state, self.status.last_error = "backoff", "local_process_exit"
                self._notify()
                await asyncio.sleep(self._retry_delays[failures])
                failures += 1
                await self._spawn(command, env)
        except asyncio.CancelledError:
            raise
        except Exception:
            self.status.state, self.status.last_error, self.status.healthy = "exhausted", "local_recovery_error", False
            await self._terminate_owned(self._process)
            await self._stop_log_tasks()
            self._notify()

    async def _stop_log_tasks(self):
        for task in self._log_tasks:
            task.cancel()
        await asyncio.gather(*self._log_tasks, return_exceptions=True)
        self._log_tasks.clear()

    async def _log_stream(self, stream, level):
        # Upstream output may contain credentials or backend payloads. Keep a
        # diagnostic occurrence, never raw text. Health supplies typed categories.
        while await stream.read(8192):
            _LOGGER.log(level, "tunnel-client emitted a diagnostic (payload omitted)")

    @staticmethod
    async def _maybe_await(value):
        return await value if hasattr(value, "__await__") else value


def _version_from_executable(executable):
    version = executable.parent.name
    return version if is_clean_version(version) else TUNNEL_CLIENT_VERSION


async def _finish_owned(task):
    """Repeated caller cancellation cannot abandon an owned creation/cleanup."""
    interrupted = False
    while not task.done():
        try:
            await asyncio.shield(task)
        except asyncio.CancelledError:
            interrupted = True
    result = task.result()
    if interrupted:
        raise asyncio.CancelledError()
    return result


def _read_health_url(health_file):
    try:
        import stat
        fd = os.open(health_file, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK)
        with os.fdopen(fd, encoding="utf-8") as source:
            if not stat.S_ISREG(os.fstat(source.fileno()).st_mode):
                return ""
            return source.read(1025).strip()
    except (OSError, UnicodeError):
        return ""


def _prepare_run_dir(run_dir, health_file):
    run_dir.mkdir(parents=True, exist_ok=True)
    health_file.unlink(missing_ok=True)


def _acquire_lease(path):
    import fcntl
    fd = os.open(path, os.O_CREAT | os.O_RDWR | os.O_NOFOLLOW, 0o600)
    try:
        fcntl.flock(fd, fcntl.LOCK_EX | fcntl.LOCK_NB)
    except BaseException:
        os.close(fd)
        raise
    return fd


def _observe_health(health_file, entry_data, poll_observations=None):
    """Read actual readiness; never trust a file, redirect or public URL."""
    import ipaddress
    import json
    from urllib.parse import urlsplit, urlunsplit
    from urllib.request import Request, ProxyHandler, build_opener
    from urllib.error import HTTPError, URLError
    from .mcp_url import _NoRedirects
    text = _read_health_url(health_file)
    try:
        parsed = urlsplit(text)
        if len(text) > 1024 or parsed.scheme != "http" or not ipaddress.ip_address(parsed.hostname).is_loopback or parsed.username or parsed.password or parsed.query or parsed.fragment or not parsed.port:
            return "readiness_unavailable", None
    except (ValueError, TypeError):
        return "readiness_unavailable", None
    base = urlunsplit((parsed.scheme, parsed.netloc, "", "", ""))
    opener = build_opener(ProxyHandler({}), _NoRedirects())
    # Bundled v0.0.10 has /readyz and HTTP metrics, but no component health
    # JSON. Classify only actual poll-route counter changes; OAuth challenges
    # and historical errors on MCP routes must not disable a working tunnel.
    try:
        import re
        from .metrics import iter_prometheus_samples
        with opener.open(base+"/metrics", timeout=1) as response:
            raw = response.read(131073)
        if len(raw) > 131072:
            raise ValueError("oversized_metrics")
        counts = {"auth": 0, "success": 0, "failure": 0}
        for sample in iter_prometheus_samples(raw.decode()):
            if sample.name != "http_client_request_duration_seconds_count" or not re.fullmatch(r"(?:/[^/]+)*/tunnels/[^/]+/poll", sample.labels.get("http_route", "")):
                continue
            status = sample.labels.get("http_response_status_code", "")
            kind = "auth" if status in {"401", "403"} else "success" if status == "200" else "failure"
            counts[kind] += sample.value
        previous = poll_observations if poll_observations is not None else {}
        category = previous.get("category", "ready")
        if counts["auth"] > previous.get("auth", 0) and counts["success"] <= previous.get("success", 0):
            category = "authentication_denied"
        elif counts["failure"] > previous.get("failure", 0) and counts["success"] <= previous.get("success", 0):
            category = "provider_unavailable"
        elif counts["success"] > previous.get("success", 0):
            category = "ready"
        if poll_observations is not None:
            poll_observations.update(counts, category=category)
        if category != "ready":
            return category, text
    except (HTTPError, URLError, OSError, ValueError):
        pass
    try:
        with opener.open(base+"/health?details=true", timeout=1) as response:
            details = json.loads(response.read(65537))
        control = details.get("components", {}).get("control-plane", {})
        status = control.get("details", {}).get("http_status")
        if status in (401, 403):
            return "authentication_denied", text
        if control.get("status") == "degraded":
            return "provider_unavailable", text
    except (HTTPError, URLError, OSError, ValueError, AttributeError):
        pass  # Older clients can lack details; /readyz remains authoritative.
    try:
        with opener.open(base+"/readyz", timeout=1) as response:
            if response.status != 200:
                return "transport_not_ready", text
    except (HTTPError, URLError, OSError):
        return "transport_not_ready", text
    # A scoped administrator backend must itself accept tools/list. This is a
    # safe protocol read, not a task replay or a device probe.
    backend = str((entry_data or {}).get(CONF_HA_MCP_URL) or "")
    if urlsplit(backend).path == "/api/hass_codex_admin/mcp":
        token = str(entry_data.get(CONF_HA_MCP_BEARER_TOKEN) or "").strip()
        payload = json.dumps({"jsonrpc": "2.0", "id": 1, "method": "tools/list", "params": {}}).encode()
        try:
            with opener.open(Request(backend, data=payload, headers={"Authorization": "Bearer "+token, "Content-Type": "application/json", "Accept": "application/json"}), timeout=2) as response:
                reply = json.loads(response.read(131073))
                if not isinstance(reply.get("result", {}).get("tools"), list):
                    return "backend_unavailable", text
        except HTTPError as exc:
            return ("authentication_denied" if exc.code in (401, 403) else "backend_unavailable"), text
        except (URLError, OSError, ValueError, AttributeError):
            return "backend_unavailable", text
    return "ready", text
