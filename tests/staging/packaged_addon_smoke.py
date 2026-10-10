"""Packaged HA-MCP add-on container acceptance (NO Supervisor, NO network).

Runs only on GitHub Actions Linux Docker daemon. Creates containers without
network connectivity, host ports, production credentials or external volumes.
Uses fake options/policy files and real pinned /start.py installed by Dockerfile.
"""
from __future__ import annotations

from contextlib import nullcontext
import json
import os
import subprocess
import tempfile
import time
from pathlib import Path
from urllib.parse import quote

IMAGE = "ha-mcp-phase2e:local"
SYNTHETIC_PATH = "/private_phase2e_synthetic_test_only"
FAKE_TOKEN = "synthetic-supervisor-placeholder"
PROBE_SCRIPT = r'''
import json,sys,urllib.request
url="http://127.0.0.1:9583" + sys.argv[1]
body=json.dumps({"jsonrpc":"2.0","id":5,"method":"initialize",
                 "params":{"protocolVersion":"2025-06-18","capabilities":{},
                           "clientInfo":{"name":"isolated-test","version":"0"}}}).encode()
req=urllib.request.Request(url,data=body,headers={
  "Content-Type":"application/json",
  "Accept":"application/json, text/event-stream",
  "Authorization":"Bearer arbitrary-synthetic"
},method="POST")
try:
  with urllib.request.urlopen(req,timeout=3) as response:
    assert response.status==200
    content_type=response.headers.get("Content-Type","")
    if "text/event-stream" in content_type:
      obj=None
      for _ in range(20):
        line=response.readline()
        if line.startswith(b"data: "):
          obj=json.loads(line[6:])
          break
    else:
      obj=json.loads(response.read())
    assert obj and obj["id"]==5 and "result" in obj
except Exception as exc:
  print(type(exc).__name__)
  sys.exit(1)
'''


def run(*args: str, timeout=80, check=True) -> subprocess.CompletedProcess[str]:
    return subprocess.run(args, encoding="utf8", capture_output=True,
                          timeout=timeout, check=check)


def prepare_data(path: Path, *, option_enabled=True, policy_state="valid"):
    path.mkdir(mode=0o700, parents=True, exist_ok=True)
    # The GitHub runner owns the temporary mount. The container drops ALL
    # capabilities, including DAC_OVERRIDE, so root cannot traverse a 0700
    # runner-owned directory. Only synthetic fixtures reside here.
    path.chmod(0o777)
    (path / "options.json").write_text(json.dumps({
        "enable_tool_security_policies": option_enabled,
        "enable_security_policy_tool": False,
        "redact_secrets": True,
        "secret_path": SYNTHETIC_PATH,
        "read_only_mode": False,
    }))
    if policy_state == "valid":
        (path / "tool_policy.json").write_text(json.dumps({
            "rule_effect": "allow",
            "rules": [{"tool_name": "ha_get_overview", "when": [],
                       "remember_minutes": 0}]
        }))
    elif policy_state == "empty":
        (path / "tool_policy.json").write_text(json.dumps({
            "rule_effect": "allow", "rules": []
        }))
    elif policy_state == "invalid":
        (path / "tool_policy.json").write_text("{synthetic-invalid-json")
    elif policy_state != "missing":
        raise ValueError("unsupported policy state")


def launch(data: Path, label: str):
    c = run("docker", "run", "-d", "--network", "none", "--cap-drop", "ALL",
            "--security-opt", "no-new-privileges", "-e",
            "SUPERVISOR_TOKEN=" + FAKE_TOKEN, "-e", "MCP_HOST=127.0.0.1",
            "-e", "HA_MCP_REQUIRE_STRICT_POLICY=true",
            "-v", str(data) + ":/data:rw", "--label", "phase2e=" + label,
            IMAGE, timeout=25)
    return c.stdout.strip()


def test_logs(container: str):
    logs = run("docker", "logs", container, timeout=20).stdout
    # docker logs sends logger output to stderr as well
    err = run("docker", "logs", container, timeout=20).stderr
    combined = logs + err
    for secret in (SYNTHETIC_PATH, quote(SYNTHETIC_PATH, safe=""),
                   SYNTHETIC_PATH.replace("/", "\\/"), FAKE_TOKEN):
        if secret in combined:
            raise AssertionError("synthetic credential observed in packaged logs")
    return len(combined)


def smoke_case(label, state, expected_ready, option_enabled=True, volume=None):
    # An optional stable synthetic /data volume proves recovery across
    # separately failed and successful starts without reinitializing storage.
    manager = tempfile.TemporaryDirectory(prefix="phase2e-") if volume is None else nullcontext(str(volume))
    with manager as t:
        data = Path(t)
        prepare_data(data, option_enabled=option_enabled, policy_state=state)
        cid = launch(data, label)
        try:
            network = json.loads(run("docker", "inspect", cid).stdout)[0]["HostConfig"]
            assert network["NetworkMode"] == "none" and not network.get("PortBindings")
            ready = False
            stopped = False
            last_probe = "none"
            for _ in range(25):
                info = json.loads(run("docker", "inspect", cid).stdout)[0]
                if not info["State"]["Running"]:
                    stopped = True
                    break
                check = run("docker", "exec", cid, "python3", "-c",
                            PROBE_SCRIPT, SYNTHETIC_PATH,
                            timeout=10, check=False)
                if check.returncode != 0:
                    last_probe = check.stdout.strip()[:40] or "process-error"
                if check.returncode == 0:
                    ready = True
                    break
                time.sleep(0.7)
            if expected_ready:
                if not ready:
                    state = json.loads(run("docker", "inspect", cid).stdout)[0]["State"]
                    diagnostics = run("docker", "logs", cid, timeout=15, check=False)
                    sample = diagnostics.stdout + diagnostics.stderr
                    classes = ("Traceback", "ModuleNotFoundError", "ConnectionRefusedError",
                               "PermissionError", "ImportError", "RuntimeError",
                               "MCP server crashed", "Required MCP policy",
                               "Starting MCP server", "Application startup complete",
                               "Uvicorn running", "Server startup", "FastMCP")
                    print("packaged log classifications=",
                          {label: label in sample for label in classes})
                    print("packaged last probe class=", last_probe)
                    print("packaged startup state=", state["Status"],
                          "exit=", state["ExitCode"], "error_type=",
                          state.get("Error", "")[:80])
                    raise AssertionError("packaged healthy startup failed: " + label)
            else:
                if ready:
                    raise AssertionError("privileged MCP reachable when strict config bad")
                if not stopped:
                    raise AssertionError("invalid config did not fail startup in time")
            size = test_logs(cid)
            print(f"{label}: {'READY' if ready else 'REFUSED'}; "
                  f"network=none; synthetic log scan passed ({size} bytes)")
        finally:
            run("docker", "rm", "-f", cid, timeout=20, check=False)


def main():
    version = run("docker", "run", "--rm", "--network", "none", "--entrypoint",
                  "python3", IMAGE, "-c",
                  "import importlib.metadata as m; print(m.version('ha-mcp'))").stdout.strip()
    assert version == "8.6.0", version
    print("Packaged version 8.6.0 verified (real /start.py; no Supervisor)")
    smoke_case("valid-policy", "valid", True)
    smoke_case("missing-policy", "missing", False)
    smoke_case("empty-policy", "empty", False)
    smoke_case("corrupt-policy", "invalid", False)
    smoke_case("disabled-engine", "valid", False, option_enabled=False)
    with tempfile.TemporaryDirectory(prefix="phase2e-recovery-") as recover:
        smoke_case("failed-config-same-volume", "invalid", False, volume=recover)
        smoke_case("restored-valid-policy", "valid", True, volume=recover)
    print("PACKAGED SYNTHETIC ENTRYPOINT ACCEPTANCE PASSED")


if __name__ == "__main__":
    main()
