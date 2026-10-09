#!/usr/bin/env python3
"""Exactly one disposable HAOS guest on GitHub-hosted Ubuntu (review only).

Synthetic credentials, localhost port forwards only, no outside household
systems. Never print raw Supervisor responses, credentials, secret paths,
guest serial output or HTTP response bodies. A partial or blocked gate is
recorded explicitly; a Docker container is never called Supervisor.
"""
from __future__ import annotations
import errno
import importlib.util
import json
import logging
import os
import pathlib
import re
import socket
import secrets
import subprocess
import sys
import time
import urllib.error
import urllib.parse
import urllib.request

ROOT=pathlib.Path(__file__).resolve().parents[3]
WORK=pathlib.Path(os.environ.get("PHASE2H_WORK","/tmp/phase2h-single-vm"))
SOURCE=ROOT/"ha_mcp_pinned"
OSVER="18.3"
IMAGE="haos_ova-18.3.qcow2.xz"
SHA256="fae6a728768cc10aff60d4820bfcd40d64cd77fab82c8bd92af13b3d9d414090"
SLUG="local_ha_mcp_phase2h"
sys.path.insert(0, str(ROOT / 'docs' / 'security'))
from phase2i.offline_harness import classify_probe, loopback_listener_ports, sanitized_code  # noqa: E402
logging.disable(logging.CRITICAL)

def report(key, result):
    # Sanitized fixed-shape test receipts only.
    print("PHASE2H_"+key+"="+str(result),flush=True)

def fetch_observation(url, timeout=4):
    """Return fixed diagnostic category and numeric status; never log URL/body/error."""
    port = urllib.parse.urlsplit(url).port
    path = urllib.parse.urlsplit(url).path
    # A missing LISTEN socket differs from a refused connection. If kernel
    # proc state is unavailable, do not assume that a listener is absent.
    try:
        listener = port in loopback_listener_ports(pathlib.Path('/proc/net/tcp').read_text())
    except OSError:
        listener = True
    try:
        with urllib.request.urlopen(url, timeout=timeout) as resp:
            status = resp.status
        return status, sanitized_code(classify_probe(listener=listener, status=status, path=path))
    except urllib.error.HTTPError as exc:
        # Valid HTTP responses (including 404) must not be reported as timeout.
        return exc.code, sanitized_code(classify_probe(listener=listener, status=exc.code, path=path))
    except urllib.error.URLError as exc:
        reason = exc.reason
        if isinstance(reason, OSError) and reason.errno == errno.ECONNREFUSED:
            error = 'refused'
        elif isinstance(reason, (TimeoutError, socket.timeout)):
            error = 'timeout'
        else:
            error = 'other'
        return 0, sanitized_code(classify_probe(listener=listener, error=error, path=path))
    except (TimeoutError, socket.timeout):
        return 0, sanitized_code(classify_probe(listener=listener, error='timeout', path=path))
    except Exception:
        return 0, 'NETWORK_ERROR'


def fetch_status(url, timeout=4):
    """Retain legacy numeric readiness contract, with HTTP errors preserved."""
    return fetch_observation(url, timeout)[0]

def upstream_loader():
    p=SOURCE/"tests/haos_image_build/build_image.py"
    spec=importlib.util.spec_from_file_location("haos_phase2h_helpers",p)
    mod=importlib.util.module_from_spec(spec)
    sys.modules[spec.name]=mod
    spec.loader.exec_module(mod)
    return mod

def launch_guest():
    disk=WORK/"haos_ova-18.3.qcow2"
    if not disk.exists():
        raise FileNotFoundError("verified guest disk not prepared")
    fw=pathlib.Path("/usr/share/OVMF/OVMF_CODE_4M.fd")
    vars_file=WORK/"OVMF_VARS_4M.fd"
    if not fw.exists() or not vars_file.exists():
        raise FileNotFoundError("matching UEFI firmware pair missing")
    cmd=["sudo","-u","phase2hvm","qemu-system-x86_64",
         "-machine","q35,accel=kvm","-cpu","host","-smp","2","-m","4096",
         "-drive",f"if=pflash,format=raw,readonly=on,file={fw}",
         "-drive",f"if=pflash,format=raw,file={vars_file}",
         "-drive",f"if=virtio,file={disk},format=qcow2",
         "-netdev",("user,id=net0,ipv6=off,hostfwd=tcp:127.0.0.1:18123-:8123,"
                    "hostfwd=tcp:127.0.0.1:18124-:80,"
                    "hostfwd=tcp:127.0.0.1:14357-:4357,"
                    "hostfwd=tcp:127.0.0.1:19583-:9583"),
         "-device","virtio-net-pci,netdev=net0",
         "-display","none","-monitor","none",
         "-serial",f"file:{WORK/'serial-private.log'}",
         "-no-reboot"]
    return subprocess.Popen(cmd,stdin=subprocess.DEVNULL,
                            stdout=subprocess.DEVNULL,stderr=subprocess.DEVNULL)

def report_sanitized_serial_milestones():
    # Only Boolean fixed-string findings, NEVER any guest log lines or data.
    # Serial console output cannot by itself prove the guest is healthy.
    serial=WORK/"serial-private.log"
    try:
        data=serial.read_bytes()[:4_000_000].lower()
    except OSError:
        report("SERIAL_READABLE","NOT_VERIFIED")
        return
    report("SERIAL_READABLE","PASS")
    for name,marker in (
        ("LINUX_KERNEL_BANNER",b"linux version"),
        ("HAOS_PLATFORM_MESSAGE",b"home assistant os"),
        ("SUPERVISOR_BOOT_MESSAGE",b"supervisor"),
        ("EMERGENCY_MODE",b"emergency mode"),
    ):
        report("SERIAL_"+name, "OBSERVED" if marker in data else "NOT_OBSERVED")


def boot_wait(proc,secs=780):
    deadline=time.monotonic()+secs
    observer=False
    last_diagnostic='GUEST_STARTUP_NOT_OBSERVABLE'
    while time.monotonic()<deadline:
        if proc.poll() is not None:
            report("HAOS_GUEST","BLOCKED_QEMU_EXIT")
            report_sanitized_serial_milestones()
            return None
        observer=observer or bool(fetch_status("http://127.0.0.1:14357/",2))
        for port in (18124,18123):
            status, last_diagnostic = fetch_observation(f"http://127.0.0.1:{port}/manifest.json",3)
            if status == 200:
                report("HAOS_OBSERVER","REACHABLE" if observer else "NOT_OBSERVED")
                report("HAOS_CORE_HTTP","PASS")
                return f"http://127.0.0.1:{port}"
        time.sleep(5)
    report("HAOS_OBSERVER","REACHABLE" if observer else "NOT_OBSERVED")
    report("HAOS_CORE_HTTP","BLOCKED_TIMEOUT")
    report("PHASE2I_READINESS_DIAGNOSTIC", sanitized_code(last_diagnostic))
    report_sanitized_serial_milestones()
    return None

def supervisor_verify(h,base):
    credentials=h.onboard(base)
    report("SYNTHETIC_ONBOARDING","PASS")
    ws=h.HAWebSocket(base,credentials)
    ws.__enter__()
    try:
        info=h._wait_supervisor_ready(ws,update_timeout=480)
        state=h._wait_supervisor_running(ws,timeout=300)
        version=info.get("version","unknown")
        report("SUPERVISOR_API","PASS")
        report("SUPERVISOR_VERSION",version if isinstance(version,str) and re.fullmatch(r"20[0-9]{2}\.[0-9]{1,2}\.[0-9]{1,2}",version) else "NOT_VERIFIED")
        report("SUPERVISOR_RUNNING","PASS" if state else "NOT_VERIFIED")
        if not state:
            raise RuntimeError("SupervisorNotRunning")
        return ws
    except Exception:
        ws.__exit__(None,None,None)
        raise

def test_addon(ws):
    # No actual HA devices or external model connections are possible here.
    synthetic_capability="/_phase2h_synthetic_"+secrets.token_hex(20)
    data={"options":{
        "backup_hint":"normal",
        "secret_path":synthetic_capability,
        "enable_tool_security_policies":True,
        "require_strict_tool_policy":True,
        "enable_security_policy_tool":False,
        "read_only_mode":False,
        "redact_secrets":True,
        "enable_mandatory_bps":True,
        "enable_strict_mandatory_bps":True,
        "enable_auto_backup":False,
        "enable_tool_search":False,
    }}
    ws.supervisor_api("/store/reload",method="post",timeout=100)
    store=ws.supervisor_api("/store",timeout=90)
    if not any(a.get("slug")==SLUG for a in store.get("addons",[])):
        report("SUPERVISOR_LOCAL_ADDON_DISCOVERY","BLOCKED_NOT_IN_STORE")
        return
    report("SUPERVISOR_LOCAL_ADDON_DISCOVERY","PASS")
    ws.supervisor_api(f"/store/addons/{SLUG}/install",method="post",timeout=850)
    report("CANDIDATE_ADDON_INSTALL","PASS")
    info=ws.supervisor_api(f"/addons/{SLUG}/info",timeout=90)
    schema=info.get("schema",{})
    if "require_strict_tool_policy" not in str(schema):
        report("SUPERVISOR_RECOGNIZES_STRICT_OPTION","FAIL")
        return
    report("SUPERVISOR_RECOGNIZES_STRICT_OPTION","PASS")
    ws.supervisor_api(f"/addons/{SLUG}/options",method="post",data=data,timeout=90)
    observed=ws.supervisor_api(f"/addons/{SLUG}/info",timeout=60)
    option=observed.get("options",{})
    report("SUPERVISOR_STRICT_OPTION_PERSISTED","PASS" if option.get("require_strict_tool_policy") is True else "FAIL")
    # This is a SYNTHETIC guest. The copied test policy is positive read-only.
    ws.supervisor_api(f"/addons/{SLUG}/start",method="post",timeout=120)
    report("CANDIDATE_ADDON_START_API","PASS")
    time.sleep(12)
    status=ws.supervisor_api(f"/addons/{SLUG}/info",timeout=45)
    report("CANDIDATE_ADDON_RUNNING","PASS" if status.get("state")=="started" else "BLOCKED_STARTUP")
    # A missing/corrupt file refusal test requires separate independent guest
    # control. Do not treat an API option toggle as a full policy corruption test.
    forbidden=dict(data)
    forbidden["options"]=dict(data["options"],require_strict_tool_policy=False)
    try:
        ws.supervisor_api(f"/addons/{SLUG}/options",method="post",data=forbidden,timeout=60)
        report("DOWNGRADE_CONFIG_WRITE","ACCEPTED_BY_SUPERVISOR")
        # Supervisor accepting the options is NOT proof that MCP starts safely.
        ws.supervisor_api(f"/addons/{SLUG}/restart",method="post",timeout=90)
        time.sleep(8)
        check=ws.supervisor_api(f"/addons/{SLUG}/info",timeout=45)
        report("DOWNGRADE_AFTER_RESTART","REFUSED" if check.get("state")!="started" else "FAIL_OPEN")
    except Exception:
        report("DOWNGRADE_AFTER_RESTART","BLOCKED_OR_REFUSED")
    # Verify independent HA admin remains available via our authenticated WS.
    ws.supervisor_api("/supervisor/info",timeout=30)
    report("INDEPENDENT_LOCAL_SUPERVISOR_WHILE_MCP_FAULT","PASS")
    # No raw add-on logs are emitted or transferred.
    try:
        logs=ws.supervisor_api(f"/addons/{SLUG}/logs",timeout=30)
        generated=str(logs)
        report("SYNTHETIC_LOG_REDACTION","PASS" if synthetic_capability not in generated else "FAIL")
    except Exception:
        report("SYNTHETIC_LOG_REDACTION","NOT_VERIFIED")
    report("ADDON_RESTART_PERSISTENCE","PARTIAL")
    report("HOST_REBOOT_PERSISTENCE","NOT_VERIFIED")
    report("FULL_RESTORE_AND_WATCHDOG","NOT_VERIFIED")

def main():
    report("IMAGE_VERSION",OSVER)
    report("SOURCE_SHA","fc54437a804858732e4bc927add98e202d879a09")
    h=upstream_loader()
    proc=launch_guest()
    try:
        base=boot_wait(proc)
        if base is None:return 3
        try:
            ws=supervisor_verify(h,base)
        except Exception as e:
            report("SUPERVISOR_API","BLOCKED_EXCEPTION")
            return 4
        try:
            if os.environ.get("PHASE2H_LOCAL_ADDON_SEEDED")=="true":
                try:
                    test_addon(ws)
                except Exception as e:
                    report("CANDIDATE_ADDON_TEST","BLOCKED_EXCEPTION")
            else:
                report("CANDIDATE_ADDON_TEST","BLOCKED_NO_SAFE_SEED")
            report("TESTED_SUPERVISOR_LEVEL","REAL_GUEST_API")
            # Most of the 16 mandatory acceptance cases remain unimplemented.
            # A responding Supervisor and an attempted add-on test are not a
            # successful release gate. Keep this nonzero until every case is
            # explicitly observed and reviewed; no implicit success on return.
            report("FULL_SUPERVISOR_ACCEPTANCE","BLOCKED_INCOMPLETE_16_CASES")
            return 6
        finally:
            ws.__exit__(None,None,None)
    finally:
        if proc.poll() is None:
            proc.terminate()
            try:proc.wait(timeout=25)
            except subprocess.TimeoutExpired:
                proc.kill()
                proc.wait(timeout=10)
        report("GUEST_PROCESS_TERMINATED","PASS")

if __name__=="__main__":
    try:
        sys.exit(main())
    except Exception as exc:
        report("HARNESS_ERROR","BLOCKED_EXCEPTION")
        sys.exit(5)
