"""Real pinned addon with supported strict option; no external network/HA."""
from __future__ import annotations
import json
import subprocess
import tempfile
import time
from pathlib import Path
from urllib.parse import quote

IMAGE="ha-mcp-phase2f:local"
SECRET="/private_synthetic_phase2f_example"
FAKE="synthetic-supervisor-no-value"
PROBE=r'''
import json,urllib.request,sys
body=json.dumps({"jsonrpc":"2.0","id":2,"method":"initialize","params":{
  "protocolVersion":"2025-06-18","capabilities":{},
  "clientInfo":{"name":"isolated-phase2f","version":"0"}}}).encode()
req=urllib.request.Request("http://127.0.0.1:9583"+sys.argv[1],
  data=body,method="POST",headers={"Content-Type":"application/json",
  "Accept":"application/json, text/event-stream"})
with urllib.request.urlopen(req,timeout=3) as r:
  if r.headers.get("Content-Type","").startswith("text/event-stream"):
    obj=None
    for _ in range(30):
      line=r.readline()
      if line.startswith(b"data: "):
        obj=json.loads(line[6:]);break
  else: obj=json.loads(r.read())
  assert r.status==200 and obj and obj["id"]==2 and "result" in obj
'''

def cmd(*args,check=True,timeout=30):
    return subprocess.run(args,encoding="utf8",capture_output=True,
                          timeout=timeout,check=check)

def write_synthetic(data, filename, value):
    # A real add-on migration may rewrite its policy file as root:root.
    # Emulate an authorized local/Supervisor-side repair in a separate
    # network-isolated root container. Do not relax actual file permissions.
    target=Path(data)/filename
    try:
        target.write_text(value)
    except PermissionError:
        assert filename in ("options.json","tool_policy.json")
        tool=("import pathlib,sys; "
              "pathlib.Path('/data/"+filename+"').write_text(sys.stdin.read())")
        result=subprocess.run(
            ["docker","run","--rm","-i","--network","none",
             "--cap-drop","ALL","--security-opt","no-new-privileges",
             "-v",str(data)+":/data:rw","--entrypoint","python3",IMAGE,
             "-c",tool],
            input=value,text=True,capture_output=True,timeout=30)
        assert result.returncode==0, "synthetic local repair failed"


def config(data,strict=True,state="valid",engine=True):
    data=Path(data);data.mkdir(exist_ok=True);data.chmod(0o777)
    options=data/"options.json"
    if state=="missing-options":
        options.unlink(missing_ok=True)
    elif state=="corrupt-options":
        write_synthetic(data,"options.json","{synthetic-corrupt")
    else:
        write_synthetic(data,"options.json",json.dumps({
           "require_strict_tool_policy":strict,
           "enable_tool_security_policies":engine,
           "secret_path":SECRET,
           "enable_security_policy_tool":False,
           "redact_secrets":True,
           "read_only_mode":False,
        }))
    policy=data/"tool_policy.json"
    if state=="missing-policy": policy.unlink(missing_ok=True)
    elif state=="corrupt-policy": write_synthetic(data,"tool_policy.json","{synthetic-corrupt")
    else:
        names = (["ha_config_remove_automation"] if state=="old-policy"
                 else ["ha_get_overview"])
        effect = "require_approval" if state=="old-policy" else "allow"
        write_synthetic(data,"tool_policy.json",json.dumps({"rule_effect":effect,
             "rules":[{"tool_name":t,"when":[],"remember_minutes":0}
                        for t in names]}))

def run_once(data,label,ready_expected):
    c=cmd("docker","run","-d","--network","none","--cap-drop","ALL",
          "--security-opt","no-new-privileges","-e","SUPERVISOR_TOKEN="+FAKE,
          "-e","MCP_HOST=127.0.0.1","-v",str(data)+":/data:rw",
          "--label","phase2f=synthetic",IMAGE).stdout.strip()
    try:
        info=json.loads(cmd("docker","inspect",c).stdout)[0]
        assert info["HostConfig"]["NetworkMode"]=="none"
        assert not info["HostConfig"].get("PortBindings")
        ready=False
        stopped=False
        for _ in range(26):
            info=json.loads(cmd("docker","inspect",c).stdout)[0]
            if not info["State"]["Running"]:
                stopped=True;break
            probe=cmd("docker","exec",c,"python3","-c",PROBE,SECRET,check=False,timeout=10)
            if probe.returncode==0:
                ready=True;break
            time.sleep(.5)
        logs=cmd("docker","logs",c,check=False)
        output=logs.stdout+logs.stderr
        for variant in (SECRET,quote(SECRET,safe=""),SECRET.replace("/","\\/"),FAKE):
            assert variant not in output, "PACKAGED_SYNTHETIC_SECRET_LEAK"
        if ready!=ready_expected:
            # Only emit static diagnostic categories. Never emit raw log
            # lines, URLs, environment, Supervisor tokens or endpoints.
            categories = (
                "Mandatory policy startup preflight rejected configuration",
                "Strict MCP policy unavailable or invalid",
                "Required MCP policy initialization failed",
                "Mandatory policy marker",
                "PermissionError",
                "ModuleNotFoundError",
                "Traceback",
                "ValueError",
                "RuntimeError",
            )
            print("phase2f_failure_categories=",
                  {category:(category in output) for category in categories},
                  "marker_exists=",
                  (Path(data)/"strict_policy_required.v1.json").exists(),
                  "running=",not stopped)
        assert ready==ready_expected,(label,"readiness mismatch",stopped)
        if not ready_expected:assert stopped,(label,"did not fail startup")
        print(label, "READY" if ready else "REFUSED", "synthetic-log-scan=PASS")
    finally:
        cmd("docker","rm","-f",c,check=False)

def main():
    v=cmd("docker","run","--rm","--network","none","--entrypoint",
          "python3",IMAGE,"-c","import importlib.metadata as m;print(m.version('ha-mcp'))")
    assert v.stdout.strip()=="8.6.0"
    with tempfile.TemporaryDirectory(prefix="phase2f-") as root:
        data=Path(root);config(data,strict=False,engine=False)
        run_once(data,"legacy-opt-out",True)
        assert not (data/"strict_policy_required.v1.json").exists()
    with tempfile.TemporaryDirectory(prefix="phase2f-") as root:
        data=Path(root)
        config(data,state="old-policy")
        run_once(data,"old-approval-policy-rejected",False)
        assert not (data/"strict_policy_required.v1.json").exists()
        config(data,state="valid")
        run_once(data,"first-opt-in",True)
        marker=data/"strict_policy_required.v1.json"
        assert marker.is_file()
        assert marker.stat().st_mode&0o777==0o600
        # The CI runner does not own the root:root 0600 marker. Verify its
        # synthetic content using the same packaged image, mounted read-only,
        # without broadening permissions or exposing anything in stdout.
        verify=cmd("docker","run","--rm","--network","none",
                   "--cap-drop","ALL","--security-opt","no-new-privileges",
                   "-v",str(data)+":/data:ro","--entrypoint","python3",
                   IMAGE,"-c",
                   'import json,pathlib; p=pathlib.Path("/data/strict_policy_required.v1.json"); '
                   'assert json.loads(p.read_text())=={"schema_version":1,"required":True}')
        config(data,state="missing-options")
        run_once(data,"missing-options-with-marker",False)
        config(data,state="corrupt-options")
        run_once(data,"corrupt-options-with-marker",False)
        config(data,strict=False)
        run_once(data,"downgrade-attempt-with-marker",False)
        config(data,state="missing-policy")
        run_once(data,"missing-policy-with-marker",False)
        config(data,state="corrupt-policy")
        run_once(data,"corrupt-policy-with-marker",False)
        config(data,state="valid")
        run_once(data,"same-volume-restored",True)
    print("PHASE2F_PACKAGED_ACCEPTANCE_PASSED")

if __name__=="__main__":
    main()
