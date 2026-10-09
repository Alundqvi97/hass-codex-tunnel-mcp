"""Pinned, one-shot numeric UID case contract and injected subprocess facade.

No processes at import; no default subprocess implementation. The future
privileged guardian must inject a streaming runner that independently checks live /proc
UID/GID/groups/capabilities before accepting a categorical result.
"""
from __future__ import annotations

from pathlib import Path
from probe_contract import validate_plan
from probe_a_client import admissible_result
from probe_contract import CASES

class WorkloadDenied(RuntimeError):
    pass

WORKER = str((Path(__file__).resolve().parent / "probe_a_worker.py"))
CASES_ORDER = tuple(item[0] for item in CASES)
EXPECTED = {
    "approved-udp": "DNS_UDP_MATCHED_NXDOMAIN",
    "approved-tcp": "DNS_TCP_MATCHED_NXDOMAIN",
    "loopback-established": "ROOT_PEER_ROUNDTRIP_COMPLETE",
}
OTHER = "SOCKET_FAILED_REQUIRES_KERNEL_COUNTER"

def exact_argv(plan, case):
    if validate_plan(plan) != "OFFLINE_SAFE_SCOPED_PLAN_NOT_KERNEL_VERIFIED":
        raise WorkloadDenied("INVALID_PLAN")
    if plan.dns != "9.9.9.9" or case not in CASES_ORDER:
        raise WorkloadDenied("DESTINATION_OR_CASE_NOT_APPROVED")
    return (
        "/usr/bin/setpriv",
        "--reuid", str(plan.uid), "--regid", str(plan.uid),
        "--clear-groups", "--bounding-set=-all",
        "/usr/bin/python3", "-I", "-B", WORKER,
        "--p2a-internal", case, plan.dns, str(plan.uid),
    )

def peer_argv():
    return ("/usr/bin/python3", "-I", "-B", WORKER,
            "--p2a-root-peer")

class FixedWorkload:
    """Invoker runs an exact argv once and verifies real UID separately.

    invoke(argv,deadline,uid,root_peer_argv_or_none)->(exit_code,stdout,
    independent_uid_verified, independent_peer_verified).
    """
    def __init__(self, plan, *, invoke, stop):
        if validate_plan(plan)!="OFFLINE_SAFE_SCOPED_PLAN_NOT_KERNEL_VERIFIED":
            raise WorkloadDenied("INVALID_PLAN")
        if not callable(invoke) or not callable(stop):
            raise WorkloadDenied("MISSING_CLIENT_BOUNDARY")
        self.plan=plan
        self.invoke=invoke
        self.stop_client=stop
        self.index=0
        self.stopped=False

    def exercise(self, case, plan, deadline):
        if (plan != self.plan or self.stopped or self.index >= len(CASES_ORDER)
                or case != CASES_ORDER[self.index]):
            raise WorkloadDenied("CASE_RETRY_OR_REORDER")
        self.index += 1  # consumed before any launch, including failures
        answer = self.invoke(exact_argv(plan,case), deadline, plan.uid,
                             peer_argv() if case=="loopback-established" else None)
        if (not isinstance(answer,tuple) or len(answer)!=4
                or type(answer[0]) is not int or type(answer[1]) is not str
                or type(answer[2]) is not bool or type(answer[3]) is not bool):
            raise WorkloadDenied("INVALID_CLIENT_REPORT")
        code,out,uid_verified,peer_verified=answer
        label=EXPECTED.get(case,OTHER)
        if (code!=0 or out.strip()!=label or out not in (label,label+"\n")
                or not uid_verified or peer_verified != (case=="loopback-established")
                or not admissible_result(case,label)):
            raise WorkloadDenied("CLIENT_NOT_INDEPENDENTLY_VERIFIED")
        return True

    def stop(self,deadline):
        self.stopped=True
        return self.stop_client(deadline) is True
