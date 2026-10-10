"""Inert cgroup-v2 full-tree containment contract; no OS writes are wired.

The reviewed future runner must supply an OS-backed adapter implementing
atomic pre-exec cgroup attachment (e.g. clone3 CLONE_INTO_CGROUP), kill all
members including detached descendants/root peer, and independently observe
cgroup.events populated=0 and empty cgroup.procs.

Merely moving a PID to a cgroup AFTER Popen is not acceptable: a hostile
child may already have executed. This file does not install any cgroup.
"""
from __future__ import annotations
import re

from probe_contract import validate_plan
from probe_a_workload import CASES_ORDER,exact_argv,peer_argv

class ContainmentDenied(RuntimeError):
    pass

class CgroupV2Containment:
    def __init__(self, plan, *, agent):
        if validate_plan(plan)!="OFFLINE_SAFE_SCOPED_PLAN_NOT_KERNEL_VERIFIED":
            raise ContainmentDenied("INVALID_PLAN")
        if agent is None or not all(callable(getattr(agent,k,None)) for k in
             ("preflight_atomic_spawn","capture_atomic","kill_all","readback","check_uid_absent")):
            raise ContainmentDenied("UNREVIEWED_CGROUP_ADAPTER")
        self.plan=plan
        self.agent=agent
        self.path="/sys/fs/cgroup/p2a-"+plan.scope
        self.armed=False
        self.spawned=[]
        self.stop_requested=False

    def arm(self):
        # Implementation of this callback needs a future qualified review.
        # It MUST attest cgroup v2, no delegates and pre-exec atomic attach.
        if self.armed or self.agent.preflight_atomic_spawn(self.path) is not True:
            raise ContainmentDenied("ATOMIC_ATTACH_UNVERIFIED")
        self.armed=True
        return True

    def capture(self,argv,timeout,**callbacks):
        worker=argv in tuple(exact_argv(self.plan,c) for c in CASES_ORDER)
        peer=argv==peer_argv()
        if (not self.armed or self.stop_requested or (not worker and not peer)
                or type(timeout) not in (int,float) or not 0<timeout<=8):
            raise ContainmentDenied("UNREVIEWED_CONTAINED_SPAWN")
        self.spawned.append(("peer" if peer else "worker",argv))
        # MUST be OS-attached before the process executes any user code.
        # The adapter receives only pinned argv, fixed path and callbacks.
        return self.agent.capture_atomic(self.path,argv,timeout,**callbacks)

    def stop(self,deadline):
        self.stop_requested=True
        if not self.armed:
            return False
        try:
            killed=self.agent.kill_all(self.path,deadline) is True
            # An untrusted kill() success cannot prove containment: verify
            # cgroup.events + cgroup.procs, and independent UID absence.
            snapshot=self.agent.readback(self.path,deadline)
            if (not isinstance(snapshot,tuple) or len(snapshot)!=2 or
                    type(snapshot[0]) is not str or type(snapshot[1]) is not str):
                return False
            events,procs=snapshot
            entries=dict(m.split(" ",1) for m in events.strip().splitlines() if " " in m)
            return (killed and entries.get("populated")=="0" and
                    not procs.strip() and
                    self.agent.check_uid_absent(self.plan.uid,deadline) is True)
        except BaseException:
            return False
