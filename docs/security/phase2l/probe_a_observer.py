"""Read-only host observer for an explicitly injected exact-command backend.

This module does not claim provenance from injected text. No execution on
import; independent real-kernel attribution and off-process recovery require
later runtime approval/review.
"""
from __future__ import annotations

import re
import time

from probe_a_exec_adapter import Reply, checked_reply
from probe_a_kernel import bounded, compare_after, expect_active, parse_packets, InvalidEvidence
from probe_a_os_boundary import SAVE4, SAVE6, VERSION4, VERSION6
from probe_contract import CLEANUP_READBACKS, validate_plan

class ObservationDenied(RuntimeError):
    pass

class KernelReadback:
    """The read callable must come from RestrictedHost, not a client result."""
    def __init__(self, plan, *, read, clock=time.monotonic):
        if validate_plan(plan) != "OFFLINE_SAFE_SCOPED_PLAN_NOT_KERNEL_VERIFIED" or not callable(read):
            raise ObservationDenied("INVALID_OBSERVER")
        self.plan = plan
        self.read = read
        self.clock = clock
        self.baseline = None
        self.versions = None

    def _query(self, argv, deadline, codes=(0,)):
        if self.clock() >= deadline:
            raise ObservationDenied("OBSERVER_DEADLINE")
        try:
            reply = checked_reply(self.read(argv, deadline))
        except BaseException:
            raise ObservationDenied("READBACK_FAILED") from None
        if reply.code not in codes:
            raise ObservationDenied("UNEXPECTED_STATUS")
        return reply.stdout

    def snapshot(self, deadline):
        return (bounded(self._query(SAVE4, deadline)),
                bounded(self._query(SAVE6, deadline)))

    def preflight(self, deadline):
        if self.baseline is not None:
            raise ObservationDenied("PREFLIGHT_REPEATED")
        v4 = self._query(VERSION4, deadline).strip()
        v6 = self._query(VERSION6, deadline).strip()
        # A mixed legacy/nft backend, or an unexpected format, is not safe.
        pattern = r"ip6?tables v1\.8\.[0-9]+ \(nf_tables\)"
        if not re.fullmatch(pattern, v4) or not re.fullmatch(pattern, v6):
            raise ObservationDenied("BACKEND_UNTRUSTED")
        # Caller must separately pin the exact runner/binary identity.
        self.versions = (v4, v6)
        uid = str(self.plan.uid)
        checks = (
            (("/usr/bin/getent", "passwd", uid), 2),
            (("/usr/bin/pgrep", "-u", uid), 1),
            (self.plan.inspect[4].argv, 1),
            (self.plan.inspect[5].argv, 1),
        )
        for argv, absent_code in checks:
            text = self._query(argv, deadline, codes=(absent_code,))
            if text.strip():
                raise ObservationDenied("IDENTITY_OR_CHAIN_COLLISION")
        self.baseline = self.snapshot(deadline)
        if self.plan.chain4 in self.baseline[0] or self.plan.chain6 in self.baseline[1]:
            raise ObservationDenied("OWNED_NAME_COLLISION")
        return True

    def require_active(self, deadline, *, final=True):
        if self.baseline is None:
            raise ObservationDenied("BASELINE_ABSENT")
        return expect_active(*self.snapshot(deadline), *self.baseline, self.plan, final=final)

    def counters(self, family, deadline):
        if family not in ("ipv4", "ipv6") or self.baseline is None:
            raise ObservationDenied("INVALID_FAMILY")
        binary, chain = (
            ("/usr/sbin/iptables", self.plan.chain4) if family == "ipv4"
            else ("/usr/sbin/ip6tables", self.plan.chain6)
        )
        rows = parse_packets(self._query(
            (binary, "-w", "5", "-L", chain, "-v", "-n", "-x"), deadline
        ), chain)
        expected = ("ACCEPT", "ACCEPT", "ACCEPT", "REJECT") if family == "ipv4" else ("REJECT",)
        if tuple(r[2] for r in rows) != expected:
            raise ObservationDenied("COUNTER_ORDER_OR_TARGET")
        return rows

    def require_restored(self, deadline):
        if self.baseline is None:
            raise ObservationDenied("NO_PRECHANGE_SNAPSHOT")
        return compare_after(*self.snapshot(deadline), *self.baseline)

    def mandatory_readbacks(self, deadline, *, independent_resources):
        """All keys are checked; externally managed resources MUST have their own observer.

        A callback is not a security attestation, and this result is not
        advertised as proven runtime evidence.
        """
        result = {}
        uid = str(self.plan.uid)
        for key in CLEANUP_READBACKS:
            try:
                if key == "numeric_uid_account_absent":
                    result[key] = not self._query(
                        ("/usr/bin/getent", "passwd", uid), deadline, codes=(2,)
                    ).strip()
                elif key == "numeric_uid_process_absent":
                    result[key] = not self._query(
                        ("/usr/bin/pgrep", "-u", uid), deadline, codes=(1,)
                    ).strip()
                elif key in ("preexisting_ipv4_filter_identical", "preexisting_ipv6_filter_identical"):
                    if self.baseline is None:
                        result[key] = False
                    else:
                        idx = 0 if "ipv4" in key else 1
                        result[key] = self.snapshot(deadline)[idx] == self.baseline[idx]
                elif key in ("ipv4_chain_absent", "ipv6_chain_absent"):
                    cmd = self.plan.inspect[4 if key.startswith("ipv4") else 5].argv
                    result[key] = not self._query(cmd, deadline, codes=(1,)).strip()
                elif key in ("ipv4_output_hook_absent", "ipv6_output_hook_absent"):
                    index = 0 if key.startswith("ipv4") else 1
                    chain = self.plan.chain4 if index == 0 else self.plan.chain6
                    result[key] = not any(
                        line.startswith("-A OUTPUT ") and chain in line.split()
                        for line in self.snapshot(deadline)[index].splitlines()
                    )
                else:
                    # Listener, files, watcher, resolver MUST be observed by an
                    # independent actor with an explicit per-key readback.
                    result[key] = independent_resources.readback(key, deadline) is True
            except BaseException:
                result[key] = False
        return result
