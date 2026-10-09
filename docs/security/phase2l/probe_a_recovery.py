"""Fail-closed partial-rule classifier and conditional owned-only recovery.

All commands are already present in the canonical plan. The supplied
read/write callbacks are dependency injected; importing this module cannot
change a firewall. This is not evidence of real kernel provenance.
"""
from __future__ import annotations

from dataclasses import dataclass
from probe_contract import validate_plan
from probe_a_kernel import bounded, extract_rules, tokens, compare_after


class RecoveryDenied(RuntimeError):
    pass


@dataclass(frozen=True)
class FamilyState:
    chain: bool
    hook: bool
    rules: int


def _family(active, baseline, chain, uid, *, ipv6=False, dns=None):
    hook = ("-A", "OUTPUT", "-m", "owner", "--uid-owner", str(uid), "-j", chain)
    other, owned = extract_rules(bounded(active), chain, hook)
    if other != tuple(bounded(baseline).splitlines()):
        raise RecoveryDenied("UNRELATED_RULE_DRIFT")
    definitions = [line for kind, line in owned if kind == "chain"]
    hooks = [line for kind, line in owned if kind == "hook"]
    raw = [tokens(line) for kind, line in owned if kind == "rule"]
    if len(definitions) > 1 or len(hooks) > 1:
        raise RecoveryDenied("AMBIGUOUS_OWNERSHIP")
    if definitions and definitions != [":" + chain + " - [0:0]"]:
        raise RecoveryDenied("CHAIN_DEFINITION_DRIFT")
    if (hooks or raw) and not definitions:
        raise RecoveryDenied("ORPHANED_RULE_OR_HOOK")
    allowed = [
        ("-A", chain, "-j", "REJECT"),
    ] if ipv6 else [
        ("-A", chain, "-j", "REJECT"),
        ("-A", chain, "-d", dns + "/32", "-p", "udp", "-m", "udp", "--dport", "53", "-j", "ACCEPT"),
        ("-A", chain, "-d", dns + "/32", "-p", "tcp", "-m", "tcp", "--dport", "53", "-j", "ACCEPT"),
        ("-A", chain, "-o", "lo", "-d", "127.0.0.1/32", "-p", "tcp",
         "-m", "conntrack", "--ctstate", "ESTABLISHED", "-j", "ACCEPT"),
    ]
    # -I 1 produces the reverse of plan insertion order.
    prefixes = [()] if not ipv6 else [(), (allowed[0],)]
    if not ipv6:
        for count in range(1, len(allowed) + 1):
            prefixes.append(tuple(reversed(allowed[:count])))
    canonical = []
    for row in raw:
        if row[-2:] == ("--reject-with", "icmp-port-unreachable"):
            row = row[:-2]
        canonical.append(row)
    if tuple(canonical) not in prefixes:
        raise RecoveryDenied("UNREVIEWED_CHAIN_RULE")
    if hooks:
        output = [tokens(line) for line in bounded(active).splitlines()
                  if line.startswith("-A OUTPUT ")]
        if not output or output[0] != hook or not raw:
            raise RecoveryDenied("OWNER_HOOK_DRIFT")
    return FamilyState(bool(definitions), bool(hooks), len(raw))


def inspect_partial(plan, before, current):
    if validate_plan(plan) != "OFFLINE_SAFE_SCOPED_PLAN_NOT_KERNEL_VERIFIED":
        raise RecoveryDenied("INVALID_PLAN")
    if not isinstance(before, tuple) or len(before) != 2 or not isinstance(current, tuple) or len(current) != 2:
        raise RecoveryDenied("SNAPSHOT_INVALID")
    v4 = _family(current[0], before[0], plan.chain4, plan.uid, dns=plan.dns)
    v6 = _family(current[1], before[1], plan.chain6, plan.uid, ipv6=True)
    return v4, v6


def recover_owned(plan, baseline, *, snapshot, execute, deadline, clock):
    """Attempt each exact teardown argv at most once, never flush unknown state.

    Must be invoked by the separate guardian, NOT by the test UID.
    Any missing/ambiguous observation blocks further destructive actions.
    Every attempted write is followed by an independent snapshot. No
    post-failure retry and no restoration of unrelated tables.
    """
    attempted = []
    failure = False
    for command in plan.teardown:
        try:
            if clock() >= deadline:
                raise RecoveryDenied("CLEANUP_DEADLINE")
            states = inspect_partial(plan, baseline, snapshot(deadline))
            state = states[0 if command.family == "ipv4" else 1]
            present = state.hook if command.phase == "unhook" else state.chain
            if command.phase == "own-chain-only" and command.argv[-2] == "-X":
                present = state.chain
                if state.hook or state.rules:
                    raise RecoveryDenied("CANNOT_DELETE_NONEMPTY_OR_HOOKED_CHAIN")
            if command.phase == "own-chain-only" and command.argv[-2] == "-F":
                if state.hook:
                    raise RecoveryDenied("CANNOT_FLUSH_HOOKED_CHAIN")
            if not present:
                continue
            attempted.append(command.argv)
            if execute(command.argv, deadline) is not True:
                failure = True
                # Do not retry. Subsequent steps still require verified
                # ownership and dependencies from fresh snapshots.
            inspect_partial(plan, baseline, snapshot(deadline))
        except BaseException:
            failure = True
            # Snapshot ambiguity disables subsequent writes. A safe actor
            # cannot infer ownership from previously attempted commands.
            try:
                inspect_partial(plan, baseline, snapshot(deadline))
            except BaseException:
                break
    try:
        if clock() >= deadline:
            raise RecoveryDenied("CLEANUP_DEADLINE")
        compare_after(*snapshot(deadline), *baseline)
    except BaseException:
        failure = True
    return ("SYNTHETIC_RECOVERED_NOT_KERNEL_ATTESTED" if not failure
            else "BLOCKED_CLEANUP_UNVERIFIED", tuple(attempted))
