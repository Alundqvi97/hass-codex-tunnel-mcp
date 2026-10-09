"""Fail-closed partial-rule classifier and conditional owned-only recovery.

All commands are already present in the canonical plan. The supplied
read/write callbacks are dependency injected; importing this module cannot
change a firewall. This is not evidence of real kernel provenance.
"""
from __future__ import annotations

from dataclasses import dataclass
from probe_contract import validate_plan, emergency_deny_commands, emergency_barrier_command
from probe_a_kernel import bounded, extract_rules, tokens, compare_after, canonical_owned_rule


class RecoveryDenied(RuntimeError):
    pass


@dataclass(frozen=True)
class FamilyState:
    chain: bool
    hook: bool
    rules: int
    barrier: bool = False


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
    if definitions and definitions[0] not in (":" + chain + " - [0:0]", ":" + chain + " - [COUNTERS]"):
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
    canonical = tuple(canonical_owned_rule(row, chain=chain, ipv6=ipv6) for row in raw)
    normalized_prefixes = tuple(
        tuple(canonical_owned_rule(row, chain=chain, ipv6=ipv6) for row in prefix)
        for prefix in prefixes
    )
    reject=canonical_owned_rule(allowed[0],chain=chain,ipv6=ipv6)
    # A verified emergency leading REJECT can coexist with the original
    # terminal REJECT without granting more permissions.
    barrier=(len(canonical)>=2 and canonical[0]==reject and canonical[-1]==reject)
    valid=(canonical in normalized_prefixes or
           (barrier and canonical[1:] in normalized_prefixes))
    if not valid:
        raise RecoveryDenied("UNREVIEWED_CHAIN_RULE")
    if hooks:
        output = [tokens(line) for line in bounded(active).splitlines()
                  if line.startswith("-A OUTPUT ")]
        if not output or output[0] != hook or not raw:
            raise RecoveryDenied("OWNER_HOOK_DRIFT")
    return FamilyState(bool(definitions), bool(hooks), len(raw),barrier)


def inspect_partial(plan, before, current):
    if validate_plan(plan) != "OFFLINE_SAFE_SCOPED_PLAN_NOT_KERNEL_VERIFIED":
        raise RecoveryDenied("INVALID_PLAN")
    if not isinstance(before, tuple) or len(before) != 2 or not isinstance(current, tuple) or len(current) != 2:
        raise RecoveryDenied("SNAPSHOT_INVALID")
    v4 = _family(current[0], before[0], plan.chain4, plan.uid, dns=plan.dns)
    v6 = _family(current[1], before[1], plan.chain6, plan.uid, ipv6=True)
    return v4, v6


def recover_owned(plan, baseline, *, snapshot, execute, deadline, clock,
                  previous_attempts=(), on_attempt=None):
    """Attempt each exact teardown argv at most once, never flush unknown state.

    Must be invoked by the separate guardian, NOT by the test UID.
    Any missing/ambiguous observation blocks further destructive actions.
    Every attempted write is followed by an independent snapshot. No
    post-failure retry and no restoration of unrelated tables.
    """
    attempted = []
    previous=set(previous_attempts)
    if not previous.issubset({x.argv for x in plan.teardown}):
        raise RecoveryDenied("UNREVIEWED_PREVIOUS_TEARDOWN")
    if on_attempt is not None and not callable(on_attempt):
        raise RecoveryDenied("INVALID_MUTATION_JOURNAL")
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
            if command.argv in previous:
                # The command's result was uncertain. NEVER automatically
                # replay it, even if the readback still shows this resource.
                failure = True
                continue
            attempted.append(command.argv)
            if on_attempt is not None:
                on_attempt(command.argv)  # durable-in-process BEFORE mutation
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


def emergency_deny_only(plan, baseline, *, snapshot, execute, deadline, clock,
                        previous_attempts=(), on_attempt=None):
    """Emergency ACCEPT removal, while keeping BOTH restrictive UID hooks.

    Never unlink a hook here. Requires dual-family hooks prior to any write:
    if a compromised worker exists during partial setup, this fails closed.
    Each action is observed before and after, preserving unrelated rules.
    """
    commands=emergency_deny_commands(plan)
    barrier_cmd=emergency_barrier_command(plan)
    previously=set(previous_attempts)
    if not previously.issubset({c.argv for c in commands}|{barrier_cmd.argv}):
        raise RecoveryDenied("UNREVIEWED_EMERGENCY_JOURNAL")
    attempted=[]
    failed=False
    # First deny all traffic by putting REJECT above EVERY temporary ACCEPT.
    # If a deletion subsequently fails, DNS remains blocked by the barrier.
    # Never retry a write whose previous outcome was uncertain.
    try:
        first=inspect_partial(plan,baseline,snapshot(deadline))
        if not (first[0].hook and first[1].hook):
            raise RecoveryDenied("DUAL_STACK_OWNER_HOOK_NOT_PRESENT")
        if not first[0].barrier:
            if barrier_cmd.argv in previously:
                raise RecoveryDenied("UNCERTAIN_BARRIER_NOT_RETRIED")
            attempted.append(barrier_cmd.argv)
            if on_attempt is not None:
                on_attempt(barrier_cmd.argv)
            if execute(barrier_cmd.argv,deadline) is not True:
                raise RecoveryDenied("EMERGENCY_BARRIER_WRITE_FAILED")
            first=inspect_partial(plan,baseline,snapshot(deadline))
            if not (first[0].barrier and first[0].hook and first[1].hook):
                raise RecoveryDenied("EMERGENCY_BARRIER_NOT_VERIFIED")
    except BaseException:
        return "BLOCKED_EMERGENCY_UNVERIFIED",tuple(attempted)
    for command in commands:
        try:
            if clock()>=deadline:
                raise RecoveryDenied("EMERGENCY_DEADLINE")
            before=inspect_partial(plan,baseline,snapshot(deadline))
            if not (before[0].hook and before[1].hook):
                raise RecoveryDenied("DUAL_STACK_OWNER_HOOK_NOT_PRESENT")
            # Require expected rule membership before exact deletion.
            active=snapshot(deadline)[0]
            _,own=extract_rules(active,plan.chain4,("-A","OUTPUT","-m","owner","--uid-owner",
                                                    str(plan.uid),"-j",plan.chain4))
            from probe_a_kernel import canonical_owned_rule
            needle=canonical_owned_rule(
                ("-A",plan.chain4)+command.argv[5:],chain=plan.chain4,ipv6=False)
            present=any(canonical_owned_rule(tokens(row),chain=plan.chain4,ipv6=False)==needle
                        for kind,row in own if kind=="rule")
            if not present:
                continue
            if command.argv in previously:
                failed=True  # already attempted, no second mutation
                continue
            attempted.append(command.argv)
            if on_attempt is not None:
                on_attempt(command.argv)
            if execute(command.argv,deadline) is not True:
                failed=True
                # Subsequent deletion would break the validated removal
                # order; stop rather than creating an unknown partial state.
                break
            after=inspect_partial(plan,baseline,snapshot(deadline))
            if not (after[0].hook and after[1].hook):
                raise RecoveryDenied("EMERGENCY_HOOK_DRIFT")
        except BaseException:
            failed=True
            # No blind continuation after unknown ownership/drift.
            try:
                state=inspect_partial(plan,baseline,snapshot(deadline))
                if not (state[0].hook and state[1].hook):
                    break
            except BaseException:
                break
    try:
        now=inspect_partial(plan,baseline,snapshot(deadline))
        if not (now[0].hook and now[1].hook and now[0].barrier) or now[0].rules!=2:
            failed=True
    except BaseException:
        failed=True
    return ("BLOCKED_EMERGENCY_UNVERIFIED" if failed else "DENY_ONLY_OWNER_HOOKS_RETAINED_NOT_LIVE_ATTESTED",
            tuple(attempted))
