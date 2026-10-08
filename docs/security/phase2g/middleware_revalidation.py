"""Isolated middleware final-dispatch revalidation candidate, pinned SHA only.

This is NOT an upstream submission or deployed add-on image. Applies to the
disposable pinned source checkout after the Phase 2F patch. Synthetic only.
"""
from __future__ import annotations
import argparse
import subprocess
from pathlib import Path
COMMIT="fc54437a804858732e4bc927add98e202d879a09"
FILE="src/ha_mcp/policy/middleware.py"
BLOB="5b431906fe7a37bbc19e466ca92a34b491289298"

def patch(source:str)->str:
    old='''        if pending.decision == "approved":
            if self._claim_approval(
'''
    new='''        if pending.decision == "approved":
            # Approval is not permission to use a stale or broken policy.
            # The wait above yielded control: policy edits or corruption
            # may have occurred while the request was in the queue.
            try:
                current_policy = await run_in_thread(self._policy_provider)
            except Exception:
                logger.error(
                    "Security policy unavailable before approved dispatch; "
                    "refusing to execute"
                )
                self._queue.remove(pending.token)
                raise_tool_error(
                    create_error_response(
                        ErrorCode.POLICY_LOAD_FAILED,
                        "Security policy could not be verified immediately "
                        "before dispatch. Ask an administrator to repair it "
                        "and submit a fresh request.",
                    )
                )
            if (
                current_policy.rule_effect != policy.rule_effect
                or current_policy.rules != policy.rules
            ):
                logger.warning(
                    "Tool security rules changed while approval was pending; "
                    "refusing stale approved dispatch"
                )
                self._queue.remove(pending.token)
                raise_tool_error(
                    create_error_response(
                        ErrorCode.USER_APPROVAL_REQUIRED,
                        "Security policy changed during approval. Reissue "
                        "this operation for a fresh decision under the "
                        "current rules.",
                    )
                )
            if self._claim_approval(
'''
    if source.count(old)!=1:raise RuntimeError("UPSTREAM_CONTEXT_NOT_EXACT")
    output=source.replace(old,new,1)

    def exact(a,b):
        nonlocal output
        if output.count(a)!=1:
            raise RuntimeError("PHASE2H_POLICY_BINDING_CONTEXT_CHANGED")
        output=output.replace(a,b,1)

    # Bind approvals to the gate rules they were created under. A new
    # policy must not consume an approved token minted under an old policy.
    exact(
        '''        if self._resolve_already_decided(
            name,
            args_hash,
''',
        '''        gate_key = (
            policy.rule_effect,
            tuple(r.model_dump_json() for r in policy.rules),
        )
        if self._resolve_already_decided(
            name,
            args_hash,
            gate_key=gate_key,
''')
    exact(
        '''        pending = self._finalize_timed_out_pending(
            pending, dynamic_targets=dynamic_targets, policy=policy, name=name
        )
        await self._announce_reissued''',
        '''        pending = self._finalize_timed_out_pending(
            pending, dynamic_targets=dynamic_targets, policy=policy, name=name
        )
        pending._phase2h_gate_key = gate_key
        await self._announce_reissued''')
    exact(
        '''        remember_minutes: int,
    ) -> bool:
        """Act on an entry this call did not create.''',
        '''        remember_minutes: int,
        gate_key: tuple,
    ) -> bool:
        """Act on an entry this call did not create.''')
    exact(
        '''        existing = self._queue.find(name, args_hash)
        if existing is None:
            return False
        if existing.decision == "approved":''',
        '''        existing = self._queue.find(name, args_hash)
        if existing is None:
            return False
        recorded_key = getattr(existing, "_phase2h_gate_key", None)
        # The original legacy block-list API permits explicit in-memory
        # test pre-approvals. Strict allow-list NEVER trusts an unbound token.
        if recorded_key != gate_key and (
            gate_key[0] == "allow" or recorded_key is not None
        ):
            self._queue.remove(existing.token)
            return False
        if existing.decision == "approved":''')
    exact(
        '''        if dynamic_targets:
            return self._queue.create(
                name, args_hash, args, ttl_minutes=policy.approval_ttl_minutes
            )
        return await self._queue.find_or_create(
            name, args_hash, args, ttl_minutes=policy.approval_ttl_minutes
        )
''',
        '''        gate_key = (policy.rule_effect,
                    tuple(r.model_dump_json() for r in policy.rules))
        if dynamic_targets:
            entry = self._queue.create(
                name, args_hash, args, ttl_minutes=policy.approval_ttl_minutes
            )
        else:
            entry = await self._queue.find_or_create(
                name, args_hash, args, ttl_minutes=policy.approval_ttl_minutes
            )
        recorded_key = getattr(entry, "_phase2h_gate_key", None)
        if recorded_key is not None and recorded_key != gate_key:
            self._queue.remove(entry.token)
            entry = self._queue.create(
                name, args_hash, args, ttl_minutes=policy.approval_ttl_minutes
            )
        # In-memory only, scoped to this process/queue lifetime.
        entry._phase2h_gate_key = gate_key
        return entry
''')
    exact(
        '''        if pending.decision == "approved":
            # Approval is not permission to use a stale or broken policy.''',
        '''        if pending.decision == "approved":
            # Approval is not permission to use a stale or broken policy.''')
    exact(
        '''            if (
                current_policy.rule_effect != policy.rule_effect
                or current_policy.rules != policy.rules
            ):''',
        '''            if (
                current_policy.rule_effect != policy.rule_effect
                or current_policy.rules != policy.rules
                or getattr(pending, "_phase2h_gate_key", None) != (
                    policy.rule_effect,
                    tuple(r.model_dump_json() for r in policy.rules),
                )
            ):''')
    return output

def main():
    a=argparse.ArgumentParser()
    a.add_argument("--root",type=Path,default=Path("ha_mcp_pinned"))
    a.add_argument("--apply",action="store_true")
    args=a.parse_args()
    root=args.root.resolve()
    commit=subprocess.check_output(["git","-C",str(root),"rev-parse","HEAD"],text=True).strip()
    blob=subprocess.check_output(["git","-C",str(root),"rev-parse","HEAD:"+FILE],text=True).strip()
    if commit != COMMIT or blob != BLOB:raise RuntimeError("PINNED_UPSTREAM_CHANGED")
    p=root/FILE
    patched=patch(p.read_text(encoding="utf8"))
    if args.apply:p.write_text(patched,encoding="utf8")
    print("PHASE2G_MIDDLEWARE_PINNED_PATCH_OK applied="+str(args.apply))
if __name__=="__main__":main()
