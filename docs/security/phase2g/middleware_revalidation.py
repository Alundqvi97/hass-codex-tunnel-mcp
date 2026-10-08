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
    return source.replace(old,new,1)

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
