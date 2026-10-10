"""Revise exactly two pinned HA-MCP approval tests for fail-closed semantics.

Change is ONLY in an isolated test checkout; never modify production or upstream.
The original upstream suite runs independently before edits. Source SHA and
test function location must match pinned v8.6.0.
"""
from __future__ import annotations
import argparse
import subprocess
from pathlib import Path
COMMIT="fc54437a804858732e4bc927add98e202d879a09"
PATH="tests/src/unit/policy/test_middleware.py"

def replace_once(source,old,new):
    if source.count(old)!=1:
        raise RuntimeError("PHASE2H_TEST_EXPECTATION_CONTEXT_CHANGED")
    return source.replace(old,new,1)

def patch(src):
    before='''        assert (
            await mw.on_call_tool(make_context("ha_call_service", args), call_next)
            == "ok"
        )
    assert queue.is_remembered("ha_call_service", compute_args_hash(args))
'''
    after='''        with pytest.raises(ToolError):
            await mw.on_call_tool(make_context("ha_call_service", args), call_next)
    call_next.assert_not_awaited()
    assert not queue.is_remembered("ha_call_service", compute_args_hash(args))
'''
    a=src.index("async def test_switching_to_an_allow_list_mid_wait_remembers_nothing")
    b=src.index("@pytest.mark.anyio",a)
    section=src[a:b]
    section=replace_once(section,before,after)
    # Synchronize on the actual pending entry, not a sleep that may race.
    section=replace_once(section,
        '        await anyio.sleep(0.05)\n        pol[0] = Policy(rule_effect="allow", rules=[Rule(tool_name="ha_get_state")])',
        '        for _ in range(100):\n'
        '            if queue.list_pending():\n'
        '                break\n'
        '            await anyio.sleep(0.01)\n'
        '        assert queue.list_pending(), "pending not created"\n'
        '        pol[0] = Policy(rule_effect="allow", rules=[Rule(tool_name="ha_get_state")])')
    src=src[:a]+section+src[b:]
    c=src.index("async def test_a_waiter_under_an_allow_list_does_not_ride_the_winners_window")
    d=src.index("@pytest.mark.anyio",c)
    section=src[c:d]
    section=replace_once(section,
        '    assert sorted(outcomes, key=str) == ["ok", "pending"]\n    assert call_next.await_count == 1',
        '    assert sorted(outcomes, key=str) == ["ok", "pending"]\n    assert call_next.await_count == 1\n    assert not queue.is_remembered("ha_call_service", compute_args_hash(args))')
    # The second caller under the new rules may receive a NEW approval,
    # never the original rule's token. Assert a changed token explicitly.
    section=replace_once(section,
        '        await _wait_until_attached(attached, 1)\n        pol[0] =',
        '        await _wait_until_attached(attached, 1)\n'
        '        prior_token = queue.list_pending()[0].token\n'
        '        pol[0] =')
    section=replace_once(section,
        '        assert len(pending) == 1\n        queue.approve(pending[0].token)',
        '        assert len(pending) == 1\n'
        '        assert pending[0].token != prior_token\n'
        '        queue.approve(pending[0].token)')
    src=src[:c]+section+src[d:]
    return src

def main():
    p=argparse.ArgumentParser()
    p.add_argument("--root",type=Path,default=Path("ha_mcp_pinned"))
    p.add_argument("--apply",action="store_true")
    args=p.parse_args()
    root=args.root.resolve()
    actual=subprocess.check_output(["git","-C",str(root),"rev-parse","HEAD"],text=True).strip()
    if actual!=COMMIT:raise RuntimeError("UPSTREAM_SHA_MISMATCH")
    file=root/PATH
    output=patch(file.read_text())
    if args.apply:file.write_text(output)
    print("PHASE2H_REVISED_TESTS_VALID applied="+str(args.apply))
if __name__=="__main__":
    main()
