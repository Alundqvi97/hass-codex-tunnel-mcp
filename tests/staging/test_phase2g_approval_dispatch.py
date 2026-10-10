"""Phase 2G real pinned middleware + real FastMCP and synthetic terminal tools.

No Home Assistant connection, real entities, network listeners or accounts.
"""
from __future__ import annotations

import asyncio
import json
from unittest.mock import AsyncMock, MagicMock

import pytest

from ha_mcp._vendor.fastmcp import Client, FastMCP
from ha_mcp._vendor.fastmcp.exceptions import ToolError
from ha_mcp.policy.approval_queue import ApprovalQueue
from ha_mcp.policy.middleware import PolicyMiddleware
from ha_mcp.policy.model import Policy, Rule
from ha_mcp.policy.persistence import load_policy, save_policy
from ha_mcp.transforms.categorized_search import CategorizedSearchTransform

APPROVAL = Policy(rule_effect="allow", rules=[Rule(tool_name="ha_get_overview")])


def fake_server(policy_provider=None):
    q=ApprovalQueue()
    state=[]
    m=FastMCP("phase2g synthetic approval harness")

    @m.tool(name="ha_get_overview", annotations={"readOnlyHint": True})
    async def read_only() -> dict:
        state.append(("ha_get_overview", {}))
        return {"ok": True}

    @m.tool(name="ha_call_service", annotations={"readOnlyHint": False, "destructiveHint": True})
    async def service(domain: str | None = None, service: str | None = None,
                      entity_id: str | None = None, ws_command: str | None = None) -> dict:
        state.append(("ha_call_service",{"domain":domain,"service":service,
                                         "entity_id":entity_id,"ws_command":ws_command}))
        return {"fake_dispatch": True}

    @m.tool(name="ha_bulk_control", annotations={"readOnlyHint": False, "destructiveHint": True})
    async def bulk(selector: dict | None = None, action: str | None = None) -> dict:
        state.append(("ha_bulk_control", {"selector":selector,"action":action}))
        return {"fake_dispatch": True}


    @m.tool(name="ha_delete_file", annotations={"readOnlyHint": False, "destructiveHint": True})
    async def delete_file(path: str) -> dict:
        state.append(("ha_delete_file", {"path":path}))
        return {"fake_dispatch": True}

    @m.tool(name="ha_restart", annotations={"readOnlyHint": False, "destructiveHint": True})
    async def restart() -> dict:
        state.append(("ha_restart", {}))
        return {"fake_dispatch": True}

    @m.tool(name="new_tool_after_upgrade", annotations={"readOnlyHint": False})
    async def new_tool() -> dict:
        state.append(("new_tool_after_upgrade", {}))
        return {"fake_dispatch": True}

    m.add_middleware(PolicyMiddleware(
        policy_provider=policy_provider or (lambda: APPROVAL),
        queue=q,wait_seconds=0))
    m.add_transform(CategorizedSearchTransform())
    return m,q,state


async def request(client,name,args):
    return await client.call_tool(name,args,raise_on_error=False)


@pytest.mark.asyncio
@pytest.mark.parametrize("name,args",[
    ("ha_call_service",{"domain":"lock","service":"unlock","entity_id":"lock.synthetic"}),
    ("ha_call_service",{"domain":"light","service":"turn_on","entity_id":"light.synthetic"}),
    ("ha_call_service",{"ws_command":'{"type":"call_service","domain":"lock","service":"unlock"}'}),
    ("ha_bulk_control",{"selector":{"domain":"lock"},"action":"unlock"}),
    ("ha_restart",{}),
    ("new_tool_after_upgrade",{}),
])
async def test_real_fastmcp_blocks_all_unmatched_operations(name,args):
    server,q,dispatched=fake_server()
    async with Client(server) as client:
        result=await request(client,name,args)
        assert result.is_error, (name, result)
        assert "USER_APPROVAL_REQUIRED" in result.content[0].text
        assert dispatched == []
        if name == "ha_bulk_control" and "selector" in args:
            # Dynamic selectors bind to a single waiting invocation.
            # With wait_seconds=0, the token is deliberately removed.
            assert q.list_pending() == []
        else:
            assert len(q.list_pending()) == 1


@pytest.mark.asyncio
async def test_only_pinned_read_auto_runs_in_real_fastmcp():
    server,q,dispatched=fake_server()
    async with Client(server) as client:
        result=await request(client,"ha_get_overview",{})
        assert not result.is_error
        assert dispatched==[("ha_get_overview",{})]
        assert q.list_pending()==[]


@pytest.mark.asyncio
@pytest.mark.parametrize("route",["direct","ha_call_write_tool"])
async def test_real_fastmcp_exact_approval_consumed_once_for_direct_and_proxy(route):
    server,q,dispatched=fake_server()
    args={"domain":"light","service":"turn_on","entity_id":"light.synthetic"}
    envelope=args if route=="direct" else {"name":"ha_call_service","arguments":args}
    name="ha_call_service" if route=="direct" else route
    async with Client(server) as client:
        first=await request(client,name,envelope)
        assert first.is_error
        pending=q.list_pending()
        assert len(pending)==1 and dispatched==[]
        token=pending[0].token
        assert q.approve(token)
        second=await request(client,name,envelope)
        assert not second.is_error
        assert len(dispatched)==1
        assert not q.approve(token)
        replay=await request(client,name,envelope)
        assert replay.is_error
        assert len(dispatched)==1


@pytest.mark.asyncio
async def test_rejected_approval_does_not_dispatch_synthetic_tool():
    server,q,dispatched=fake_server()
    async with Client(server) as c:
        first=await request(c,"ha_restart",{})
        assert first.is_error and len(q.list_pending())==1
        token=q.list_pending()[0].token
        assert q.deny(token)
        denied=await request(c,"ha_restart",{})
        assert denied.is_error and "USER_DENIED" in denied.content[0].text
        assert dispatched==[]


@pytest.mark.asyncio
async def test_mutated_arguments_never_inherit_approved_token():
    server,q,dispatched=fake_server()
    a={"domain":"light","service":"turn_on","entity_id":"light.synthetic"}
    b={"domain":"lock","service":"unlock","entity_id":"lock.synthetic"}
    async with Client(server) as c:
        assert (await request(c,"ha_call_service",a)).is_error
        token=q.list_pending()[0].token
        assert q.approve(token)
        assert (await request(c,"ha_call_service",b)).is_error
        assert dispatched==[]


@pytest.mark.asyncio
async def test_corruption_after_pending_approval_never_reaches_final_action(tmp_path):
    save_policy(tmp_path,APPROVAL)
    q=ApprovalQueue()
    def provider():
        return load_policy(tmp_path)
    mw=PolicyMiddleware(policy_provider=provider,queue=q,wait_seconds=4)
    context=MagicMock()
    context.message.name="ha_restart"
    context.message.arguments={}
    context.fastmcp_context=None
    next_action=AsyncMock(return_value="synthetic-action-dispatched")

    async def request_action():
        return await mw.on_call_tool(context,next_action)

    worker=asyncio.create_task(request_action())
    try:
        for _ in range(150):
            if q.list_pending():break
            await asyncio.sleep(.01)
        assert len(q.list_pending())==1
        (tmp_path/"tool_policy.json").write_text("{synthetic-invalid-json")
        assert q.approve(q.list_pending()[0].token)
        with pytest.raises(ToolError):
            await asyncio.wait_for(worker,3)
        next_action.assert_not_awaited()
    finally:
        if not worker.done():
            worker.cancel()
            try:await worker
            except asyncio.CancelledError:pass


@pytest.mark.asyncio
async def test_modified_policy_during_pending_approval_requires_fresh_decision():
    state=[APPROVAL]
    queue=ApprovalQueue()
    mw=PolicyMiddleware(policy_provider=lambda: state[0],queue=queue,wait_seconds=4)
    context=MagicMock()
    context.message.name="ha_restart"
    context.message.arguments={}
    context.fastmcp_context=None
    dispatch=AsyncMock(return_value="synthetic-only")
    worker=asyncio.create_task(mw.on_call_tool(context,dispatch))
    try:
        for _ in range(150):
            if queue.list_pending():break
            await asyncio.sleep(.01)
        assert len(queue.list_pending())==1
        state[0]=Policy(rule_effect="allow",rules=[
            Rule(tool_name="ha_get_overview"),
            Rule(tool_name="ha_list_services")])
        assert queue.approve(queue.list_pending()[0].token)
        with pytest.raises(ToolError):
            await asyncio.wait_for(worker,3)
        dispatch.assert_not_awaited()
    finally:
        if not worker.done():
            worker.cancel()
            try:await worker
            except asyncio.CancelledError:pass


@pytest.mark.asyncio
async def test_genuine_delete_proxy_gates_final_synthetic_file_delete():
    server,queue,dispatched=fake_server()
    envelope={"name":"ha_delete_file","arguments":{"path":"/synthetic-do-not-create"}}
    async with Client(server) as client:
        first=await request(client,"ha_call_delete_tool",envelope)
        assert first.is_error
        assert "USER_APPROVAL_REQUIRED" in first.content[0].text
        assert not dispatched and len(queue.list_pending())==1
        token=queue.list_pending()[0].token
        assert queue.approve(token)
        success=await request(client,"ha_call_delete_tool",envelope)
        assert not success.is_error
        assert dispatched==[("ha_delete_file",{"path":"/synthetic-do-not-create"})]
        replay=await request(client,"ha_call_delete_tool",envelope)
        assert replay.is_error and len(dispatched)==1


@pytest.mark.asyncio
async def test_read_search_proxy_cannot_invoke_synthetic_write_action():
    server,queue,dispatched=fake_server()
    envelope={"name":"ha_call_service","arguments":{
        "domain":"lock","service":"unlock","entity_id":"lock.synthetic"}}
    async with Client(server) as client:
        result=await request(client,"ha_call_read_tool",envelope)
        assert result.is_error
        assert dispatched==[]
        assert queue.list_pending()==[]
