"""One final-dispatch task path: approve, claim, execute, read back, recover."""
from __future__ import annotations

import asyncio

from .model import AdminError, FAMILIES, HELPERS, effects, fingerprint, operation, redact


class Administrator:
    def __init__(self, store, backend, policy, authenticate, approved_session):
        self.store, self.backend, self.policy, self.authenticate = store, backend, policy, authenticate
        self.lock = asyncio.Lock()
        self.approved_session = approved_session

    async def db(self, method, *args, **kwargs):
        return await asyncio.to_thread(getattr(self.store, method), *args, **kwargs)

    def current(self, actor):
        actual = self.authenticate(actor.bearer)
        if (actual.user, actual.session) != (actor.user, actor.session):
            raise AdminError("caller_changed")
        return actual

    async def inspect(self, actor, family, target, detail="config", run_id=None):
        self.current(actor)
        if family not in FAMILIES | {"system"} or type(target) is not str or len(target) > 101:
            raise AdminError("unsupported_inspection")
        # Reuse the target validator; no slashes, URL or raw WS arguments.
        import re
        if not re.fullmatch(r"[A-Za-z0-9_][A-Za-z0-9_.-]{0,100}", target):
            raise AdminError("invalid_object_id")
        if run_id is not None and (type(run_id) is not str or not re.fullmatch(r"[a-f0-9]{32}", run_id)):
            raise AdminError("invalid_trace_id")
        async with asyncio.timeout(12):
            return redact(await self.backend.inspect(actor, family, target, detail, run_id))

    async def propose(self, actor, operations, ttl=600):
        self.current(actor)
        if type(ttl) is not int or not 30 <= ttl <= 900 or not isinstance(operations, list) or not 1 <= len(operations) <= 20:
            raise AdminError("task_limits")
        ops = [operation(value) for value in operations]
        before = []
        predicted = {}
        service_entities = set()
        async with asyncio.timeout(20):
            for n, op in enumerate(ops):
                if op["family"] == "service":
                    entities = set(op["value"]["entity_ids"])
                    if entities & service_entities:
                        raise AdminError("overlapping_device_task_not_supported")
                    service_entities.update(entities)
                key = (op["family"], op["target"])
                value = predicted[key] if key in predicted else await self.backend.snapshot(actor, op)
                if op["family"] in HELPERS and op["action"] == "put" and value is not None:
                    # Native helpers replace whole definitions. Make the exact
                    # merged definition visible in the immutable approval plan.
                    op = {**op, "value": {**{k:v for k,v in value.items() if k != "id"}, **op["value"]}}
                op = ops[n] = await self.backend.prepare(actor, op, planned_absent=key in predicted and predicted[key] is None)
                if fingerprint(redact(op["value"])) != fingerprint(op["value"]):
                    raise AdminError("literal_secrets_not_supported")
                key = (op["family"], op["target"])
                if op["action"] == "create" and value is not None:
                    raise AdminError("object_already_exists")
                if op["action"] in {"put", "delete", "reload"} and value is None:
                    raise AdminError("object_not_found")
                before.append(value)
                if op["family"] not in {"service", "integration", "maintenance"}:
                    predicted[key] = self.backend.expected(op, value)
            self.current(actor)
            plan = {"v": 1, "operations": ops, "effects": [effects(op) for op in ops]}
            plan["before"] = before
            plan["rollback"] = "Exact recorded before-definitions, reverse order, only within expiry and without overwriting intervening changes. Restoring a renamed helper creates it using the target ID as a temporary name, then restores its recorded name; each write rechecks the grant. Services/restarts have no automatic inverse."
            task = await self.db("create", actor, fingerprint(self.policy), plan, before, ttl)
        return await self.status(actor, task)

    async def status(self, actor, task):
        self.current(actor)
        row = await self.db("get", task)
        if (row["user"], row["session"]) != (actor.user, actor.session):
            raise AdminError("wrong_caller")
        return redact(row)

    async def execute(self, actor, task, plan_hash, *, rollback=False):
        self.current(actor)
        try:
            async with asyncio.timeout(1):
                await self.lock.acquire()
        except TimeoutError:
            raise AdminError("executor_busy") from None
        try:
            row = await self.db("get", task)
            if (row["user"], row["session"], row["policy"], row["hash"]) != (actor.user, actor.session, fingerprint(self.policy), plan_hash):
                raise AdminError("caller_scope_or_policy_changed")
            ops = row["plan"]["operations"]
            if not rollback and all(x["status"] == "applied" for x in row["operations"]):
                # Saved receipts are history, not a promise that HA's buffered
                # helper stores survived an abrupt crash or later edits.
                latest = {(op["family"], op["target"]) if op["family"] not in {"service", "integration", "maintenance"} else n: n for n, op in enumerate(ops)}
                for n in latest.values():
                    observed = await self.backend.snapshot(actor, ops[n])
                    if fingerprint(observed) != fingerprint(row["operations"][n]["after_state"]):
                        raise AdminError("recorded_result_has_drift")
                return await self.status(actor, task)
            indices = range(len(ops)-1, -1, -1) if rollback else range(len(ops))
            for n in indices:
                prior = await self.db("get", task)
                item = prior["operations"][n]
                if item["status"] == ("rolled_back" if rollback else "applied"):
                    continue  # Durable result retrieval, never another write.
                if rollback and item["status"] == "pending":
                    continue  # Restore the applied prefix, not undispatched work.
                if item["status"] != ("applied" if rollback else "pending"):
                    raise AdminError("operation_consumed_or_uncertain")
                op = ops[n]
                if rollback and op["family"] in {"service", "integration", "maintenance"}:
                    raise AdminError("operation_has_no_safe_inverse")
                expected_before = item["after_state"] if rollback else item["before_state"]
                if not rollback and op["family"] not in {"service", "integration", "maintenance"}:
                    for p in prior["operations"][:n]:
                        previous = ops[p["n"]]
                        if (previous["family"], previous["target"]) == (op["family"], op["target"]):
                            expected_before = p["after_state"]
                async with asyncio.timeout(20):
                    actual = await self.backend.snapshot(actor, op)
                    if fingerprint(actual) != fingerprint(expected_before):
                        raise AdminError("object_changed_requires_new_approval")
                    dispatched = op
                    if rollback:
                        before = item["before_state"]
                        dispatched = {**op, "action": "delete" if before is None else "create" if actual is None else "put", "value": before}
                        if op["family"] in {"automation", "input_boolean", "input_number", "input_text", "input_select", "input_datetime", "input_button", "counter", "timer"} and before:
                            dispatched["value"] = {k:v for k,v in before.items() if k != "id"}
                    if dispatched["action"] == "delete":
                        references = await self.backend.references(actor, op["target"], op["family"])
                        if references:
                            raise AdminError("referenced_object_requires_explicit_repair")
                    self.current(actor)
                    await self.db("claim", task, n, actor, fingerprint(self.policy), plan_hash, rollback=rollback)
                    # Recheck after persistence and immediately before dispatch.
                    await self.db("authorize", task, actor, fingerprint(self.policy), plan_hash)
                    self.approved_session(prior["approved_by"])
                    self.current(actor)
                    try:
                        async def final_check():
                            await self.db("authorize", task, actor, fingerprint(self.policy), plan_hash)
                            self.approved_session(prior["approved_by"])
                            self.current(actor)
                        with self.backend.dispatch(final_check):
                            result = await self.backend.write(actor, dispatched)
                        self.current(actor)
                        after = await self.backend.after(actor, op)
                        wanted = item["before_state"] if rollback else self.backend.expected(op, actual)
                        if not (fingerprint(after) == fingerprint(wanted) if rollback else self.backend.verified(op, actual, after, result)):
                            status = "uncertain"
                        else:
                            status = "rolled_back" if rollback else "applied"
                        await self.db("finish", task, n, status, after, {"backend_acknowledged": True, "stored_definition_or_ha_state_verified": status in {"applied", "rolled_back"}, "physical_behavior_verified": False, "result": redact(result)}, expected="rolling_back" if rollback else "dispatching")
                        if status not in {"applied", "rolled_back"}:
                            raise AdminError("outcome_requires_reconciliation")
                    except BaseException as exc:
                        # Cancellation/timeout can occur after a completed write.
                        # A retained dispatching prefix also blocks restart replay
                        # if storage itself fails; never run a blind retry.
                        if not isinstance(exc, AdminError) or exc.code != "outcome_requires_reconciliation":
                            try:
                                await asyncio.shield(self.db("finish", task, n, "uncertain", item["after_state"] if rollback else None, {"rollback": rollback, "error": exc.code if isinstance(exc, AdminError) else "interrupted"}, expected="rolling_back" if rollback else "dispatching"))
                            except (AdminError, asyncio.CancelledError):
                                pass
                        raise
            return await self.status(actor, task)
        finally:
            self.lock.release()

    async def reconcile(self, actor, task, plan_hash):
        """Read current definitions after interruption; never repeat a write."""
        self.current(actor)
        async with self.lock:
            row = await self.db("get", task)
            if (row["user"], row["session"], row["policy"], row["hash"]) != (actor.user, actor.session, fingerprint(self.policy), plan_hash):
                raise AdminError("caller_scope_or_policy_changed")
            for n, item in enumerate(row["operations"]):
                if item["status"] not in {"dispatching", "rolling_back", "uncertain"}:
                    continue
                op = row["plan"]["operations"][n]
                if op["family"] in {"service", "integration", "maintenance"}:
                    raise AdminError("external_outcome_requires_owner_reconciliation")
                after = await self.backend.snapshot(actor, op)
                restoring = item["status"] == "rolling_back" or (item["result"] or {}).get("rollback", False)
                wanted = item["before_state"] if restoring else self.backend.expected(op, item["before_state"])
                opposite = item["after_state"] if restoring else item["before_state"]
                if fingerprint(after) == fingerprint(wanted) and fingerprint(after) != fingerprint(opposite):
                    await self.db("finish", task, n, "rolled_back" if restoring else "applied", after, {"current_definition_verified": True, "mutation_attribution_verified": False}, expected=item["status"])
                else:
                    raise AdminError("outcome_requires_owner_reconciliation")
            return await self.status(actor, task)
