"""One final-dispatch task path: approve, claim, execute, read back, recover."""
from __future__ import annotations

import asyncio

from .model import AdminError, FAMILIES, HELPERS, effects, fingerprint, operation, redact


class Administrator:
    def __init__(self, store, backend, policy, authenticate, approved_session):
        self.store, self.backend, self.policy, self.authenticate = store, backend, policy, authenticate
        self.lock = asyncio.Lock()
        self.revoked_tasks = set()
        self.approved_session = approved_session

    async def db(self, method, *args, **kwargs):
        return await asyncio.to_thread(getattr(self.store, method), *args, **kwargs)

    def current(self, actor):
        actual = self.authenticate(actor.bearer)
        if (actual.user, actual.session) != (actor.user, actor.session):
            raise AdminError("caller_changed")
        return actual

    def check_revocation(self, task):
        if task in self.revoked_tasks:
            raise AdminError("approval_revoked")

    async def revoke(self, task, actor, plan_hash):
        # The owner command authenticates before reaching this latch. Failed
        # persistence must never leave a currently approved task dispatchable.
        self.revoked_tasks.add(task)
        await self.db("decide", task, actor, plan_hash, "revoked")

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
                if op["target"].startswith("@") and key not in predicted:
                    source = int(op["target"][1:])
                    if source >= n or ops[source]["family"] != op["family"] or ops[source]["action"] != "allocate":
                        raise AdminError("invalid_allocation_reference")
                    predicted[key] = self.backend.expected({**ops[source], "target": op["target"]}, None)
                value = predicted[key] if key in predicted and op["action"] != "allocate" else await self.backend.snapshot(actor, op)
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
            plan = {"v": 1, "allocation_contract": "HA-assigned new IDs; same-task receipt binding; exact IDs are not reserved", "operations": ops, "effects": [effects(op) for op in ops]}
            plan["before"] = before
            plan["edit_window"] = {"required": any(op["family"] in {"automation", "script", "dashboard"} | HELPERS for op in ops), "objects": sorted({op["family"]+"."+op["target"] for op in ops if op["family"] in {"automation", "script", "dashboard"} | HELPERS}), "policy": self.policy.get("edit_coordination", "unaccepted"), "limit": "Project writes are serialized; other local editors must cooperate for these named objects until expiry. HA provides no atomic revision precondition."}
            plan["rollback"] = "Exact recorded before-definitions, reverse order, only within expiry and without overwriting intervening changes. Restoring a renamed helper creates it using the target ID as a temporary name, then restores its recorded name; each write rechecks the grant. Services/restarts have no automatic inverse."
            task = await self.db("create", actor, fingerprint(self.policy), plan, before, ttl)
        return await self.status(actor, task)

    async def status(self, actor, task):
        self.current(actor)
        row = await self.db("get", task)
        if (row["user"], row["session"]) != (actor.user, actor.session):
            raise AdminError("wrong_caller")
        return redact(row)

    def bound_operation(self, row, n):
        op = row["plan"]["operations"][n]
        source = int(op["target"][1:]) if op["target"].startswith("@") else None
        if source is None:
            for previous in row["operations"][:n]:
                definition = row["plan"]["operations"][previous["n"]]
                if definition["action"] == "allocate" and (definition["family"], definition["target"]) == (op["family"], op["target"]):
                    source = previous["n"]
        if op["action"] == "allocate":
            source = n
        if source is None:
            return op
        item = row["operations"][source]
        result = item["result"] or {}
        binding = result.get("created_target")
        if binding is None:
            if op["action"] == "allocate" and item["status"] == "pending":
                return op
            raise AdminError("allocation_receipt_required")
        import re
        if not result.get("backend_acknowledged") or not re.fullmatch(r"[a-z0-9_]+", binding) or not isinstance(item["after_state"], dict) or item["after_state"].get("id") != binding or result.get("result", {}).get("id") != binding:
            raise AdminError("allocation_receipt_invalid")
        if source != n and item["status"] != "applied":
            raise AdminError("allocation_receipt_required")
        return {**op, "target": binding, "action": "create" if op["action"] == "allocate" else op["action"]}

    async def execute(self, actor, task, plan_hash, *, rollback=False):
        self.current(actor)
        self.check_revocation(task)
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
            if row["plan"].get("edit_window", {}).get("required") and self.policy.get("edit_coordination") != "owner_window":
                raise AdminError("owner_edit_policy_acceptance_required")
            if not rollback and all(x["status"] == "applied" for x in row["operations"]):
                # Saved receipts are history, not a promise that HA's buffered
                # helper stores survived an abrupt crash or later edits.
                latest = {}
                for n in range(len(ops)):
                    bound = self.bound_operation(row, n)
                    latest[(bound["family"], bound["target"]) if bound["family"] not in {"service", "integration", "maintenance"} else n] = n
                for n in latest.values():
                    observed = await self.backend.snapshot(actor, self.bound_operation(row, n))
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
                op = self.bound_operation(prior, n)
                if rollback and op["family"] in {"service", "integration", "maintenance"}:
                    raise AdminError("operation_has_no_safe_inverse")
                expected_before = item["after_state"] if rollback else item["before_state"]
                if not rollback and op["action"] != "allocate" and op["family"] not in {"service", "integration", "maintenance"}:
                    for p in prior["operations"][:n]:
                        previous = ops[p["n"]]
                        previous = self.bound_operation(prior, p["n"])
                        if (previous["family"], previous["target"]) == (op["family"], op["target"]):
                            expected_before = p["after_state"]
                async with asyncio.timeout(20):
                    actual = await self.backend.snapshot(actor, op)
                    if op["action"] != "allocate" and fingerprint(actual) != fingerprint(expected_before):
                        raise AdminError("object_changed_requires_new_approval")
                    dispatched = op
                    if rollback:
                        before = None if ops[n]["action"] == "allocate" else item["before_state"]
                        if op["target"] != ops[n]["target"] and isinstance(before, dict) and "id" in before:
                            before = {**before, "id": op["target"]}
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
                    self.check_revocation(task)
                    await self.db("authorize", task, actor, fingerprint(self.policy), plan_hash)
                    self.check_revocation(task)
                    self.approved_session(prior["approved_by"])
                    self.current(actor)
                    try:
                        checked_object = False
                        async def final_check():
                            nonlocal checked_object
                            # Recheck after durable intent and backend auth, not
                            # only before them. Native HA has no conditional CRUD:
                            # this narrows the race, it is not compare-and-swap.
                            if not checked_object:
                                observed = await self.backend.snapshot(actor, op)
                                if op["action"] != "allocate" and fingerprint(observed) != fingerprint(expected_before):
                                    raise AdminError("object_changed_requires_new_approval")
                                if dispatched["action"] == "delete" and await self.backend.references(actor, op["target"], op["family"]):
                                    raise AdminError("referenced_object_requires_explicit_repair")
                                checked_object = True
                            self.check_revocation(task)
                            await self.db("authorize", task, actor, fingerprint(self.policy), plan_hash)
                            self.check_revocation(task)
                            self.approved_session(prior["approved_by"])
                            self.current(actor)
                        with self.backend.dispatch(final_check):
                            result = await self.backend.write(actor, dispatched)
                        receipt = {"rollback": rollback, "backend_acknowledged": True, "result": redact(result)}
                        if op["action"] == "allocate":
                            import re
                            binding = result.get("id") if isinstance(result, dict) else None
                            if type(binding) is not str or not re.fullmatch(r"[a-z0-9_]+", binding) or binding in actual["existing_ids"]:
                                raise AdminError("allocation_receipt_invalid")
                            receipt["created_target"] = binding
                            op = {**op, "action": "create", "target": binding}
                        elif ops[n]["action"] == "allocate":
                            receipt["created_target"] = op["target"]
                        await self.db("acknowledge", task, n, receipt, expected="rolling_back" if rollback else "dispatching")
                        self.current(actor)
                        after = await self.backend.after(actor, op)
                        wanted = before if rollback else self.backend.expected(op, actual)
                        if not (fingerprint(after) == fingerprint(wanted) if rollback else self.backend.verified(op, actual, after, result)):
                            status = "uncertain"
                        else:
                            status = "rolled_back" if rollback else "applied"
                        await self.db("finish", task, n, status, after, {**receipt, "stored_definition_or_ha_state_verified": status in {"applied", "rolled_back"}, "physical_behavior_verified": False, "result": redact(result)}, expected="rolling_back" if rollback else "dispatching")
                        if status not in {"applied", "rolled_back"}:
                            raise AdminError("outcome_requires_reconciliation")
                    except BaseException as exc:
                        # Cancellation/timeout can occur after a completed write.
                        # A retained dispatching prefix also blocks restart replay
                        # if storage itself fails; never run a blind retry.
                        if not isinstance(exc, AdminError) or exc.code != "outcome_requires_reconciliation":
                            try:
                                saved = (await self.db("get", task))["operations"][n]["result"] or {}
                                await asyncio.shield(self.db("finish", task, n, "uncertain", item["after_state"] if rollback else None, {**saved, "rollback": rollback, "error": exc.code if isinstance(exc, AdminError) else "interrupted"}, expected="rolling_back" if rollback else "dispatching"))
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
                original_op = row["plan"]["operations"][n]
                if original_op["action"] == "allocate":
                    # Without a committed verified definition we do not search
                    # by name or let an unverified ID supply ownership.
                    raise AdminError("allocation_outcome_requires_owner_reconciliation")
                op = self.bound_operation(row, n)
                if op["family"] == "maintenance" and op["target"] in {"homeassistant.restart", "hassio.host_reboot"}:
                    receipt = item["result"] or {}
                    if not receipt.get("backend_acknowledged") or receipt.get("rollback"):
                        raise AdminError("external_outcome_requires_owner_reconciliation")
                    after = await self.backend.snapshot(actor, op)
                    if not self.backend.verified(op, item["before_state"], after, receipt.get("result") or {}):
                        raise AdminError("external_outcome_requires_owner_reconciliation")
                    await self.db("finish", task, n, "applied", after, {**receipt, "current_lifecycle_facts_verified": True, "physical_behavior_verified": False}, expected=item["status"])
                    continue
                if op["family"] in {"service", "integration", "maintenance"}:
                    raise AdminError("external_outcome_requires_owner_reconciliation")
                after = await self.backend.snapshot(actor, op)
                restoring = item["status"] == "rolling_back" or (item["result"] or {}).get("rollback", False)
                wanted = item["before_state"] if restoring else self.backend.expected(op, item["before_state"])
                if restoring and op["target"] != original_op["target"] and isinstance(wanted, dict) and "id" in wanted:
                    wanted = {**wanted, "id": op["target"]}
                opposite = item["after_state"] if restoring else item["before_state"]
                # State equality is not attribution. A missing create receipt
                # cannot give us ownership of an external identical object.
                if not restoring and item["before_state"] is None and not (item["result"] or {}).get("backend_acknowledged"):
                    raise AdminError("creation_ownership_requires_owner_reconciliation")
                if fingerprint(after) == fingerprint(wanted) and fingerprint(after) != fingerprint(opposite):
                    await self.db("finish", task, n, "rolled_back" if restoring else "applied", after, {**(item["result"] or {}), "current_definition_verified": True, "mutation_attribution_verified": bool((item["result"] or {}).get("backend_acknowledged"))}, expected=item["status"])
                else:
                    raise AdminError("outcome_requires_owner_reconciliation")
            return await self.status(actor, task)
