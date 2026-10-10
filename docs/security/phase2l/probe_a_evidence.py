"""Independent evidence composition. Trusted runtime PASS remains unavailable.

Signed collector claims are reviewed inputs, never self-attestation. Synthetic
tests have their own namespace. Even a complete kernel receipt package stays
blocked pending independent acceptance of the collector and real OS evidence.
"""
from __future__ import annotations

from dataclasses import dataclass
from probe_a_session import canonical, decode, digest, identity_record, identity_from, SessionDenied
from probe_contract import CASES, CLEANUP_READBACKS
from probe_a_kernel import expect_active, compare_after, require_counter_delta
from probe_a_os_inventory import ROLES

KINDS = {"SYNTHETIC_TEST", "SOURCE_VALIDATION", "INDEPENDENT_KERNEL"}
PRE = ("plan-inventory", "actor-identities", "cgroup-membership", "firewall-before", "firewall-active")
POST = ("workers-peer-stopped", "emergency-deny", "owned-cleanup", "firewall-restored",
        "guardian-reaped", "observer-shutdown", "no-residuals")
FACTS = PRE + tuple("case:" + case for case, _family, _index in CASES) + POST


class EvidenceDenied(SessionDenied):
    pass


@dataclass(frozen=True)
class EvidencePackage:
    provenance: str
    context: str
    receipts: tuple
    missing: tuple
    defects: tuple
    result: str = "BLOCKED_NO_TRUSTED_RUNTIME_PASS"
    work: str = "not-started"
    cleanup: str = "not-observed"

    def __post_init__(self):
        if self.result != "BLOCKED_NO_TRUSTED_RUNTIME_PASS":
            raise EvidenceDenied("TRUSTED_PASS_ACCEPTANCE_PATH_UNAVAILABLE")


class EvidenceComposer:
    """A one-context append-only bounded transcript from external authorities.

    verify_collector(message,signature,authority) validates an external trust
    root and approved independent collector source identity. This constructor
    must be controlled by the reviewed runner, not by workers or guardian RPC.
    Actual source modules still contain NO accepted runtime PASS path.
    """
    def __init__(self, context, identities, *, verify_collector=None, authorities=None, groups=None):
        if set(identities) != {"guardian", "observer", "controller"}:
            raise EvidenceDenied("ALL_ACTUAL_ACTOR_IDENTITIES_REQUIRED")
        self.context, self.identities = context, dict(identities)
        self.verify_collector = verify_collector
        self.authorities = dict(authorities or {})
        self.groups = decode(canonical(groups or {}))
        if self.groups and (set(self.groups) != ROLES or any(type(g) is not list or len(g) != 2
            or any(type(n) is not int or n <= 0 for n in g) for g in self.groups.values())
            or len({tuple(g) for g in self.groups.values()}) != len(ROLES)):
            raise EvidenceDenied("EXACT_OWNED_ALL_ROLE_CGROUP_IDENTITIES_REQUIRED")
        self.receipts, self.sequence, self.kind, self.defects = {}, {}, None, []
        self.sealed_receipts, self.worker_identities = {}, set()
        self.last_time = -1
        self.quarantined = set()
        self.work_outcome = "not-started"

    def append(self, raw, signature=None):
        try:
            record = decode(raw, 300000)
            fields = {"v", "kind", "context", "inventory", "source", "authority", "collector",
                      "sequence", "time", "fact", "value"}
            if (type(record) is not dict or set(record) != fields
                    or type(record["v"]) is not int or record["v"] != 1
                    or record["kind"] not in KINDS or record["context"] != self.context.identifier
                    or record["inventory"] != self.context.inventory or record["source"] != self.context.source_commit
                    or type(record["authority"]) is not str or record["authority"] not in ("observer", "supervisor", "offline")
                    or record["fact"] not in FACTS or record["fact"] in self.receipts
                    or type(record["sequence"]) is not int
                    or (record["sequence"] <= self.sequence.get(record["authority"], 0)
                        or record["fact"] not in POST and record["sequence"] != self.sequence.get(record["authority"], 0)+1)
                    or type(record["time"]) not in (int, float)
                    or not max(0, self.last_time) <= record["time"] < self.context.end
                    or record["fact"] not in POST and record["time"] >= self.context.cutoff):
                raise EvidenceDenied("EVIDENCE_CONTEXT_REPLAY_OR_SCHEMA")
            kind, authority = record["kind"], record["authority"]
            if authority in self.quarantined:
                raise EvidenceDenied("COMPROMISED_AUTHORITY_CANNOT_BE_REHABILITATED")
            if self.kind is not None and self.kind != kind:
                raise EvidenceDenied("SYNTHETIC_SOURCE_KERNEL_PROVENANCE_MIX")
            if kind == "INDEPENDENT_KERNEL":
                expected = self.authorities.get(authority)
                if (not self.groups or authority == "offline" or expected is None or record["collector"] != expected
                        or authority == "observer" and record["fact"] in ("observer-shutdown", "no-residuals")
                        or authority == "supervisor" and record["fact"] not in ("guardian-reaped", "observer-shutdown", "no-residuals")
                        or not callable(self.verify_collector) or type(signature) is not bytes or not signature
                        or self.verify_collector(b"ProbeA kernel evidence\x00"+raw, signature, authority) is not True):
                    raise EvidenceDenied("UNTRUSTED_OR_SELF_OBSERVED_KERNEL_CLAIM")
            elif authority != "offline" or signature is not None or record["collector"] != "offline-test":
                raise EvidenceDenied("SYNTHETIC_EVIDENCE_CLAIMING_REAL_PROVENANCE")
            # Work remains ordered. Cleanup has its own causal domain and may
            # survive failed or absent work; restoration still needs baseline.
            fact = record["fact"]
            required = FACTS[:FACTS.index(fact)] if fact not in POST else ()
            if fact == "firewall-restored": required = ("firewall-before",)
            # Synthetic receipts still demonstrate shutdown order explicitly.
            if kind != "INDEPENDENT_KERNEL" and fact in POST[4:]:
                required = POST[:POST.index(fact)]
            if any(prior not in self.receipts for prior in required):
                raise EvidenceDenied("INCOMPLETE_OR_REORDERED_EVIDENCE")
            if record["sequence"] > self.sequence.get(authority,0)+1:
                self.defects.append("UNOBSERVED_SEQUENCE_GAP:"+authority)
            self._check(record["fact"], record["value"], kind=kind)
            self.kind = kind
            self.sequence[authority] = record["sequence"]
            self.receipts[record["fact"]] = record
            self.sealed_receipts[record["fact"]] = raw
            self.last_time = record["time"]
            return True
        except BaseException as error:
            if str(error) != "INCOMPLETE_OR_REORDERED_EVIDENCE" and "record" in locals() and type(record) is dict:
                authority = record.get("authority")
                if type(authority) is str: self.quarantined.add(authority)
            self.defects.append("BLOCKED_INVALID_INDEPENDENT_EVIDENCE")
            raise

    def _check(self, fact, value, *, kind="SYNTHETIC_TEST"):
        if kind == "INDEPENDENT_KERNEL" and fact in POST and fact != "firewall-restored":
            from probe_a_native_evidence import validate_cleanup_measurement
            return validate_cleanup_measurement(fact,value,self)

        if fact == "plan-inventory":
            if value != {"context": self.context.identifier, "inventory": self.context.inventory,
                         "source": self.context.source_commit}:
                raise EvidenceDenied("PLAN_INVENTORY_NOT_IMMUTABLE")
        elif fact == "actor-identities":
            if value != {r: identity_record(i) for r, i in self.identities.items()}:
                raise EvidenceDenied("ACTOR_IMPERSONATION_OR_STALE_INCARNATION")
        elif fact == "cgroup-membership":
            if (type(value) is not dict or set(value) != {"actors", "scopes", "no_escape"}
                    or value["actors"] != {r: {"identity": [i.pid, i.starttime], "group": self.groups.get(r)} for r, i in self.identities.items()}
                    or value["scopes"] != self.groups
                    or value["no_escape"] is not True):
                raise EvidenceDenied("WORKER_OR_PEER_CONTAINMENT_UNPROVED")
        elif fact == "firewall-before":
            if type(value) is not list or len(value) != 2 or any(type(s) is not str for s in value):
                raise EvidenceDenied("BASELINE_FIREWALL_EVIDENCE_MISSING")
        elif fact == "firewall-active":
            if type(value) is not list or len(value) != 2:
                raise EvidenceDenied("BOTH_FIREWALL_FAMILIES_REQUIRED")
            expect_active(*value, *self.receipts["firewall-before"]["value"], self.context.plan, final=True)
        elif fact.startswith("case:"):
            case, family, index = next(c for c in CASES if fact == "case:"+c[0])
            if (type(value) is not dict or set(value) != {"family", "before", "after", "behavior", "identity", "group", "peer", "rules"}
                    or value["family"] != family or (kind != "INDEPENDENT_KERNEL" and value["behavior"] != case)
                    or value["group"] != self.groups.get("worker")):
                raise EvidenceDenied("NETWORK_CASE_OR_ACTUAL_WORKER_UNOBSERVED")
            worker = identity_from(value["identity"])
            if (worker.uids != (self.context.plan.uid,)*4 or worker.gids != (self.context.plan.uid,)*4
                    or worker.groups or any(worker.capabilities) or worker.no_new_privs != 1
                    or (worker.pid, worker.starttime) in self.worker_identities):
                raise EvidenceDenied("WORKER_IDENTITY_OR_INCARNATION_REPLAY")
            if case == "loopback-established":
                peer = value["peer"]
                if type(peer) is not dict or set(peer) != {"identity", "group"} or peer["group"] != self.groups.get("peer"):
                    raise EvidenceDenied("ROOT_PEER_CONTAINMENT_UNOBSERVED")
                root_peer = identity_from(peer["identity"])
                if root_peer.uids != (0,)*4 or root_peer.no_new_privs != 1:
                    raise EvidenceDenied("ROOT_PEER_IDENTITY_UNOBSERVED")
            elif value["peer"] is not None:
                raise EvidenceDenied("UNEXPECTED_ROOT_PEER")
            from probe_a_native_evidence import counters, validate_network_measurement
            counters(value["before"],family); counters(value["after"],family)
            if kind == "INDEPENDENT_KERNEL":
                peer_identity = identity_from(value["peer"]["identity"]) if case == "loopback-established" else None
                validate_network_measurement(case,value["behavior"],self.context,worker,peer_identity)
            require_counter_delta(tuple(value["before"]), tuple(value["after"]), index)
            expect_active(*value["rules"], *self.receipts["firewall-before"]["value"], self.context.plan, final=True)
            self.worker_identities.add((worker.pid, worker.starttime))
        elif fact == "firewall-restored":
            if type(value) is not list or len(value) != 2:
                raise EvidenceDenied("RESTORATION_UNOBSERVED")
            compare_after(*value, *self.receipts["firewall-before"]["value"])
        elif fact == "owned-cleanup":
            if value != {key: True for key in CLEANUP_READBACKS}:
                raise EvidenceDenied("OWNED_ONLY_CLEANUP_INCOMPLETE")
        elif fact == "emergency-deny":
            if value != {"relevant_failures": "independently-observed", "deny_first": True,
                         "barrier": True, "mutation_outcomes": "certain"}:
                raise EvidenceDenied("EMERGENCY_BARRIER_OR_UNCERTAIN_MUTATION")
        elif value is not True:
            raise EvidenceDenied("TERMINATION_OR_RESIDUAL_RESOURCES_UNOBSERVED")

    def note_work(self, outcome):
        if outcome not in ("not-started", "partial", "failed", "cancelled", "completed"):
            raise EvidenceDenied("UNKNOWN_WORK_OUTCOME")
        if self.work_outcome in ("failed", "cancelled") and outcome == "completed":
            raise EvidenceDenied("FAILED_WORK_CANNOT_BE_PROMOTED")
        self.work_outcome = outcome

    def package(self):
        if any(canonical(r) != self.sealed_receipts[f] for f, r in self.receipts.items()):
            raise EvidenceDenied("VERIFIED_EVIDENCE_CHANGED_AFTER_COLLECTION")
        missing = tuple(f for f in FACTS if f not in self.receipts)
        provenance = self.kind or "SOURCE_VALIDATION"
        if missing and provenance == "INDEPENDENT_KERNEL": provenance = "INCOMPLETE_RUNTIME_EVIDENCE"
        if self.defects and provenance == "INDEPENDENT_KERNEL": provenance = "INCOMPLETE_RUNTIME_EVIDENCE"
        return EvidencePackage(provenance, self.context.identifier,
            tuple(canonical(self.receipts[f]) for f in FACTS if f in self.receipts), missing, tuple(self.defects),
            work=self.work_outcome if self.work_outcome != "not-started" else (
                "completed" if all("case:"+c[0] in self.receipts for c in CASES) else
                "partial" if any(f.startswith("case:") for f in self.receipts) else "not-started"),
            cleanup="uncertain" if any(not d.startswith("UNOBSERVED:") or d[11:] in POST for d in self.defects) else "verified" if all(f in self.receipts for f in POST)
                    else "incomplete" if any(f in self.receipts for f in POST) else "not-observed")


class IndependentEvidenceAudit:
    """Lifecycle-bound reader of a separately reviewed independent signed journal.

    collect(fact, context_digest) returns (canonical receipt, signature). It
    reads the actual observer/supervisor journal, not guardian or worker output.
    The collector captures active-rule/counter/network evidence DURING work;
    post-cleanup reads cannot reconstruct it. No collector or key is bundled.
    """
    def __init__(self, composer=None, *, context=None, groups=None, verify_collector=None,
                 authorities=None, collect=None, journal=None):
        if composer is not None and not isinstance(composer, EvidenceComposer):
            raise EvidenceDenied("INDEPENDENT_EVIDENCE_COMPOSER_REQUIRED")
        if composer is None and context is None:
            raise EvidenceDenied("IMMUTABLE_AUDIT_CONTEXT_REQUIRED")
        self.context = composer.context if composer is not None else context
        self.groups = composer.groups if composer is not None else decode(canonical(groups or {}))
        self.verify_collector, self.authorities = verify_collector, authorities
        self.composer, self.collect, self.failed = composer, collect, False
        self.journal = journal

    def _through(self, stop, *, cleanup=False):
        if not callable(self.collect) or self.composer is None:
            self.failed = True
            raise EvidenceDenied("INDEPENDENT_KERNEL_COLLECTOR_MISSING")
        if self.failed and not cleanup:
            raise EvidenceDenied("FAILED_BASELINE_CANNOT_RELEASE_WORK")
        failed = False
        facts = FACTS[:FACTS.index(stop)+1]
        for fact in facts:
            if fact in self.composer.receipts: continue
            try:
                pair = self.collect(fact, self.composer.context.identifier)
                if type(pair) is not tuple or len(pair) != 2:
                    raise EvidenceDenied("INDEPENDENT_COLLECTOR_RECEIPT_MISSING")
                self.composer.append(*pair)
            except BaseException:
                self.failed = failed = True
                # Missing work is not fabricated and cannot suppress unrelated
                # later cleanup facts. Invalid authority remains quarantined.
                if not cleanup: raise
                marker = "UNOBSERVED:"+fact
                if marker not in self.composer.defects: self.composer.defects.append(marker)
        if self.composer.kind != "INDEPENDENT_KERNEL":
            self.failed = True
            raise EvidenceDenied("SYNTHETIC_JOURNAL_CANNOT_RELEASE_RUNTIME")
        return not failed and not self.composer.defects

    def partial_package(self):
        if self.composer is None:
            return EvidencePackage("INCOMPLETE_RUNTIME_EVIDENCE", self.context.identifier,
                (), FACTS, ("ACTOR_HANDOFF_OR_COLLECTOR_UNAVAILABLE",))
        return self.composer.package()

    def persist_partial(self):
        package = self.partial_package()
        from probe_a_native_evidence import UnsignedObservationJournal
        if not isinstance(self.journal, UnsignedObservationJournal):
            return False  # exact source assembly gap, never pretend durable
        record = {"context":package.context, "type":"partial-evidence-package",
            "provenance":package.provenance, "work":package.work, "cleanup":package.cleanup,
            "missing":list(package.missing), "defects":list(package.defects),
            "receipt_digests":[digest(decode(r,300000)) for r in package.receipts],
            "result":package.result}
        try:
            self.journal.append(record)
            return True
        except BaseException:
            self.failed = True
            return False

    def before_controller(self, coordinator):
        if self.composer is None:
            self.composer = EvidenceComposer(self.context, {r:a.binding.identity for r,a in coordinator.actors.items()},
                groups=self.groups, verify_collector=self.verify_collector, authorities=self.authorities)
        if (coordinator.context != self.composer.context or set(coordinator.actors) != set(self.composer.identities)
                or any(a.binding.identity != self.composer.identities[r] for r,a in coordinator.actors.items())
                or any(coordinator.actors[r].state != "RUNNING" for r in ("guardian", "observer"))):
            raise EvidenceDenied("AUDIT_ACTOR_OR_READY_CONTEXT_MISMATCH")
        return self._through("firewall-before")

    def observe_after(self):
        # Called only after the supervisor has reaped guardian/controller.
        return self._through("guardian-reaped", cleanup=True)

    def after_observer_shutdown(self):
        try:
            self._through("no-residuals", cleanup=True)
        except BaseException:
            self.failed = True
        return self.partial_package()  # ALWAYS blocked, including partial exits
