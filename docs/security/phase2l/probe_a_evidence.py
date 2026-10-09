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

    def append(self, raw, signature=None):
        try:
            if self.defects:
                raise EvidenceDenied("UNCERTAIN_EVIDENCE_CANNOT_BE_REUSED")
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
                    or record["sequence"] != self.sequence.get(record["authority"], 0)+1
                    or type(record["time"]) not in (int, float)
                    or not max(0, self.last_time) <= record["time"] < self.context.end
                    or record["fact"] not in POST and record["time"] >= self.context.cutoff):
                raise EvidenceDenied("EVIDENCE_CONTEXT_REPLAY_OR_SCHEMA")
            kind, authority = record["kind"], record["authority"]
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
            # Strict ordering, including all cases before any cleanup receipt.
            index = FACTS.index(record["fact"])
            if any(fact not in self.receipts for fact in FACTS[:index]):
                raise EvidenceDenied("INCOMPLETE_OR_REORDERED_EVIDENCE")
            self._check(record["fact"], record["value"])
            self.kind = kind
            self.sequence[authority] = record["sequence"]
            self.receipts[record["fact"]] = record
            self.sealed_receipts[record["fact"]] = raw
            self.last_time = record["time"]
            return True
        except BaseException:
            self.defects.append("BLOCKED_INVALID_INDEPENDENT_EVIDENCE")
            raise

    def _check(self, fact, value):
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
                    or value["family"] != family or value["behavior"] != case
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

    def package(self):
        if any(canonical(r) != self.sealed_receipts[f] for f, r in self.receipts.items()):
            raise EvidenceDenied("VERIFIED_EVIDENCE_CHANGED_AFTER_COLLECTION")
        missing = tuple(f for f in FACTS if f not in self.receipts)
        provenance = self.kind or "SOURCE_VALIDATION"
        if missing and provenance == "INDEPENDENT_KERNEL": provenance = "INCOMPLETE_RUNTIME_EVIDENCE"
        if self.defects and provenance == "INDEPENDENT_KERNEL": provenance = "INCOMPLETE_RUNTIME_EVIDENCE"
        return EvidencePackage(provenance, self.context.identifier,
            tuple(canonical(self.receipts[f]) for f in FACTS if f in self.receipts), missing, tuple(self.defects))


class IndependentEvidenceAudit:
    """Lifecycle-bound reader of a separately reviewed independent signed journal.

    collect(fact, context_digest) returns (canonical receipt, signature). It
    reads the actual observer/supervisor journal, not guardian or worker output.
    The collector captures active-rule/counter/network evidence DURING work;
    post-cleanup reads cannot reconstruct it. No collector or key is bundled.
    """
    def __init__(self, composer=None, *, context=None, groups=None, verify_collector=None,
                 authorities=None, collect=None):
        if composer is not None and not isinstance(composer, EvidenceComposer):
            raise EvidenceDenied("INDEPENDENT_EVIDENCE_COMPOSER_REQUIRED")
        if composer is None and context is None:
            raise EvidenceDenied("IMMUTABLE_AUDIT_CONTEXT_REQUIRED")
        self.context = composer.context if composer is not None else context
        self.groups = composer.groups if composer is not None else decode(canonical(groups or {}))
        self.verify_collector, self.authorities = verify_collector, authorities
        self.composer, self.collect, self.failed = composer, collect, False

    def _through(self, stop):
        if self.failed or not callable(self.collect):
            self.failed = True
            raise EvidenceDenied("INDEPENDENT_KERNEL_COLLECTOR_MISSING")
        try:
            for fact in FACTS[:FACTS.index(stop)+1]:
                if fact in self.composer.receipts: continue
                pair = self.collect(fact, self.composer.context.identifier)
                if type(pair) is not tuple or len(pair) != 2:
                    raise EvidenceDenied("INDEPENDENT_COLLECTOR_RECEIPT_MISSING")
                self.composer.append(*pair)
            if self.composer.kind != "INDEPENDENT_KERNEL":
                raise EvidenceDenied("SYNTHETIC_JOURNAL_CANNOT_RELEASE_RUNTIME")
            return True
        except BaseException:
            self.failed = True
            raise

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
        return self._through("guardian-reaped")

    def after_observer_shutdown(self):
        self._through("no-residuals")
        package = self.composer.package()
        if package.missing or package.defects:
            raise EvidenceDenied("INCOMPLETE_INDEPENDENT_RUNTIME_PACKAGE")
        return package  # result is STILL BLOCKED_NO_TRUSTED_RUNTIME_PASS
