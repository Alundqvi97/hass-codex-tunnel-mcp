"""Source-only adversarial integration. No privileged operation is exercised.

All identities, descriptors, signatures, kernel facts and scope observations
below are synthetic. Passing this suite cannot authorize or attest Probe A.
"""
from copy import deepcopy
from dataclasses import replace
import fcntl
import hashlib
import os
from pathlib import Path
import stat
import sys
from types import SimpleNamespace
import unittest
from unittest.mock import Mock, patch

sys.path.insert(0, str(Path(__file__).resolve().parents[2] / "docs/security/phase2l"))
from probe_contract import compile_plan, CASES, CLEANUP_READBACKS
from probe_a_session import (ExecutionContext, RoleConfiguration, SessionDenied,
    canonical, decode, identity_record, identity_from, load_sealed, DelegatedProcessBinding,
    PendingRoleConfiguration)
from probe_a_linux_identity import ProcessIdentity, IdentityDenied
from probe_a_coordinator import ActorReadinessCoordinator, RoleStartup, readiness_message, CoordinationDenied
from probe_a_execution_contract import OwnedScopeSet, ReviewedExecutionContract, ExecutionDenied, local_nss
from probe_a_inventory_integration import IntegratedInventory, inventory_candidate, REQUIREMENTS
from probe_a_integrated_bootstrap import AttemptPermit, IntegratedBootstrap, ReviewedActorFactory, ActorPreparation
from probe_a_linux_launcher import ExecSpec
from probe_a_linux_launcher import NativeAtomicSpawner, LaunchDenied
from probe_a_role_entrypoints import run_role, RoleServices, ContainedRootCommands, IndependentControllerIO
from probe_a_evidence import EvidenceComposer, EvidenceDenied, IndependentEvidenceAudit, FACTS
from probe_a_os_inventory import InventoryDenied, ROLES
import test_phase2l_probe_a_linux_foundation as foundation
from test_phase2l_probe_a_protocol import BASE, snapshot as protocol_snapshot

PLAN = compile_plan(scope="1234ABCD", uid=42001, dns="9.9.9.9")
CONTEXT = ExecutionContext("a"*32, "b"*40, "c"*64, PLAN, 240, 180)
ROOT = ProcessIdentity(50, 100, (0,)*4, (0,)*4, (), (0,)*5, 1, (1, 2))
IDENTITIES = {r: replace(ROOT, pid=100+i, starttime=200+i) for i, r in enumerate(("guardian", "observer", "controller"))}
IDENTITIES["controller"] = replace(IDENTITIES["controller"], uids=(65534,)*4, gids=(65534,)*4)
NSS = b"passwd: files\ngroup: files\nshadow: files\ngshadow: files\nhosts: files\n"
GROUPS = {r:[1,i] for i,r in enumerate(sorted(ROLES),1)}

def snapshot(plan, **kwargs):
    return protocol_snapshot(plan, **kwargs).replace("--uid-owner 45123", "--uid-owner " + str(plan.uid))


def config(role="controller", context=CONTEXT):
    names = ("startup", "guardian", "observer", "guardian-pidfd", "observer-pidfd", "startup-pidfd") if role == "controller" \
        else (("startup", "controller") if role == "guardian" else ("startup", "controller", "audit"))
    return RoleConfiguration(context, role, IDENTITIES[role], ROOT,
        tuple((name, 10+i) for i, name in enumerate(names)),
        tuple((r, IDENTITIES[r]) for r in ("guardian", "observer")) if role == "controller" else ())


def permit(context=CONTEXT, **kwargs):
    return AttemptPermit(context, {"v": 1, "context": context.identifier, "boot": "synthetic-boot",
        "purpose": "one-probe-a-attempt", "expires": context.end}, b"synthetic-signature",
        verify=kwargs.get("verify", lambda *a: True), consume=kwargs.get("consume", lambda *a: True),
        boot_identity=kwargs.get("boot_identity", lambda: "synthetic-boot"), clock=kwargs.get("clock", lambda: 0))


def scopes(context=CONTEXT):
    groups = {r: SimpleNamespace(identity=(1, i)) for i, r in enumerate(sorted(ROLES), 1)}
    records = {r: {"context": context.identifier, "role": r, "identity": list(g.identity), "version": 2,
        "owner": [0, 0, 0o700], "ancestry": ["/sys/fs/cgroup", "p2a-"+PLAN.scope, r],
        "delegated": False, "children": [], "members": [], "populated": False, "atomic": True, "pidfd": True}
        for r, g in groups.items()}
    return OwnedScopeSet(context, groups, observe=lambda r, *_: deepcopy(records[r])), records


def contract():
    owned, records = scopes()
    inv = Mock(); inv.verify_integration.return_value = True
    rules = {r: {"uids": [65534]*4 if r == "controller" else [PLAN.uid]*4 if r == "worker" else [0]*4,
        "gids": [65534]*4 if r == "controller" else [PLAN.uid]*4 if r == "worker" else [0]*4,
        "caps": [0]*5, "pre_exec_caps": [0]*5, "network": "case-scoped" if r in ("worker", "peer") else "deny-inet-inet6",
        "nss": "files-only", "fd_isolation": "exact-sealed-descriptors", "source_mount": "immutable-reviewed"} for r in ROLES}
    result = ReviewedExecutionContract(CONTEXT, inv, owned,
        {"v": 1, "context": CONTEXT.identifier, "inventory": CONTEXT.inventory, "roles": rules, "policy_digest": "d"*64},
        b"synthetic", verify_policy=lambda *a: True, enforce_child=lambda *a: True,
        inspect_actor=lambda *a: True, clock=lambda: 0)
    result.permit = permit(); result.permit.claim()
    return result, records


def coordinator(ready=True, stopped=True):
    c = ActorReadinessCoordinator(CONTEXT, verify_ready=lambda *a: ready,
        verify_stopped=lambda *a: stopped, clock=lambda: 0)
    for role in IDENTITIES:
        binding = Mock(identity=IDENTITIES[role]); binding.verify.return_value = True
        handle = Mock(pid=IDENTITIES[role].pid); handle.exited.return_value = False; handle.reap.return_value = 0
        channel = Mock()
        c.register(role, config(role), binding, channel, handle)
    return c


def ready(c, role):
    for seq, state in enumerate(("STARTING", "IDENTITY_VERIFIED", "READY"), 1):
        c.accept(role, readiness_message(config(role), state, seq))


class SessionTests(unittest.TestCase):
    def test_roundtrip_all_explicit_roles(self):
        for role in IDENTITIES:
            self.assertEqual(RoleConfiguration.from_bytes(config(role).encode()), config(role))
    def test_no_implicit_entrypoint_or_environment_opt_in(self):
        for role in IDENTITIES:
            with self.assertRaises(SessionDenied): run_role(role)
        with self.assertRaises(SessionDenied): PendingRoleConfiguration.allocate(build=Mock())
    def test_wrong_role(self):
        with self.assertRaises(SessionDenied): replace(config(), role="peer")
    def test_controller_capabilities(self):
        with self.assertRaises(IdentityDenied): replace(config(), identity=replace(IDENTITIES["controller"], capabilities=(0,1,0,0,0)))
    def test_controller_uid_gid(self):
        for field in ("uids", "gids"):
            with self.assertRaises(IdentityDenied): replace(config(), identity=replace(IDENTITIES["controller"], **{field: (0,)*4}))
    def test_descriptor_injection_and_duplicate_ownership(self):
        for descriptors in (config().descriptors+(("unexpected", 91),), config().descriptors+(("guardian", 91),),
                            tuple((n, 10) for n, _ in config().descriptors)):
            with self.assertRaises(SessionDenied): replace(config(), descriptors=descriptors)
    def test_privileged_peer_handoff_required(self):
        with self.assertRaises(SessionDenied): replace(config(), peers=())
    def test_deadline_reserve_cannot_change(self):
        for end in (241, float("nan"), float("inf")):
            with self.assertRaises(SessionDenied): replace(CONTEXT, end=end)
    def test_deadline_exhaustion(self):
        for now in (180, 240, float("nan")):
            with self.assertRaises(SessionDenied): CONTEXT.check_time(now)
        CONTEXT.check_time(239, cleanup=True)
    def test_duplicate_malformed_and_noncanonical_json(self):
        for raw in (b'{"v":1,"v":1}', b'{', b'{"v":NaN}', b'{"v": 1}', b'[]'*40000):
            with self.assertRaises(SessionDenied): decode(raw)
    def test_identity_bool_rejected(self):
        value = identity_record(ROOT); value["pid"] = True
        with self.assertRaises(SessionDenied): identity_from(value)
    def test_sealed_loader_uses_actual_root_descriptor(self):
        raw = config().encode()
        st = SimpleNamespace(st_mode=stat.S_IFREG|0o600, st_uid=0, st_size=len(raw))
        self.assertEqual(load_sealed(8, read=lambda *a: raw, inspect=lambda _: st,
            flags=lambda fd, op: 15 if op == 1034 else os.O_RDONLY), config())
    def test_unsealed_writable_or_nonroot_config_rejected(self):
        raw = config().encode()
        for uid, mode, seals, flags in ((1000,0o600,15,0), (0,0o622,15,0), (0,0o600,0,0), (0,0o600,15,os.O_RDWR)):
            st = SimpleNamespace(st_mode=stat.S_IFREG|mode, st_uid=uid, st_size=len(raw))
            with self.assertRaises(SessionDenied): load_sealed(8, read=lambda *a: raw, inspect=lambda _: st,
                flags=lambda fd, op: seals if op == 1034 else flags)
    def test_config_changes_during_read_rejected(self):
        raw = config().encode(); st = SimpleNamespace(st_mode=stat.S_IFREG|0o600, st_uid=0, st_size=len(raw))
        with self.assertRaises(SessionDenied): load_sealed(8, read=lambda *a: raw,
            inspect=Mock(side_effect=[st, object()]), flags=lambda fd, op: 15 if op == 1034 else 0)
    def test_delegated_binding_never_reads_root_proc_metadata(self):
        binding = DelegatedProcessBinding(IDENTITIES["guardian"], 13, sealed=config(), role="guardian",
            inspect_fdinfo=lambda _: "Pid: 100\n", alive=lambda: True)
        self.assertTrue(binding.verify())
    def test_stale_pidfd(self):
        for info, alive in (("Pid: 999\n", True), ("Pid: 100\nPid: 100\n", True), ("Pid: 100\n", False)):
            with self.assertRaises(SessionDenied): DelegatedProcessBinding(IDENTITIES["guardian"], 13,
                sealed=config(), role="guardian", inspect_fdinfo=lambda _: info, alive=lambda: alive)
    def test_numeric_pid_without_sealed_handoff_denied(self):
        with self.assertRaises(SessionDenied): DelegatedProcessBinding(ROOT, 13)
    def test_wrong_role_process_executable_or_incarnation_failstop(self):
        for actual in (replace(IDENTITIES["guardian"], executable=(9,9)), replace(IDENTITIES["guardian"], starttime=1)):
            class Halt(BaseException): pass
            with patch("probe_a_role_entrypoints.os.geteuid", return_value=0), \
                 patch("probe_a_role_entrypoints.load_sealed", return_value=config("guardian")), \
                 patch("probe_a_role_entrypoints.ProcessBinding", return_value=Mock(identity=actual)), \
                 patch("probe_a_role_entrypoints.os._exit", side_effect=Halt) as stop:
                with self.assertRaises(Halt): run_role("guardian", config_fd=7, services=RoleServices(contract=None), activated=True, clock=lambda:0)
                stop.assert_called_once_with(78)
    def test_root_controller_never_imports_controller_work(self):
        class Halt(BaseException): pass
        with patch("probe_a_role_entrypoints.os.geteuid", return_value=0), \
             patch("probe_a_role_entrypoints.load_sealed", return_value=config()), \
             patch("probe_a_role_entrypoints.os._exit", side_effect=Halt):
            with self.assertRaises(Halt): run_role("controller", config_fd=7, services=RoleServices(contract=None), activated=True, clock=lambda:0)

    def test_startup_interruption_at_every_root_boundary_is_irreversible(self):
        class Halt(BaseException): pass
        for boundary in ("config", "own-identity", "fd-audit", "peer-identity", "channel", "starting",
                         "identity-verified", "services", "ready", "release", "running"):
            own=Mock(identity=IDENTITIES["guardian"],procfd=70,pidfd=71);own.verify.return_value=True
            peer=Mock(identity=ROOT);peer.verify.return_value=True
            services=RoleServices(contract=None);services.prepare=Mock(return_value=True);services.run=Mock(return_value="source-only")
            startup=Mock();startup.announce.return_value=None;startup.wait_for_release.return_value=None
            loader=Mock(return_value=config("guardian"));binder=Mock(side_effect=[own,peer]);channel=Mock(return_value=Mock())
            listing=lambda path: ["99"] if boundary=="fd-audit" else []
            if boundary=="config":loader.side_effect=KeyboardInterrupt
            if boundary=="own-identity":own.verify.side_effect=KeyboardInterrupt
            if boundary=="peer-identity":binder.side_effect=[own,KeyboardInterrupt]
            if boundary=="channel":channel.side_effect=KeyboardInterrupt
            if boundary=="services":services.prepare.side_effect=KeyboardInterrupt
            if boundary in ("starting","identity-verified","ready"):
                index={"starting":0,"identity-verified":1,"ready":2}[boundary]
                startup.announce.side_effect=[None]*index+[KeyboardInterrupt]
            if boundary=="release":startup.wait_for_release.side_effect=KeyboardInterrupt
            if boundary=="running":services.run.side_effect=KeyboardInterrupt
            with self.subTest(boundary=boundary),patch("probe_a_role_entrypoints.os.geteuid",return_value=0), \
                 patch("probe_a_role_entrypoints.load_sealed",loader),patch("probe_a_role_entrypoints.ProcessBinding",binder), \
                 patch("probe_a_role_entrypoints.os.listdir",side_effect=listing),patch("probe_a_role_entrypoints.os.fstat",return_value=Mock()), \
                 patch("probe_a_role_entrypoints.authenticated_channel",channel),patch("probe_a_role_entrypoints.RoleStartup",return_value=startup), \
                 patch("probe_a_role_entrypoints.os._exit",side_effect=Halt) as stop:
                with self.assertRaises(Halt):run_role("guardian",config_fd=7,services=services,activated=True,clock=lambda:0)
                stop.assert_called_once_with(78)

    def test_pending_configuration_kernel_identity_sealing_and_replay(self):
        binding=Mock(identity=IDENTITIES["guardian"]);binding.alive.return_value=True
        pending=PendingRoleConfiguration(30,31,build=lambda identity:config("guardian"),observe=lambda _:binding)
        with patch("probe_a_session.select.select",return_value=([],[],[])), \
             patch("probe_a_session.os.write",side_effect=lambda fd,data:len(data)), \
             patch("probe_a_session.os.close"),patch("probe_a_session.fcntl.fcntl") as seal:
            self.assertEqual(pending.complete(IDENTITIES["guardian"].pid,99),config("guardian"))
            seal.assert_called_once_with(31,1033,15)
            with self.assertRaises(SessionDenied):pending.complete(IDENTITIES["guardian"].pid,99)
        binding.close.assert_called_once()

    def test_pending_configuration_partial_write_does_not_seal(self):
        binding=Mock(identity=IDENTITIES["guardian"]);binding.alive.return_value=True
        pending=PendingRoleConfiguration(30,31,build=lambda identity:config("guardian"),observe=lambda _:binding)
        with patch("probe_a_session.select.select",return_value=([],[],[])),patch("probe_a_session.os.write",return_value=1), \
             patch("probe_a_session.fcntl.fcntl") as seal:
            with self.assertRaises(SessionDenied):pending.complete(IDENTITIES["guardian"].pid,99)
            seal.assert_not_called()
        self.assertTrue(pending.completed)


class ReadinessTests(unittest.TestCase):
    def test_all_verified_readiness_before_controller_release(self):
        c=coordinator(); self.assertFalse(c.running_authorized)
        for role in IDENTITIES: ready(c, role)
        c.release_work(); self.assertTrue(c.running_authorized)
        for role in IDENTITIES:
            c.accept(role, readiness_message(config(role), "RUNNING", 4))
            self.assertEqual(c.actors[role].state, "RUNNING")
    def test_existence_or_exit_never_implies_ready(self):
        c=coordinator(); c.actors["guardian"].handle.exited.return_value=True
        with self.assertRaises(CoordinationDenied): c.await_ready("guardian")
        self.assertTrue(c.aborted)
    def test_release_requires_independent_readiness(self):
        c=coordinator(ready=False)
        c.accept("guardian",readiness_message(config("guardian"),"STARTING",1))
        c.accept("guardian",readiness_message(config("guardian"),"IDENTITY_VERIFIED",2))
        with self.assertRaises(CoordinationDenied): c.accept("guardian",readiness_message(config("guardian"),"READY",3))
    def test_duplicate_registration_and_identity_substitution(self):
        c=coordinator()
        with self.assertRaises(CoordinationDenied): c.register("guardian",config("guardian"),Mock(),Mock(),Mock())
    def test_replayed_readiness(self):
        c=coordinator(); msg=readiness_message(config("guardian"),"STARTING",1);c.accept("guardian",msg)
        with self.assertRaises(CoordinationDenied): c.accept("guardian",msg)
        self.assertTrue(c.aborted)
    def test_reordered_readiness(self):
        c=coordinator()
        with self.assertRaises(CoordinationDenied): c.accept("guardian",readiness_message(config("guardian"),"READY",1))
    def test_work_before_release(self):
        c=coordinator();ready(c,"guardian")
        with self.assertRaises(CoordinationDenied): c.accept("guardian",readiness_message(config("guardian"),"RUNNING",4))
    def test_partial_ready_release_denied(self):
        c=coordinator();ready(c,"guardian");ready(c,"observer")
        with self.assertRaises(CoordinationDenied): c.release_work()
    def test_interrupted_release_closes_all_channels(self):
        for boundary in IDENTITIES:
            c=coordinator()
            for role in IDENTITIES: ready(c,role)
            c.actors[boundary].channel.send_bytes.side_effect=KeyboardInterrupt
            with self.assertRaises(KeyboardInterrupt): c.release_work()
            self.assertTrue(c.aborted);self.assertFalse(c.running_authorized)
            for actor in c.actors.values(): actor.channel.close.assert_called()
    def test_no_cleanup_inference_from_exit(self):
        c=coordinator(stopped=False);c.request_cleanup("cancelled")
        c.actors["guardian"].handle.exited.return_value=True
        self.assertFalse(c.independently_stopped("guardian"))
        self.assertEqual(c.actors["guardian"].state,"CLEANUP_INCOMPLETE")
    def test_independent_stop_and_reap_required(self):
        c=coordinator();c.request_cleanup("cancelled");c.actors["guardian"].handle.exited.return_value=True
        self.assertTrue(c.independently_stopped("guardian"))
        self.assertEqual(c.actors["guardian"].state,"STOPPED_INDEPENDENTLY_OBSERVED")
    def test_actor_cannot_self_attest_disappearance(self):
        c=coordinator()
        with self.assertRaises(CoordinationDenied):c.accept("guardian",readiness_message(config("guardian"),"STOPPED_INDEPENDENTLY_OBSERVED",1))
    def test_supervisor_eof_observer_or_guardian_failure_closes_startup(self):
        for reason in ("SUPERVISOR_INTERRUPTED","GUARDIAN_EOF","OBSERVER_FAILED","CONTROLLER_CANCELLED"):
            c=coordinator();c.request_cleanup(reason);self.assertTrue(c.aborted)
            self.assertTrue(all(a.state=="CLEANUP_REQUESTED" for a in c.actors.values()))
    def test_expired_readiness(self):
        c=coordinator();c.clock=lambda:180
        with self.assertRaises(SessionDenied):c.accept("guardian",readiness_message(config("guardian"),"STARTING",1))
    def test_stale_identity_after_registration(self):
        c=coordinator();c.actors["guardian"].binding.verify.return_value=False
        with self.assertRaises(CoordinationDenied):c.accept("guardian",readiness_message(config("guardian"),"STARTING",1))
    def test_malformed_ipc_eof_stalled_read_and_verifier_exception_are_sticky(self):
        for error in (EOFError,TimeoutError,KeyboardInterrupt):
            c=coordinator();c.actors["guardian"].channel.recv_bytes.side_effect=error
            with self.assertRaises(BaseException):c.await_ready("guardian")
            self.assertTrue(c.aborted)
        c=coordinator()
        with self.assertRaises(SessionDenied):c.accept("guardian",b'{')
        self.assertTrue(c.aborted)
        c=coordinator();c.verify_ready=Mock(side_effect=RuntimeError)
        c.accept("guardian",readiness_message(config("guardian"),"STARTING",1));c.accept("guardian",readiness_message(config("guardian"),"IDENTITY_VERIFIED",2))
        with self.assertRaises(RuntimeError):c.accept("guardian",readiness_message(config("guardian"),"READY",3))
        self.assertTrue(c.aborted)
    def test_actor_release_rejects_wrong_context_or_controller(self):
        s=RoleStartup(config(),Mock(),clock=lambda:0);s.sequence=3
        s.channel.recv_bytes.return_value=canonical({"v":1,"context":CONTEXT.identifier,"role":"controller",
            "seq":1,"command":"RUN","controller":identity_record(replace(IDENTITIES["controller"],starttime=999))})
        with self.assertRaises(CoordinationDenied):s.wait_for_release()
        self.assertFalse(s.released)
    def test_lifecycle_cleanup_order_and_unexpected_failure(self):
        c=coordinator()
        for role in IDENTITIES:ready(c,role)
        c.release_work()
        for seq,state in enumerate(("RUNNING","CLEANUP_REQUESTED","CLEANUP_IN_PROGRESS","CLEANUP_INCOMPLETE"),4):
            c.accept("guardian",readiness_message(config("guardian"),state,seq))
        self.assertEqual(c.actors["guardian"].state,"CLEANUP_INCOMPLETE")
        c=coordinator();c.accept("observer",readiness_message(config("observer"),"UNEXPECTED_FAILURE",1))
        self.assertTrue(c.aborted);self.assertEqual(c.actors["observer"].state,"UNEXPECTED_FAILURE")
    def test_supervisor_interruption_is_blocked_and_shutdown_still_attempted(self):
        from probe_a_linux_launcher import IndependentSupervisor
        for boundary in ("cancel","close","audit"):
            actors=foundation.ContainmentAndSupervisionTests().actors()
            supervisor=IndependentSupervisor(actors,end=240,cutoff=180,clock=lambda:0)
            cancel=Mock(side_effect=KeyboardInterrupt) if boundary=="cancel" else lambda:True
            close=Mock(side_effect=KeyboardInterrupt) if boundary=="close" else Mock()
            audit=Mock(side_effect=KeyboardInterrupt) if boundary=="audit" else lambda:True
            with patch("probe_a_linux_launcher.os.geteuid",return_value=0):
                result=supervisor.run(close_controller_channel=close,observe_after=audit,cancelled=cancel,activated=True)
            self.assertEqual(result,"BLOCKED_SUPERVISOR_INTERRUPTED")
            actors["observer"].signal.assert_called()
            close.assert_called()


def forged_readiness(field, value):
    def test(self):
        c=coordinator();data=decode(readiness_message(config("guardian"),"STARTING",1));data[field]=value
        with self.assertRaises(CoordinationDenied):c.accept("guardian",canonical(data))
        self.assertTrue(c.aborted)
    return test
for _field,_value in (("context","x"*64),("role","observer"),("identity","d"*64),("config","e"*64),("seq",True),("state","PASS"),("v",True)):
    setattr(ReadinessTests,"test_forged_"+_field,forged_readiness(_field,_value))


class AuthorizationTests(unittest.TestCase):
    def test_claim_only_once(self):
        p=permit();self.assertTrue(p.claim())
        with self.assertRaises(SessionDenied):p.claim()
    def test_missing_external_signature_or_ledger(self):
        for kw in ({"verify":None},{"consume":None},{"verify":lambda *a:False},{"consume":lambda *a:False}):
            p=permit(**kw)
            with self.assertRaises(SessionDenied):p.claim()
            self.assertFalse(p.active())
    def test_changed_signed_context_or_boot_identity(self):
        p=permit();p.record["expires"]=300
        with self.assertRaises(SessionDenied):p.claim()
        p=permit(boot_identity=lambda:"another-boot")
        with self.assertRaises(SessionDenied):p.claim()
    def test_cleanup_reserve_does_not_reopen_work(self):
        p=permit();p.claim();p.clock=lambda:181
        self.assertFalse(p.active());self.assertTrue(p.active(cleanup=True))
        p.clock=lambda:240;self.assertFalse(p.active(cleanup=True))
    def test_default_native_and_integrated_launch_denied_before_any_clone(self):
        syscalls=Mock();s=NativeAtomicSpawner(syscalls=syscalls)
        with self.assertRaises(LaunchDenied):s.spawn(None,deadline=10)
        f=ReviewedActorFactory(CONTEXT,ROOT,allocate=Mock());b=IntegratedBootstrap(spawner=s,factory=f,permit=permit(),clock=lambda:0)
        with self.assertRaises(SessionDenied):b.launch()
        syscalls.clone_into.assert_not_called();f.allocate.assert_not_called()
    def test_missing_root_confinement_blocks_even_approved_inventory(self):
        inv=Mock();inv.authorize_exec.return_value=True;syscalls=Mock();s=NativeAtomicSpawner(inventory=inv,syscalls=syscalls,clock=lambda:0)
        with patch("probe_a_linux_launcher.os.geteuid",return_value=0),patch("probe_a_linux_launcher.os.listdir",return_value=["1"]):
            with self.assertRaises(LaunchDenied):s.spawn(Mock(),deadline=180,activated=True,approval=b"synthetic")
        syscalls.clone_into.assert_not_called()
    def test_failed_atomic_clone_has_no_fallback(self):
        c,_=contract();inv=c.inventory;inv.authorize_exec.return_value=True;syscalls=Mock()
        syscalls.clone_into.side_effect=OSError("unsupported clone3")
        s=NativeAtomicSpawner(inventory=inv,contract=c,syscalls=syscalls,clock=lambda:0)
        spec=SimpleNamespace(role="read-command",group=c.scopes.groups["read-command"],validate=Mock(),argv=PLAN.inspect[0].argv)
        spec.group.fd=8;spec.group.verify=Mock(return_value=True)
        with patch("probe_a_linux_launcher.os.geteuid",return_value=0),patch("probe_a_linux_launcher.os.listdir",return_value=["1"]), \
             patch("probe_a_linux_launcher.os.pipe2",return_value=(20,21)),patch("probe_a_linux_launcher.os.close") as close:
            with self.assertRaises(OSError):s.spawn(spec,deadline=180,activated=True,approval=b"synthetic")
            self.assertEqual(close.call_count,2)
        syscalls.clone_into.assert_called_once_with(8)

    def test_integrated_bootstrap_uses_existing_spawner_and_readiness_before_controller(self):
        c,records=contract();events=[]
        spawner=NativeAtomicSpawner(inventory=c.inventory,contract=c,clock=lambda:0)
        def allocate(role,bindings,_permit,_contract):
            events.append("allocate:"+role)
            if role=="controller":self.assertEqual(set(bindings),{"guardian","observer"})
            conf=config(role);reader=90+len(events)
            inherited=tuple(("pidfd" if name.endswith("pidfd") else "ipc",fd) for name,fd in conf.descriptors)+(("config",reader),)
            spec=ExecSpec(role,80,("/usr/bin/python3","-I","-B","/reviewed/entry.py"),c.scopes.groups[role],inherited)
            channel=Mock()
            def receive(_maximum,*,deadline):
                sequence=channel.recv_bytes.call_count
                events.append("readiness:"+role+":"+str(sequence))
                return readiness_message(conf,("STARTING","IDENTITY_VERIFIED","READY","RUNNING")[sequence-1],sequence)
            channel.recv_bytes.side_effect=receive
            channel.send_bytes.side_effect=lambda *_a,**_kw:events.append("release:"+role)
            return ActorPreparation(spec,PendingRoleConfiguration(reader,reader+20,build=lambda identity:conf),channel)
        factory=ReviewedActorFactory(CONTEXT,ROOT,allocate=allocate)
        audit=Mock(spec=IndependentEvidenceAudit);audit.context=CONTEXT;audit.groups=GROUPS;audit.before_controller.return_value=True
        def spawn(spec,**kwargs):
            events.append("clone:"+spec.role)
            self.assertIs(kwargs["pending"].build(IDENTITIES[spec.role]).context,CONTEXT)
            identity=IDENTITIES[spec.role]
            records[spec.role].update(members=[[identity.pid,identity.starttime]],populated=True)
            h=Mock(pid=identity.pid,pidfd=400+identity.pid,group=spec.group)
            h.exited.return_value=False
            return h
        spawner.spawn=spawn
        def bind(pid):
            b=Mock(identity=next(i for i in IDENTITIES.values() if i.pid==pid));b.verify.return_value=True;return b
        with patch("probe_a_integrated_bootstrap.os.geteuid",return_value=0), \
             patch("probe_a_integrated_bootstrap.os.fstat",return_value=SimpleNamespace(st_dev=1,st_ino=2)), \
             patch("probe_a_integrated_bootstrap.os.close"),patch("probe_a_integrated_bootstrap.ProcessBinding",side_effect=bind), \
             patch("probe_a_integrated_bootstrap.CredentialSocket",side_effect=lambda stream,_peer:stream), \
             patch("probe_a_integrated_bootstrap.BoundedSocketIPC",side_effect=lambda stream,**kw:stream):
            supervisor=IntegratedBootstrap(spawner=spawner,factory=factory,permit=permit(),clock=lambda:0).launch(activated=True,approval=b"synthetic",evidence_audit=audit)
        self.assertTrue(supervisor.coordinator.running_authorized)
        self.assertLess(events.index("readiness:observer:3"),events.index("clone:guardian"))
        self.assertLess(events.index("readiness:guardian:3"),events.index("clone:controller"))
        self.assertEqual([e for e in events if e.startswith("release:")],["release:observer","release:guardian","release:controller"])

    def test_integrated_startup_failure_consumes_permit_and_failstops(self):
        class Halt(BaseException):pass
        for fault in ("ledger","scope","factory"):
            c,records=contract();p=permit(consume=(lambda *a:False) if fault=="ledger" else lambda *a:True)
            if fault=="scope":records["peer"]["delegated"]=True
            f=ReviewedActorFactory(CONTEXT,ROOT,allocate=Mock(side_effect=KeyboardInterrupt))
            audit=IndependentEvidenceAudit(context=CONTEXT,groups=GROUPS)
            b=IntegratedBootstrap(spawner=NativeAtomicSpawner(inventory=c.inventory,contract=c,clock=lambda:0),factory=f,permit=p,clock=lambda:0)
            with patch("probe_a_integrated_bootstrap.os.geteuid",return_value=0),patch("probe_a_integrated_bootstrap.os._exit",side_effect=Halt) as stop:
                with self.assertRaises(Halt):b.launch(activated=True,approval=b"synthetic",evidence_audit=audit)
                stop.assert_called_once_with(76)
            self.assertTrue(b.used);self.assertTrue(p.used)
            with self.assertRaises(SessionDenied):b.launch(activated=True)


class ContainmentIntegrationTests(unittest.TestCase):
    def test_all_separate_scopes_and_preflight(self):
        s,_=scopes();self.assertTrue(s.preflight());self.assertTrue(s.cleanup_observed())
    def test_partial_provisioning_denied(self):
        s,_=scopes();del s.groups["peer"]
        with self.assertRaises(KeyError):s.preflight()
        self.assertTrue(s.uncertain)
    def test_scope_uncertainty_sticky(self):
        s,records=scopes();records["worker"]["populated"]=True
        self.assertFalse(s.cleanup_observed());records["worker"]["populated"]=False
        self.assertFalse(s.cleanup_observed())
    def test_detached_descendant_prevents_cleanup(self):
        s,records=scopes();records["worker"].update(members=[[99,999]],populated=True)
        self.assertFalse(s.cleanup_observed())
    def test_wrong_incarnation_not_membership(self):
        s,records=scopes();records["guardian"].update(members=[[100,999]],populated=True)
        with self.assertRaises(ExecutionDenied):s.check("guardian",identity=IDENTITIES["guardian"])
    def test_no_default_enforcement_adapter(self):
        c,_=contract();c.enforce_child=None
        with self.assertRaises(ExecutionDenied):c.verify()
    def test_policy_signature_and_runtime_drift(self):
        c,_=contract();c.verify_policy=lambda *a:False
        with self.assertRaises(ExecutionDenied):c.verify()
        c,_=contract();c.policy["roles"]["observer"]["network"]="allow-all"
        with self.assertRaises(ExecutionDenied):c.verify()
    def test_child_policy_failure_cannot_fall_back(self):
        c,_=contract();c.enforce_child=lambda *a:False
        with self.assertRaises(ExecutionDenied):c.child_ready_for_exec(Mock(role="guardian",inherited=()))
    def test_execution_deadline_extension_and_role_replay(self):
        c,_=contract();spec=SimpleNamespace(role="guardian",group=c.scopes.groups["guardian"],argv=())
        with self.assertRaises(ExecutionDenied):c.before_spawn(spec,181)
        self.assertTrue(c.before_spawn(spec,180))
        with self.assertRaises(ExecutionDenied):c.before_spawn(spec,180)
    def test_root_identity_caps_or_nnp_mismatch(self):
        for identity in (replace(IDENTITIES["guardian"],uids=(1000,)*4),replace(IDENTITIES["guardian"],capabilities=(1,)*5),replace(IDENTITIES["guardian"],no_new_privs=0)):
            c,records=contract();records["guardian"].update(members=[[identity.pid,identity.starttime]],populated=True)
            with self.assertRaises(ExecutionDenied):c.ready("guardian",identity)
    def test_files_only_nss(self):self.assertTrue(local_nss(NSS))
    def test_nss_network_backends_or_duplicate_config_denied(self):
        for raw in (NSS.replace(b"passwd: files",b"passwd: files sss"),NSS.replace(b"hosts: files",b"hosts: files dns"),NSS+b"passwd: files\n",b"passwd: files\n"):
            with self.assertRaises(ExecutionDenied):local_nss(raw)
    def test_root_command_cannot_use_unrestricted_callable(self):
        capture=Mock();cmd=ContainedRootCommands(capture,clock=lambda:0)
        with self.assertRaises(SessionDenied):cmd(("/bin/sh","-c","id"),8)
        capture.assert_not_called()
    def test_child_effective_identity_verified_after_policy(self):
        c,_=contract()
        for identity in (IDENTITIES["controller"],replace(IDENTITIES["controller"],gids=(0,)*4),replace(IDENTITIES["controller"],capabilities=(1,)*5)):
            own=Mock(identity=identity);own.verify.return_value=True
            with patch("probe_a_linux_identity.ProcessBinding",return_value=own):
                if identity==IDENTITIES["controller"]:self.assertTrue(c.verify_child_identity(Mock(role="controller")))
                else:
                    with self.assertRaises(ExecutionDenied):c.verify_child_identity(Mock(role="controller"))
            own.close.assert_called_once()


def bad_scope(field,value):
    def test(self):
        s,records=scopes();records["observer"][field]=value
        with self.assertRaises(ExecutionDenied):s.preflight()
        self.assertTrue(s.uncertain)
    return test
for _field,_value in (("version",1),("owner",[1000,1000,0o777]),("ancestry",["/outside"]),("delegated",True),
                      ("children",["escape"]),("atomic",False),("pidfd",False),("identity",[9,9]),("context","f"*64)):
    setattr(ContainmentIntegrationTests,"test_wrong_"+_field,bad_scope(_field,_value))


def inventory_fixture(**kwargs):
    base=foundation.InventoryTests().document();base["source_commit"]=CONTEXT.source_commit
    assets={p:b"reviewed bytes" for p in base["files"]};assets["/etc/nsswitch.conf"]=NSS
    base["files"]={p:hashlib.sha256(b).hexdigest() for p,b in assets.items()}
    metadata={p:{"device":1,"inode":i,"uid":0,"gid":0,"mode":stat.S_IFREG|0o555,"size":len(assets[p])}
              for i,p in enumerate(assets,1)}
    deps={p:[] for p in assets};categories=base["categories"]
    closure=categories["dynamic_loader"]+categories["libcap"]+categories["libc_nss"]
    for p in categories["executables"]:deps[p]=list(closure)
    doc=inventory_candidate(base,metadata,{},deps)
    options={"verify_signature":lambda *a:True,"read_asset":lambda p:assets[p],
        "inspect_asset":lambda p:deepcopy(metadata[p]),"read_alias":lambda p:None,
        "read_facts":lambda:dict(base["facts"]),"read_requirements":lambda:dict(REQUIREMENTS),"verify_source":lambda *a:True}
    options.update(kwargs)
    return doc,options,assets,metadata


class IntegratedInventoryTests(unittest.TestCase):
    def test_complete_external_inventory_contract(self):
        doc,options,_,_=inventory_fixture();i=IntegratedInventory(doc,b"synthetic",**options)
        self.assertTrue(i.verify_integration(replace(CONTEXT,inventory=i.identifier)))
    def test_no_trust_root_or_own_signature(self):
        doc,options,_,_=inventory_fixture(verify_signature=None)
        with self.assertRaises(InventoryDenied):IntegratedInventory(doc,b"synthetic",**options).verify()
    def test_wrong_signature(self):
        doc,options,_,_=inventory_fixture(verify_signature=lambda *a:False)
        with self.assertRaises(InventoryDenied):IntegratedInventory(doc,b"synthetic",**options).verify()
    def test_changed_binary_and_sticky_drift(self):
        doc,options,assets,_=inventory_fixture();i=IntegratedInventory(doc,b"synthetic",**options)
        i.verify();path="/usr/bin/python3";original=assets[path];assets[path]=b"evil"
        with self.assertRaises(InventoryDenied):i.verify()
        assets[path]=original
        with self.assertRaises(InventoryDenied):i.verify()
    def test_same_binary_bytes_wrong_executable_fd_identity_denied(self):
        doc,options,_,_=inventory_fixture();i=IntegratedInventory(doc,b"synthetic",**options)
        spec=SimpleNamespace(argv=("/usr/bin/python3",),executable_fd=77)
        with patch("probe_a_inventory_integration.os.fstat",return_value=SimpleNamespace(st_dev=9,st_ino=9,st_uid=0,st_gid=0,st_mode=stat.S_IFREG|0o555,st_size=14)):
            with self.assertRaises(InventoryDenied):i.authorize_exec(spec,b"synthetic")
    def test_boolean_kernel_facts_cannot_be_integer_aliases(self):
        doc,options,_,_=inventory_fixture(read_requirements=lambda:dict(REQUIREMENTS,clone3=1))
        with self.assertRaises(InventoryDenied):IntegratedInventory(doc,b"synthetic",**options).verify()
    def test_changed_metadata_between_asset_reads(self):
        doc,options,_,metadata=inventory_fixture();calls={}
        def inspect(path):
            calls[path]=calls.get(path,0)+1
            result=deepcopy(metadata[path])
            if calls[path]>1:result["inode"]+=1
            return result
        options["inspect_asset"]=inspect
        with self.assertRaises(InventoryDenied):IntegratedInventory(doc,b"synthetic",**options).verify()
    def test_source_commit_mismatch(self):
        doc,options,_,_=inventory_fixture();i=IntegratedInventory(doc,b"synthetic",**options)
        with self.assertRaises(InventoryDenied):i.verify_integration(CONTEXT)
    def test_unexpected_transitive_dependency(self):
        doc,options,_,_=inventory_fixture();doc["dependencies"]["/usr/bin/python3"].append("/unexpected/lib.so")
        with self.assertRaises(InventoryDenied):IntegratedInventory(doc,b"synthetic",**options)
    def test_missing_loader_libcap_nss_closure(self):
        doc,options,_,_=inventory_fixture();doc["dependencies"]["/usr/bin/python3"]=[]
        with self.assertRaises(InventoryDenied):IntegratedInventory(doc,b"synthetic",**options)
    def test_changed_configuration_metadata(self):
        doc,options,_,metadata=inventory_fixture();i=IntegratedInventory(doc,b"synthetic",**options)
        metadata["/etc/nsswitch.conf"]["inode"]+=1
        with self.assertRaises(InventoryDenied):i.verify()
    def test_changed_configuration_contents(self):
        doc,options,assets,_=inventory_fixture();i=IntegratedInventory(doc,b"synthetic",**options)
        assets["/etc/nsswitch.conf"]+=b"hosts: dns\n"
        with self.assertRaises(InventoryDenied):i.verify()
    def test_unsupported_kernel_fact(self):
        doc,options,_,_=inventory_fixture(read_requirements=lambda:dict(REQUIREMENTS,clone3=False))
        with self.assertRaises(InventoryDenied):IntegratedInventory(doc,b"synthetic",**options).verify()
    def test_manifest_mutation_after_verification(self):
        doc,options,_,_=inventory_fixture();i=IntegratedInventory(doc,b"synthetic",**options);i.verify()
        i.document["aliases"]["/usr/bin/python3"]="/unreviewed"
        with self.assertRaises(InventoryDenied):i.verify()
    def test_source_not_from_approved_commit(self):
        doc,options,_,_=inventory_fixture(verify_source=lambda *a:False)
        with self.assertRaises(InventoryDenied):IntegratedInventory(doc,b"synthetic",**options).verify()
    def test_symlink_alias_explicit_target_and_drift(self):
        doc,options,assets,metadata=inventory_fixture();alias="/usr/bin/python3";target="/reviewed/python-real"
        assets[target]=assets[alias];metadata[target]=dict(metadata[alias]);doc["inventory"]["files"][target]=doc["inventory"]["files"][alias]
        doc["inventory"]["categories"]["python_runtime"].append(target);doc["metadata"][target]=dict(metadata[target]);doc["dependencies"][target]=[]
        doc["aliases"][alias]=target;options["read_alias"]=lambda _:target
        i=IntegratedInventory(doc,b"synthetic",**options);self.assertTrue(i.verify())
        i.read_alias=lambda _:"/evil"
        with self.assertRaises(InventoryDenied):i.verify()


class EvidenceTests(unittest.TestCase):
    def record(self,fact,value,seq=1,**kw):
        d={"v":1,"kind":"SYNTHETIC_TEST","context":CONTEXT.identifier,"inventory":CONTEXT.inventory,
           "source":CONTEXT.source_commit,"authority":"offline","collector":"offline-test","sequence":seq,
           "time":10,"fact":fact,"value":value};d.update(kw);return canonical(d)
    def values(self):
        return {"plan-inventory":{"context":CONTEXT.identifier,"inventory":CONTEXT.inventory,"source":CONTEXT.source_commit},
            "actor-identities":{r:identity_record(i) for r,i in IDENTITIES.items()},
            "cgroup-membership":{"actors":{r:{"identity":[i.pid,i.starttime],"group":GROUPS[r]} for r,i in IDENTITIES.items()},"scopes":GROUPS,"no_escape":True},
            "firewall-before":[BASE,BASE],"firewall-active":[snapshot(PLAN),snapshot(PLAN,family="ipv6")],
            "workers-peer-stopped":True,"emergency-deny":{"relevant_failures":"independently-observed","deny_first":True,"barrier":True,"mutation_outcomes":"certain"},
            "owned-cleanup":{key:True for key in CLEANUP_READBACKS},"firewall-restored":[BASE,BASE],
            "guardian-reaped":True,"observer-shutdown":True,"no-residuals":True}
    def complete(self):
        c=EvidenceComposer(CONTEXT,IDENTITIES,groups=GROUPS);values=self.values()
        for number,(case,family,index) in enumerate(CASES):
            before=[[0,0,"ACCEPT"],[0,0,"ACCEPT"],[0,0,"ACCEPT"],[0,0,"REJECT"]] if family=="ipv4" else [[0,0,"REJECT"]]
            after=deepcopy(before);after[index][0]=1;after[index][1]=60
            worker=replace(ROOT,pid=500+number,starttime=600+number,uids=(PLAN.uid,)*4,gids=(PLAN.uid,)*4)
            values["case:"+case]={"family":family,"before":before,"after":after,"behavior":case,
                "identity":identity_record(worker),"group":GROUPS["worker"],
                "peer":{"identity":identity_record(replace(ROOT,pid=5010,starttime=6010)),"group":GROUPS["peer"]} if case=="loopback-established" else None,
                "rules":values["firewall-active"]}
        for n,fact in enumerate(FACTS,1):c.append(self.record(fact,values[fact],n))
        return c
    def test_complete_synthetic_package_cannot_promote_pass(self):
        p=self.complete().package();self.assertEqual(p.provenance,"SYNTHETIC_TEST");self.assertEqual(p.missing,())
        self.assertEqual(p.result,"BLOCKED_NO_TRUSTED_RUNTIME_PASS")
    def test_missing_runtime_evidence_blocked(self):
        p=EvidenceComposer(CONTEXT,IDENTITIES).package();self.assertTrue(p.missing);self.assertIn("BLOCKED",p.result)
    def test_synthetic_claim_of_real_provenance_rejected(self):
        c=EvidenceComposer(CONTEXT,IDENTITIES)
        with self.assertRaises(EvidenceDenied):c.append(self.record("plan-inventory",self.values()["plan-inventory"],kind="INDEPENDENT_KERNEL"))
        self.assertTrue(c.package().defects)
    def test_untrusted_observer_claim_rejected(self):
        c=EvidenceComposer(CONTEXT,IDENTITIES,verify_collector=lambda *a:True,authorities={"observer":"approved"})
        with self.assertRaises(EvidenceDenied):c.append(self.record("plan-inventory",self.values()["plan-inventory"],kind="INDEPENDENT_KERNEL",authority="observer",collector="worker"),b"synthetic")
    def test_replay_and_wrong_cleanup_order(self):
        c=EvidenceComposer(CONTEXT,IDENTITIES);raw=self.record("plan-inventory",self.values()["plan-inventory"]);c.append(raw)
        with self.assertRaises(EvidenceDenied):c.append(raw)
        with self.assertRaises(EvidenceDenied):EvidenceComposer(CONTEXT,IDENTITIES).append(self.record("guardian-reaped",True))
    def test_uncertain_mutation_or_barrier_failure_blocked(self):
        for value in ({"barrier":False},{"mutation_outcomes":"uncertain"},{"deny_first":False}):
            c=self.complete();bad=dict(self.values()["emergency-deny"],**value)
            with self.assertRaises(EvidenceDenied):c._check("emergency-deny",bad)
    def test_firewall_restoration_or_counter_failure(self):
        c=self.complete()
        with self.assertRaises(Exception):c._check("firewall-restored",[snapshot(PLAN),BASE])
        value=deepcopy(c.receipts["case:"+CASES[0][0]]["value"]);value["after"]=value["before"]
        with self.assertRaises(Exception):c._check("case:"+CASES[0][0],value)
    def test_worker_escape_and_incomplete_owned_cleanup(self):
        c=self.complete();value=deepcopy(c.receipts["case:"+CASES[0][0]]["value"]);value["identity"]=[999,999]
        with self.assertRaises(SessionDenied):c._check("case:"+CASES[0][0],value)
        with self.assertRaises(EvidenceDenied):c._check("owned-cleanup",{key:True for key in CLEANUP_READBACKS[:-1]})
    def test_external_kernel_receipt_is_still_incomplete_not_pass(self):
        c=EvidenceComposer(CONTEXT,IDENTITIES,groups=GROUPS,verify_collector=lambda *a:True,authorities={"observer":"synthetic-approved-collector"})
        c.append(self.record("plan-inventory",self.values()["plan-inventory"],kind="INDEPENDENT_KERNEL",authority="observer",collector="synthetic-approved-collector"),b"synthetic-signature")
        p=c.package();self.assertEqual(p.provenance,"INCOMPLETE_RUNTIME_EVIDENCE");self.assertIn("BLOCKED",p.result)
    def test_collected_receipt_cannot_be_changed_after_verification(self):
        c=self.complete();c.receipts["no-residuals"]["value"]=False
        with self.assertRaises(EvidenceDenied):c.package()
    def test_guardian_self_report_cannot_enter_kernel_evidence(self):
        c=EvidenceComposer(CONTEXT,IDENTITIES,groups=GROUPS,verify_collector=lambda *a:True,
            authorities={"guardian":"signed-worker"})
        with self.assertRaises(EvidenceDenied):c.append(self.record("plan-inventory",self.values()["plan-inventory"],
            kind="INDEPENDENT_KERNEL",authority="guardian",collector="signed-worker"),b"synthetic")
    def test_inventory_or_source_mismatch_blocks(self):
        for field,value in (("source","a"*40),("inventory","b"*64),("context","d"*64)):
            c=EvidenceComposer(CONTEXT,IDENTITIES)
            with self.assertRaises(EvidenceDenied):c.append(self.record("plan-inventory",self.values()["plan-inventory"],**{field:value}))
    def test_absent_or_synthetic_journal_cannot_release_native_controller(self):
        c=coordinator()
        for role in IDENTITIES:ready(c,role)
        c.actors["guardian"].state=c.actors["observer"].state="RUNNING"
        audit=IndependentEvidenceAudit(context=CONTEXT,groups=GROUPS)
        with self.assertRaises(EvidenceDenied):audit.before_controller(c)
        audit=IndependentEvidenceAudit(EvidenceComposer(CONTEXT,IDENTITIES,groups=GROUPS),collect=lambda fact,_ctx:(self.record(fact,self.values()[fact],FACTS.index(fact)+1),None))
        with self.assertRaises(EvidenceDenied):audit.before_controller(c)
        self.assertTrue(audit.failed)
    def test_blocked_package_cannot_be_converted_to_pass(self):
        p=self.complete().package()
        with self.assertRaises(EvidenceDenied):replace(p,result="PASS")
        self.assertEqual(p.result,"BLOCKED_NO_TRUSTED_RUNTIME_PASS")
