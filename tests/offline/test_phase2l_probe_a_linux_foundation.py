"""Disabled OS foundation: DI failures plus nonprivileged Unix IPC/procfs.

Never invokes clone3, privilege drop, firewall/cgroup writes or Probe A. DI
tests are source regressions, not evidence of kernel containment/readiness.
"""
from dataclasses import replace
import hashlib
import json
import os
from pathlib import Path
import socket
import struct
import subprocess
import sys
import time
from types import SimpleNamespace
import unittest
from unittest.mock import Mock, patch

ROOT = Path(__file__).resolve().parents[2]
MODULES = ROOT / "docs/security/phase2l"
sys.path.insert(0, str(MODULES))

from probe_contract import CASES, compile_plan, verdict, CLEANUP_READBACKS
from probe_a_ipc import BoundedSocketIPC
from probe_a_exec_adapter import Reply, UnsafeCommand
from probe_a_linux_identity import (CredentialSocket, IdentityDenied, ProcessBinding,
                                    ProcessIdentity, parse_identity, read_at, read_fd)
from probe_a_linux_launcher import (ACTORS, CloneArgs, ExecSpec, LaunchDenied,
                                    LinuxSyscalls, NativeAtomicSpawner, NativeBoundedCapture,
                                    IndependentSupervisor, TrustedActorBootstrap,
                                    close_except, deadline_pair, empty_group,
                                    CLONE_INTO_CGROUP, CLONE_PIDFD)
from probe_a_os_inventory import (CATEGORIES, FACTS, InventoryDenied, RuntimeInventory,
                                  absolute, root_asset)
from probe_a_readonly_broker import (BrokerClient, BrokerDenied, NativeReadCommands,
                                    ReadOnlyBroker, catalog, unique_json)
from probe_a_attestation import PINNED, BINARY_PATHS, CONFIG_PATHS
from probe_a_linux_containment import NativeContainmentAdapter
from probe_a_os_inventory import ROLES
from probe_a_workload import CASES_ORDER, exact_argv, peer_argv

PLAN = compile_plan(scope="1234ABCD", uid=42001, dns="9.9.9.9")
IDENTITY = ProcessIdentity(123, 456, (0,)*4, (0,)*4, (), (0,)*5, 1, (1, 2))


class IdentityTests(unittest.TestCase):
    def test_real_self_pidfd_and_proc_binding(self):
        self.assertNotEqual(os.geteuid(), 0, "this suite must run without root")
        binding = ProcessBinding(os.getpid())
        try:
            self.assertTrue(binding.verify())
            self.assertEqual(binding.identity.pid, os.getpid())
            self.assertEqual(binding.identity.uids[1], os.geteuid())
            self.assertTrue(binding.alive())
        finally:
            binding.close()
        self.assertFalse(binding.alive())

    def test_real_credentials_preserve_existing_framing(self):
        binding = ProcessBinding(os.getpid())
        left, right = socket.socketpair()
        receiver = BoundedSocketIPC(CredentialSocket(left, binding))
        sender = BoundedSocketIPC(right)
        try:
            sender.send_bytes(b'{"op":"read:0"}', deadline=time.monotonic()+2)
            self.assertEqual(receiver.recv_bytes(256, deadline=time.monotonic()+2), b'{"op":"read:0"}')
        finally:
            receiver.close()
            sender.close()
            binding.close()

    def test_descriptor_injection_is_closed_and_denied(self):
        binding = ProcessBinding(os.getpid())
        left, right = socket.socketpair()
        guarded = CredentialSocket(left, binding)
        fd = os.open("/dev/null", os.O_RDONLY | os.O_CLOEXEC)
        before = len(os.listdir("/proc/self/fd"))
        try:
            right.sendmsg([b"x"], [(socket.SOL_SOCKET, socket.SCM_RIGHTS, struct.pack("i", fd))])
            with self.assertRaises(IdentityDenied):
                guarded.recv(1)
            # Receiving and rejecting rights leaks no descriptors.
            self.assertEqual(len(os.listdir("/proc/self/fd")), before-1)
        finally:
            guarded.close()
            right.close()
            binding.close()
            os.close(fd)

    def test_delegated_or_wrong_credentials_denied(self):
        binding = ProcessBinding(os.getpid())
        left, right = socket.socketpair()
        guarded = CredentialSocket(left, binding)
        binding.identity = replace(binding.identity, pid=binding.identity.pid+1)
        # Isolate message check from the separate fresh-procfs check.
        with patch.object(binding, "verify", return_value=True):
            right.send(b"x")
            with self.assertRaises(IdentityDenied):
                guarded.recv(1)
        right.close()
        binding.close()

    def test_controller_all_credentials_caps_and_nnp(self):
        good = replace(IDENTITY, uids=(65534,)*4, gids=(65534,)*4)
        self.assertIs(good.require_controller(), good)
        for value in (replace(good, uids=(65534, 0, 65534, 65534)),
                      replace(good, gids=(65534, 65534, 0, 65534)),
                      replace(good, groups=(65534,)), replace(good, no_new_privs=0)):
            with self.assertRaises(IdentityDenied):
                value.require_controller()
        for index in range(5):
            caps = [0]*5
            caps[index] = 1
            with self.assertRaises(IdentityDenied):
                replace(good, capabilities=tuple(caps)).require_controller()

    def test_ambiguous_status_and_resource_name_denied(self):
        with self.assertRaises(IdentityDenied):
            parse_identity(123, "123 (odd ) name) " + " ".join(["1"]*20),
                           "Uid: 0 0 0 0\nUid: 0 0 0 0\n", (1, 2))
        with patch("probe_a_linux_identity.os.open") as opened:
            with self.assertRaises(IdentityDenied):
                read_at(9, "../../etc/shadow")
            opened.assert_not_called()

    def test_bounded_fd_read(self):
        with patch("probe_a_linux_identity.os.read", side_effect=[b"abcd", b"e"]):
            with self.assertRaises(IdentityDenied):
                read_fd(3, maximum=4)

    def test_privileged_modules_do_not_import_controller(self):
        # Safe unprivileged import in a fresh interpreter; no entrypoints run.
        source = ("import sys; sys.path.insert(0," + repr(str(MODULES)) + "); "
                  "import probe_a_linux_launcher, probe_a_readonly_broker, probe_a_os_inventory, "
                  "probe_a_linux_containment, probe_a_guardian; "
                  "assert 'probe_a_controller' not in sys.modules")
        subprocess.run([sys.executable, "-I", "-B", "-c", source], check=True,
                       timeout=10, env={"PATH": os.defpath, "PYTHONDONTWRITEBYTECODE": "1"})
        self.assertEqual(CASES_ORDER, tuple(x[0] for x in CASES))


class LauncherTests(unittest.TestCase):
    def test_disabled_launch_has_no_syscall_or_inventory_access(self):
        inventory, syscalls = Mock(), Mock()
        spawner = NativeAtomicSpawner(inventory=inventory, syscalls=syscalls)
        with self.assertRaises(LaunchDenied):
            spawner.spawn(None, deadline=time.monotonic()+1)
        inventory.authorize_exec.assert_not_called()
        syscalls.clone_into.assert_not_called()

    def test_unprivileged_activated_launch_denied(self):
        syscalls = Mock()
        with self.assertRaises(LaunchDenied):
            NativeAtomicSpawner(inventory=Mock(), syscalls=syscalls).spawn(
                None, deadline=time.monotonic()+1, activated=True, approval=b"fixture")
        syscalls.clone_into.assert_not_called()

    def test_absolute_deadline_and_reserve(self):
        deadline_pair(240, 180, 0)
        for args in ((241, 181, 0), (240, 181, 0), (float("nan"), 180, 0),
                     (240, 180, 180), (240, 180, False)):
            with self.assertRaises(LaunchDenied):
                deadline_pair(*args)

    def test_clone3_atomic_flags_no_fork_fallback(self):
        observed = []
        class Library:
            def __init__(self):
                self.syscall = Mock(side_effect=self.call)
            def call(self, number, pointer, size):
                args = pointer._obj
                observed.append((number.value, args.flags, args.cgroup, size))
                return -1
        with patch("probe_a_linux_launcher.os.geteuid", return_value=0), \
             patch("probe_a_linux_launcher.os.uname", return_value=SimpleNamespace(machine="x86_64")), \
             patch("probe_a_linux_launcher.ctypes.CDLL", return_value=Library()):
            with self.assertRaisesRegex(LaunchDenied, "NO_FORK_FALLBACK"):
                LinuxSyscalls().clone_into(21)
        self.assertEqual(observed, [(435, CLONE_PIDFD | CLONE_INTO_CGROUP, 21,
                                     __import__("ctypes").sizeof(CloneArgs))])

    def test_child_drop_precedes_exec_failure_hard_stop(self):
        calls = []
        spec = SimpleNamespace(role="controller", group=Mock(fd=12), executable_fd=13,
                               argv=("/pinned/python",), inherited=(), validate=lambda: True)
        inventory = Mock()
        inventory.authorize_exec.return_value = True
        syscalls = Mock()
        syscalls.clone_into.return_value = (0, -1)
        syscalls.prepare_child.side_effect = lambda *args: calls.append("trusted-drop")
        class Stopped(BaseException): pass
        with patch("probe_a_linux_launcher.os.geteuid", return_value=0), \
             patch("probe_a_linux_launcher.os.listdir", return_value=["1"]), \
             patch("probe_a_linux_launcher.os.open", return_value=20), \
             patch("probe_a_linux_launcher.os.fstat", return_value=SimpleNamespace(
                 st_mode=__import__("stat").S_IFCHR, st_uid=0, st_rdev=os.makedev(1, 3))), \
             patch("probe_a_linux_launcher.os.dup2"), \
             patch("probe_a_linux_launcher.close_except"), \
             patch("probe_a_linux_launcher.os.execve", side_effect=lambda *args: calls.append("exec")), \
             patch("probe_a_linux_launcher.os._exit", side_effect=Stopped):
            with self.assertRaises(Stopped):
                NativeAtomicSpawner(inventory=inventory, syscalls=syscalls, clock=lambda: 0).spawn(
                    spec, deadline=180, activated=True, approval=b"fixture")
        self.assertEqual(calls, ["trusted-drop", "exec"])

    def test_parent_death_signal_restored_after_uid_drop(self):
        calls = []
        library = SimpleNamespace(prctl=lambda *args: calls.append("pdeath") or 0)
        with patch("probe_a_linux_launcher.os.setsid"), \
             patch("probe_a_linux_launcher.os.getppid", return_value=123), \
             patch("probe_a_linux_launcher.ctypes.CDLL", return_value=library), \
             patch("probe_a_linux_launcher.drop_controller", side_effect=lambda: calls.append("drop") or True), \
             patch("probe_a_linux_launcher.verify_unprivileged", return_value=True):
            LinuxSyscalls().prepare_child("controller", 123)
        self.assertEqual(calls, ["pdeath", "drop", "pdeath"])

    def test_fd_close_ranges_preserve_only_handoff(self):
        with patch("probe_a_linux_launcher.resource.getrlimit", return_value=(30, 30)), \
             patch("probe_a_linux_launcher.os.closerange") as close:
            close_except({7, 12})
        self.assertEqual([x.args for x in close.call_args_list], [(3, 7), (8, 12), (13, 30)])

    def test_config_and_privileged_fd_leaks_denied(self):
        group = SimpleNamespace(fd=8)
        for role, argv, inherited in (("shell", ("/bin/sh",), ()),
                                      ("worker", ("/bin/sh",), (("ipc", 8),)),
                                      ("worker", ("/bin/sh", "x\x00y"), ())):
            with self.assertRaises(LaunchDenied):
                ExecSpec(role, 8, argv, group, inherited).validate()

    def test_strict_kernel_group_readback(self):
        self.assertTrue(empty_group("populated 0\nfrozen 0\n", ""))
        self.assertFalse(empty_group("populated 1\n", "22\n"))
        for events, procs in (("populated 0\npopulated 1\n", ""),
                              ("frozen 0\n", ""), ("populated 0\n", "bogus\n")):
            with self.assertRaises(LaunchDenied):
                empty_group(events, procs)

    def test_disabled_capture_no_pipe_or_process(self):
        argv = PLAN.inspect[0].argv
        spec = SimpleNamespace(argv=argv, role="read-command")
        with patch("probe_a_linux_launcher.os.pipe2") as pipe:
            with self.assertRaises(LaunchDenied):
                NativeBoundedCapture({argv: spec}, spawner=Mock(), plan=PLAN)(argv, 1)
        pipe.assert_not_called()

    def test_capture_bounds_failure_poison_executor_and_kill_owned_group(self):
        argv = PLAN.inspect[0].argv
        group = Mock()
        child = Mock(pid=123, pidfd=42)
        child.exited.return_value = True
        spawner = Mock()
        spawner.spawn.return_value = child
        spec = SimpleNamespace(argv=argv, role="read-command", group=group)
        capture = NativeBoundedCapture({argv: spec}, spawner=spawner, plan=PLAN, activated=True,
                                       approval=b"fixture", clock=lambda: 0)
        with patch("probe_a_linux_launcher.select.select", side_effect=lambda r, *args: (r, [], [])), \
             patch("probe_a_linux_launcher.os.read", return_value=b"x"*8192):
            with self.assertRaisesRegex(LaunchDenied, "OUTPUT_OVERFLOW"):
                capture(argv, 1)
        group.kill_all.assert_called_once_with()
        child.close.assert_called_once_with()
        self.assertFalse(capture.activated)
        self.assertFalse(capture.busy)

    def test_detached_descendant_prevents_capture_success(self):
        argv = PLAN.inspect[0].argv
        group = Mock()
        group.readback.return_value = ("populated 1\n", "999\n")
        child = Mock(pid=123, pidfd=42, exitcode=0)
        child.exited.return_value = True
        spawner = Mock()
        spawner.spawn.return_value = child
        spec = SimpleNamespace(argv=argv, role="guardian-command", group=group)
        ticks = iter([0, 0, 0, 0.5, 0.5, 1, 1])
        capture = NativeBoundedCapture({argv: spec}, spawner=spawner, plan=PLAN, activated=True,
                                       clock=lambda: next(ticks))
        with patch("probe_a_linux_launcher.select.select", side_effect=lambda r, *args: (r, [], [])), \
             patch("probe_a_linux_launcher.os.read", return_value=b""):
            with self.assertRaisesRegex(LaunchDenied, "DESCENDANT"):
                capture(argv, 1)
        group.kill_all.assert_called_once_with()

    def test_root_read_commands_require_contained_executor(self):
        with self.assertRaises(BrokerDenied):
            NativeReadCommands(PLAN, capture=lambda *args: Reply(0, ""), inventory=Mock())
        argv = PLAN.setup[0].argv
        capture = NativeBoundedCapture({argv: SimpleNamespace(role="guardian-command", argv=argv)},
                                       spawner=Mock(), plan=PLAN)
        with self.assertRaises(BrokerDenied):
            NativeReadCommands(PLAN, capture=capture, inventory=Mock())

    def test_capture_exact_allowlist_cannot_be_widened_by_inventory(self):
        for argv in (("/bin/sh", "-c", "anything"), ("/usr/bin/sudo", "anything"),
                     ("/usr/sbin/iptables", "-F"), ("/usr/bin/getent", "passwd", "0")):
            with self.assertRaises(LaunchDenied):
                NativeBoundedCapture({argv: SimpleNamespace(role="guardian-command", argv=argv)},
                                      spawner=Mock(), plan=PLAN)

    def make_bootstrap(self, fail_role=None):
        specs = {role: SimpleNamespace(role=role, group=Mock(identity=(1, i)),
                                       inherited=(), validate=lambda: True)
                 for i, role in enumerate(ACTORS, start=1)}
        spawner = NativeAtomicSpawner(inventory=Mock(), clock=lambda: 0)
        order = []
        def spawn(spec, **kwargs):
            order.append(spec.role)
            if spec.role == fail_role:
                raise RuntimeError("uncertain child")
            return SimpleNamespace(pid=100+len(order))
        spawner.spawn = spawn
        return TrustedActorBootstrap(specs, spawner=spawner, end=240, cutoff=180,
                                     clock=lambda: 0), order

    def test_bootstrap_default_denial_and_one_use(self):
        bootstrap, order = self.make_bootstrap()
        with self.assertRaises(LaunchDenied):
            bootstrap.launch()
        self.assertEqual(order, [])
        with patch("probe_a_linux_launcher.os.geteuid", return_value=0):
            bootstrap.launch(activated=True, approval=b"fixture")
            with self.assertRaises(LaunchDenied):
                bootstrap.launch(activated=True, approval=b"fixture")
        self.assertEqual(order, ["observer", "guardian", "controller"])

    def test_uncertain_partial_bootstrap_is_irreversible(self):
        bootstrap, order = self.make_bootstrap("guardian")
        class Stopped(BaseException): pass
        with patch("probe_a_linux_launcher.os.geteuid", return_value=0), \
             patch("probe_a_linux_launcher.os._exit", side_effect=Stopped) as stop:
            with self.assertRaises(Stopped):
                bootstrap.launch(activated=True, approval=b"fixture")
        stop.assert_called_once_with(76)
        self.assertEqual(order, ["observer", "guardian"])


class BrokerTests(unittest.TestCase):
    def make(self, command=None, resource=None):
        return ReadOnlyBroker(PLAN, command=command or (lambda *args: Reply(0, "kernel observation")),
                              read_resource=resource or (lambda *args: False),
                              observer_identity=IDENTITY, inventory_id="a"*64,
                              end=240, clock=lambda: 0)

    def request(self, op, seq=1):
        return json.dumps({"v": 1, "seq": seq, "op": op}).encode()

    def test_catalog_has_no_writes_or_shell(self):
        reads = set(catalog(PLAN).values())
        self.assertTrue(all(command.argv not in reads for command in PLAN.setup))
        self.assertTrue(any(argv[0] == "/usr/bin/pgrep" for argv in reads))
        self.assertTrue(any(argv[0] == "/usr/bin/getent" for argv in reads))
        self.assertNotIn(("/bin/sh",), reads)

    def test_observation_explicitly_unverified(self):
        response = unique_json(self.make().handle(self.request("read:0")))
        self.assertEqual(response["evidence"], "UNVERIFIED_NOT_PROBE_PASS")
        self.assertEqual(response["observer"], [123, 456])
        self.assertEqual(response["inventory"], "a"*64)
        self.assertEqual(verdict(dict.fromkeys(CLEANUP_READBACKS, True),
                                 provenance="REAL_INDEPENDENT_HOST_READBACK"), "BLOCKED_NO_TRUSTED_OBSERVER")

    def test_write_unknown_argv_path_and_resource_denied(self):
        for op in ("write:0", "resource:/etc/shadow", "read:999", "sudo /bin/sh"):
            with self.assertRaises(BrokerDenied):
                self.make().handle(self.request(op))
        request = {"v": 1, "seq": 1, "op": "read:0", "argv": ["/bin/sh"]}
        with self.assertRaises(BrokerDenied):
            self.make().handle(json.dumps(request).encode())

    def test_replay_and_uncertain_request_consumed(self):
        broker = self.make(command=Mock(side_effect=RuntimeError("uncertain read")))
        with self.assertRaises(RuntimeError):
            broker.handle(self.request("read:0"))
        with self.assertRaises(BrokerDenied):
            broker.handle(self.request("read:0"))

    def test_duplicate_keys_and_nonfinite_messages_denied(self):
        for raw in (b'{"v":1,"v":1,"seq":1,"op":"read:0"}',
                    b'{"v":1,"seq":NaN,"op":"read:0"}', b"\xff", b"[]"):
            with self.assertRaises(BrokerDenied):
                self.make().handle(raw)

    def test_boolean_sequence_oversize_and_expired_denied(self):
        for raw in (b'{"v":1,"seq":true,"op":"read:0"}', b"x"*257):
            with self.assertRaises(BrokerDenied):
                self.make().handle(raw)
        broker = self.make()
        broker.clock = lambda: 240
        with self.assertRaises(BrokerDenied):
            broker.handle(self.request("read:0"))

    def test_resource_type_and_output_overflow_denied(self):
        with self.assertRaises(BrokerDenied):
            self.make(resource=lambda *args: "PASS").handle(self.request("resource:watchdog_absent"))
        with self.assertRaises(UnsafeCommand):
            self.make(command=lambda *args: Reply(0, "x"*131073)).handle(self.request("read:0"))

    def test_unauthenticated_client_and_default_serve_denied(self):
        with self.assertRaises(BrokerDenied):
            BrokerClient(PLAN, channel=Mock(), observer_identity=IDENTITY, inventory_id="a"*64)
        with self.assertRaises(BrokerDenied):
            self.make().serve(Mock(), Mock())

    def test_real_client_rejects_worker_provenance(self):
        binding = ProcessBinding(os.getpid())
        left, right = socket.socketpair()
        channel = BoundedSocketIPC(CredentialSocket(left, binding))
        sender = BoundedSocketIPC(right)
        try:
            client = BrokerClient(PLAN, channel=channel, observer_identity=binding.identity,
                                  inventory_id="a"*64)
            forged = {"v": 1, "seq": 1, "op": "read:0", "observer": [123, 456],
                      "inventory": "a"*64, "code": 0, "stdout": "PASS",
                      "evidence": "REAL_INDEPENDENT_HOST_READBACK"}
            sender.send_bytes(json.dumps(forged).encode(), deadline=time.monotonic()+2)
            with self.assertRaises(BrokerDenied):
                client.query("read:0", time.monotonic()+2)
        finally:
            channel.close()
            sender.close()
            binding.close()


class InventoryTests(unittest.TestCase):
    def document(self):
        files = {path: hashlib.sha256(b"reviewed bytes").hexdigest() for path in PINNED}
        categories = {"source": list(set(PINNED) - set(BINARY_PATHS) - set(CONFIG_PATHS)),
                      "executables": list(BINARY_PATHS), "nss_configuration": list(CONFIG_PATHS)}
        for key in CATEGORIES - set(categories):
            path = "/reviewed/" + key
            categories[key] = [path]
            files[path] = hashlib.sha256(b"reviewed bytes").hexdigest()
        facts = dict.fromkeys(FACTS, "pinned")
        facts.update({"cgroup.version": "2", "nss.passwd_backend": "files"})
        return {"v": 1, "source_commit": "a"*40, "reviewer": "external test double",
                "categories": categories, "files": files, "facts": facts,
                "exec": {role: [[BINARY_PATHS[0]]] for role in ROLES},
                "groups": {role: {"device": 1, "inode": i}
                           for i, role in enumerate(sorted(ROLES), start=1)}}

    def make(self, doc=None, **kwargs):
        doc = self.document() if doc is None else doc
        return RuntimeInventory(doc, b"test signature", read_asset=lambda _: b"reviewed bytes",
                                read_facts=lambda: dict(doc["facts"]), **kwargs)

    def test_no_default_signature_verifier_or_runtime_approval(self):
        with self.assertRaises(InventoryDenied):
            self.make().verify()
        inventory = self.make(verify_signature=lambda *args: True)
        self.assertTrue(inventory.verify())  # DI only; never trusted evidence
        with self.assertRaises(InventoryDenied):
            inventory.authorize_exec(None, None)

    def test_authenticated_inventory_mutation_denied(self):
        inventory = self.make(verify_signature=lambda *args: True)
        inventory.document["exec"]["controller"] = [["/bin/sh"]]
        with self.assertRaisesRegex(InventoryDenied, "MUTATED"):
            inventory.verify()

    def test_caller_cannot_mutate_canonical_copy(self):
        doc = self.document()
        inventory = self.make(doc, verify_signature=lambda *args: True)
        doc["files"].clear()
        self.assertTrue(inventory.verify())

    def test_python_pathname_without_source_digest_cannot_execute(self):
        doc = self.document()
        argv = ("/usr/bin/python3", "-I", "-B", "/unreviewed/entry.py")
        doc["exec"]["guardian"] = [list(argv)]
        inventory = self.make(doc, verify_signature=lambda *args: True)
        group = doc["groups"]["guardian"]
        spec = SimpleNamespace(role="guardian", argv=argv,
                               group=SimpleNamespace(identity=(group["device"], group["inode"])))
        with self.assertRaisesRegex(InventoryDenied, "ENTRYPOINT_MISSING"):
            inventory.authorize_exec(spec, b"separate test approval")

    def test_all_dependency_categories_mandatory(self):
        for key in CATEGORIES:
            doc = self.document()
            doc["categories"][key] = []
            with self.assertRaises(InventoryDenied):
                self.make(doc)
        doc = self.document()
        doc["categories"]["source"] = [{}]
        with self.assertRaises(InventoryDenied):
            self.make(doc)

    def test_ambiguous_dependency_categories_and_shared_role_groups_denied(self):
        doc = self.document()
        doc["categories"]["dynamic_loader"] = [BINARY_PATHS[0]]
        with self.assertRaises(InventoryDenied):
            self.make(doc)
        doc = self.document()
        doc["groups"]["read-command"] = dict(doc["groups"]["guardian"])
        with self.assertRaises(InventoryDenied):
            self.make(doc)

    def test_missing_dependency_hash_and_os_drift_denied(self):
        doc = self.document()
        del doc["files"][next(iter(PINNED))]
        with self.assertRaises(InventoryDenied):
            self.make(doc)
        inventory = self.make(verify_signature=lambda *args: True)
        inventory.read_asset = lambda _: b"drift"
        with self.assertRaises(InventoryDenied):
            inventory.verify()
        inventory = self.make(verify_signature=lambda *args: True)
        inventory.read_facts = lambda: {"ImageVersion": "self reported"}
        with self.assertRaises(InventoryDenied):
            inventory.verify()

    def test_path_alias_or_traversal_denied(self):
        for path in ("/usr/../bin/python3", "/usr//bin/python3", "relative", "/usr/bin/./python3"):
            with self.assertRaises(InventoryDenied):
                absolute(path)
        # Actual no-follow read is safe/nonprivileged; /proc/self is a symlink.
        with self.assertRaises((OSError, InventoryDenied)):
            root_asset("/proc/self/status")


class ContainmentAndSupervisionTests(unittest.TestCase):
    def test_containment_contract_exact_specs_and_default_denial(self):
        specs = {exact_argv(PLAN, case): SimpleNamespace(argv=exact_argv(PLAN, case),
                 role="worker", inherited=(), group=Mock(identity=(1, 10))) for case in CASES_ORDER}
        specs[peer_argv()] = SimpleNamespace(argv=peer_argv(), role="peer", inherited=(),
                                            group=Mock(identity=(1, 11)))
        adapter = NativeContainmentAdapter(PLAN, specs, spawner=NativeAtomicSpawner(),
                                           independent_uid_absent=lambda *args: False)
        with self.assertRaises(LaunchDenied):
            adapter.preflight_atomic_spawn(adapter.path)
        with self.assertRaises(LaunchDenied):
            adapter.capture_atomic(adapter.path, next(iter(specs)), 1)
        del specs[peer_argv()]
        with self.assertRaises(LaunchDenied):
            NativeContainmentAdapter(PLAN, specs, spawner=NativeAtomicSpawner(),
                                     independent_uid_absent=lambda *args: True)

    def actors(self, guardian_code=0, observer_dead=False):
        actors = {}
        for i, role in enumerate(ACTORS, start=10):
            actors[role] = Mock(pid=i, pidfd=i, exitcode=guardian_code if role == "guardian" else 0)
            actors[role].exited.return_value = role != "observer" or observer_dead
            actors[role].reap.return_value = actors[role].exitcode
            actors[role].group.readback.return_value = ("populated 0\n", "")
            if role == "observer":
                actors[role].signal.side_effect = lambda *args: setattr(actors["observer"].exited, "return_value", True)
        return actors

    def test_supervision_never_pass_and_nonzero_or_missing_observer_blocks(self):
        for code, observer_dead, expected in ((0, False, "UNVERIFIED_ABORT_OR_DEADLINE_NOT_PROBE_PASS"),
                                              (10, False, "BLOCKED_INDEPENDENT_POST_GUARDIAN_OBSERVATION"),
                                              (0, True, "BLOCKED_INDEPENDENT_POST_GUARDIAN_OBSERVATION")):
            supervisor = IndependentSupervisor(self.actors(code, observer_dead), end=240, cutoff=180,
                                                clock=lambda: 0)
            with patch("probe_a_linux_launcher.os.geteuid", return_value=0):
                self.assertEqual(supervisor.run(close_controller_channel=lambda: None,
                                                 observe_after=lambda: True, activated=True), expected)

    def test_supervisor_deadline_returns_uncertain(self):
        clock = Mock(side_effect=[0, 240])
        supervisor = IndependentSupervisor(self.actors(), end=240, cutoff=180, clock=clock)
        with patch("probe_a_linux_launcher.os.geteuid", return_value=0):
            self.assertEqual(supervisor.run(close_controller_channel=lambda: None,
                                             observe_after=lambda: True, activated=True),
                             "BLOCKED_GUARDIAN_OR_DESCENDANT_CLEANUP_UNCERTAIN")

    def test_supervisor_default_has_no_actor_side_effects(self):
        actors = self.actors()
        supervisor = IndependentSupervisor(actors, end=240, cutoff=180, clock=lambda: 0)
        with self.assertRaises(LaunchDenied):
            supervisor.run(close_controller_channel=Mock(), observe_after=Mock())
        for actor in actors.values():
            actor.signal.assert_not_called()


if __name__ == "__main__":
    unittest.main()
