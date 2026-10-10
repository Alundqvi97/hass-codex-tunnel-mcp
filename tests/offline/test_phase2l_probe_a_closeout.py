"""Disabled closeout regressions. OS identities/policy/kernel are synthetic.
No native activation, privilege changes, trace loading or probe traffic.
"""
import fcntl, hashlib, os, stat, struct, sys, tempfile, unittest
from pathlib import Path
from dataclasses import replace
from types import SimpleNamespace
from unittest.mock import patch, Mock
sys.path.insert(0,str(Path(__file__).resolve().parents[2]/'docs/security/phase2l'))
from test_phase2l_probe_a_integration import CONTEXT,ROOT,IDENTITIES,contract,config,coordinator,ready
import test_phase2l_probe_a_native_delivery as prior
from probe_a_os_inventory import InventoryDenied
from probe_a_execution_contract import CAP_SYS_ADMIN,CAP_SYS_PTRACE,ROLE_CAPABILITY_LIMITS,ExecutionDenied
from probe_a_session import canonical,SessionDenied,RoleConfiguration,identity_record
from probe_a_linux_identity import read_at,read_process_attribute,read_network_table,IdentityDenied
from probe_a_native_policy import NativePolicyAdapter,InstalledPolicyInspector,ALLOW,DENY
from probe_a_readonly_broker import ReadOnlyBroker,BrokerDenied
from probe_a_native_package import DescriptorOwner,read_package,run_native_role
from probe_a_native_trace import TraceDecoder,NativeTraceLoader,EVENT
from probe_a_coordinator import RoleStartup,CoordinationDenied


class CapabilityNumbers(unittest.TestCase):
    def test_uapi_numbers_and_no_sysadmin_in_any_authenticated_role_field(self):
        header=Path('/usr/include/linux/capability.h').read_text()
        self.assertRegex(header,r'#define CAP_SYS_PTRACE\s+19\b');self.assertRegex(header,r'#define CAP_SYS_ADMIN\s+21\b')
        self.assertEqual(CAP_SYS_PTRACE,19);self.assertEqual(CAP_SYS_ADMIN,21)
        for role in ROLE_CAPABILITY_LIMITS:
            self.assertEqual(ROLE_CAPABILITY_LIMITS[role]&(1<<CAP_SYS_ADMIN),0)
            for field in ('caps','pre_exec_caps'):
                for position in range(5):
                    c,_=contract();c.policy['roles'][role][field][position]=1<<CAP_SYS_ADMIN
                    c.policy_bytes=canonical(c.policy)
                    with self.subTest(role=role,field=field,position=position),self.assertRaisesRegex(ExecutionDenied,'PERMISSIVE|EXCESSIVE'):
                        c.verify()
    def test_sys_ptrace_only_for_fixed_cross_identity_metadata(self):
        for role in ROLE_CAPABILITY_LIMITS:
            self.assertEqual(bool(ROLE_CAPABILITY_LIMITS[role]&(1<<19)),role in ('guardian','observer'))


class InheritedPolicies(unittest.TestCase):
    def test_legitimate_socket_and_exec_operations_survive_all_ancestors(self):
        emulator=prior.PolicyStaticFixtures()
        # Kernel seccomp precedence is the intersection of every ancestor.
        # LSM BASE remains; role-specific IP denial is separate, not removed.
        paths={'worker':('supervisor','guardian','worker'),'peer':('supervisor','guardian','peer'),
               'read-command':('supervisor','observer','read-command'),
               'guardian-command':('supervisor','guardian','guardian-command')}
        for role,path in paths.items():
            for syscall,domain,protocol in ((322,0,0),(0,0,0),(1,0,0),(262,0,0)):
                self.assertTrue(all(emulator.run_filter(r,syscall,domain,protocol)==ALLOW for r in path),(role,syscall))
            if role in ('worker','peer'):
                for domain in (2,10):self.assertTrue(all(emulator.run_filter(r,41,domain,0)==ALLOW for r in path))
            else:
                self.assertEqual(emulator.run_filter(role,41,2,0),DENY)
                self.assertTrue(all(emulator.run_filter(r,41,16,12)==ALLOW for r in path))
    def test_every_inherited_policy_denies_memory_descriptor_and_namespace_bypasses(self):
        emulator=prior.PolicyStaticFixtures()
        for role in ('supervisor','guardian','observer','worker','peer','read-command','guardian-command','controller'):
            for syscall in (101,165,272,308,310,311,312,321,425,438):
                self.assertEqual(emulator.run_filter(role,syscall),DENY,(role,syscall))
        for role in ('supervisor','guardian','observer','worker','peer','read-command','guardian-command','controller'):
            for flag in (0x20000,0x2000000,0x4000000,0x8000000,0x10000000,0x20000000,0x40000000):
                self.assertEqual(emulator.run_filter(role,56,flag,0),DENY,(role,flag))
            self.assertEqual(emulator.run_filter(role,56,17,0),ALLOW)
            self.assertEqual(emulator.run_filter(role,435),ALLOW if role in ('supervisor','guardian','observer') else DENY)


class RealReaderInspector(unittest.TestCase):
    def setUp(self):
        self.temp=tempfile.TemporaryDirectory(prefix='probe-a-policy-fixture-');self.root=Path(self.temp.name)
        (self.root/'attr').mkdir();(self.root/'attr/current').write_text('probe-a-base//&probe-a-guardian (enforce)\n')
        (self.root/'status').write_text('Seccomp:\t2\nNoNewPrivs:\t1\n')
        self.fd=os.open(self.root,os.O_RDONLY|os.O_DIRECTORY)
        self.binding=SimpleNamespace(procfd=self.fd,identity=ROOT,verify=lambda:True,close=lambda:None)
        self.inspector=NativePolicyAdapter(CONTEXT,profiles={'guardian':'probe-a-guardian'},source_mount='/fixed',backend='iptables-nft',policy_identity='d'*64,
            verify_policy_package=lambda _:True,grant=SimpleNamespace(active=lambda **k:True),activated=True)
    def tearDown(self):os.close(self.fd);self.temp.cleanup()
    def inspect(self):
        # Only unavoidable identity/root/kernel boundaries are substituted.
        with patch('probe_a_native_policy.os.geteuid',return_value=0),patch('probe_a_native_policy.platform.machine',return_value='x86_64'),patch('probe_a_linux_identity.ProcessBinding',return_value=self.binding):
            return self.inspector.inspect_actor('guardian',ROOT,CONTEXT.identifier,b'policy')
    def test_valid_actual_reader_and_inspector_contract(self):self.assertTrue(self.inspect())
    def test_wrong_label_missing_nnp_duplicate_status_and_bad_package(self):
        for text in ('Seccomp: 2\n','Seccomp: 2\nSeccomp: 2\nNoNewPrivs: 1\n','Seccomp: broken\nNoNewPrivs: 1\n'):
            (self.root/'status').write_text(text)
            with self.assertRaisesRegex(SessionDenied,'MALFORMED|NOT_ENFORCING'):self.inspect()
        (self.root/'status').write_text('Seccomp: 2\nNoNewPrivs: 1\n');(self.root/'attr/current').write_text('unconfined\n')
        with self.assertRaisesRegex(SessionDenied,'NOT_ENFORCING'):self.inspect()
        self.inspector.verify_package=lambda _:False
        with self.assertRaisesRegex(SessionDenied,'RUNNER_PACKAGE_UNSUPPORTED'):self.inspect()
    def test_stale_identity_symlink_path_and_oversized_attribute(self):
        self.binding.identity=replace(ROOT,starttime=101)
        with self.assertRaisesRegex(SessionDenied,'STALE_PROCESS'):self.inspect()
        self.binding.identity=ROOT;(self.root/'attr/current').write_text('x'*4097)
        with self.assertRaisesRegex(IdentityDenied,'UNBOUNDED'):self.inspect()
        (self.root/'attr/current').unlink();(self.root/'attr/current').symlink_to(self.root/'status')
        with self.assertRaises(OSError):self.inspect()
    def test_fixed_catalogs_do_not_enable_arbitrary_path_reads(self):
        for name in ('attr/current','../status','environ','cmdline','mem'):
            with self.assertRaisesRegex(IdentityDenied,'RESOURCE_NOT_ALLOWLISTED'):read_at(self.fd,name)
        with self.assertRaisesRegex(IdentityDenied,'RESOURCE_NOT_ALLOWLISTED'):read_process_attribute(self.binding,'exec')
        with self.assertRaisesRegex(IdentityDenied,'RESOURCE_NOT_ALLOWLISTED'):read_network_table(self.fd,'udp')
    def test_cgroup_and_network_readers_return_text(self):
        for name,data in (('cgroup.type','domain\n'),('cgroup.subtree_control',''),('cgroup','0::/owned\n'),('tcp','header\n')):
            (self.root/name).write_text(data)
            self.assertEqual(read_network_table(self.fd,name) if name=='tcp' else read_at(self.fd,name),data)


class GuardianAuditHandoff(unittest.TestCase):
    def test_sealed_channels_and_observer_identity_roundtrip(self):
        g=replace(config('guardian'),descriptors=config('guardian').descriptors+(('observer-audit',30),),peers=(('observer',IDENTITIES['observer']),))
        o=replace(config('observer'),descriptors=config('observer').descriptors+(('guardian-audit',31),))
        for c in (g,o):self.assertEqual(RoleConfiguration.from_bytes(c.encode()),c)
        with self.assertRaisesRegex(SessionDenied,'OBSERVER_HANDOFF'):replace(g,peers=())
    def test_authenticated_release_supplies_later_guardian_without_ready_deadlock(self):
        o=replace(config('observer'),descriptors=config('observer').descriptors+(('guardian-audit',31),))
        c=coordinator();c.actors['observer'].config=o
        for role in IDENTITIES:
            cfg=c.actors[role].config
            from probe_a_coordinator import readiness_message
            for seq,state in enumerate(('STARTING','IDENTITY_VERIFIED','READY'),1):c.accept(role,readiness_message(cfg,state,seq))
        c.release_work();raw=c.actors['observer'].channel.send_bytes.call_args.args[0]
        transport=SimpleNamespace(recv_bytes=lambda *a,**k:raw,send_bytes=lambda *a,**k:None)
        startup=RoleStartup(o,transport,clock=lambda:0);startup.sequence=3;startup.wait_for_release()
        self.assertEqual(startup.actors['guardian'],IDENTITIES['guardian']);self.assertEqual(startup.sequence,3)
        # RUNNING is emitted by the real service after dispatcher construction.
    def test_guardian_server_purpose_cannot_borrow_commands_or_other_resources(self):
        from probe_a_exec_adapter import Reply
        calls=[]
        b=ReadOnlyBroker(CONTEXT.plan,command=lambda *a:calls.append('command'),read_resource=lambda key,end:calls.append((key,end)) or True,
            observer_identity=IDENTITIES['observer'],inventory_id=CONTEXT.inventory,end=240,clock=lambda:210,purpose='guardian-uid-audit')
        response=b.handle(canonical({'v':1,'seq':1,'op':'resource:numeric_uid_process_absent'}))
        self.assertIn(b'UNVERIFIED_NOT_PROBE_PASS',response);self.assertEqual(calls,[('numeric_uid_process_absent',218)])
        for op in ('read:0','resource:temporary_files_absent','resource:numeric_uid_process_absent'):
            with self.assertRaisesRegex(BrokerDenied,'CATALOG_ONLY|REPLAY'):b.handle(canonical({'v':1,'seq':1,'op':op}))
        b.clock=lambda:240
        with self.assertRaisesRegex(BrokerDenied,'DEADLINE'):b.handle(canonical({'v':1,'seq':2,'op':'resource:numeric_uid_process_absent'}))


class PackageAndTraceBoundaries(unittest.TestCase):
    def test_native_entry_and_trace_defaults_do_not_load_or_execute(self):
        with self.assertRaisesRegex(SessionDenied,'NATIVE_ENTRY_DISABLED'):run_native_role('guardian')
        loader=NativeTraceLoader(CONTEXT,Mock(),reader=Mock(),clock=lambda:0)
        with self.assertRaisesRegex(SessionDenied,'PROVISIONING_REQUIRED'):loader.attach('/fixed','a'*64,{},b'',verify=lambda *a:True)
        self.assertIsNone(loader.object);self.assertEqual(loader.links,[])
    def test_unsealed_package_is_not_authority(self):
        with tempfile.TemporaryFile() as f:
            f.write(b'{}');f.flush()
            with self.assertRaisesRegex(SessionDenied,'SEALED_READONLY_ROOT_PACKAGE'):read_package(f.fileno())
    def test_owned_descriptor_disposal_does_not_close_reused_slot_even_same_inode(self):
        # F_DUPFD_QUERY is the actual unprivileged open-description operation,
        # not a privileged process metadata or capability experiment.
        with tempfile.NamedTemporaryFile() as f:
            fd=os.open(f.name,os.O_RDONLY);owner=DescriptorOwner();owner.acquire(fd)
            os.close(fd);replacement=os.open(f.name,os.O_RDONLY)
            self.assertEqual(fd,replacement)
            with self.assertRaisesRegex(SessionDenied,'DISPOSAL_UNCERTAIN'):owner.close()
            owner.close()
            self.assertEqual(os.fstat(replacement).st_ino,os.fstat(f.fileno()).st_ino);os.close(replacement)
    def test_trace_truncation_duplicate_loss_incarnation_and_interval_fail_closed(self):
        decoder=TraceDecoder(begin_ns=10,end_ns=100,incarnations_ns={50:200})
        def event(seq=1,stamp=20,start=200):return EVENT.pack(seq,stamp,50<<32|50,start,1,1,7,0)
        decoder.consume(event());self.assertEqual(len(decoder.events),1)
        for raw in (event(),event(seq=3),event(seq=2,start=201),event(seq=2,stamp=100),event(seq=2)[:-1]):
            with self.assertRaisesRegex(SessionDenied,'TRACE_'):decoder.consume(raw)
        package=decoder.finish(kernel_lost_events=1)
        self.assertTrue(package['defects']);self.assertIn('BLOCKED',package['result']);self.assertTrue(package['missing'])
    def test_valid_syscall_events_are_still_incomplete_case_measurements(self):
        d=TraceDecoder(begin_ns=10,end_ns=100,incarnations_ns={50:200})
        d.consume(EVENT.pack(1,20,50<<32|50,200,1,2,0,-13))
        self.assertIn('BLOCKED',d.finish(kernel_lost_events=0)['result'])

class AdditionalReviewRegressions(unittest.TestCase):
    def test_failed_acquisition_closes_new_handle_and_ledger_finally(self):
        from probe_a_native_package import NativePackageLoader
        owner=DescriptorOwner(query=lambda *a:0)
        opened=[]
        with tempfile.NamedTemporaryFile() as f:
            def open_one():
                fd=os.open(f.name,os.O_RDONLY);opened.append(fd);return fd
            with self.assertRaisesRegex(SessionDenied,'OFD_QUERY'):owner.open(open_one)
            with self.assertRaises(OSError):os.fstat(opened[0])
        loader=NativePackageLoader.__new__(NativePackageLoader)
        loader.owned=Mock();loader.owned.close.side_effect=SessionDenied('uncertain')
        loader.ledger=Mock();ledger=loader.ledger
        with self.assertRaises(SessionDenied):loader.close()
        ledger.close.assert_called_once();self.assertIsNone(loader.ledger)
    def test_wrong_guard_is_rejected_before_callback(self):
        from probe_a_native_package import NativePackageLoader
        loader=NativePackageLoader.__new__(NativePackageLoader);loader.guard=Mock()
        with self.assertRaisesRegex(SessionDenied,'EXACT_NATIVE_GUARD'):loader._build(config())
        loader.guard.call.assert_not_called()
    def test_verified_exec_fd_rejects_substitution_before_open(self):
        fixture=prior.NativeAssetFixtures();fixture.setUp()
        try:
            fd=fixture.reader.open_verified_fd(fixture.path)
            try:self.assertEqual(os.pread(fd,64,0),b'fixture')
            finally:os.close(fd)
            original=fixture.reader.read_asset
            def replace_after_read(path):
                raw=original(path);replacement=path+'.replacement'
                Path(replacement).write_bytes(raw);os.chmod(replacement,0o400);os.replace(replacement,path)
                return raw
            fixture.reader.read_asset=replace_after_read
            with self.assertRaisesRegex(InventoryDenied,'METADATA_SUBSTITUTION'):fixture.reader.open_verified_fd(fixture.path)
        finally:fixture.tearDown()
    def test_installed_raw_policy_and_mount_inspection_reject_nested_or_escaped(self):
        import io
        raw=b'compiled-policy-fixture';digest=hashlib.sha256(raw).hexdigest()
        profiles={'guardian':'probe-a-guardian'}
        record={'identity':'d'*64,'raw_profiles':{name:{'path':'/sys/kernel/security/apparmor/policy/profiles/'+name+'.1/raw_data','sha256':digest} for name in ('probe-a-base','probe-a-guardian')},'source_mount_id':42}
        inspector=InstalledPolicyInspector(record,reader=SimpleNamespace(read_asset=lambda path:raw),profiles=profiles,source_mount='/approved/source')
        def inspect(text):
            with tempfile.TemporaryFile() as f:
                f.write(text.encode('ascii'));f.seek(0)
                with patch('probe_a_native_policy.os.open',side_effect=lambda *a,**k:os.dup(f.fileno())):return inspector('d'*64)
        mount='42 1 0:1 / /approved/source ro,nosuid,nodev - ext4 /dev/fixture ro\n'
        self.assertTrue(inspect(mount))
        for extra in ('43 42 0:2 / /approved/source/lib rw - tmpfs tmpfs rw\n','43 42 0:2 / /approved/source/lib\\040bad rw - tmpfs tmpfs rw\n'):
            with self.assertRaisesRegex(SessionDenied,'DESCENDANT|ESCAPED'):inspect(mount+extra)
        record['raw_profiles']['probe-a-base']['sha256']='e'*64
        with self.assertRaisesRegex(SessionDenied,'CONTENT_DRIFT'):inspect(mount)
    def test_uid_observation_accepts_kernel_thread_without_executable_and_rejects_stale(self):
        from probe_a_linux_identity import observe_numeric_uids
        with tempfile.TemporaryDirectory(prefix='probe-a-proc-fixture-') as directory:
            root=Path(directory);(root/'2').mkdir()
            # No exe. comm contains parentheses; starttime is stat field22.
            (root/'2/stat').write_text('2 (kernel (thread)) S '+' '.join(['0']*18+['123'])+'\n')
            (root/'2/status').write_text('Uid: 0 0 0 0\n')
            fd=os.open(root,os.O_RDONLY|os.O_DIRECTORY)
            try:
                with patch('probe_a_linux_identity.os.pidfd_open',side_effect=lambda *a:os.dup(fd)),patch('probe_a_linux_identity.select.select',return_value=([],[],[])):
                    self.assertEqual(observe_numeric_uids(fd,'2'),(2,123,(0,0,0,0)))
                    (root/'2/status').write_text('Uid: 0 0 0 0\nUid: 0 0 0 0\n')
                    with self.assertRaisesRegex(IdentityDenied,'MALFORMED'):observe_numeric_uids(fd,'2')
                    (root/'2/status').write_text('Uid: 0 0 0 0\n')
                    with patch('probe_a_linux_identity.select.select',return_value=([fd],[],[])):
                        with self.assertRaisesRegex(IdentityDenied,'INCARNATION'):observe_numeric_uids(fd,'2')
            finally:os.close(fd)
    def test_nested_guard_restores_enclosing_budget_after_failure(self):
        from probe_a_native_deadline import NativeDeadlineGuard
        guard=NativeDeadlineGuard.__new__(NativeDeadlineGuard);guard.context=CONTEXT;guard.deadlines=[]
        guard.lib=SimpleNamespace(probe_a_guard_arm=Mock(return_value=0))
        def inner():raise SessionDenied('failure')
        def outer():
            with self.assertRaises(SessionDenied):guard.call(inner,deadline=15)
        with patch('probe_a_native_deadline.time.monotonic',return_value=0):guard.call(outer,deadline=8)
        self.assertEqual([call.args[0] for call in guard.lib.probe_a_guard_arm.call_args_list],[8,8,8,240]);self.assertEqual(guard.deadlines,[])
    def test_native_credential_plan_and_full_worker_drop_vectors(self):
        from probe_a_native_credentials import role_mask
        from probe_a_execution_contract import WORKER_BOOTSTRAP_LIMIT
        from probe_a_workload import exact_argv
        c,_=contract()
        for role in ROLE_CAPABILITY_LIMITS:
            c.policy['roles'][role]['pre_exec_caps']=[WORKER_BOOTSTRAP_LIMIT if role=='worker' else ROLE_CAPABILITY_LIMITS[role]]*5
            self.assertEqual(role_mask(role,c.policy),c.policy['roles'][role]['pre_exec_caps'][0])
            c.policy['roles'][role]['pre_exec_caps'][3]|=1<<CAP_SYS_ADMIN
            with self.assertRaisesRegex(SessionDenied,'UNSUPPORTED'):role_mask(role,c.policy)
        argv=exact_argv(CONTEXT.plan,'approved-udp')
        for flag in ('--bounding-set=-all','--inh-caps=-all','--ambient-caps=-all'):self.assertIn(flag,argv)
    def test_native_credential_installation_order_and_failure_with_only_kernel_ops_substituted(self):
        from probe_a_native_credentials import NativeRoleCredentials
        c,_=contract();mask=ROLE_CAPABILITY_LIMITS['guardian'];c.policy['roles']['guardian']['pre_exec_caps']=[mask]*5
        ops=NativeRoleCredentials();events=[]
        ops.thread_count=lambda:1;ops.last_capability=lambda:21;ops.no_new_privs=lambda:True;ops.clear_ambient=lambda:True
        ops.bounding_member=lambda cap:True
        ops.drop_bounding=lambda cap:events.append(('drop',cap)) or True
        ops._prctl=lambda *args:events.append(('prctl',args)) or 0
        ops.set_process_sets=lambda value:events.append(('sets',value)) or True
        with patch('probe_a_native_credentials.os.geteuid',return_value=0),patch('probe_a_native_credentials.os.getgroups',return_value=[]),patch('probe_a_native_credentials.os.setgroups',side_effect=lambda groups:events.append(('groups',groups))) as setgroups:
            self.assertTrue(ops.install('guardian',c.policy))
            self.assertIn(('drop',21),events);self.assertNotIn(('drop',19),events)
            self.assertLess(events.index(('drop',21)),events.index(('sets',mask)))
            setgroups.assert_not_called()
            ops.set_process_sets=lambda value:False
            with self.assertRaisesRegex(SessionDenied,'PROCESS_SETS'):ops.install('guardian',c.policy)
            ops.set_process_sets=lambda value:True
            c.policy['roles']['read-command']['pre_exec_caps']=[ROLE_CAPABILITY_LIMITS['read-command']]*5
            self.assertTrue(ops.install('read-command',c.policy));setgroups.assert_not_called()
            with patch('probe_a_native_credentials.os.getgroups',return_value=[1000]),patch('probe_a_native_credentials.os.setgroups',side_effect=PermissionError):
                with self.assertRaises(PermissionError):ops.install('read-command',c.policy)
    def test_trace_identity_units_are_explicit_and_reordered_delivery_is_blocked(self):
        with self.assertRaises(TypeError):TraceDecoder(begin_ns=10,end_ns=100,incarnations={50:200})
        with self.assertRaisesRegex(SessionDenied,'NANOSECOND'):TraceDecoder(begin_ns=10,end_ns=100,incarnations_ns={50:True})
        d=TraceDecoder(begin_ns=10,end_ns=100,incarnations_ns={50:200})
        with self.assertRaises(SessionDenied):d.consume(EVENT.pack(2,20,50<<32|50,200,1,1,7,0))
        self.assertTrue(d.finish(kernel_lost_events=0)['defects'])

class CloneGuardRegressions(unittest.TestCase):
    def test_live_syscall_backend_requires_guard_before_inventory_or_clone(self):
        from probe_a_linux_launcher import NativeAtomicSpawner,LaunchDenied
        inventory=Mock();spawner=NativeAtomicSpawner(inventory=inventory,clock=lambda:0)
        with patch('probe_a_linux_launcher.os.geteuid',return_value=0):
            with self.assertRaisesRegex(LaunchDenied,'CLONE_DEADLINE_GUARD_REQUIRED'):spawner.spawn(object(),deadline=8,activated=True)
        inventory.authorize_exec.assert_not_called()
    def test_explicit_clone_rearm_resets_inherited_python_deadline_stack(self):
        from probe_a_native_deadline import NativeDeadlineGuard
        guard=NativeDeadlineGuard.__new__(NativeDeadlineGuard);guard.context=CONTEXT;guard.deadlines=[8,3]
        guard.lib=SimpleNamespace(probe_a_guard_reinitialize_child=Mock(return_value=0),probe_a_guard_arm=Mock(return_value=0))
        guard.after_clone(8)
        guard.lib.probe_a_guard_reinitialize_child.assert_called_once_with(240)
        guard.lib.probe_a_guard_arm.assert_called_once_with(8);self.assertEqual(guard.deadlines,[8])
        guard.lib.probe_a_guard_reinitialize_child.return_value=-1
        with patch('probe_a_native_deadline.os._exit',side_effect=prior.Halt) as stop:
            with self.assertRaises(prior.Halt):guard.after_clone(8)
        stop.assert_called_once_with(76)

if __name__=='__main__':unittest.main()
