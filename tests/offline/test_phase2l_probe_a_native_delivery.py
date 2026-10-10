"""Synthetic remediation/native-source fixtures; no privileged native execution."""
from dataclasses import replace
from copy import deepcopy
import ctypes.util
import hashlib
import os
from pathlib import Path
import sqlite3
import stat
import struct
import sys
import tempfile
import unittest
from unittest.mock import Mock, patch
from types import SimpleNamespace
sys.path.insert(0,str(Path(__file__).resolve().parents[2]/'docs/security/phase2l'))
from test_phase2l_probe_a_integration import (CONTEXT, ROOT, IDENTITIES, GROUPS, config, contract,
    PLAN, NSS)
import test_phase2l_probe_a_integration as integration
from probe_a_session import SessionDenied, canonical
from probe_a_linux_launcher import TrustedActorBootstrap, NativeAtomicSpawner, NativeBoundedCapture, command_catalog
from probe_a_readonly_broker import NativeReadCommands
from probe_a_execution_contract import CleanupAuditAuthority, ExecutionDenied
from probe_a_evidence import EvidenceComposer, IndependentEvidenceAudit, POST, FACTS, EvidenceDenied
from probe_a_native_ledger import DurableAttemptLedger, ExistingAttemptGrant
from probe_a_native_inventory import NativeAssetReader, elf_loading
from probe_a_native_verifier import OpenSSLEd25519
from probe_a_native_evidence import UnsignedObservationJournal, SignedJournalCollector, validate_network_measurement, counters
from probe_a_native_policy import socket_filter, ALLOW, DENY, KILL
from probe_a_ipc import BoundedSocketIPC, IncrementalRequest, IpcDeadline

class Halt(BaseException): pass


class OuterRootBoundaryTests(unittest.TestCase):
    def bootstrap(self):
        b=TrustedActorBootstrap.__new__(TrustedActorBootstrap)
        b.used=False;b.end=240;b.cutoff=180;b.clock=lambda:0;b.spawner=NativeAtomicSpawner(syscalls=Mock())
        return b
    def test_missing_wrong_factory_deadline_constructor_and_property_are_fail_stop(self):
        class Broken:
            @property
            def context(self): raise KeyboardInterrupt
        factories=(None,object(),Broken(),SimpleNamespace(context=replace(CONTEXT,end=241,cutoff=181)),
                   SimpleNamespace(context=CONTEXT))
        for factory in factories:
            b=self.bootstrap();permit=integration.permit()
            with self.subTest(factory=type(factory).__name__),patch('probe_a_linux_launcher.os.geteuid',return_value=0), \
                 patch('probe_a_linux_launcher.os._exit',side_effect=Halt) as stop:
                with self.assertRaises(Halt):b.launch_integrated(factory=factory,permit=permit,activated=True)
                self.assertTrue(b.used);self.assertTrue(permit.used);stop.assert_called_with(76)
    def test_disabled_and_unprivileged_calls_are_harmless(self):
        for activated,uid in ((False,0),(True,1000)):
            b=self.bootstrap()
            with patch('probe_a_linux_launcher.os.geteuid',return_value=uid),patch('probe_a_linux_launcher.os._exit') as stop:
                with self.assertRaises(Exception):b.launch_integrated(activated=activated)
                stop.assert_not_called();self.assertFalse(b.used)
    def test_consumed_root_attempt_cannot_return(self):
        b=self.bootstrap();b.used=True
        with patch('probe_a_linux_launcher.os.geteuid',return_value=0),patch('probe_a_linux_launcher.os._exit',side_effect=Halt):
            with self.assertRaises(Halt):b.launch_integrated(activated=True)


class CleanupAuditRouteTests(unittest.TestCase):
    def route(self, now, audit):
        c,_=contract();c.clock=lambda:now;c.permit.clock=lambda:now
        spec=SimpleNamespace(role='read-command',argv=('/usr/sbin/iptables-save','-t','filter'),
                             group=c.scopes.groups['read-command'],validate=Mock())
        spec.group.fd=77;spec.group.verify=Mock(return_value=True)
        syscalls=Mock();syscalls.clone_into.side_effect=Halt
        inv=c.inventory;inv.verify.return_value=True;inv.authorize_exec.return_value=True
        spawner=NativeAtomicSpawner(inventory=inv,contract=c,syscalls=syscalls,clock=lambda:now)
        capture=NativeBoundedCapture({spec.argv:spec},spawner=spawner,plan=PLAN,activated=True,clock=lambda:now)
        command=NativeReadCommands(PLAN,capture=capture,inventory=inv)
        if audit:
            peer=Mock(identity=ROOT);peer.verify.return_value=True
            command=command.for_audit(config('observer'),peer)
        return command,syscalls,c
    def test_actual_command_capture_spawn_contract_route_crosses_cutoff_only_for_audit(self):
        for now in (179,180,210,239):
            for audit in (False,True):
                command,kernel,_=self.route(now,audit)
                with self.subTest(now=now,audit=audit),patch('probe_a_linux_launcher.os.geteuid',return_value=0), \
                     patch('probe_a_linux_launcher.os.listdir',return_value=['100']):
                    if audit or now<180:
                        with self.assertRaises(Halt):command(('/usr/sbin/iptables-save','-t','filter'),min(240,now+1))
                        kernel.clone_into.assert_called_once()
                    else:
                        with self.assertRaises(ExecutionDenied):command(('/usr/sbin/iptables-save','-t','filter'),now+1)
                        kernel.clone_into.assert_not_called()
    def test_final_deadline_wrong_authority_worker_and_argv_remain_blocked(self):
        command,kernel,c=self.route(240,True)
        with self.assertRaises(Exception):command(('/usr/sbin/iptables-save','-t','filter'),240)
        kernel.clone_into.assert_not_called()
        for authority in (object(),c.audit_authority):
            with self.assertRaises(ExecutionDenied):c.before_spawn(SimpleNamespace(role='worker'),240,audit_authority=authority)
        command,kernel,c=self.route(210,True)
        with self.assertRaises(Exception):command(('/bin/sh','-c','true'),211)
        c.audit_authority.peer.verify.return_value=False
        with self.assertRaises(ExecutionDenied):c.before_spawn(next(iter(command.capture.specs.values())),211,audit_authority=c.audit_authority)
    def test_controller_partial_header_does_not_block_audit_turn_and_expires(self):
        clock=[0];stream=Mock();stream.recv.side_effect=[b'\0',b'\0\0\3',b'abc']
        channel=BoundedSocketIPC(stream,clock=lambda:clock[0],select_fn=lambda *a:([stream],[],[]))
        frame=IncrementalRequest(channel,end=180)
        self.assertIsNone(frame.receive_available());self.assertIsNone(frame.receive_available())
        self.assertEqual(frame.receive_available(),b'abc')
        stream.recv.return_value=b'\0';stream.recv.side_effect=None
        self.assertIsNone(frame.receive_available());clock[0]=1
        with self.assertRaises(IpcDeadline):frame.receive_available()


class FailedWorkEvidenceTests(unittest.TestCase):
    def test_missing_cases_do_not_suppress_valid_synthetic_cleanup(self):
        helper=integration.EvidenceTests();values=helper.values();composer=EvidenceComposer(CONTEXT,IDENTITIES,groups=GROUPS)
        # Valid baseline, missing active/work; cleanup independently progresses.
        initial=('plan-inventory','actor-identities','cgroup-membership','firewall-before')
        for n,fact in enumerate(initial+POST,1):composer.append(helper.record(fact,values[fact],n))
        composer.note_work('failed');package=composer.package()
        self.assertEqual(package.work,'failed');self.assertEqual(package.cleanup,'verified')
        self.assertTrue(package.missing);self.assertEqual(package.provenance,'SYNTHETIC_TEST')
        self.assertIn('BLOCKED',package.result)
        with self.assertRaises(EvidenceDenied):composer.note_work('completed')
    def test_collector_failure_attempts_every_available_cleanup_fact_and_keeps_partial_package(self):
        helper=integration.EvidenceTests();values=helper.values();composer=EvidenceComposer(CONTEXT,IDENTITIES,groups=GROUPS)
        calls=[];seq=[0]
        def collect(fact,context):
            calls.append(fact)
            if fact not in values:raise LookupError('work unavailable')
            if fact=='firewall-active':raise LookupError('not set up')
            seq[0]+=1
            return helper.record(fact,values[fact],seq[0]),None
        audit=IndependentEvidenceAudit(composer,collect=collect)
        with self.assertRaises(EvidenceDenied):audit.observe_after()
        package=audit.after_observer_shutdown()
        self.assertTrue(all(fact in calls for fact in POST));self.assertTrue(package.defects)
        self.assertIn('owned-cleanup',composer.receipts);self.assertIn('BLOCKED',package.result)
    def test_forged_authority_is_not_rehabilitated_by_later_cleanup(self):
        helper=integration.EvidenceTests();composer=EvidenceComposer(CONTEXT,IDENTITIES,groups=GROUPS)
        with self.assertRaises(EvidenceDenied):composer.append(helper.record('plan-inventory',False))
        with self.assertRaises(EvidenceDenied):composer.append(helper.record('workers-peer-stopped',True))
        self.assertTrue(composer.package().defects)


class LedgerFixtures(unittest.TestCase):
    def setUp(self):
        self.temp=tempfile.TemporaryDirectory(prefix='probe-a-ledger-');os.chmod(self.temp.name,0o700)
        self.store=DurableAttemptLedger(self.temp.name,synthetic=True);self.store.initialize_fixture()
        self.record={'session':'a'*32,'boot':'synthetic','context':CONTEXT.identifier,'purpose':'SYNTHETIC_TEST'}
    def tearDown(self):self.store.close();self.temp.cleanup()
    def test_committed_claim_restart_and_replay(self):
        import time
        self.assertTrue(self.store.claim_record(self.record,deadline=time.monotonic()+1))
        self.store.close();self.store=DurableAttemptLedger(self.temp.name,synthetic=True)
        self.assertTrue(self.store.committed(self.record,deadline=time.monotonic()+1,native=False))
        self.assertFalse(self.store.claim_record(self.record,deadline=time.monotonic()+1))
        with self.assertRaises(SessionDenied):self.store.committed(self.record,deadline=time.monotonic()+1)
    def test_lost_acknowledgement_cannot_grant_twice(self):
        import time
        with patch('probe_a_native_ledger.os.fsync',side_effect=OSError('uncertain sync')):
            with self.assertRaises(OSError):self.store.claim_record(self.record,deadline=time.monotonic()+1)
        self.store.close();self.store=DurableAttemptLedger(self.temp.name,synthetic=True)
        self.assertFalse(self.store.claim_record(self.record,deadline=time.monotonic()+1))
    def test_competing_connections_produce_one_claim(self):
        import time
        other=DurableAttemptLedger(self.temp.name,synthetic=True)
        try:
            self.assertTrue(self.store.claim_record(self.record,deadline=time.monotonic()+1))
            self.assertFalse(other.claim_record(self.record,deadline=time.monotonic()+1))
        finally:other.close()
    def test_contention_and_corruption_fail_closed(self):
        import time
        db=sqlite3.connect(self.temp.name+'/attempts.sqlite',isolation_level=None);db.execute('BEGIN IMMEDIATE')
        try:
            with self.assertRaises(sqlite3.OperationalError):self.store.claim_record(self.record,deadline=time.monotonic()+.05)
            self.assertTrue(self.store.poisoned)
        finally:db.execute('ROLLBACK');db.close()
    def test_cross_exec_substitution_and_synthetic_storage_rejected(self):
        import time
        r={'v':2,'session':CONTEXT.session,'context':CONTEXT.identifier,'inventory':CONTEXT.inventory,
           'source':CONTEXT.source_commit,'policy':'d'*64,'boot':'synthetic','purpose':'one-probe-a-attempt','cutoff':180,'expires':240}
        grant=ExistingAttemptGrant(CONTEXT,r,b'fixture',verify=lambda *a:True,ledger=self.store,
            boot_identity=lambda:'synthetic',policy_digest='d'*64,clock=lambda:0)
        self.assertTrue(grant.validate_approval())
        with self.assertRaises(SessionDenied):grant.active()
        for field,value in (('source','e'*40),('policy','e'*64),('boot','old'),('cutoff',181),('session','e'*32)):
            grant.record=dict(r,**{field:value});self.assertFalse(grant.validate_approval())


class NativeAssetFixtures(unittest.TestCase):
    def setUp(self):
        self.temp=tempfile.TemporaryDirectory(prefix='probe-a-assets-');self.path=self.temp.name+'/binary'
        Path(self.path).write_bytes(b'fixture');os.chmod(self.path,0o400)
        self.reader=NativeAssetReader({},deadline=999999999,fixture_uid=os.geteuid())
        _,metadata=self.reader.collect(self.path);self.reader.expected[self.path]=metadata
    def tearDown(self):self.temp.cleanup()
    def test_descriptor_bound_bytes_and_ordinary_parent_identity(self):
        self.assertEqual(self.reader.read_asset(self.path),b'fixture')
        expected=self.reader.expected[self.path];expected['parents'][-1]['inode']+=1
        with self.assertRaises(Exception):self.reader.read_asset(self.path)
    def test_same_bytes_different_inode_symlink_and_writable_asset_rejected(self):
        os.unlink(self.path);Path(self.path).write_bytes(b'fixture');os.chmod(self.path,0o400)
        with self.assertRaises(Exception):self.reader.read_asset(self.path)
        os.unlink(self.path);os.symlink('/etc/passwd',self.path)
        with self.assertRaises(Exception):self.reader.collect(self.path)
    def test_writable_or_oversize_and_deadline_rejected(self):
        os.chmod(self.path,0o666)
        with self.assertRaises(Exception):self.reader.collect(self.path)
        self.reader.deadline=0
        with self.assertRaises(Exception):self.reader.collect(self.path)
    def test_elf_bounded_parser_rejects_truncation_and_untrusted_rpath(self):
        for raw in (b'',b'\x7fELF'+b'\0'*100,b'\x7fELF\x02\x01'+b'\0'*100):
            with self.assertRaises(Exception):elf_loading(raw)
    def test_existing_interpreter_metadata_without_execution(self):
        # Ordinary nonprivileged file read of the existing interpreter, not a
        # candidate runtime manifest or assertion of runner compatibility.
        result=elf_loading(Path(os.path.realpath(sys.executable)).read_bytes())
        self.assertIn('libc.so.6',result['needed'])


class VettedVerifierVectors(unittest.TestCase):
    def test_rfc8032_ed25519_test_vector_one_and_wrong_message_signature_domain(self):
        # RFC8032 section7.1, public key/signature for the empty test message.
        public=bytes.fromhex('d75a980182b10ab7d54bfed3c964073a0ee172f3daa62325af021a68f707511a')
        signature=bytes.fromhex('e5564300c360ac729086e2cc806e828a84877f1eb8e5d974d873e06522490155'
                                '5fb8821590a33bacc61e39701cf9b46bd25bf5f0595bbe24655141438e7a100b')
        library=Path('/usr/lib/x86_64-linux-gnu/libcrypto.so.3')
        if not library.is_file():self.fail('Existing vetted OpenSSL3 library unavailable; no package install permitted')
        fd=os.open(library,os.O_RDONLY|os.O_CLOEXEC)
        try:
            info=os.fstat(fd)
            # Cloud image files are uid65534; root ownership here is an
            # explicit synthetic filesystem boundary, NOT native acceptance.
            observed=SimpleNamespace(st_mode=info.st_mode,st_uid=0,st_dev=info.st_dev,st_ino=info.st_ino)
            with patch('probe_a_native_verifier.os.fstat',return_value=observed):
                verifier=OpenSSLEd25519(fd,library_identity=(info.st_dev,info.st_ino),public_key=public,domains=(b'ProbeA inventory v2\0',))
            self.assertTrue(verifier.verify_raw(b'',signature));self.assertFalse(verifier.verify_raw(b'changed',signature))
            self.assertFalse(verifier.verify_raw(b'',b'\0'*64));self.assertFalse(verifier(b'',signature))
            self.assertFalse(verifier(b'ProbeA activation v2\0',signature))
        finally:os.close(fd)


class JournalFixtures(unittest.TestCase):
    def test_partial_crash_prefix_and_unsigned_cannot_become_runtime_authority(self):
        with tempfile.TemporaryDirectory(prefix='probe-a-journal-') as temp:
            fd=os.open(temp+'/journal',os.O_RDWR|os.O_CREAT|os.O_EXCL|os.O_APPEND|os.O_CLOEXEC,0o600)
            try:
                journal=UnsignedObservationJournal(fd,CONTEXT,writable=True,clock=lambda:10)
                record={'context':CONTEXT.identifier,'fact':'plan-inventory','provenance':'SYNTHETIC_TEST'}
                journal.append(record);prefix=journal.read_prefix();self.assertEqual(len(prefix['records']),1)
                with self.assertRaises(SessionDenied):SignedJournalCollector(journal,{})('plan-inventory',CONTEXT.identifier)
                os.write(fd,b'\0\0');prefix=journal.read_prefix();self.assertTrue(prefix['uncertain'])
                self.assertEqual(len(prefix['records']),1);self.assertIn('BLOCKED',prefix['result'])
            finally:os.close(fd)


class PolicyStaticFixtures(unittest.TestCase):
    def run_filter(self,role,nr,domain=0,protocol=0,arch=0xc000003e):
        data={0:nr,4:arch,16:domain,32:protocol};code=socket_filter(role);pc=0;value=0
        while pc<len(code):
            operation,yes,no,k=code[pc]
            if operation==0x20:value=data[k]
            elif operation==0x15:pc+=yes if value==k else no
            elif operation==0x45:pc+=yes if value&k else no
            elif operation==0x06:return k
            else:self.fail('Unexpected BPF instruction')
            pc+=1
        self.fail('Missing BPF disposition')
    def test_root_direct_and_delegated_egress_denied_netfilter_only(self):
        for role in ('guardian','observer','read-command','guardian-command','supervisor'):
            for domain,protocol in ((1,0),(2,0),(10,0),(17,0),(16,0),(16,16)):
                self.assertEqual(self.run_filter(role,41,domain,protocol),DENY)
            self.assertEqual(self.run_filter(role,41,16,12),ALLOW)
            self.assertEqual(self.run_filter(role,53),DENY)
    def test_wrong_arch_x32_kernel_bypass_mechanisms_denied(self):
        self.assertEqual(self.run_filter('guardian',41,arch=0),KILL)
        self.assertEqual(self.run_filter('guardian',0x40000029),KILL)
        for nr in (101,165,272,308,321,425):self.assertEqual(self.run_filter('guardian',nr),DENY)


class AdditionalNativeRegressions(unittest.TestCase):
    def test_real_simultaneous_fixture_claims_have_one_winner(self):
        from concurrent.futures import ThreadPoolExecutor
        import threading,time
        with tempfile.TemporaryDirectory(prefix='probe-a-ledger-race-') as temp:
            os.chmod(temp,0o700);one=DurableAttemptLedger(temp,synthetic=True);one.initialize_fixture()
            two=DurableAttemptLedger(temp,synthetic=True);barrier=threading.Barrier(2)
            record={'session':'f'*32,'boot':'synthetic','context':CONTEXT.identifier}
            def claim(store):
                barrier.wait(timeout=1);return store.claim_record(record,deadline=time.monotonic()+1)
            try:
                with ThreadPoolExecutor(max_workers=2) as pool:
                    results=list(pool.map(claim,(one,two)))
                self.assertEqual(sorted(results),[False,True])
            finally:one.close();two.close()
    def test_corrupt_fixture_storage_is_not_a_fresh_attempt(self):
        import time
        with tempfile.TemporaryDirectory(prefix='probe-a-ledger-corrupt-') as temp:
            os.chmod(temp,0o700);store=DurableAttemptLedger(temp,synthetic=True);store.initialize_fixture()
            try:
                Path(temp+'/attempts.sqlite').write_bytes(b'corrupt-storage')
                with self.assertRaises(sqlite3.DatabaseError):store.claim_record({'session':'a'*32,'boot':'fixture'},deadline=time.monotonic()+1)
                self.assertTrue(store.poisoned)
            finally:store.close()
    def test_structured_positive_dns_and_correlated_reject_semantics(self):
        from probe_a_dns import query
        worker=replace(ROOT,pid=900,starttime=901,uids=(PLAN.uid,)*4,gids=(PLAN.uid,)*4)
        def record(case):
            _,family,index=next(c for c in integration.CASES if c[0]==case)
            from probe_a_dns import targets
            endpoints={c:[a,p] for c,a,p in targets(PLAN.dns,'1.1.1.1')}
            return {'v':1,'case':case,'context':CONTEXT.identifier,'worker':[900,901],'group':'worker',
                'socket_cookie':5,'endpoint':endpoints[case],'interval':[1,2],'mechanism':'kernel-socket-and-netfilter-trace',
                'outcome':'firewall-rejected','observations':{'verdict':'NF_REJECT','hook':'LOCAL_OUT','errno':111,'cookie':5,'worker':[900,901]},
                'family':family,'rule_index':index,'rule_chain':PLAN.chain4}
        value=record('alternate-udp');self.assertTrue(validate_network_measurement('alternate-udp',value,CONTEXT,worker))
        for name,change in (('outcome','timeout'),('socket_cookie',True),('rule_index',True),('endpoint',['1.1.1.1',443])):
            bad=dict(value,**{name:change})
            with self.assertRaises(Exception):validate_network_measurement('alternate-udp',bad,CONTEXT,worker)
        value=record('approved-udp');request=query(6699);response=request[:2]+struct.pack('!H',0x8183)+request[4:]
        value.update(outcome='matched-transaction',observations={'request_hex':request.hex(),'response_hex':response.hex(),'txid':6699,'transport':'udp'})
        self.assertTrue(validate_network_measurement('approved-udp',value,CONTEXT,worker))
        value['observations']['txid']=6700
        with self.assertRaises(Exception):validate_network_measurement('approved-udp',value,CONTEXT,worker)
    def test_counter_boolean_shape_target_and_overflow_rejected(self):
        valid=[[0,0,'ACCEPT']]*3+[[0,0,'REJECT']];counters(valid,'ipv4')
        for value in ([[True,0,'REJECT']],[[0,-1,'REJECT']],[[2**64,0,'REJECT']],[[0,0,'ACCEPT']]):
            with self.assertRaises(SessionDenied):counters(value,'ipv6')
    def test_kernel_case_label_and_signed_cleanup_boolean_are_insufficient(self):
        helper=integration.EvidenceTests();composer=helper.complete()
        value=composer.receipts['case:approved-udp']['value']
        with self.assertRaises(Exception):composer._check('case:approved-udp',value,kind='INDEPENDENT_KERNEL')
        for fact in POST:
            if fact!='firewall-restored':
                with self.assertRaises(Exception):composer._check(fact,True,kind='INDEPENDENT_KERNEL')
    def test_separate_provisioning_and_native_entry_defaults_have_no_effect(self):
        from probe_a_native_scopes import provision_scopes,teardown_scopes
        from probe_a_native_deadline import NativeDeadlineGuard
        from probe_a_native_resources import NativeResourceCollector
        with patch('probe_a_native_scopes.os.mkdir') as mkdir:
            with self.assertRaises(SessionDenied):provision_scopes(CONTEXT,9,{},b'',verify=lambda *a:True)
            mkdir.assert_not_called()
        with patch('probe_a_native_scopes.os.rmdir') as remove:
            with self.assertRaises(SessionDenied):teardown_scopes(CONTEXT,{},permission={},signature=b'',verify=lambda *a:True)
            remove.assert_not_called()
        with patch('probe_a_native_deadline.ctypes.CDLL') as load:
            with self.assertRaises(SessionDenied):NativeDeadlineGuard(9,CONTEXT,artifact_identity=(1,2))
            load.assert_not_called()
        with patch('probe_a_native_resources.os.open') as opened:
            collector=NativeResourceCollector(CONTEXT,None,None,clock=lambda:0)
            with self.assertRaises(SessionDenied):collector.numeric_uid_absence(1)
            opened.assert_not_called()
    def test_partial_package_is_persisted_as_unsigned_fixture(self):
        with tempfile.TemporaryDirectory(prefix='probe-a-journal-partial-') as temp:
            fd=os.open(temp+'/journal',os.O_RDWR|os.O_CREAT|os.O_EXCL|os.O_APPEND|os.O_CLOEXEC,0o600)
            try:
                journal=UnsignedObservationJournal(fd,CONTEXT,writable=True,clock=lambda:10)
                audit=IndependentEvidenceAudit(context=CONTEXT,groups=GROUPS,journal=journal)
                self.assertTrue(audit.persist_partial())
                prefix=journal.read_prefix();self.assertEqual(len(prefix['records']),1)
                self.assertIn(b'BLOCKED_NO_TRUSTED_RUNTIME_PASS',prefix['records'][0])
            finally:os.close(fd)
    def test_guardian_nonzero_exit_still_attempts_independent_audit(self):
        from probe_a_linux_launcher import IndependentSupervisor
        import test_phase2l_probe_a_linux_foundation as foundation
        actors=foundation.ContainmentAndSupervisionTests().actors(guardian_code=10)
        supervisor=IndependentSupervisor(actors,end=240,cutoff=180,clock=lambda:0)
        audit=Mock(return_value=True)
        with patch('probe_a_linux_launcher.os.geteuid',return_value=0):
            result=supervisor.run(close_controller_channel=Mock(),observe_after=audit,cancelled=lambda:False,activated=True)
        audit.assert_called_once();self.assertIn('BLOCKED',result)


class FinalBoundaryRegressions(unittest.TestCase):
    def test_claim_receipt_is_one_use_and_not_caller_substitutable(self):
        permit=integration.permit();self.assertTrue(permit.claim())
        receipt=permit._bootstrap_receipt
        with self.assertRaises(SessionDenied):permit.consume_bootstrap_receipt(object())
        self.assertTrue(permit.consume_bootstrap_receipt(receipt))
        with self.assertRaises(SessionDenied):permit.consume_bootstrap_receipt(receipt)
        with self.assertRaises(SessionDenied):permit.claim()

    def test_disabled_c_guard_source_compiles_without_installation_or_execution(self):
        import shutil,subprocess
        compiler=shutil.which('cc')
        self.assertIsNotNone(compiler,'Existing C compiler required; package installation is prohibited')
        source=Path(__file__).resolve().parents[2]/'docs/security/phase2l/probe_a_deadline_guard.c'
        result=subprocess.run([compiler,'-fsyntax-only','-std=c11','-Wall','-Wextra','-Werror',str(source)],
                              capture_output=True,text=True,timeout=8,check=False)
        self.assertEqual(result.returncode,0,result.stderr)

if __name__=='__main__':unittest.main()
