"""Offline synthetic tests: no shell, sockets, sudo, QEMU or kernel rules."""
import importlib.util
from pathlib import Path
import unittest

ROOT = Path(__file__).resolve().parents[2]
SPEC = importlib.util.spec_from_file_location('phase2i_model', ROOT / 'docs/security/phase2i/offline_harness.py')
model = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(model)


class OfflineHarnessTests(unittest.TestCase):
    def test_loopback_expected_established(self):
        self.assertEqual(model.classify_synthetic_packet(destination='127.0.0.1', protocol='tcp', port=18123, interface='lo', conntrack='ESTABLISHED'), 'ALLOW_ESTABLISHED_LOOPBACK_REPLY')
        for state in ('NEW', 'INVALID', 'RELATED'):
            self.assertEqual(model.classify_synthetic_packet(destination='127.0.0.1', protocol='tcp', port=18123, interface='lo', conntrack=state), 'REJECT_RESERVED')
        self.assertEqual(model.classify_synthetic_packet(destination='127.0.0.2', protocol='tcp', port=18123, interface='lo', conntrack='ESTABLISHED'), 'REJECT_RESERVED')
        self.assertEqual(model.classify_synthetic_packet(destination='127.0.0.1', protocol='udp', port=53, interface='lo', conntrack='ESTABLISHED'), 'REJECT_RESERVED')

    def test_public_and_reserved(self):
        cases = [('10.0.2.2','tcp',443,'REJECT_RESERVED'),('10.0.2.3','udp',53,'REJECT_RESERVED'),('192.168.1.1','tcp',443,'REJECT_RESERVED'),('1.1.1.1','tcp',443,'ALLOW_PUBLIC_WEB'),('1.1.1.1','udp',53,'ALLOW_PUBLIC_DNS_OR_NTP'),('1.1.1.1','tcp',22,'REJECT_OTHER'),('::1','tcp',443,'REJECT_IPV6'),('2606:4700:4700::1111','udp',53,'REJECT_IPV6')]
        for addr, proto, port, expected in cases:
            with self.subTest(addr=addr):
                self.assertEqual(model.classify_synthetic_packet(destination=addr,protocol=proto,port=port),expected)

    def test_resolver_risk(self):
        self.assertEqual(model.parse_resolvers('nameserver 127.0.0.53\n# comment'), ('127.0.0.53',))
        self.assertEqual(model.resolver_assessment(('127.0.0.53',)), 'DNS_LOOPBACK_RISK')
        self.assertEqual(model.resolver_assessment(('10.0.0.1',)), 'DNS_PRIVATE_RISK')
        self.assertEqual(model.resolver_assessment(('1.1.1.1',)), 'DNS_PUBLIC_POSSIBLE')
        self.assertEqual(model.resolver_assessment(()), 'DNS_UNKNOWN')

    def test_netdev_lint(self):
        f = ','.join('hostfwd=tcp:127.0.0.1:%d-:%d' % item for item in model.FORWARDS.items())
        good = 'user,id=net0,ipv6=off,' + f
        self.assertEqual(model.validate_qemu_user_netdev(good), ())
        self.assertIn('GUEST_IPV6_NOT_EXPLICITLY_OFF', model.validate_qemu_user_netdev(good.replace('ipv6=off,','')))
        self.assertIn('UNSAFE_HOST_FORWARD', model.validate_qemu_user_netdev(good.replace('127.0.0.1:18123','0.0.0.0:18123')))
        self.assertIn('UNEXPECTED_HOST_FORWARD_SET', model.validate_qemu_user_netdev(good.replace(',hostfwd=tcp:127.0.0.1:19583-:9583','')))

    def test_proc_net_tcp(self):
        fixture = 'sl  local_address rem_address st\n  0: 0100007F:46CB 00000000:0000 0A\n  1: 00000000:46CC 00000000:0000 0A\n  2: 0100007F:46CC 00000000:0000 01'
        self.assertEqual(model.loopback_listener_ports(fixture), frozenset({18123}))

    def test_probe_distinguishes_failure_classes(self):
        examples = [({'running':False},'QEMU_EXIT'),({'listener':False},'HOST_FORWARD_ABSENT'),({'error':'refused'},'TCP_REFUSED'),({'error':'timeout'},'TCP_TIMEOUT'),({'error':'secret outside error'},'NETWORK_ERROR'),({'status':404},'HTTP_404'),({'status':503},'HTTP_VALID_OTHER'),({'status':200,'path':'/'},'HTTP_FIRST_BOOT_POSSIBLE'),({'status':200,'path':'/manifest.json'},'HA_CORE_MANIFEST'),({'status':401,'path':'/api/'},'HA_API_RESPONDING'),({'serial_observed':False},'GUEST_STARTUP_NOT_OBSERVABLE')]
        for kwargs, expected in examples:
            with self.subTest(expected=expected):
                self.assertEqual(model.classify_probe(**kwargs),expected)

    def test_synthetic_secret_never_leaks_diagnostics(self):
        secret = '/_phase2i_secret_dont_print_me'
        self.assertEqual(model.sanitized_code(secret), 'NETWORK_ERROR')
        self.assertEqual(model.classify_probe(error=secret),'NETWORK_ERROR')
        self.assertNotIn(secret, model.sanitized_code(secret))

    def test_partition_label_mandatory(self):
        sample = [{'PATH':'/dev/nbd0p8','LABEL':'hassos-data','TYPE':'ext4'}]
        self.assertEqual(model.choose_data_partition(sample),'/dev/nbd0p8')
        for bad in ([],sample*2,[{'PATH':'/dev/nbd0p8','LABEL':'root','TYPE':'ext4'}],[{'PATH':'/dev/nbd0p8','LABEL':'hassos-data','TYPE':'vfat'}],[{'PATH':'/dev/sda8','LABEL':'hassos-data','TYPE':'ext4'}]):
            with self.assertRaises(ValueError):
                model.choose_data_partition(bad)

    def test_supervisor_layout_guard(self):
        from tempfile import TemporaryDirectory
        with TemporaryDirectory() as d:
            root=Path(d)
            (root/'supervisor/addons/local').mkdir(parents=True)
            with self.assertRaises(ValueError):model.supervisor_local_store(root)
            (root/'supervisor/apps/local').mkdir(parents=True)
            self.assertEqual(model.supervisor_local_store(root),root/'supervisor/apps/local')

    def test_cleanup_fail_closed(self):
        self.assertEqual(model.cleanup_receipt({}),model.CLEANUP_ITEMS)
        all_good={key:True for key in model.CLEANUP_ITEMS}
        self.assertEqual(model.cleanup_receipt(all_good),())
        all_good['kvm_acl_removed']=False
        self.assertEqual(model.cleanup_receipt(all_good),('kvm_acl_removed',))
        self.assertFalse(model.future_guest_authorized())

    def test_supervisor_and_addon_milestones_do_not_skip_prerequisites(self):
        self.assertEqual(model.runtime_milestones({'addon_running': True}), ())
        evidence = {key: True for key in ('supervisor_api_reachable', 'supervisor_running', 'addon_in_store', 'addon_installed', 'addon_running')}
        self.assertEqual(model.runtime_milestones(evidence)[-1], 'ADDON_RUNNING')
        evidence['addon_installed'] = False
        self.assertEqual(model.runtime_milestones(evidence)[-1], 'ADDON_IN_STORE')
        self.assertEqual(model.cleanup_intentions(), model.CLEANUP_ITEMS)

    def test_runtime_probe_wiring_is_static_only(self):
        future = ROOT / 'docs/security/phase2h/single_haos_guest.py'
        if not future.is_file():
            self.skipTest('Future runner file not present in scratch')
        content = future.read_text()
        self.assertIn('def fetch_observation(', content)
        self.assertIn('PHASE2I_READINESS_DIAGNOSTIC', content)
        self.assertIn('ipv6=off', content)
        self.assertNotIn('report("RAW_HTTP_BODY"', content)

    def test_vm_trigger_guard_from_source(self):
        workflow=(ROOT/'.github/workflows/phase2h-haos-vm-once.yml')
        if not workflow.is_file():self.skipTest('GitHub workflow not mounted locally')
        text=workflow.read_text()
        self.assertIn('paths: [.github/workflows/phase2h-haos-vm-once.yml]',text)
        self.assertNotIn('workflow_dispatch:',text)


if __name__ == '__main__':
    unittest.main()
