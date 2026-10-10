"""Phase 2L offline security test suite; no network, QEMU, sudo or Docker."""
from __future__ import annotations
import contextlib
import importlib.util
import io
import json
import os
from pathlib import Path
import sys
import tempfile
import unittest

ROOT=Path(__file__).resolve().parents[2]
sys.path.insert(0,str(ROOT/"docs/security/phase2l"))
import network_preflight as net
import packaging_preflight as package
import runner_preflight as runner
import stage_candidate as stage

NETDEV=runner.NETDEV

def manifest():
    return {
        "schema_version":1,
        "approved_dns_ipv4":"9.9.9.9",
        "effective_upstream_ipv4":"9.9.9.9",
        "qemu_route_evidence":"CONTROLLED_RESOLVER_PATH_REVIEWED",
        "dns_udp_53":True, "dns_tcp_53":True,
        "host_ipv6_reject":True,"private_ipv4_reject":True,
        "egress_default_reject":True, "cleanup_evidence":True,
        "approved_web_ipv4":["140.82.113.4"],"web_tcp_ports":[80,443],
        "reviewed_bootstrap_hosts":["ghcr.io"],
    }
# Addresses above are synthetic fixture data, NEVER approved endpoints.

def good_config():
    return "nameserver 9.9.9.9\n"

class ResolverTests(unittest.TestCase):
    def test_public_ipv4_consistent_is_still_only_offline(self):
        x=net.inspect_network(good_config(),manifest(),NETDEV)
        self.assertEqual(x.status,net.CONSISTENT)
        self.assertEqual(net.before_guest_authorization(x).status,"BLOCKED")
        self.assertEqual(net.before_guest_authorization(x).reason,"ACTUAL_ROUTE_AND_KERNEL_NOT_VERIFIED")
    def test_stub_resolver(self):
        x=net.inspect_network("nameserver 127.0.0.53\n",manifest(),NETDEV)
        self.assertEqual(x.reason,"LOCAL_STUB")
    def test_other_loopback(self):
        self.assertEqual(net.inspect_network("nameserver 127.0.0.1",manifest(),NETDEV).reason,"LOOPBACK_RESOLVER")
    def test_private_and_link_local(self):
        for address in ("10.0.0.2","192.168.1.1","172.18.0.1","169.254.169.254","100.64.0.1"):
            with self.subTest(address=address):
                self.assertEqual(net.inspect_network("nameserver "+address,manifest(),NETDEV).status,"BLOCKED")
    def test_ipv6_rejected(self):
        self.assertEqual(net.inspect_network("nameserver 2606:4700:4700::1111",manifest(),NETDEV).reason,"IPV6_RESOLVER")
        self.assertEqual(net.inspect_network("nameserver ::1",manifest(),NETDEV).reason,"IPV6_RESOLVER")
    def test_missing_malformed_multiple(self):
        self.assertEqual(net.inspect_network("",manifest(),NETDEV).reason,"MISSING_RESOLVER")
        self.assertEqual(net.inspect_network("nameserver something",manifest(),NETDEV).reason,"MALFORMED_RESOLVER")
        self.assertEqual(net.inspect_network("nameserver 9.9.9.9\nnameserver 1.1.1.1",manifest(),NETDEV).reason,"MULTIPLE_RESOLVERS")
        self.assertEqual(net.inspect_network("nameserver 9.9.9.9 1.1.1.1",manifest(),NETDEV).reason,"MALFORMED_RESOLVER")
    def test_different_and_unknown_upstream(self):
        m=manifest();m["effective_upstream_ipv4"]=None
        self.assertEqual(net.inspect_network(good_config(),m,NETDEV).reason,"QEMU_UPSTREAM_UNKNOWN")
        m["effective_upstream_ipv4"]="8.8.8.8"
        self.assertEqual(net.inspect_network(good_config(),m,NETDEV).reason,"QEMU_UPSTREAM_MISMATCH")
    def test_route_unproved(self):
        m=manifest();m["qemu_route_evidence"]="unknown"
        self.assertEqual(net.inspect_network(good_config(),m,NETDEV).reason,"QEMU_ROUTE_UNVERIFIED")
    def test_udp_only_refused(self):
        m=manifest();m["dns_tcp_53"]=False
        self.assertEqual(net.inspect_network(good_config(),m,NETDEV).reason,"DNS_TCP_NOT_RESTRICTED")
    def test_tcp_only_refused(self):
        m=manifest();m["dns_udp_53"]=False
        self.assertEqual(net.inspect_network(good_config(),m,NETDEV).reason,"DNS_UDP_NOT_RESTRICTED")
    def test_unapproved_dns_ip(self):
        m=manifest();m["approved_dns_ipv4"]="8.8.8.8"
        self.assertEqual(net.inspect_network(good_config(),m,NETDEV).reason,"DNS_TARGET_NOT_APPROVED")
    def test_web_allow_list_invalid_or_unexpected(self):
        for x in ([],["192.168.1.7"],["140.82.113.4","192.168.1.7"],["140.82.113.4","140.82.113.4"],["example.com"]):
            m=manifest();m["approved_web_ipv4"]=x
            self.assertEqual(net.inspect_network(good_config(),m,NETDEV).reason,"UNAPPROVED_WEB_DESTINATION")
    def test_invalid_host_and_ports(self):
        for hosts in ([],["host:443"],["*"],["local"]):
            m=manifest();m["reviewed_bootstrap_hosts"]=hosts
            self.assertEqual(net.inspect_network(good_config(),m,NETDEV).status,"BLOCKED")
        for ports in ([443],[80,443,22],[80,80]):
            m=manifest();m["web_tcp_ports"]=ports
            self.assertEqual(net.inspect_network(good_config(),m,NETDEV).reason,"UNAPPROVED_WEB_PORT")
    def test_missing_guest_ipv6_off(self):
        self.assertEqual(net.inspect_network(good_config(),manifest(),NETDEV.replace(",ipv6=off","")).reason,"GUEST_IPV6_NOT_DISABLED")
    def test_missing_host_ipv6_reject(self):
        m=manifest();m["host_ipv6_reject"]=False
        self.assertEqual(net.inspect_network(good_config(),m,NETDEV).reason,"HOST_IPV6_NOT_REJECTED")
    def test_missing_private_and_default_reject(self):
        for k in ("private_ipv4_reject","egress_default_reject","cleanup_evidence"):
            m=manifest();m[k]=False
            self.assertEqual(net.inspect_network(good_config(),m,NETDEV).status,"BLOCKED")
    def test_forward_injection(self):
        for bad in (NETDEV.replace("127.0.0.1:18123","0.0.0.0:18123"),
                    NETDEV.replace("18124-:80","18124-:22"),
                    NETDEV+",hostfwd=tcp:127.0.0.1:19999-:22"):
            self.assertEqual(net.inspect_network(good_config(),manifest(),bad).status,"BLOCKED")
    def test_manifest_missing_fields_and_invalid_json(self):
        m=manifest();m.pop("approved_web_ipv4")
        self.assertEqual(net.inspect_network(good_config(),m,NETDEV).reason,"MANIFEST_MISSING_OR_INVALID")
        with self.assertRaises(ValueError):net.load_manifest("{not JSON")
    def test_no_untrusted_diagnostics(self):
        secret="local_host_token_abcdef"
        x=net.inspect_network("nameserver "+secret,manifest(),NETDEV)
        self.assertNotIn(secret,x.receipt())
    def test_runner_missing_manifest_aborts(self):
        with tempfile.TemporaryDirectory() as d:
            p=Path(d)
            (p/"resolve").write_text(good_config())
            guest=p/"guest.py"
            guest.write_text("ipv6=off 18123-:8123 18124-:80 14357-:4357 19583-:9583")
            output=io.StringIO()
            with contextlib.redirect_stdout(output):
                rc=runner.main(["--resolv-conf",str(p/"resolve"),"--manifest",str(p/"absent"),"--guest-source",str(guest)])
            self.assertEqual(rc,3)
            self.assertIn("BLOCKED_MANIFEST_UNAVAILABLE",output.getvalue())
    def test_runner_positive_fixture_still_aborts(self):
        with tempfile.TemporaryDirectory() as d:
            p=Path(d);(p/"resolve").write_text(good_config())
            (p/"manifest").write_text(json.dumps(manifest()))
            (p/"guest.py").write_text("ipv6=off 18123-:8123 18124-:80 14357-:4357 19583-:9583")
            out=io.StringIO()
            with contextlib.redirect_stdout(out):
                code=runner.main(["--resolv-conf",str(p/"resolve"),"--manifest",str(p/"manifest"),"--guest-source",str(p/"guest.py")])
            self.assertEqual(code,3)
            self.assertIn("BLOCKED_ACTUAL_ROUTE_AND_KERNEL_NOT_VERIFIED",out.getvalue())
    def test_script_orders_preflight_before_privileges(self):
        sh=(ROOT/"docs/security/phase2h/runner_once.sh").read_text()
        self.assertLess(sh.index("docs/security/phase2l/runner_preflight.py"),sh.index("sudo apt-get"))
        self.assertLess(sh.index("docs/security/phase2l/stage_candidate.py"),sh.index("sudo modprobe nbd"))
        self.assertNotIn("supervisor/addons/data/local_ha_mcp_phase2h",sh)
    def test_no_vm_trigger_modified(self):
        s=(ROOT/".github/workflows/phase2h-haos-vm-once.yml").read_text()
        self.assertIn("paths: [.github/workflows/phase2h-haos-vm-once.yml]",s)
        self.assertNotIn("workflow_dispatch",s)

class PackagingTests(unittest.TestCase):
    def setUp(self):
        self.d=tempfile.TemporaryDirectory()
        self.addCleanup(self.d.cleanup)
        self.root=Path(self.d.name)
        self.staged=self.root/"stage"
        self.staged.mkdir()
        self.ref=self.root/"reference"
        self.ref.mkdir()
        actual=ROOT/"docs/security/phase2k"
        for f in ("bootstrap_policy.py","phase2k_policy.json"):
            src=actual/f
            target=self.ref/f
            target.write_bytes(src.read_bytes())
        self.source=ROOT/"docs/security/phase2k"
        self.make_good()
    def make_good(self):
        content={
            "config.yaml":'slug: "ha_mcp_phase2h"\n  require_strict_tool_policy: bool?\n  bootstrap_reviewed_policy: bool?\n  require_strict_tool_policy: false\n  bootstrap_reviewed_policy: false\n',
            "Dockerfile":"COPY pyproject.toml uv.lock ./\nCOPY src/ ./src/\nCOPY --from=builder /app/.venv /app/.venv\nCOPY start.py /\nCOPY phase2k_bootstrap.py /phase2k_bootstrap.py\nCOPY phase2k_policy.json /phase2k_policy.json\n",
            "start.py":'bootstrap_reviewed_policy(\nstrict_required = configure_supported_strict_policy(\nfrom phase2k_bootstrap import bootstrap_reviewed_policy\nPath("/phase2k_policy.json")\n',
            "pyproject.toml":"project",
            "uv.lock":"lock",
        }
        for name,body in content.items():(self.staged/name).write_text(body)
        for n in ("phase2k_bootstrap.py","phase2k_policy.json"):
            (self.staged/n).write_bytes((self.ref/("bootstrap_policy.py" if n=="phase2k_bootstrap.py" else n)).read_bytes())
        for n in ("__init__.py","server.py","policy/middleware.py"):
            target=self.staged/"src/ha_mcp"/n
            target.parent.mkdir(parents=True,exist_ok=True)
            target.write_text("HA_MCP_REQUIRE_STRICT_POLICY" if n=="server.py" else "source")
    def test_complete_fixture_only_static(self):
        self.assertEqual(package.inspect_context(self.staged,self.ref),"OFFLINE_BUILD_CONTEXT_CONSISTENT_NO_DOCKER_BUILD")
    def test_missing_files(self):
        for n in ("phase2k_bootstrap.py","phase2k_policy.json","uv.lock","start.py","src/ha_mcp/server.py"):
            with self.subTest(n=n):
                p=self.staged/n;original=p.read_bytes();p.unlink()
                self.assertNotEqual(package.inspect_context(self.staged,self.ref),"OFFLINE_BUILD_CONTEXT_CONSISTENT_NO_DOCKER_BUILD")
                p.write_bytes(original)
    def test_tampered_policy(self):
        p=self.staged/"phase2k_policy.json";p.write_text('{"rule_effect":"require_approval"}')
        self.assertNotEqual(package.inspect_context(self.staged,self.ref),"OFFLINE_BUILD_CONTEXT_CONSISTENT_NO_DOCKER_BUILD")
    def test_modified_helper(self):
        p=self.staged/"phase2k_bootstrap.py";p.write_text("bad")
        self.assertEqual(package.inspect_context(self.staged,self.ref),"BLOCKED_PINNED_PACKAGED_FILE")
    def test_invalid_schema(self):
        p=self.staged/"config.yaml";p.write_text(p.read_text().replace("bootstrap_reviewed_policy: bool?","bootstrap_reviewed_policy: str?"))
        self.assertEqual(package.inspect_context(self.staged,self.ref),"BLOCKED_ADDON_SCHEMA")
    def test_invalid_strict_schema(self):
        p=self.staged/"config.yaml";p.write_text(p.read_text().replace("require_strict_tool_policy: bool?","require_strict_tool_policy: str?"))
        self.assertEqual(package.inspect_context(self.staged,self.ref),"BLOCKED_ADDON_SCHEMA")
    def test_wrong_docker_copy(self):
        p=self.staged/"Dockerfile";p.write_text(p.read_text().replace("COPY phase2k_policy.json /phase2k_policy.json","COPY nowhere /phase2k_policy.json"))
        self.assertEqual(package.inspect_context(self.staged,self.ref),"BLOCKED_DOCKER_COPY")
    def test_bootstrap_after_server_fails(self):
        p=self.staged/"start.py";p.write_text("strict_required = configure_supported_strict_policy(\nbootstrap_reviewed_policy(\nPath('/phase2k_policy.json')\n")
        self.assertEqual(package.inspect_context(self.staged,self.ref),"BLOCKED_STARTUP_ORDER")
    def test_source_symlink_refused(self):
        f=self.staged/"phase2k_policy.json";f.unlink();f.symlink_to(self.ref/"phase2k_policy.json")
        self.assertNotEqual(package.inspect_context(self.staged,self.ref),"OFFLINE_BUILD_CONTEXT_CONSISTENT_NO_DOCKER_BUILD")
    def test_no_build_claim(self):
        self.assertNotIn("IMAGE_BUILT",package.inspect_context(self.staged,self.ref))

if __name__ == '__main__':unittest.main()
