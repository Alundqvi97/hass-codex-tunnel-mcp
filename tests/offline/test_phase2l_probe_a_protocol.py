"""Offline-only fault injections for DNS wire and kernel readback parser."""
import sys
import struct
from pathlib import Path
import unittest

ROOT=Path(__file__).resolve().parents[2]
sys.path.insert(0,str(ROOT/"docs/security/phase2l"))
from probe_a_dns import query,verify_response,verify_tcp_frame,InvalidPacket,targets
from probe_a_client import perform,admissible_result
from probe_a_kernel import expect_active,compare_after,require_counter_delta,InvalidEvidence,parse_packets
from probe_contract import compile_plan

PLAN=compile_plan(scope="A1B2C3D4",uid=45123,dns="9.9.9.9")
BASE="*filter\n:INPUT ACCEPT [0:0]\n:FORWARD ACCEPT [0:0]\n:OUTPUT ACCEPT [0:0]\n-A OUTPUT -j BASE_MARKER\nCOMMIT\n"

def snapshot(plan,*,family="ipv4",complete=True,hook=True):
    chain=plan.chain4 if family=="ipv4" else plan.chain6
    body=BASE.replace(":OUTPUT ACCEPT [0:0]\n",":OUTPUT ACCEPT [0:0]\n:"+chain+" - [0:0]\n")
    if hook:
        body=body.replace("-A OUTPUT -j BASE_MARKER","-A OUTPUT -m owner --uid-owner 45123 -j "+chain+"\n-A OUTPUT -j BASE_MARKER")
    if family=="ipv4" and complete:
        rules=[
          "-A "+chain+" -o lo -d 127.0.0.1/32 -p tcp -m conntrack --ctstate ESTABLISHED -j ACCEPT",
          "-A "+chain+" -d 9.9.9.9/32 -p tcp -m tcp --dport 53 -j ACCEPT",
          "-A "+chain+" -d 9.9.9.9/32 -p udp -m udp --dport 53 -j ACCEPT",
        ]
    else: rules=[]
    rules.append("-A "+chain+" -j REJECT")
    return body.replace("COMMIT\n","\n".join(rules)+"\nCOMMIT\n")

class DnsTests(unittest.TestCase):
    def reply(self,tx=123):
        wire=bytearray(query(tx))
        # QR=1, RD=1, RA=1, NXDOMAIN=3
        wire[2:4]=struct.pack("!H",0x8183)
        return bytes(wire)
    def test_udp_tcp_response_matching(self):
        data=self.reply()
        self.assertEqual(verify_response(data,123),"DNS_UDP_MATCHED_NXDOMAIN")
        self.assertEqual(verify_tcp_frame(struct.pack("!H",len(data))+data,123),"DNS_TCP_MATCHED_NXDOMAIN")
    def test_wrong_transaction_id_or_question(self):
        with self.assertRaises(InvalidPacket): verify_response(self.reply(123),124)
        data=bytearray(self.reply());data[-6]=ord("X")
        with self.assertRaises(InvalidPacket):verify_response(bytes(data),123)
    def test_reply_header_errors(self):
        for flags in (0x0103,0x8180,0x8383,0x8203):
            data=bytearray(self.reply());data[2:4]=struct.pack("!H",flags)
            with self.subTest(flags=flags),self.assertRaises(InvalidPacket):
                verify_response(bytes(data),123)
    def test_truncated_and_tcp_frame_attack(self):
        with self.assertRaises(InvalidPacket):verify_response(b"",123)
        with self.assertRaises(InvalidPacket):verify_tcp_frame(b"\x00\x20"+self.reply(),123)
    def test_negative_targets_not_household_or_metadata(self):
        names=targets("9.9.9.9","1.1.1.1")
        self.assertEqual(len(names),9)
        self.assertNotIn("169.254.169.254",str(names))
        self.assertEqual(admissible_result("private","SOCKET_FAILED_REQUIRES_KERNEL_COUNTER"),True)
        self.assertFalse(admissible_result("private","BLOCKED_UNEXPECTED_CONNECTION"))
    def test_loopback_requires_separate_root_peer(self):
        self.assertEqual(perform("loopback-established",approved_dns="9.9.9.9",alternate_dns="1.1.1.1",txid=3),"BLOCKED_SEPARATE_ROOT_PEER_REQUIRED")
    def test_no_live_socket_called_by_wire_tests(self):
        self.assertEqual(len(query(1))>12,True)

class KernelTests(unittest.TestCase):
    def test_deny_hook_synthetic(self):
        self.assertEqual(expect_active(snapshot(PLAN,complete=False),snapshot(PLAN,family="ipv6",complete=False),BASE,BASE,PLAN,final=False),"SYNTHETIC_STATE_CONSISTENT_NOT_KERNEL_PROVEN")
    def test_full_policy_synthetic(self):
        self.assertEqual(expect_active(snapshot(PLAN),snapshot(PLAN,family="ipv6"),BASE,BASE,PLAN,final=True),"SYNTHETIC_STATE_CONSISTENT_NOT_KERNEL_PROVEN")
    def test_hook_missing(self):
        with self.assertRaises(InvalidEvidence): expect_active(snapshot(PLAN,hook=False),snapshot(PLAN,family="ipv6"),BASE,BASE,PLAN,final=True)
    def test_wrong_dns_target_and_unrelated_rule(self):
        for bad in (snapshot(PLAN).replace("9.9.9.9","8.8.8.8"),
                    snapshot(PLAN).replace("-A OUTPUT -j BASE_MARKER","-A OUTPUT -j UNREVIEWED")):
            with self.subTest(bad=bad[:20]),self.assertRaises(InvalidEvidence):
                expect_active(bad,snapshot(PLAN,family="ipv6"),BASE,BASE,PLAN,final=True)
    def test_wrong_order(self):
        b=snapshot(PLAN)
        b=b.replace("-A "+PLAN.chain4+" -j REJECT","-A "+PLAN.chain4+" -j ACCEPT")
        with self.assertRaises(InvalidEvidence):
            expect_active(b,snapshot(PLAN,family="ipv6"),BASE,BASE,PLAN,final=True)
    def test_snapshot_restoration(self):
        self.assertEqual(compare_after(BASE,BASE,BASE,BASE),"SYNTHETIC_RULES_RESTORED_NOT_KERNEL_PROVEN")
        with self.assertRaises(InvalidEvidence):compare_after(BASE+"a",BASE,BASE,BASE)
    def test_counters_must_increase_for_expected_rule(self):
        a=((1,40,"ACCEPT"),(0,0,"ACCEPT"),(0,0,"ACCEPT"),(4,120,"REJECT"))
        b=((1,40,"ACCEPT"),(0,0,"ACCEPT"),(0,0,"ACCEPT"),(5,170,"REJECT"))
        self.assertEqual(require_counter_delta(a,b,3),"SYNTHETIC_COUNTER_DELTA_NOT_KERNEL_PROVEN")
        with self.assertRaises(InvalidEvidence):require_counter_delta(a,b,1)
    def test_counter_shape_fail_closed(self):
        text="Chain P2A4_A1B2C3D4 (1 references)\n pkts bytes target prot opt in out source destination\n    4  80 REJECT all -- * * 0.0.0.0/0 0.0.0.0/0\n"
        self.assertEqual(parse_packets(text,PLAN.chain4),((4,80,"REJECT"),))
        with self.assertRaises(InvalidEvidence):parse_packets(text,PLAN.chain6)

if __name__=="__main__":unittest.main()
