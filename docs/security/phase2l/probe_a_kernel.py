"""Strict pure readback checks for Probe A's proposed iptables filter state.

Do not confuse text read from a mock with kernel provenance. A future live
adapter must independently execute read-only tools under verified identity.
"""
from __future__ import annotations
import re
import shlex
from dataclasses import dataclass
from probe_contract import validate_plan

MAX_RULE_BYTES=131072
MAX_COUNTER_BYTES=32768

class InvalidEvidence(ValueError):
    pass

def bounded(value,limit=MAX_RULE_BYTES):
    if not isinstance(value,str) or not 0<len(value)<=limit or "\x00" in value:
        raise InvalidEvidence("UNREADABLE_EVIDENCE")
    return value

def tokens(text):
    try: return tuple(shlex.split(text,posix=True))
    except ValueError: raise InvalidEvidence("INVALID_RULE_SYNTAX")

def extract_rules(snapshot, chain, output_hook):
    """Strip exact owned chain and hook; return rest in original order.

    Only call after complete active-chain validation; otherwise stripping a
    malicious extra ACCEPT could falsely classify a firewall as clean.
    """
    lines=bounded(snapshot).splitlines()
    removed=[]
    other=[]
    for line in lines:
        if line.startswith(":"+chain+" "):
            removed.append(("chain",line));continue
        try: t=tokens(line)
        except InvalidEvidence: raise
        if len(t)>=2 and t[0]=="-A" and t[1]==chain:
            removed.append(("rule",line));continue
        if t==output_hook:
            removed.append(("hook",line));continue
        if any(chain in t for _ in (0,)):
            raise InvalidEvidence("UNKNOWN_SCOPE_REFERENCE")
        other.append(line)
    return tuple(other),tuple(removed)

def expect_active(snapshot_v4,snapshot_v6, baseline_v4,baseline_v6, plan, *, final=False):
    if validate_plan(plan)!="OFFLINE_SAFE_SCOPED_PLAN_NOT_KERNEL_VERIFIED":
        raise InvalidEvidence("INVALID_PLAN")
    def family(active,baseline,chain,uid,ipver):
        active_lines=bounded(active).splitlines()
        before=bounded(baseline).splitlines()
        hook=("-A","OUTPUT","-m","owner","--uid-owner",str(uid),"-j",chain)
        remaining,owned=extract_rules(active,chain,hook)
        if tuple(before)!=remaining:
            raise InvalidEvidence("UNRELATED_RULES_CHANGED")
        defs=[x for k,x in owned if k=="chain"]
        hooks=[x for k,x in owned if k=="hook"]
        ownrules=[tokens(x) for k,x in owned if k=="rule"]
        if len(defs)!=1 or len(hooks)!=1 or defs[0]!=":"+chain+" - [0:0]":
            raise InvalidEvidence("HOOK_OR_CHAIN_MISSING")
        expected=[("-A",chain,"-j","REJECT")]
        if ipver=="ipv4" and final:
            expected=[
                ("-A",chain,"-o","lo","-d","127.0.0.1/32","-p","tcp",
                 "-m","conntrack","--ctstate","ESTABLISHED","-j","ACCEPT"),
                ("-A",chain,"-d",plan.dns+"/32","-p","tcp","-m","tcp","--dport","53","-j","ACCEPT"),
                ("-A",chain,"-d",plan.dns+"/32","-p","udp","-m","udp","--dport","53","-j","ACCEPT"),
                ("-A",chain,"-j","REJECT"),
            ]
        # Common iptables-save canonical forms include -m tcp/udp and
        # --reject-with icmp-port-unreachable; narrow exact variants only.
        def normalized(t):
            if t[-2:]==("--reject-with","icmp-port-unreachable"):
                return t[:-2]
            return t
        def reduce_port_module(t):
            # Permit only the canonical xtables injected matching module for
            # the specific protocol and the fixed 53 port.
            if len(t)>8 and "-m" in t and "--dport" in t:
                index=t.index("-m")
                if index+1<len(t) and t[index+1] in ("tcp","udp") and t[index+1] in t:
                    return t[:index]+t[index+2:]
            return t
        if ipver=="ipv4" and final:
            expected=[reduce_port_module(x) for x in expected]
        got=[reduce_port_module(normalized(t)) for t in ownrules]
        if got!=expected:
            raise InvalidEvidence("CHAIN_RULE_ORDER_OR_CONTENT")
        # Inserting at OUTPUT position 1 must precede all existing OUTPUT
        # rules. Do not trust an owner jump hidden after a broader ACCEPT.
        outputlines=[tokens(x) for x in active_lines if x.startswith("-A OUTPUT ")]
        if not outputlines or outputlines[0]!=hook:
            raise InvalidEvidence("OWNER_HOOK_NOT_FIRST")
    family(snapshot_v4,baseline_v4,plan.chain4,plan.uid,"ipv4")
    family(snapshot_v6,baseline_v6,plan.chain6,plan.uid,"ipv6")
    return "SYNTHETIC_STATE_CONSISTENT_NOT_KERNEL_PROVEN"

def compare_after(clean_v4,clean_v6,before_v4,before_v6):
    if bounded(clean_v4)!=bounded(before_v4) or bounded(clean_v6)!=bounded(before_v6):
        raise InvalidEvidence("RESTORATION_DIFF")
    return "SYNTHETIC_RULES_RESTORED_NOT_KERNEL_PROVEN"

def parse_packets(text, chain):
    """Read dedicated-chain -L -v -n -x counters, never parse verbose logs."""
    lines=bounded(text,MAX_COUNTER_BYTES).splitlines()
    if not lines or not lines[0].startswith("Chain "+chain+" ("):
        raise InvalidEvidence("COUNTER_CHAIN_MISMATCH")
    records=[]
    for line in lines[1:]:
        if not line.strip() or line.lstrip().startswith("pkts "):
            continue
        cols=line.split()
        if len(cols)<8 or not cols[0].isdigit() or not cols[1].isdigit():
            raise InvalidEvidence("COUNTER_PARSE")
        records.append((int(cols[0]),int(cols[1]),cols[2]))
    if not records or len(records)>16:
        raise InvalidEvidence("COUNTER_COUNT")
    return tuple(records)

def require_counter_delta(before,after,index):
    if len(before)!=len(after) or type(index) is not int or not 0<=index<len(before):
        raise InvalidEvidence("COUNTER_SHAPE")
    for x,y in zip(before,after):
        if y[0]<x[0] or y[1]<x[1]:
            raise InvalidEvidence("COUNTER_RESET")
    if after[index][0]<=before[index][0]:
        raise InvalidEvidence("NO_RULE_COUNTER_INCREASE")
    return "SYNTHETIC_COUNTER_DELTA_NOT_KERNEL_PROVEN"
