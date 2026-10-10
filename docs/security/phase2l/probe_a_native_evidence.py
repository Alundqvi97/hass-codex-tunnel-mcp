"""Bounded unsigned journal + structured measurement validation, no signing.

No sockets, traffic, collector installation or privileged observations on
import. An authenticated collector is necessary but does not itself make a
measurement adequate. Missing kernel trace/transaction facts remain blocked.
"""
from __future__ import annotations

import hashlib
import os
import stat
import struct
import time
from probe_a_session import canonical, decode, SessionDenied
from probe_contract import CASES
from probe_a_dns import targets, verify_response, verify_tcp_frame, query

MAX_JOURNAL = 4*1024*1024


class UnsignedObservationJournal:
    """Descriptor-bound append-only bounded records with crash-prefix recovery.

    Owner creates a private regular file outside source via O_EXCL. Readers
    hold readonly FDs; no actor can pass a pathname over RPC. Signatures must
    arrive from a separately authorized boundary, never fabricated here.
    """
    def __init__(self, fd, context, *, writable=False, clock=time.monotonic):
        info = os.fstat(fd)
        import fcntl
        access = fcntl.fcntl(fd,fcntl.F_GETFL)
        if (not stat.S_ISREG(info.st_mode) or info.st_nlink != 1 or info.st_mode & 0o077
                or info.st_size > MAX_JOURNAL or writable and not access & os.O_APPEND):
            raise SessionDenied("JOURNAL_DESCRIPTOR_NOT_PRIVATE_OR_BOUNDED")
        self.fd, self.context, self.writable, self.clock = fd, context, writable is True, clock
        self.identity, self.uncertain = (info.st_dev,info.st_ino), False

    def append(self, observation):
        if not self.writable or self.uncertain or self.clock() >= self.context.end:
            raise SessionDenied("JOURNAL_DISABLED_UNCERTAIN_OR_EXPIRED")
        raw = canonical(observation)
        if len(raw) > 300000 or observation.get("context") != self.context.identifier:
            raise SessionDenied("JOURNAL_CONTEXT_OR_RECORD_BOUNDS")
        data = struct.pack("!I",len(raw))+raw+hashlib.sha256(raw).digest()
        try:
            if os.fstat(self.fd).st_size+len(data) > MAX_JOURNAL:
                raise SessionDenied("JOURNAL_CAPACITY_EXHAUSTED")
            # One writer owns a journal. No multiwriter append can interleave.
            if os.write(self.fd,data) != len(data): raise SessionDenied("JOURNAL_PARTIAL_WRITE")
            os.fsync(self.fd)
            if self.clock() >= self.context.end: raise SessionDenied("JOURNAL_SYNC_DEADLINE_UNCERTAIN")
        except BaseException:
            self.uncertain = True
            raise

    def read_prefix(self):
        info = os.fstat(self.fd)
        if (info.st_dev,info.st_ino) != self.identity or info.st_size > MAX_JOURNAL:
            raise SessionDenied("JOURNAL_REPLACED_OR_OVERSIZE")
        raw = os.pread(self.fd,MAX_JOURNAL+1,0)
        records, position, uncertain = [], 0, self.uncertain
        while position < len(raw):
            if len(records) >= 4096 or len(raw)-position < 4: uncertain = True; break
            length = struct.unpack_from("!I",raw,position)[0]; position += 4
            if not 0 < length <= 300000 or position+length+32 > len(raw): uncertain = True; break
            item = raw[position:position+length]; position += length
            checksum = raw[position:position+32]; position += 32
            if hashlib.sha256(item).digest() != checksum: uncertain = True; break
            try:
                record = decode(item,300000)
                if record.get("context") != self.context.identifier: raise SessionDenied("JOURNAL_STALE_SESSION")
            except BaseException: uncertain = True; break
            records.append(item)
        # Checksums are corruption detection, NEVER authority/signatures.
        return {"provenance":"INCOMPLETE_RUNTIME_EVIDENCE","records":tuple(records),"uncertain":uncertain,
                "result":"BLOCKED_NO_TRUSTED_RUNTIME_PASS"}


class SignedJournalCollector:
    """Concrete audit collection adapter; externally supplied public receipts."""
    def __init__(self, journal, signatures):
        self.journal, self.signatures = journal, dict(signatures)

    def __call__(self, fact, context):
        if context != self.journal.context.identifier: raise SessionDenied("JOURNAL_CONTEXT_SUBSTITUTION")
        prefix = self.journal.read_prefix()
        candidates = [raw for raw in prefix["records"] if decode(raw,300000).get("fact") == fact]
        if prefix["uncertain"] or len(candidates) != 1:
            raise SessionDenied("JOURNAL_FACT_MISSING_DUPLICATE_OR_UNCERTAIN")
        signature = self.signatures.get(hashlib.sha256(candidates[0]).hexdigest())
        if type(signature) is not bytes or len(signature) != 64:
            raise SessionDenied("EXTERNAL_COLLECTOR_SIGNATURE_UNAVAILABLE")
        return candidates[0],signature


def counters(value, family):
    expected = ("ACCEPT","ACCEPT","ACCEPT","REJECT") if family == "ipv4" else ("REJECT",)
    if (type(value) is not list or len(value) != len(expected)
            or any(type(row) is not list or len(row) != 3 or type(row[0]) is not int
                or type(row[1]) is not int or not 0 <= row[0] < 2**64 or not 0 <= row[1] < 2**64
                or row[2] != target for row,target in zip(value,expected))):
        raise SessionDenied("MEASUREMENT_COUNTER_TYPE_SHAPE_OR_TARGET")


def validate_network_measurement(case, value, context, worker, peer=None):
    """Case-specific kernel measurement, not a case label or worker stdout.

    Socket-cookie + process-incarnation + cgroup binding is collected at the
    kernel trace boundary. A loader for that boundary remains a named source/
    dependency blocker; callers cannot synthesize native provenance from this
    validator. Fixture records are always labelled SYNTHETIC_TEST.
    """
    fields = {"v","case","context","worker","group","socket_cookie","endpoint","interval",
              "mechanism","outcome","observations","family","rule_index","rule_chain"}
    if type(value) is not dict or set(value) != fields or type(value["v"]) is not int or value["v"] != 1:
        raise SessionDenied("STRUCTURED_NETWORK_MEASUREMENT_REQUIRED")
    _case,family,index = next((c for c in CASES if c[0] == case), (None,None,None))
    expected_endpoint = {c:[address,port] for c,address,port in targets(context.plan.dns,"1.1.1.1")}
    expected_endpoint["loopback-established"] = ["127.0.0.1",19468]
    if (value["case"] != case or value["context"] != context.identifier
            or value["worker"] != [worker.pid,worker.starttime] or value["group"] != "worker"
            or type(value["socket_cookie"]) is not int or not 0 < value["socket_cookie"] < 2**64
            or value["endpoint"] != expected_endpoint.get(case) or value["family"] != family
            or type(value["rule_index"]) is not int or value["rule_index"] != index
            or value["rule_chain"] != (context.plan.chain4 if family == "ipv4" else context.plan.chain6)
            or type(value["interval"]) is not list or len(value["interval"]) != 2
            or any(type(n) not in (float,int) for n in value["interval"])
            or not 0 <= value["interval"][0] < value["interval"][1] < context.cutoff
            or value["mechanism"] != "kernel-socket-and-netfilter-trace"):
        raise SessionDenied("NETWORK_MEASUREMENT_CONTEXT_ENDPOINT_OR_KERNEL_BINDING")
    observations = value["observations"]
    if type(observations) is not dict:
        raise SessionDenied("NETWORK_MEASUREMENT_OBSERVATIONS_MISSING")
    if case in ("approved-udp","approved-tcp"):
        if value["outcome"] != "matched-transaction" or set(observations) != {"request_hex","response_hex","txid","transport"}:
            raise SessionDenied("POSITIVE_DNS_TRANSACTION_UNOBSERVED")
        txid = observations["txid"]
        if type(txid) is not int or txid != 6699 or observations["transport"] != case[9:]:
            raise SessionDenied("DNS_TRANSACTION_OR_TRANSPORT_SUBSTITUTION")
        for key in ("request_hex","response_hex"):
            if type(observations[key]) is not str or len(observations[key]) > 8196:
                raise SessionDenied("DNS_OBSERVATION_BOUNDS")
        request, response = bytes.fromhex(observations["request_hex"]),bytes.fromhex(observations["response_hex"])
        expected = query(txid)
        if request != (struct.pack("!H",len(expected))+expected if case == "approved-tcp" else expected):
            raise SessionDenied("DNS_REQUEST_NOT_EXPECTED_TRANSACTION")
        (verify_tcp_frame if case == "approved-tcp" else verify_response)(response,txid)
    elif case == "loopback-established":
        if (peer is None or value["outcome"] != "established-exchange" or set(observations) != {"peer","established","hello_hex","reply_hex"}
                or observations.get("established") is not True
                or observations != {"peer":[peer.pid,peer.starttime],"established":True,
                                    "hello_hex":b"P2AHELLO".hex(),"reply_hex":b"P2AACK!!".hex()}):
            raise SessionDenied("ESTABLISHED_LOOPBACK_EXCHANGE_UNOBSERVED")
    else:
        # NF_REJECT is not a Linux netfilter verdict. The nft reject expression
        # emits a rejection and returns NF_DROP (0). A bare NF_DROP, socket
        # errno or timeout cannot establish that the owned reject rule ran.
        if (value["outcome"] != "firewall-rejected" or set(observations) != {"verdict","verdict_code","expression","hook","errno","cookie","worker"}
                or observations["verdict"] != "NF_DROP" or type(observations['verdict_code']) is not int
                or observations['verdict_code']!=0 or observations['expression']!='reject' or observations["hook"] != "LOCAL_OUT"
                or type(observations["errno"]) is not int or observations["errno"] not in (1,13,111)
                or type(observations["cookie"]) is not int or observations["cookie"] != value["socket_cookie"] or observations["worker"] != [worker.pid,worker.starttime]):
            raise SessionDenied("DENIAL_NOT_ATTRIBUTED_TO_EXPECTED_FIREWALL_REJECTION")
    return True


def empty_scope_observation(value, expected):
    """Raw independently read kernel fields, not a signed 'empty=True' bit."""
    from probe_a_linux_launcher import empty_group
    if (type(value) is not dict or set(value)!={'identity','events','procs'}
            or value['identity']!=expected or not empty_group(value['events'],value['procs'])):
        raise SessionDenied('CLEANUP_SCOPE_KERNEL_READBACK_INCOMPLETE')


def validate_cleanup_measurement(fact, value, composer):
    context,groups=composer.context,composer.groups
    if type(value) is not dict:
        raise SessionDenied('SIGNED_BOOLEAN_IS_NOT_CLEANUP_MEASUREMENT')
    if fact in ('guardian-reaped','observer-shutdown'):
        role='guardian' if fact=='guardian-reaped' else 'observer'
        identity=composer.identities[role]
        if (set(value)!={'incarnation','pidfd_exited','waitpid','scope'}
                or value['incarnation']!=[identity.pid,identity.starttime] or value['pidfd_exited'] is not True
                or type(value['waitpid']) is not dict or set(value['waitpid'])!={'pid','exit'}
                or type(value['waitpid']['pid']) is not int or value['waitpid']['pid']!=identity.pid
                or type(value['waitpid']['exit']) is not int):
            raise SessionDenied('SUPERVISING_OWNER_REAP_OBSERVATION_REQUIRED')
        empty_scope_observation(value['scope'],groups[role])
    elif fact=='workers-peer-stopped':
        if set(value)!={'scopes'} or set(value['scopes'])!={'worker','peer'}:
            raise SessionDenied('WORKER_PEER_EMPTY_SCOPES_REQUIRED')
        for role in ('worker','peer'):empty_scope_observation(value['scopes'][role],groups[role])
    elif fact=='owned-cleanup':
        from probe_contract import CLEANUP_READBACKS
        if set(value)!={'observations'} or set(value['observations'])!=set(CLEANUP_READBACKS):
            raise SessionDenied('OWNED_CLEANUP_RAW_OBSERVATIONS_REQUIRED')
        # These categorical booleans are explicitly inadmissible. A complete
        # resource-measurement schema/collector is a named implementation gap.
        raise SessionDenied('SOURCE_GAP_COMPLETE_RESOURCE_MEASUREMENT_SCHEMA')
    elif fact=='emergency-deny':
        raise SessionDenied('SOURCE_GAP_INDEPENDENT_EMERGENCY_MUTATION_TRACE')
    elif fact=='no-residuals':
        # The root supervisor is still alive when its own package is made.
        # Only a later external runner owner can observe its absence; this
        # delivery has no accepted final-owner protocol or runtime PASS path.
        raise SessionDenied('SOURCE_GAP_EXTERNAL_OWNER_FINAL_RESIDUAL_OBSERVATION')
    return True
