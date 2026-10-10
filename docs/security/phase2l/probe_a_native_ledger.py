"""Durable one-attempt claims. No storage, approval or service on import.

SQLite is the existing stdlib transactional mechanism. Protected local storage
must be provisioned separately; fixture stores are explicitly synthetic and
cannot satisfy native grant verification. Storage rollback is NOT prevented.
"""
from __future__ import annotations

import os
import sqlite3
import stat
import time
from urllib.parse import quote
from probe_a_session import SessionDenied, canonical, decode, digest, hexvalue

SCHEMA = "CREATE TABLE claims(session TEXT PRIMARY KEY, binding TEXT NOT NULL UNIQUE, boot TEXT NOT NULL, record BLOB NOT NULL) WITHOUT ROWID"


def protected_directory(path, uid):
    if type(path) is not str or not path.startswith("/") or any(x in (".", "..", "") for x in path.split("/")[1:]):
        raise SessionDenied("LEDGER_PATH_AMBIGUOUS")
    fd = os.open("/", os.O_RDONLY | os.O_DIRECTORY | os.O_CLOEXEC)
    try:
        for component in path.split("/")[1:]:
            child = os.open(component, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW | os.O_CLOEXEC, dir_fd=fd)
            os.close(fd); fd = child
            info = os.fstat(fd)
            if info.st_uid != uid or info.st_mode & 0o022:
                raise SessionDenied("LEDGER_PARENT_UNCONTROLLED")
        return fd
    except BaseException:
        os.close(fd)
        raise


class DurableAttemptLedger:
    """Atomic claim, durable commit, lost acknowledgement never yields regrant.

    For native use all ancestors are root controlled and the final directory is
    root:root 0700; DB is 0600, one link, regular. No actor writes this database.
    Authenticated roles receive read access only under a reviewed OS policy.
    No retry after contention/corruption/disk/full/sync error. An uncertain
    commit may have consumed the attempt; callers must treat it as consumed.
    """
    def __init__(self, directory, *, clock=time.monotonic, synthetic=False):
        self.synthetic, self.clock, self.poisoned = synthetic is True, clock, False
        self.fd = None
        if self.synthetic:
            # Only a nonprivileged, owned temporary fixture directory; this
            # branch cannot be used to mint a native claim or grant.
            if os.geteuid() == 0 or not os.path.realpath(directory).startswith("/tmp/"):
                raise SessionDenied("NONPRIVILEGED_TEMPORARY_LEDGER_FIXTURE_ONLY")
            self.fd = os.open(directory, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW | os.O_CLOEXEC)
            uid = os.geteuid()
        else:
            uid = 0
            self.fd = protected_directory(directory, uid)
        self.uid = uid
        info = os.fstat(self.fd)
        if info.st_uid != uid or stat.S_IMODE(info.st_mode) != 0o700:
            self.close(); raise SessionDenied("LEDGER_DIRECTORY_NOT_PRIVATE")
        self.path = "/proc/self/fd/"+str(self.fd)+"/attempts.sqlite"
        self.directory_identity = (info.st_dev, info.st_ino)

    def _inspect(self):
        info = os.stat("attempts.sqlite", dir_fd=self.fd, follow_symlinks=False)
        if (not stat.S_ISREG(info.st_mode) or info.st_uid != self.uid
                or info.st_gid != os.fstat(self.fd).st_gid or info.st_nlink != 1
                or stat.S_IMODE(info.st_mode) != 0o600 or info.st_size > 4*1024*1024):
            raise SessionDenied("LEDGER_FILE_UNCONTROLLED_OR_OVERSIZE")
        identity = (info.st_dev, info.st_ino)
        if hasattr(self, "database_identity") and self.database_identity != identity:
            raise SessionDenied("LEDGER_DATABASE_REPLACED")
        self.database_identity = identity
        return identity

    def initialize_fixture(self):
        if not self.synthetic:
            raise SessionDenied("LEDGER_PROVISIONING_APPROVAL_REQUIRED")
        self._initialize()

    def _initialize(self):
        # Exclusive creation prevents accidental reuse/truncation of storage.
        fd = os.open("attempts.sqlite", os.O_CREAT | os.O_EXCL | os.O_RDWR | os.O_NOFOLLOW | os.O_CLOEXEC,
                     0o600, dir_fd=self.fd)
        os.close(fd)
        db = self._connection(self.clock()+1, require_schema=False)
        try:
            db.execute(SCHEMA)
        finally:
            db.close()
        os.fsync(self.fd)

    def _connection(self, deadline, *, readonly=False, require_schema=True):
        if self.poisoned or not self.clock() < deadline <= self.clock()+8:
            raise SessionDenied("LEDGER_UNCERTAIN_OR_DEADLINE")
        before = self._inspect()
        uri = "file:"+quote(self.path, safe="/")+"?mode="+("ro" if readonly else "rw")
        db = sqlite3.connect(uri, uri=True, isolation_level=None, timeout=min(.2, max(0, deadline-self.clock())))
        try:
            db.set_progress_handler(lambda: int(self.clock() >= deadline), 100)
            if self._inspect() != before:
                raise SessionDenied("LEDGER_REPLACED_DURING_OPEN")
            if not readonly:
                if db.execute("PRAGMA journal_mode=DELETE").fetchone() != ("delete",):
                    raise SessionDenied("UNSUPPORTED_LEDGER_JOURNAL")
                db.execute("PRAGMA synchronous=EXTRA")
            if db.execute("PRAGMA quick_check").fetchone() != ("ok",):
                raise SessionDenied("CORRUPT_ATTEMPT_LEDGER")
            if require_schema and db.execute("SELECT type,name,sql FROM sqlite_master WHERE name NOT LIKE 'sqlite_%'").fetchall() != [("table","claims",SCHEMA)]:
                raise SessionDenied("UNEXPECTED_ATTEMPT_LEDGER_SCHEMA")
            return db
        except BaseException:
            db.close(); self.poisoned = True
            raise

    def claim_record(self, record, *, deadline):
        raw = canonical(record); binding = digest(record)
        if len(raw) > 65536 or not hexvalue(record.get("session"), 32) or type(record.get("boot")) is not str:
            raise SessionDenied("LEDGER_CLAIM_SCHEMA")
        db = None
        try:
            db = self._connection(deadline)
            db.execute("BEGIN IMMEDIATE")
            if db.execute("SELECT 1 FROM claims WHERE session=? OR binding=?",
                          (record["session"], binding)).fetchone() is not None:
                db.execute("ROLLBACK")
                return False
            if db.execute("SELECT count(*) FROM claims").fetchone()[0] >= 10000:
                raise SessionDenied("LEDGER_CAPACITY_EXHAUSTED")
            db.execute("INSERT INTO claims VALUES(?,?,?,?)", (record["session"], binding, record["boot"], raw))
            db.execute("COMMIT")  # EXTRA sync; success is not acknowledged yet
            os.fsync(self.fd)  # protects journal removal/directory entry durability
            if self.clock() >= deadline:
                raise SessionDenied("LEDGER_COMMIT_ACKNOWLEDGEMENT_UNCERTAIN")
            return True
        except BaseException:
            self.poisoned = True
            raise
        finally:
            if db is not None: db.close()

    def committed(self, record, *, deadline, native=True):
        if native and self.synthetic:
            raise SessionDenied("SYNTHETIC_LEDGER_IS_NOT_NATIVE_AUTHORITY")
        db = self._connection(deadline, readonly=True)
        try:
            row = db.execute("SELECT binding,boot,record FROM claims WHERE session=?", (record["session"],)).fetchone()
            return row == (digest(record), record["boot"], canonical(record)) and self.clock() < deadline
        except BaseException:
            self.poisoned = True
            raise
        finally:
            db.close()

    def close(self):
        if self.fd is not None:
            os.close(self.fd); self.fd = None


class ExistingAttemptGrant:
    """Cross-exec validation of an existing external grant; never claim again.

    The approval signature authenticates context/policy/deadlines/purpose.
    The protected ledger establishes that the supervisor committed exactly one
    claim. Sealed JSON, local used/granted flags and signature presence do not.
    """
    def __init__(self, context, record, signature, *, verify, ledger, boot_identity,
                 policy_digest, clock=time.monotonic):
        self.context, self.record = context, decode(canonical(record))
        self.signature, self.verify, self.ledger = signature, verify, ledger
        self.boot_identity, self.policy_digest, self.clock = boot_identity, policy_digest, clock

    def validate_approval(self, *, cleanup=False):
        r = self.record
        if (set(r) != {"v", "session", "context", "inventory", "source", "policy", "boot", "purpose", "cutoff", "expires"}
                or type(r["v"]) is not int or r["v"] != 2 or r["session"] != self.context.session
                or r["context"] != self.context.identifier or r["inventory"] != self.context.inventory
                or r["source"] != self.context.source_commit or r["policy"] != self.policy_digest
                or r["purpose"] != "one-probe-a-attempt" or r["cutoff"] != self.context.cutoff
                or r["expires"] != self.context.end or r["boot"] != self.boot_identity()
                or type(self.signature) is not bytes or self.verify(b"ProbeA attempt v2\x00"+canonical(r), self.signature) is not True
                or not self.clock() < (self.context.end if cleanup else self.context.cutoff)):
            return False
        return True

    def active(self, *, cleanup=False):
        return self.validate_approval(cleanup=cleanup) and self.ledger.committed(
            self.record, deadline=min(self.context.end, self.clock()+.5), native=True) is True


def provision_ledger(store, record, signature, *, verify, activated=False):
    """Separately gated source, unexecuted here. No directory creation.

    The approved provisioner first supplies a private root-owned directory.
    This narrow operation creates only the exclusive reviewed SQLite schema.
    Provisioning is neither inventory acceptance nor a runtime attempt.
    """
    expected = {"v": 1, "purpose": "provision-probe-a-ledger",
                "directory": list(store.directory_identity)}
    if (activated is not True or os.geteuid() != 0 or store.synthetic
            or record != expected or type(signature) is not bytes
            or verify(b"ProbeA ledger provisioning\x00"+canonical(expected), signature) is not True):
        raise SessionDenied("SEPARATE_LEDGER_PROVISIONING_APPROVAL_REQUIRED")
    store._initialize()


# Retains the reviewed AttemptPermit type at the existing bootstrap boundary.
from probe_a_integrated_bootstrap import AttemptPermit


class NativeAttemptPermit(AttemptPermit):
    def __init__(self, context, record, signature, *, verify, ledger, boot_identity,
                 policy_digest, clock=time.monotonic):
        super().__init__(context, record, signature, clock=clock)
        self.grant = ExistingAttemptGrant(context, record, signature, verify=verify,
            ledger=ledger, boot_identity=boot_identity, policy_digest=policy_digest, clock=clock)
        self.ledger = ledger

    def claim(self):
        if self.used:
            raise SessionDenied("NATIVE_ATTEMPT_ALREADY_CONSUMED")
        self.used = True  # all uncertain outcomes are irreversible for this object
        r = self.grant.record
        if not self.grant.validate_approval():
            raise SessionDenied("EXTERNAL_V2_ATTEMPT_INVALID")
        if self.ledger.synthetic:
            raise SessionDenied("NATIVE_ATTEMPT_REJECTS_SYNTHETIC_STORAGE")
        if self.ledger.claim_record(r, deadline=min(self.context.cutoff, self.clock()+.5)) is not True:
            raise SessionDenied("REPLAY_OR_UNCERTAIN_NATIVE_CLAIM")
        self.granted = True
        self._bootstrap_receipt = object()
        return self.active()

    def active(self, *, cleanup=False):
        return self.used and self.granted and self.grant.active(cleanup=cleanup)
