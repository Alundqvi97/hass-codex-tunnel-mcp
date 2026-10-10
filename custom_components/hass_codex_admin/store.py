"""Small transactional task store; mutation intent survives a process restart."""
from __future__ import annotations

import os
import re
from pathlib import Path
import sqlite3
import stat
import time
import uuid
from contextlib import contextmanager

from .model import AdminError, canonical, decode, fingerprint


class TaskStore:
    def retire_connectors(self):
        with self.transaction() as db:
            db.execute("DELETE FROM connectors")

    def __init__(self, directory, *, clock=time.time):
        self.clock = clock
        self.directory = Path(directory)
        self.directory.mkdir(mode=0o700, parents=True, exist_ok=True)
        info = self.directory.lstat()
        if not stat.S_ISDIR(info.st_mode) or info.st_uid != os.geteuid() or info.st_mode & 0o077:
            raise AdminError("private_storage_required")
        self.intents = self.directory / "connector_revocations"
        self.intents.mkdir(mode=0o700, exist_ok=True)
        info = self.intents.lstat()
        if not stat.S_ISDIR(info.st_mode) or info.st_uid != os.geteuid() or info.st_mode & 0o077:
            raise AdminError("private_storage_required")
        directory_fd = os.open(self.directory, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)
        try:
            os.fsync(directory_fd)
        finally:
            os.close(directory_fd)
        self.path = self.directory / "tasks.sqlite"
        if not self.path.exists():
            fd = os.open(self.path, os.O_RDWR | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o600)
            os.close(fd)
        self._inspect()
        with self.transaction() as db:
            version = db.execute("PRAGMA user_version").fetchone()[0]
            if version not in (0, 1, 2):
                raise AdminError("unsupported_storage_version")
            schema = """
              CREATE TABLE IF NOT EXISTS tasks(id TEXT PRIMARY KEY, user TEXT, session TEXT, policy TEXT, plan TEXT, hash TEXT, status TEXT, expires REAL, approved_by TEXT);
              CREATE TABLE IF NOT EXISTS operations(task TEXT, n INTEGER, status TEXT, before_state TEXT, after_state TEXT, result TEXT, PRIMARY KEY(task,n));
              CREATE TABLE IF NOT EXISTS approvers(session TEXT PRIMARY KEY, user TEXT);
              CREATE TABLE IF NOT EXISTS metadata(key TEXT PRIMARY KEY, value REAL);
              CREATE TABLE IF NOT EXISTS audit(n INTEGER PRIMARY KEY, task TEXT, event TEXT, timestamp REAL);
              CREATE TABLE IF NOT EXISTS connectors(id TEXT PRIMARY KEY, digest TEXT UNIQUE, owner_session TEXT, expires REAL, label TEXT);
              CREATE TABLE IF NOT EXISTS pending_connectors(id TEXT PRIMARY KEY, digest TEXT UNIQUE, owner_session TEXT, expires REAL, label TEXT);
              PRAGMA user_version=2;
            """
            for statement in schema.split(";"):
                if statement.strip():
                    db.execute(statement)

    def _inspect(self):
        try:
            info = self.path.lstat()
        except OSError:
            raise AdminError("storage_unavailable") from None
        if not stat.S_ISREG(info.st_mode) or info.st_uid != os.geteuid() or info.st_mode & 0o077 or info.st_nlink != 1:
            raise AdminError("private_storage_required")
        identity = (info.st_dev, info.st_ino)
        if hasattr(self, "identity") and self.identity != identity:
            raise AdminError("storage_replaced")
        self.identity = identity

    @contextmanager
    def transaction(self):
        self._inspect()
        db = None
        begun = False
        try:
            db = sqlite3.connect(self.path, timeout=.1, isolation_level=None)
            db.row_factory = sqlite3.Row
            db.execute("PRAGMA synchronous=FULL")
            db.execute("BEGIN IMMEDIATE")
            begun = True
            self._inspect()
            yield db
            db.execute("COMMIT")
        except sqlite3.OperationalError as exc:
            # A losing claim is bounded, not a second authorization or retry.
            busy = getattr(exc, "sqlite_errorcode", None) in (sqlite3.SQLITE_BUSY, sqlite3.SQLITE_LOCKED)
            raise AdminError("storage_transaction_uncertain" if begun else "storage_busy" if busy else "storage_unavailable") from None
        except sqlite3.DatabaseError:
            raise AdminError("storage_corrupt") from None
        finally:
            if db is not None:
                db.close()

    def _now(self, db):
        now = self.clock()
        row = db.execute("SELECT value FROM metadata WHERE key='clock'").fetchone()
        if row and now < row[0] - 1:
            raise AdminError("clock_moved_backwards")
        db.execute("INSERT OR REPLACE INTO metadata VALUES('clock',?)", (max(now, row[0] if row else now),))
        return now

    def create(self, actor, policy, plan, before, ttl):
        task = uuid.uuid4().hex
        with self.transaction() as db:
            now = self._now(db)
            # Expired approvals never regain authority. Retain thirty days of
            # recovery/audit history without an extra service or daily task.
            expired = [r[0] for r in db.execute("SELECT id FROM tasks WHERE expires<?", (now-30*86400,))]
            for old in expired:
                db.execute("DELETE FROM operations WHERE task=?", (old,))
                db.execute("DELETE FROM audit WHERE task=?", (old,))
                db.execute("DELETE FROM tasks WHERE id=?", (old,))
            if db.execute("SELECT count(*) FROM tasks").fetchone()[0] >= 10000:
                raise AdminError("storage_capacity")
            db.execute("INSERT INTO tasks VALUES(?,?,?,?,?,?,?,?,'')", (task, actor.user, actor.session, policy, canonical(plan), fingerprint(plan), "pending", now+ttl))
            for n, value in enumerate(before):
                db.execute("INSERT INTO operations VALUES(?,?,'pending',?,NULL,NULL)", (task, n, canonical(value)))
            db.execute("INSERT INTO audit(task,event,timestamp) VALUES(?,'proposed',?)", (task, now))
        return task

    def get(self, task):
        with self.transaction() as db:
            row = db.execute("SELECT * FROM tasks WHERE id=?", (task,)).fetchone()
            if row is None:
                raise AdminError("task_not_found")
            result = dict(row);result["plan"] = decode(result["plan"])
            if fingerprint(result["plan"]) != result["hash"]:
                raise AdminError("stored_plan_integrity")
            result["operations"] = [dict(r) for r in db.execute("SELECT * FROM operations WHERE task=? ORDER BY n", (task,))]
            for op in result["operations"]:
                for key in ("before_state", "after_state", "result"):
                    op[key] = decode(op[key]) if op[key] is not None else None
            if len(result["operations"]) != len(result["plan"]["operations"]) or any(fingerprint(op["before_state"]) != fingerprint(result["plan"]["before"][op["n"]]) for op in result["operations"]):
                raise AdminError("stored_plan_integrity")
            return result

    def list_tasks(self):
        with self.transaction() as db:
            return [r[0] for r in db.execute("SELECT id FROM tasks ORDER BY rowid DESC LIMIT 10")]

    def enroll(self, actor):
        with self.transaction() as db:
            db.execute("INSERT OR REPLACE INTO approvers VALUES(?,?)", (actor.session, actor.user))

    def connectors(self):
        with self.transaction() as db:
            return [dict(r) for r in db.execute("SELECT * FROM connectors")]

    def _intent_path(self, identifier):
        if type(identifier) is not str or not re.fullmatch(r"[a-f0-9]{32}", identifier):
            raise AdminError("invalid_connector_id")
        return self.intents / identifier

    def _revocation_ids(self):
        # Corrupt/unexpected intent storage blocks renewal; it is not ignored.
        identifiers = []
        for path in self.intents.iterdir():
            self._intent_path(path.name)
            info = path.lstat()
            if not stat.S_ISREG(info.st_mode) or info.st_uid != os.geteuid() or info.st_mode & 0o077 or info.st_nlink != 1 or info.st_size != 0:
                raise AdminError("invalid_revocation_storage")
            identifiers.append(path.name)
            if len(identifiers) > 10000:
                raise AdminError("revocation_storage_capacity")
        return identifiers

    def begin_connector_revoke(self, identifier):
        path = self._intent_path(identifier)
        revoked = self._revocation_ids()
        if len(revoked) >= 10000 and identifier not in revoked:
            raise AdminError("revocation_storage_capacity")
        fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_NOFOLLOW, 0o600)
        try:
            info = os.fstat(fd)
            if not stat.S_ISREG(info.st_mode) or info.st_uid != os.geteuid() or info.st_mode & 0o077 or info.st_nlink != 1 or info.st_size:
                raise AdminError("invalid_revocation_storage")
            os.fsync(fd)
        finally:
            os.close(fd)
        self._sync_intents()

    def _sync_intents(self):
        fd = os.open(self.intents, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)
        try:
            os.fsync(fd)
        finally:
            os.close(fd)

    def activate_connectors(self):
        """At boot settle durable denies before rotating stable connection IDs.

        Pending issuance never renews. Markers survive in-process cancellation
        and late executor commits; only a later boot retires them after deletion.
        """
        import hashlib
        import secrets
        revoked = self._revocation_ids()
        with self.transaction() as db:
            db.execute("DELETE FROM pending_connectors")
            for identifier in revoked:
                db.execute("DELETE FROM connectors WHERE id=?", (identifier,))
            rows = [dict(r) for r in db.execute("SELECT * FROM connectors")]
            for row in rows:
                row["credential"] = "hca_"+secrets.token_urlsafe(32)
                row["digest"] = hashlib.sha256(row["credential"].encode()).hexdigest()
                db.execute("UPDATE connectors SET digest=? WHERE id=?", (row["digest"], row["id"]))
        for identifier in revoked:
            self._intent_path(identifier).unlink()
        self._sync_intents()
        return rows

    def save_connector(self, identifier, digest, owner_session, expires, label):
        self._intent_path(identifier)
        with self.transaction() as db:
            if self._intent_path(identifier).exists():
                raise AdminError("connector_revoked_or_expired")
            if db.execute("SELECT (SELECT count(*) FROM connectors)+(SELECT count(*) FROM pending_connectors)").fetchone()[0] >= 32:
                raise AdminError("connector_capacity")
            db.execute("INSERT INTO pending_connectors VALUES(?,?,?,?,?)", (identifier, digest, owner_session, expires, label))

    def confirm_connector(self, identifier):
        with self.transaction() as db:
            if self._intent_path(identifier).exists():
                raise AdminError("connector_revoked_or_expired")
            if db.execute("INSERT INTO connectors SELECT * FROM pending_connectors WHERE id=?", (identifier,)).rowcount != 1:
                raise AdminError("connector_issuance_incomplete")
            db.execute("DELETE FROM pending_connectors WHERE id=?", (identifier,))

    def revoke_connector(self, identifier):
        # Persist intent before SQL. Keep it until boot so a late issuance
        # transaction cannot undo cancellation or revocation.
        self.begin_connector_revoke(identifier)
        with self.transaction() as db:
            db.execute("DELETE FROM connectors WHERE id=?", (identifier,))
            db.execute("DELETE FROM pending_connectors WHERE id=?", (identifier,))

    def retire_grants(self):
        """HA boot/restore never revives a saved approval or enrollment."""
        with self.transaction() as db:
            now = self._now(db)
            for row in db.execute("SELECT id FROM tasks WHERE status IN ('approved','pending')").fetchall():
                db.execute("INSERT INTO audit(task,event,timestamp) VALUES(?,'startup_authority_retired',?)", (row[0], now))
            db.execute("UPDATE tasks SET status='revoked' WHERE status IN ('approved','pending')")
            db.execute("DELETE FROM approvers")

    def decide(self, task, actor, expected_hash, decision):
        if decision not in {"approved", "revoked"}:
            raise AdminError("invalid_decision")
        with self.transaction() as db:
            now = self._now(db)
            row = db.execute("SELECT * FROM tasks WHERE id=?", (task,)).fetchone()
            if not row or row["hash"] != expected_hash or (decision == "approved" and now >= row["expires"]):
                raise AdminError("task_changed_or_expired")
            if actor.session == row["session"] or not db.execute("SELECT 1 FROM approvers WHERE session=? AND user=?", (actor.session, actor.user)).fetchone():
                raise AdminError("independent_enrolled_approver_required")
            if decision == "approved" and row["status"] != "pending":
                raise AdminError("approval_not_reusable")
            db.execute("UPDATE tasks SET status=?,approved_by=? WHERE id=?", (decision, actor.session, task))
            db.execute("INSERT INTO audit(task,event,timestamp) VALUES(?,?,?)", (task, decision, now))

    def claim(self, task, n, actor, policy, expected_hash, *, rollback=False):
        with self.transaction() as db:
            now = self._now(db)
            row = db.execute("SELECT * FROM tasks WHERE id=?", (task,)).fetchone()
            if not row or (row["user"], row["session"], row["policy"], row["hash"]) != (actor.user, actor.session, policy, expected_hash):
                raise AdminError("caller_scope_or_policy_changed")
            if row["status"] != "approved" or now >= row["expires"]:
                raise AdminError("approval_required_or_expired")
            current = db.execute("SELECT status FROM operations WHERE task=? AND n=?", (task, n)).fetchone()
            allowed = {"applied"} if rollback else {"pending"}
            if not current or current[0] not in allowed:
                raise AdminError("operation_consumed_or_uncertain")
            if not rollback and db.execute("SELECT 1 FROM operations WHERE task=? AND n<? AND status!='applied'", (task,n)).fetchone():
                raise AdminError("operation_order")
            if rollback and db.execute("SELECT 1 FROM operations WHERE task=? AND n>? AND status='applied'", (task,n)).fetchone():
                raise AdminError("rollback_order")
            db.execute("UPDATE operations SET status=? WHERE task=? AND n=?", ("rolling_back" if rollback else "dispatching", task, n))
            db.execute("UPDATE operations SET result=? WHERE task=? AND n=?", (canonical({"rollback": rollback}), task, n))
            db.execute("INSERT INTO audit(task,event,timestamp) VALUES(?,?,?)", (task, "rollback_started" if rollback else "dispatch_started", now))

    def acknowledge(self, task, n, result, *, expected):
        # Capture a received mutation acknowledgement before independent
        # readback. A missing response never creates an ownership receipt.
        with self.transaction() as db:
            changed = db.execute("UPDATE operations SET result=? WHERE task=? AND n=? AND status=?", (canonical(result), task, n, expected))
            if changed.rowcount != 1:
                raise AdminError("stale_operation_completion")

    def finish(self, task, n, status, after, result, *, expected):
        # A to_thread transaction may finish after caller cancellation. Its
        # result must never overwrite a later reconciliation or rollback.
        if expected not in {"dispatching", "rolling_back", "uncertain"} or status not in {"applied", "rolled_back", "uncertain"}:
            raise AdminError("invalid_operation_transition")
        with self.transaction() as db:
            changed = db.execute("UPDATE operations SET status=?,after_state=?,result=? WHERE task=? AND n=? AND status=?", (status, canonical(after), canonical(result), task, n, expected))
            if changed.rowcount != 1:
                raise AdminError("stale_operation_completion")
            db.execute("INSERT INTO audit(task,event,timestamp) VALUES(?,?,?)", (task, status, self._now(db)))

    def authorize(self, task, actor, policy, expected_hash):
        """Final grant check after the durable claim, before backend dispatch."""
        with self.transaction() as db:
            row = db.execute("SELECT * FROM tasks WHERE id=?", (task,)).fetchone()
            if not row or (row["user"], row["session"], row["policy"], row["hash"]) != (actor.user, actor.session, policy, expected_hash):
                raise AdminError("caller_scope_or_policy_changed")
            if row["status"] != "approved" or self._now(db) >= row["expires"]:
                raise AdminError("approval_required_or_expired")
