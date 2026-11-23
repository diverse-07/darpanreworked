"""Local station identity, role permissions, encrypted cases, and activity log."""
from __future__ import annotations

import getpass
import hashlib
import hmac
import json
import os
import re
import secrets
import sqlite3
import time
from contextlib import closing
from datetime import datetime, timezone
from pathlib import Path
from uuid import uuid4

from cryptography.fernet import Fernet, InvalidToken

ROLES = {
    "investigator": frozenset({"view", "import", "query", "export", "create"}),
    "reviewer": frozenset({"view", "query", "export", "review"}),
}
USER = re.compile(r"[a-zA-Z0-9][a-zA-Z0-9._-]{2,63}\Z")


def password_hash(password, salt):
    return hashlib.scrypt(password.encode("utf-8"), salt=bytes.fromhex(salt), n=2**14, r=8, p=1).hex()


class Station:
    def __init__(self, directory, key_path=None, *, bootstrap=False):
        self.directory = Path(directory).expanduser()
        self.database = self.directory / "station.sqlite3"
        self.key_path = Path(key_path).expanduser() if key_path else self.directory / "station.key"
        if bootstrap:
            self.directory.mkdir(mode=0o700, parents=True, exist_ok=True)
            self.key_path.parent.mkdir(mode=0o700, parents=True, exist_ok=True)
            if not self.key_path.exists():
                if self.database.exists():
                    raise ValueError("The station key is missing. Restore the original key before opening this vault.")
                fd = os.open(self.key_path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
                with os.fdopen(fd, "wb") as key_file:
                    key_file.write(Fernet.generate_key())
        if not self.key_path.is_file() or (not bootstrap and not self.database.is_file()):
            raise ValueError("Station vault is not initialized. Create the first station account with the CLI.")
        self.cipher = Fernet(self.key_path.read_bytes().strip())
        if bootstrap:
            with closing(self.connect()) as db, db:
                db.executescript("""
                    CREATE TABLE IF NOT EXISTS users(
                        username TEXT PRIMARY KEY, role TEXT NOT NULL, salt TEXT NOT NULL, digest TEXT NOT NULL,
                        failures INTEGER NOT NULL DEFAULT 0, retry_at REAL NOT NULL DEFAULT 0
                    );
                    CREATE TABLE IF NOT EXISTS cases(
                        id TEXT PRIMARY KEY, label BLOB NOT NULL, revision INTEGER NOT NULL, payload BLOB NOT NULL
                    );
                    CREATE TABLE IF NOT EXISTS activity(
                        sequence INTEGER PRIMARY KEY, at TEXT NOT NULL, event BLOB NOT NULL
                    );
                """)

    def connect(self):
        db = sqlite3.connect(self.database, timeout=10)
        db.row_factory = sqlite3.Row
        return db

    def seal(self, value):
        return self.cipher.encrypt(json.dumps(value, ensure_ascii=False, separators=(",", ":")).encode())

    def unseal(self, data):
        try:
            return json.loads(self.cipher.decrypt(data))
        except (InvalidToken, ValueError) as error:
            raise ValueError("The station key could not verify the encrypted record.") from error

    def add_account(self, username, role, password):
        if not USER.fullmatch(username) or role not in ROLES or len(password) < 12:
            raise ValueError("Use a 3–64 character account name and a password of at least 12 characters.")
        salt = secrets.token_hex(16)
        with closing(self.connect()) as db, db:
            db.execute("INSERT INTO users(username,role,salt,digest) VALUES(?,?,?,?)",
                       (username.casefold(), role, salt, password_hash(password, salt)))
        self.log(username.casefold(), "account_created", role=role)

    def authenticate(self, username, password):
        username = username.strip().casefold()
        if not USER.fullmatch(username) or len(password) > 1024:
            self.log("unknown", "login_failed")
            return None
        with closing(self.connect()) as db, db:
            db.execute("BEGIN IMMEDIATE")
            row = db.execute("SELECT * FROM users WHERE username=?", (username,)).fetchone()
            now = time.time()
            valid = False
            if row and row["retry_at"] <= now:
                valid = hmac.compare_digest(password_hash(password, row["salt"]), row["digest"])
                if valid:
                    db.execute("UPDATE users SET failures=0,retry_at=0 WHERE username=?", (username,))
                else:
                    failures = row["failures"] + 1
                    retry = now + min(300, 2 ** min(8, failures)) if failures >= 3 else now
                    db.execute("UPDATE users SET failures=?,retry_at=? WHERE username=?", (failures, retry, username))
            elif row is None:
                password_hash(password, "0" * 32)
        self.log(username, "login_succeeded" if valid else "login_failed")
        return {"username": username, "role": row["role"]} if valid else None

    @staticmethod
    def allows(identity, action):
        return action in ROLES.get(identity.get("role"), ())

    def require(self, identity, action):
        if not self.allows(identity, action):
            raise PermissionError(f"The {identity.get('role', 'guest')} role cannot {action}.")

    def list_cases(self, identity):
        self.require(identity, "view")
        with closing(self.connect()) as db:
            return [(r["id"], self.unseal(r["label"])["label"])
                    for r in db.execute("SELECT id,label FROM cases ORDER BY rowid DESC")]

    def create(self, identity, label, payload):
        self.require(identity, "create")
        case_id = uuid4().hex
        with closing(self.connect()) as db, db:
            db.execute("INSERT INTO cases VALUES(?,?,?,?)",
                       (case_id, self.seal({"label": label}), 1, self.seal(payload)))
        self.log(identity["username"], "case_created", case_id=case_id)
        return case_id, 1

    def load(self, identity, case_id):
        self.require(identity, "view")
        with closing(self.connect()) as db:
            row = db.execute("SELECT revision,payload FROM cases WHERE id=?", (case_id,)).fetchone()
        if row is None:
            raise ValueError("The selected station case no longer exists.")
        self.log(identity["username"], "case_opened", case_id=case_id)
        return row["revision"], self.unseal(row["payload"])

    def save(self, identity, case_id, revision, payload, action):
        self.require(identity, action)
        with closing(self.connect()) as db, db:
            change = db.execute("UPDATE cases SET revision=?,payload=? WHERE id=? AND revision=?",
                                (revision + 1, self.seal(payload), case_id, revision))
            if change.rowcount != 1:
                raise ValueError("Another session updated this case. Reopen it and retry your change.")
        return revision + 1

    def log(self, actor, action, **details):
        timestamp = datetime.now(timezone.utc).isoformat(timespec="seconds")
        event = dict(actor=actor, action=action, **details)
        with closing(self.connect()) as db, db:
            db.execute("INSERT INTO activity(at,event) VALUES(?,?)", (timestamp, self.seal(event)))

    def activity(self, identity, *, case_id=None):
        self.require(identity, "view")
        with closing(self.connect()) as db:
            rows = []
            for row in db.execute("SELECT sequence,at,event FROM activity ORDER BY sequence DESC LIMIT 500"):
                event = self.unseal(row["event"])
                if event.get("case_id") == case_id and (identity["role"] == "reviewer" or event["actor"] == identity["username"]):
                    rows.append({"Sequence": row["sequence"], "UTC": row["at"], "Actor": event["actor"],
                                 "Action": event["action"], "Details": json.dumps({k: v for k, v in event.items()
                                 if k not in {"actor", "action", "case_id"}}, ensure_ascii=False)})
            return rows


def station_path():
    return Path(os.getenv("DARPAN_STATION_DIR", str(Path.home() / ".darpan-station")))


def setup_account(args):
    station = Station(args.station, os.getenv("DARPAN_KEY_FILE"), bootstrap=True)
    first = getpass.getpass("Account password (at least 12 characters): ")
    second = getpass.getpass("Confirm password: ")
    if first != second:
        raise SystemExit("Passwords did not match.")
    station.add_account(args.username, args.role, first)
    print(f"Created {args.role} account {args.username} for {args.station}.")
