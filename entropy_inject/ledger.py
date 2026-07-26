"""Encrypted local ledger mapping entropy tokens back to real provenance.

Each ledger entry stores:
  - token (plaintext; the lookup key)
  - input_hash, output_hash, binding (plaintext; needed for verification)
  - timestamp (plaintext)
  - signature, verify_key (plaintext; empty unless injected with --sign)
  - ciphertext — XChaCha20-Poly1305 encryption of the original-metadata
    snapshot and user notes, keyed from the passphrase via Argon2id

The passphrase is never stored.  A random salt lives next to the DB and
is required to derive the key.  Back up salt + DB together.

Portable transfer
-----------------
Use ``export_bundle`` / ``import_bundle`` to move entries between devices.
The bundle re-encrypts every entry under an export passphrase so the
owner's main passphrase is never included in the bundle.
"""
from __future__ import annotations

import base64
import json
import os
import sqlite3
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Iterator

import nacl.pwhash
import nacl.secret
import nacl.utils


DEFAULT_DB_PATH = Path.home() / ".entropy-ledger" / "ledger.db"
SALT_FILENAME = "salt.bin"
BUNDLE_VERSION = 1


@dataclass
class LedgerEntry:
    token: str
    input_hash: str
    output_hash: str
    binding: str
    timestamp: str
    original_metadata: dict[str, Any] = field(default_factory=dict)
    notes: str = ""
    signature: str = ""    # Ed25519 hex signature (empty if not signed)
    verify_key: str = ""   # Ed25519 hex verify key (empty if not signed)


class Ledger:
    """Encrypted append-mostly ledger.

    Typical use::

        with Ledger.open("my-passphrase") as ledger:
            ledger.append(entry)
            found = ledger.lookup(token)
    """

    def __init__(self, conn: sqlite3.Connection, key: bytes):
        self._conn = conn
        self._box = nacl.secret.SecretBox(key)
        self._ensure_schema()

    # ---- construction --------------------------------------------------

    @classmethod
    def open(
        cls,
        passphrase: str,
        db_path: str | Path | None = None,
        *,
        _opslimit: int | None = None,
        _memlimit: int | None = None,
    ) -> "Ledger":
        """Open (or create) the ledger at *db_path*.

        The first call generates a random salt and writes
        ``~/.entropy-ledger/salt.bin`` (mode 0o600).  Subsequent calls
        reuse the salt so the key derives deterministically.
        """
        db_path = Path(db_path) if db_path else DEFAULT_DB_PATH
        db_path.parent.mkdir(parents=True, exist_ok=True)

        salt_path = db_path.parent / SALT_FILENAME
        if salt_path.exists():
            salt = salt_path.read_bytes()
        else:
            salt = nacl.utils.random(nacl.pwhash.argon2id.SALTBYTES)
            try:
                fd = os.open(
                    str(salt_path), os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600
                )
                try:
                    os.write(fd, salt)
                finally:
                    os.close(fd)
            except OSError:
                salt_path.write_bytes(salt)
                try:
                    salt_path.chmod(0o600)
                except Exception:
                    pass

        key = nacl.pwhash.argon2id.kdf(
            nacl.secret.SecretBox.KEY_SIZE,
            passphrase.encode("utf-8"),
            salt,
            opslimit=_opslimit or nacl.pwhash.argon2id.OPSLIMIT_MODERATE,
            memlimit=_memlimit or nacl.pwhash.argon2id.MEMLIMIT_MODERATE,
        )

        old_umask = os.umask(0o177)
        try:
            conn = sqlite3.connect(str(db_path))
        finally:
            os.umask(old_umask)
        conn.execute("PRAGMA journal_mode=WAL")
        return cls(conn, key)

    def _ensure_schema(self) -> None:
        self._conn.execute(
            """
            CREATE TABLE IF NOT EXISTS entries (
                token         TEXT PRIMARY KEY,
                input_hash    TEXT NOT NULL,
                output_hash   TEXT NOT NULL,
                binding       TEXT NOT NULL,
                timestamp     TEXT NOT NULL,
                ciphertext    BLOB NOT NULL,
                signature     TEXT NOT NULL DEFAULT '',
                verify_key    TEXT NOT NULL DEFAULT ''
            )
            """
        )
        # Migrate databases created before signature support was added.
        existing = {
            row[1]
            for row in self._conn.execute("PRAGMA table_info(entries)")
        }
        for col in ("signature", "verify_key"):
            if col not in existing:
                self._conn.execute(
                    f"ALTER TABLE entries ADD COLUMN {col} TEXT NOT NULL DEFAULT ''"
                )
        self._conn.commit()

    # ---- core ops ------------------------------------------------------

    def append(self, entry: LedgerEntry) -> None:
        """Insert a new entry.  Raises ``sqlite3.IntegrityError`` on duplicate token."""
        payload = json.dumps(
            {"original_metadata": entry.original_metadata, "notes": entry.notes},
            ensure_ascii=False,
        ).encode("utf-8")
        ciphertext = self._box.encrypt(payload)
        self._conn.execute(
            """
            INSERT INTO entries
                (token, input_hash, output_hash, binding, timestamp,
                 ciphertext, signature, verify_key)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?)
            """,
            (
                entry.token,
                entry.input_hash,
                entry.output_hash,
                entry.binding,
                entry.timestamp,
                ciphertext,
                entry.signature,
                entry.verify_key,
            ),
        )
        self._conn.commit()

    def lookup(self, token: str) -> LedgerEntry | None:
        row = self._conn.execute(
            "SELECT token, input_hash, output_hash, binding, timestamp,"
            " ciphertext, signature, verify_key"
            " FROM entries WHERE token = ?",
            (token,),
        ).fetchone()
        return None if row is None else self._row_to_entry(row)

    def all_entries(self) -> Iterator[LedgerEntry]:
        cur = self._conn.execute(
            "SELECT token, input_hash, output_hash, binding, timestamp,"
            " ciphertext, signature, verify_key"
            " FROM entries ORDER BY timestamp ASC"
        )
        for row in cur:
            yield self._row_to_entry(row)

    def verify(self, token: str, current_file_hash: str) -> bool:
        """Return True iff the file is one of the two known-good versions
        (original input or sanitised output) recorded in the ledger.
        """
        entry = self.lookup(token)
        if entry is None:
            return False
        return current_file_hash in (entry.input_hash, entry.output_hash)

    def delete(self, token: str) -> bool:
        """Delete the entry for *token*.  Returns True if it existed."""
        cur = self._conn.execute(
            "DELETE FROM entries WHERE token = ?", (token,)
        )
        self._conn.commit()
        return cur.rowcount > 0

    def update_notes(self, token: str, notes: str) -> bool:
        """Replace the notes for *token* with *notes*.

        The original-metadata snapshot is preserved; only the notes field
        is updated.  Returns True if the entry existed.
        """
        entry = self.lookup(token)
        if entry is None:
            return False
        payload = json.dumps(
            {"original_metadata": entry.original_metadata, "notes": notes},
            ensure_ascii=False,
        ).encode("utf-8")
        ciphertext = self._box.encrypt(payload)
        self._conn.execute(
            "UPDATE entries SET ciphertext = ? WHERE token = ?",
            (ciphertext, token),
        )
        self._conn.commit()
        return True

    # ---- portable export / import -------------------------------------

    def export_bundle(
        self,
        bundle_path: str | Path,
        export_passphrase: str,
        *,
        _opslimit: int | None = None,
        _memlimit: int | None = None,
    ) -> int:
        """Export all entries to an encrypted portable bundle.

        Each entry's sensitive payload (metadata + notes) is re-encrypted
        under *export_passphrase* with a fresh random salt, so the bundle
        is self-contained and the owner's main passphrase is never exposed.

        Returns the number of entries exported.
        """
        bundle_path = Path(bundle_path)

        export_salt = nacl.utils.random(nacl.pwhash.argon2id.SALTBYTES)
        export_key = nacl.pwhash.argon2id.kdf(
            nacl.secret.SecretBox.KEY_SIZE,
            export_passphrase.encode("utf-8"),
            export_salt,
            opslimit=_opslimit or nacl.pwhash.argon2id.OPSLIMIT_MODERATE,
            memlimit=_memlimit or nacl.pwhash.argon2id.MEMLIMIT_MODERATE,
        )
        export_box = nacl.secret.SecretBox(export_key)

        records = []
        for entry in self.all_entries():
            payload = json.dumps(
                {"original_metadata": entry.original_metadata, "notes": entry.notes},
                ensure_ascii=False,
            ).encode("utf-8")
            ct = export_box.encrypt(payload)
            records.append(
                {
                    "token": entry.token,
                    "input_hash": entry.input_hash,
                    "output_hash": entry.output_hash,
                    "binding": entry.binding,
                    "timestamp": entry.timestamp,
                    "signature": entry.signature,
                    "verify_key": entry.verify_key,
                    "ciphertext": base64.b64encode(ct).decode(),
                }
            )

        bundle = {
            "version": BUNDLE_VERSION,
            "salt": base64.b64encode(export_salt).decode(),
            "entries": records,
        }
        bundle_path.write_text(json.dumps(bundle, indent=2, ensure_ascii=False))
        return len(records)

    @classmethod
    def import_bundle(
        cls,
        bundle_path: str | Path,
        export_passphrase: str,
        target_ledger: "Ledger",
        *,
        skip_duplicates: bool = True,
        _opslimit: int | None = None,
        _memlimit: int | None = None,
    ) -> tuple[int, int]:
        """Import entries from a bundle into *target_ledger*.

        Decrypts using *export_passphrase* + the bundle's embedded salt,
        then re-encrypts under the target ledger's key.

        Returns ``(imported_count, skipped_count)``.
        """
        bundle_path = Path(bundle_path)
        bundle = json.loads(bundle_path.read_text())

        if bundle.get("version") != BUNDLE_VERSION:
            raise ValueError(
                f"unsupported bundle version: {bundle.get('version')!r}"
            )

        export_salt = base64.b64decode(bundle["salt"])
        export_key = nacl.pwhash.argon2id.kdf(
            nacl.secret.SecretBox.KEY_SIZE,
            export_passphrase.encode("utf-8"),
            export_salt,
            opslimit=_opslimit or nacl.pwhash.argon2id.OPSLIMIT_MODERATE,
            memlimit=_memlimit or nacl.pwhash.argon2id.MEMLIMIT_MODERATE,
        )
        export_box = nacl.secret.SecretBox(export_key)

        imported = skipped = 0
        for rec in bundle["entries"]:
            if skip_duplicates and target_ledger.lookup(rec["token"]) is not None:
                skipped += 1
                continue
            ct = base64.b64decode(rec["ciphertext"])
            plaintext = export_box.decrypt(ct)
            payload = json.loads(plaintext.decode("utf-8"))
            entry = LedgerEntry(
                token=rec["token"],
                input_hash=rec["input_hash"],
                output_hash=rec["output_hash"],
                binding=rec["binding"],
                timestamp=rec["timestamp"],
                signature=rec.get("signature", ""),
                verify_key=rec.get("verify_key", ""),
                original_metadata=payload.get("original_metadata", {}),
                notes=payload.get("notes", ""),
            )
            target_ledger.append(entry)
            imported += 1

        return imported, skipped

    # ---- internals -----------------------------------------------------

    def _row_to_entry(self, row: tuple) -> LedgerEntry:
        (
            token, input_hash, output_hash, binding,
            timestamp, ciphertext, signature, verify_key,
        ) = row
        plaintext = self._box.decrypt(ciphertext)
        payload = json.loads(plaintext.decode("utf-8"))
        return LedgerEntry(
            token=token,
            input_hash=input_hash,
            output_hash=output_hash,
            binding=binding,
            timestamp=timestamp,
            original_metadata=payload.get("original_metadata", {}),
            notes=payload.get("notes", ""),
            signature=signature or "",
            verify_key=verify_key or "",
        )

    # ---- lifecycle -----------------------------------------------------

    def close(self) -> None:
        self._conn.close()

    def __enter__(self) -> "Ledger":
        return self

    def __exit__(self, exc_type, exc, tb) -> None:
        self.close()
