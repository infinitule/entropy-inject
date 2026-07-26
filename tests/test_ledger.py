"""Tests for entropy_inject.ledger."""
from __future__ import annotations

import pytest

from entropy_inject.ledger import Ledger, LedgerEntry
from .conftest import EXPORT_PASSPHRASE, PASSPHRASE


def _make_entry(**kwargs) -> LedgerEntry:
    defaults = dict(
        token="a" * 64,
        input_hash="b" * 64,
        output_hash="c" * 64,
        binding="d" * 64,
        timestamp="2024-01-01T00:00:00+00:00",
        original_metadata={"info": {"/Author": "Alice"}},
        notes="test note",
        signature="",
        verify_key="",
    )
    defaults.update(kwargs)
    return LedgerEntry(**defaults)


class TestOpenAndSchema:
    def test_creates_db(self, ledger_dir):
        db = ledger_dir / "l.db"
        with Ledger.open(PASSPHRASE, db_path=db) as ledger:
            pass
        assert db.exists()

    def test_creates_salt(self, ledger_dir):
        db = ledger_dir / "l.db"
        with Ledger.open(PASSPHRASE, db_path=db):
            pass
        assert (ledger_dir / "salt.bin").exists()

    def test_salt_permissions(self, ledger_dir):
        import stat
        db = ledger_dir / "l.db"
        with Ledger.open(PASSPHRASE, db_path=db):
            pass
        mode = (ledger_dir / "salt.bin").stat().st_mode
        assert not (mode & stat.S_IRGRP)
        assert not (mode & stat.S_IROTH)

    def test_reopen_same_key(self, open_ledger):
        entry = _make_entry()
        with open_ledger() as l:
            l.append(entry)
        with open_ledger() as l:
            found = l.lookup(entry.token)
        assert found is not None
        assert found.notes == "test note"


class TestAppendAndLookup:
    def test_roundtrip(self, open_ledger):
        entry = _make_entry(notes="hello world")
        with open_ledger() as l:
            l.append(entry)
            found = l.lookup(entry.token)
        assert found.token == entry.token
        assert found.notes == "hello world"
        assert found.original_metadata == entry.original_metadata

    def test_lookup_missing(self, open_ledger):
        with open_ledger() as l:
            assert l.lookup("0" * 64) is None

    def test_duplicate_raises(self, open_ledger):
        import sqlite3
        entry = _make_entry()
        with open_ledger() as l:
            l.append(entry)
            with pytest.raises(sqlite3.IntegrityError):
                l.append(entry)

    def test_signature_stored(self, open_ledger):
        entry = _make_entry(signature="sig" * 20, verify_key="vk" * 20)
        with open_ledger() as l:
            l.append(entry)
            found = l.lookup(entry.token)
        assert found.signature == entry.signature
        assert found.verify_key == entry.verify_key


class TestAllEntries:
    def test_ordering(self, open_ledger):
        entries = [
            _make_entry(token="a" * 64, timestamp="2024-01-01T00:00:00+00:00"),
            _make_entry(token="b" * 64, timestamp="2024-01-02T00:00:00+00:00"),
            _make_entry(token="c" * 64, timestamp="2024-01-03T00:00:00+00:00"),
        ]
        with open_ledger() as l:
            for e in entries:
                l.append(e)
            result = list(l.all_entries())
        assert [e.token for e in result] == [e.token for e in entries]

    def test_empty(self, open_ledger):
        with open_ledger() as l:
            assert list(l.all_entries()) == []


class TestVerify:
    def test_matches_input_hash(self, open_ledger):
        entry = _make_entry()
        with open_ledger() as l:
            l.append(entry)
            assert l.verify(entry.token, entry.input_hash) is True

    def test_matches_output_hash(self, open_ledger):
        entry = _make_entry()
        with open_ledger() as l:
            l.append(entry)
            assert l.verify(entry.token, entry.output_hash) is True

    def test_wrong_hash(self, open_ledger):
        entry = _make_entry()
        with open_ledger() as l:
            l.append(entry)
            assert l.verify(entry.token, "e" * 64) is False

    def test_unknown_token(self, open_ledger):
        with open_ledger() as l:
            assert l.verify("0" * 64, "anything") is False


class TestDelete:
    def test_deletes_existing(self, open_ledger):
        entry = _make_entry()
        with open_ledger() as l:
            l.append(entry)
            assert l.delete(entry.token) is True
            assert l.lookup(entry.token) is None

    def test_returns_false_for_missing(self, open_ledger):
        with open_ledger() as l:
            assert l.delete("0" * 64) is False


class TestUpdateNotes:
    def test_updates(self, open_ledger):
        entry = _make_entry(notes="old")
        with open_ledger() as l:
            l.append(entry)
            assert l.update_notes(entry.token, "new") is True
            found = l.lookup(entry.token)
        assert found.notes == "new"

    def test_preserves_metadata(self, open_ledger):
        meta = {"info": {"/Author": "Bob"}}
        entry = _make_entry(original_metadata=meta)
        with open_ledger() as l:
            l.append(entry)
            l.update_notes(entry.token, "updated")
            found = l.lookup(entry.token)
        assert found.original_metadata == meta

    def test_missing_token(self, open_ledger):
        with open_ledger() as l:
            assert l.update_notes("0" * 64, "x") is False


class TestExportImport:
    def test_roundtrip(self, open_ledger, tmp_path):
        entries = [
            _make_entry(token="a" * 64, notes="note-a"),
            _make_entry(token="b" * 64, notes="note-b"),
        ]
        bundle = tmp_path / "bundle.json"

        with open_ledger() as src:
            for e in entries:
                src.append(e)
            count = src.export_bundle(bundle, EXPORT_PASSPHRASE)
        assert count == 2

        target_db = tmp_path / "target.db"
        with Ledger.open(PASSPHRASE, db_path=target_db) as dst:
            imported, skipped = Ledger.import_bundle(
                bundle, EXPORT_PASSPHRASE, dst
            )
        assert imported == 2
        assert skipped == 0

        with Ledger.open(PASSPHRASE, db_path=target_db) as dst:
            for e in entries:
                found = dst.lookup(e.token)
                assert found is not None
                assert found.notes == e.notes

    def test_skip_duplicates(self, open_ledger, tmp_path):
        entry = _make_entry()
        bundle = tmp_path / "bundle.json"

        with open_ledger() as src:
            src.append(entry)
            src.export_bundle(bundle, EXPORT_PASSPHRASE)

        with open_ledger() as dst:
            _, skipped = Ledger.import_bundle(bundle, EXPORT_PASSPHRASE, dst)
        assert skipped == 1

    def test_wrong_passphrase_raises(self, open_ledger, tmp_path):
        from nacl.exceptions import CryptoError
        entry = _make_entry()
        bundle = tmp_path / "bundle.json"
        with open_ledger() as src:
            src.append(entry)
            src.export_bundle(bundle, EXPORT_PASSPHRASE)
        target_db = tmp_path / "t.db"
        with Ledger.open(PASSPHRASE, db_path=target_db) as dst:
            with pytest.raises((CryptoError, Exception)):
                Ledger.import_bundle(bundle, "wrong-passphrase", dst)

    def test_wrong_version_raises(self, open_ledger, tmp_path):
        import json
        bundle = tmp_path / "bundle.json"
        bundle.write_text(json.dumps({"version": 99, "salt": "", "entries": []}))
        target_db = tmp_path / "t.db"
        with Ledger.open(PASSPHRASE, db_path=target_db) as dst:
            with pytest.raises(ValueError):
                Ledger.import_bundle(bundle, EXPORT_PASSPHRASE, dst)

    def test_wrong_main_passphrase_raises_on_decrypt(self, ledger_dir):
        from nacl.exceptions import CryptoError
        db = ledger_dir / "ledger.db"
        entry = _make_entry()
        with Ledger.open(PASSPHRASE, db_path=db) as l:
            l.append(entry)
        # Open with wrong passphrase succeeds (key derived from wrong pw + same salt)
        # but decryption must fail when we try to read the entry.
        with Ledger.open("wrong-passphrase", db_path=db) as l:
            with pytest.raises((CryptoError, Exception)):
                l.lookup(entry.token)
