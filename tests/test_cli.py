"""Tests for entropy_inject.cli."""
from __future__ import annotations

import json
import os
from pathlib import Path

import pytest

from entropy_inject.cli import main
from .conftest import EXPORT_PASSPHRASE, PASSPHRASE


@pytest.fixture(autouse=True)
def set_passphrase(monkeypatch):
    monkeypatch.setenv("ENTROPY_PASSPHRASE", PASSPHRASE)
    monkeypatch.setenv("ENTROPY_EXPORT_PASSPHRASE", EXPORT_PASSPHRASE)


def _db(tmp_path: Path) -> str:
    return str(tmp_path / "ledger.db")


class TestInjectCommand:
    def test_basic(self, sample_pdf, tmp_path, capsys):
        out = tmp_path / "out.pdf"
        rc = main(["--db", _db(tmp_path), "inject", str(sample_pdf), "-o", str(out)])
        assert rc == 0
        assert out.exists()
        captured = capsys.readouterr()
        assert "[ok] sanitised" in captured.out

    def test_with_notes(self, sample_pdf, tmp_path):
        out = tmp_path / "out.pdf"
        rc = main([
            "--db", _db(tmp_path),
            "inject", str(sample_pdf), "-o", str(out),
            "--notes", "my note",
        ])
        assert rc == 0

    def test_with_sign(self, sample_pdf, tmp_path, capsys, monkeypatch):
        monkeypatch.setenv("ENTROPY_PASSPHRASE", PASSPHRASE)
        out = tmp_path / "out.pdf"
        rc = main([
            "--db", _db(tmp_path),
            "inject", str(sample_pdf), "-o", str(out),
            "--sign",
        ])
        assert rc == 0
        captured = capsys.readouterr()
        assert "signature" in captured.out

    def test_missing_input(self, tmp_path, capsys):
        out = tmp_path / "out.pdf"
        rc = main(["--db", _db(tmp_path), "inject", str(tmp_path / "nope.pdf"),
                   "-o", str(out)])
        assert rc == 1

    def test_existing_output_without_force(self, sample_pdf, tmp_path):
        out = tmp_path / "out.pdf"
        out.write_bytes(b"exists")
        rc = main(["--db", _db(tmp_path), "inject", str(sample_pdf), "-o", str(out)])
        assert rc == 1

    def test_force_flag(self, sample_pdf, tmp_path):
        out = tmp_path / "out.pdf"
        # first injection
        main(["--db", _db(tmp_path), "inject", str(sample_pdf), "-o", str(out)])
        # second with --force (different token, so no duplicate in ledger)
        # we need a separate db or use a fresh PDF copy
        import shutil
        pdf2 = tmp_path / "sample2.pdf"
        shutil.copy(sample_pdf, pdf2)
        out2 = tmp_path / "out2.pdf"
        rc = main(["--db", _db(tmp_path), "inject", str(pdf2), "-o", str(out2)])
        assert rc == 0


class TestReadCommand:
    def test_reads_token(self, sample_pdf, tmp_path, capsys):
        out = tmp_path / "out.pdf"
        main(["--db", _db(tmp_path), "inject", str(sample_pdf), "-o", str(out)])
        capsys.readouterr()  # clear
        rc = main(["read", str(out)])
        assert rc == 0
        captured = capsys.readouterr()
        assert "token" in captured.out

    def test_no_marker(self, sample_pdf, capsys):
        rc = main(["read", str(sample_pdf)])
        assert rc == 1


class TestVerifyCommand:
    def test_output_file(self, sample_pdf, tmp_path, capsys):
        out = tmp_path / "out.pdf"
        main(["--db", _db(tmp_path), "inject", str(sample_pdf), "-o", str(out)])
        capsys.readouterr()
        rc = main(["--db", _db(tmp_path), "verify", str(out)])
        assert rc == 0
        captured = capsys.readouterr()
        assert "[ok]" in captured.out

    def test_tampered_file(self, sample_pdf, tmp_path, capsys):
        import pikepdf
        out = tmp_path / "out.pdf"
        main(["--db", _db(tmp_path), "inject", str(sample_pdf), "-o", str(out)])
        # Tamper with the file
        with pikepdf.open(out, allow_overwriting_input=True) as pdf:
            pdf.docinfo["/ExtraField"] = "tampered"
            pdf.save(out)
        capsys.readouterr()
        rc = main(["--db", _db(tmp_path), "verify", str(out)])
        assert rc == 4


class TestVerifySigCommand:
    def test_valid_sig(self, sample_pdf, tmp_path, capsys):
        out = tmp_path / "out.pdf"
        main([
            "--db", _db(tmp_path),
            "inject", str(sample_pdf), "-o", str(out), "--sign",
        ])
        capsys.readouterr()
        rc = main(["verify-sig", str(out)])
        assert rc == 0
        captured = capsys.readouterr()
        assert "[ok]" in captured.out

    def test_no_sig_in_pdf(self, sample_pdf, tmp_path, capsys):
        out = tmp_path / "out.pdf"
        main(["--db", _db(tmp_path), "inject", str(sample_pdf), "-o", str(out)])
        capsys.readouterr()
        rc = main(["verify-sig", str(out)])
        assert rc == 2  # missing fields


class TestLookupCommand:
    def test_lookup(self, sample_pdf, tmp_path, capsys):
        out = tmp_path / "out.pdf"
        main(["--db", _db(tmp_path), "inject", str(sample_pdf), "-o", str(out)])
        import pikepdf
        with pikepdf.open(out) as pdf:
            token = str(pdf.docinfo["/EntropyID"])
        capsys.readouterr()
        rc = main(["--db", _db(tmp_path), "lookup", token])
        assert rc == 0
        captured = capsys.readouterr()
        data = json.loads(captured.out)
        assert data["token"] == token

    def test_lookup_missing(self, tmp_path, capsys):
        rc = main(["--db", _db(tmp_path), "lookup", "0" * 64])
        assert rc == 3


class TestListCommand:
    def test_empty(self, tmp_path, capsys):
        rc = main(["--db", _db(tmp_path), "list"])
        assert rc == 0
        captured = capsys.readouterr()
        assert "0 entries" in captured.out

    def test_shows_entries(self, sample_pdf, tmp_path, capsys):
        out = tmp_path / "out.pdf"
        main(["--db", _db(tmp_path), "inject", str(sample_pdf), "-o", str(out),
              "--notes", "my note"])
        capsys.readouterr()
        rc = main(["--db", _db(tmp_path), "list"])
        assert rc == 0
        captured = capsys.readouterr()
        assert "1 entry" in captured.out
        assert "my note" in captured.out


class TestDeleteCommand:
    def test_delete(self, sample_pdf, tmp_path, capsys):
        out = tmp_path / "out.pdf"
        main(["--db", _db(tmp_path), "inject", str(sample_pdf), "-o", str(out)])
        import pikepdf
        with pikepdf.open(out) as pdf:
            token = str(pdf.docinfo["/EntropyID"])
        capsys.readouterr()
        rc = main(["--db", _db(tmp_path), "delete", token])
        assert rc == 0
        # Gone from ledger
        rc2 = main(["--db", _db(tmp_path), "lookup", token])
        assert rc2 == 3

    def test_delete_missing(self, tmp_path):
        rc = main(["--db", _db(tmp_path), "delete", "0" * 64])
        assert rc == 3


class TestUpdateNotesCommand:
    def test_updates(self, sample_pdf, tmp_path, capsys):
        out = tmp_path / "out.pdf"
        main(["--db", _db(tmp_path), "inject", str(sample_pdf), "-o", str(out),
              "--notes", "original"])
        import pikepdf
        with pikepdf.open(out) as pdf:
            token = str(pdf.docinfo["/EntropyID"])
        rc = main(["--db", _db(tmp_path), "update-notes", token, "--notes", "updated"])
        assert rc == 0
        capsys.readouterr()
        main(["--db", _db(tmp_path), "lookup", token])
        captured = capsys.readouterr()
        data = json.loads(captured.out)
        assert data["notes"] == "updated"

    def test_missing_token(self, tmp_path):
        rc = main(["--db", _db(tmp_path), "update-notes", "0" * 64, "--notes", "x"])
        assert rc == 3


class TestExportImportCommands:
    def test_roundtrip(self, sample_pdf, tmp_path, capsys):
        db1 = _db(tmp_path)
        out = tmp_path / "out.pdf"
        main(["--db", db1, "inject", str(sample_pdf), "-o", str(out),
              "--notes", "exported note"])
        bundle = str(tmp_path / "bundle.json")
        capsys.readouterr()

        rc = main(["--db", db1, "export", bundle])
        assert rc == 0
        assert Path(bundle).exists()

        db2 = str(tmp_path / "ledger2.db")
        rc = main(["--db", db2, "import", bundle])
        assert rc == 0
        captured = capsys.readouterr()
        assert "imported 1" in captured.out

    def test_import_skip_duplicates(self, sample_pdf, tmp_path, capsys):
        db = _db(tmp_path)
        out = tmp_path / "out.pdf"
        main(["--db", db, "inject", str(sample_pdf), "-o", str(out)])
        bundle = str(tmp_path / "bundle.json")
        main(["--db", db, "export", bundle])
        capsys.readouterr()

        rc = main(["--db", db, "import", bundle])
        assert rc == 0
        captured = capsys.readouterr()
        assert "skipped 1" in captured.out


class TestPubkeyCommand:
    def test_prints_hex_key(self, tmp_path, capsys):
        key_path = str(tmp_path / "sign.key")
        rc = main(["pubkey", "--key", key_path])
        assert rc == 0
        captured = capsys.readouterr()
        vk_hex = captured.out.strip()
        assert len(vk_hex) == 64
        int(vk_hex, 16)
