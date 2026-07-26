"""Shared pytest fixtures."""
from __future__ import annotations

from pathlib import Path

import nacl.pwhash
import pikepdf
import pytest

PASSPHRASE = "test-passphrase"
EXPORT_PASSPHRASE = "export-passphrase"

# Use minimum KDF settings across ALL tests so the suite runs in seconds.
@pytest.fixture(autouse=True)
def fast_kdf(monkeypatch):
    import entropy_inject.ledger as _ledger_mod
    monkeypatch.setattr(
        _ledger_mod.nacl.pwhash.argon2id,
        "OPSLIMIT_MODERATE",
        nacl.pwhash.argon2id.OPSLIMIT_MIN,
    )
    monkeypatch.setattr(
        _ledger_mod.nacl.pwhash.argon2id,
        "MEMLIMIT_MODERATE",
        nacl.pwhash.argon2id.MEMLIMIT_MIN,
    )


def _append_blank_page(pdf: pikepdf.Pdf) -> None:
    """Add a minimal blank page to a PDF (compatible with pikepdf >= 8)."""
    page_obj = pdf.make_indirect(pikepdf.Dictionary(
        Type=pikepdf.Name.Page,
        MediaBox=[0, 0, 612, 792],
        Resources=pikepdf.Dictionary(),
    ))
    pdf.pages.append(pikepdf.Page(page_obj))


@pytest.fixture
def tmp_dir(tmp_path: Path) -> Path:
    return tmp_path


@pytest.fixture
def sample_pdf(tmp_path: Path) -> Path:
    """Minimal PDF with common metadata fields."""
    path = tmp_path / "sample.pdf"
    with pikepdf.new() as pdf:
        pdf.docinfo["/Author"] = "Test Author"
        pdf.docinfo["/Title"] = "Test Title"
        pdf.docinfo["/Creator"] = "TestTool 1.0"
        pdf.docinfo["/Producer"] = "TestProducer"
        pdf.docinfo["/CreationDate"] = "D:20240101120000Z"
        _append_blank_page(pdf)
        pdf.save(path)
    return path


@pytest.fixture
def sample_pdf_with_fonts(tmp_path: Path) -> Path:
    """PDF containing font objects with subsetting prefixes."""
    path = tmp_path / "fonts.pdf"
    with pikepdf.new() as pdf:
        font_desc = pdf.make_indirect(pikepdf.Dictionary(
            Type=pikepdf.Name("/FontDescriptor"),
            FontName=pikepdf.Name("/ABCDEF+Arial"),
            Flags=32,
            ItalicAngle=0,
            Ascent=900,
            Descent=-200,
            CapHeight=700,
            StemV=80,
        ))
        font = pdf.make_indirect(pikepdf.Dictionary(
            Type=pikepdf.Name("/Font"),
            Subtype=pikepdf.Name("/TrueType"),
            BaseFont=pikepdf.Name("/ABCDEF+Arial"),
            FontDescriptor=font_desc,
        ))
        page_obj = pdf.make_indirect(pikepdf.Dictionary(
            Type=pikepdf.Name.Page,
            MediaBox=[0, 0, 612, 792],
            Resources=pikepdf.Dictionary(
                Font=pikepdf.Dictionary(F1=font),
            ),
        ))
        pdf.pages.append(pikepdf.Page(page_obj))
        pdf.save(path)
    return path


@pytest.fixture
def ledger_dir(tmp_path: Path) -> Path:
    return tmp_path / "ledger"


@pytest.fixture
def open_ledger(ledger_dir):
    """Factory fixture returning an open Ledger bound to a temp directory.

    Uses minimum Argon2id settings so the test suite runs in seconds rather
    than minutes.  Production code always uses MODERATE.
    """
    import nacl.pwhash
    from entropy_inject.ledger import Ledger

    kdf_kwargs = dict(
        _opslimit=nacl.pwhash.argon2id.OPSLIMIT_MIN,
        _memlimit=nacl.pwhash.argon2id.MEMLIMIT_MIN,
    )

    def _open(passphrase: str = PASSPHRASE) -> Ledger:
        db = ledger_dir / "ledger.db"
        return Ledger.open(passphrase, db_path=db, **kdf_kwargs)

    return _open
