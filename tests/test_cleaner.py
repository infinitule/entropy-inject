"""Tests for entropy_inject.cleaner."""
from __future__ import annotations

import pikepdf
import pytest

from entropy_inject.cleaner import (
    deep_clean,
    randomize_font_subset_prefixes,
    strip_catalog_fingerprints,
    strip_page_artifacts,
)

TOKEN = "a" * 64


def _append_blank_page(pdf: pikepdf.Pdf) -> None:
    page_obj = pdf.make_indirect(pikepdf.Dictionary(
        Type=pikepdf.Name.Page,
        MediaBox=[0, 0, 612, 792],
        Resources=pikepdf.Dictionary(),
    ))
    pdf.pages.append(pikepdf.Page(page_obj))


def _pdf_with_catalog_keys(path):
    with pikepdf.new() as pdf:
        _append_blank_page(pdf)
        pdf.Root["/MarkInfo"] = pikepdf.Dictionary(Marked=True)
        pdf.Root["/Lang"] = "en-US"
        pdf.Root["/SpiderInfo"] = pikepdf.Dictionary(nPages=1)
        pdf.save(path)


def _pdf_with_thumb(path):
    with pikepdf.new() as pdf:
        page_obj = pdf.make_indirect(pikepdf.Dictionary(
            Type=pikepdf.Name.Page,
            MediaBox=[0, 0, 612, 792],
            Resources=pikepdf.Dictionary(),
            Thumb=pikepdf.Dictionary(Width=0, Height=0),
        ))
        pdf.pages.append(pikepdf.Page(page_obj))
        pdf.save(path)


class TestStripCatalogFingerprints:
    def test_removes_keys(self, tmp_path):
        p = tmp_path / "c.pdf"
        _pdf_with_catalog_keys(p)
        with pikepdf.open(p, allow_overwriting_input=True) as pdf:
            removed = strip_catalog_fingerprints(pdf)
            pdf.save(p)
        assert "/MarkInfo" in removed
        assert "/Lang" in removed
        assert "/SpiderInfo" in removed

    def test_noop_on_clean_pdf(self, sample_pdf):
        with pikepdf.open(sample_pdf, allow_overwriting_input=True) as pdf:
            removed = strip_catalog_fingerprints(pdf)
        assert removed == []


class TestStripPageArtifacts:
    def test_removes_thumb(self, tmp_path):
        p = tmp_path / "thumb.pdf"
        _pdf_with_thumb(p)
        with pikepdf.open(p, allow_overwriting_input=True) as pdf:
            count = strip_page_artifacts(pdf)
        assert count == 1

    def test_noop_on_clean_pdf(self, sample_pdf):
        with pikepdf.open(sample_pdf) as pdf:
            assert strip_page_artifacts(pdf) == 0


class TestRandomizeFontPrefixes:
    def test_rewrites_prefixes(self, sample_pdf_with_fonts):
        with pikepdf.open(sample_pdf_with_fonts, allow_overwriting_input=True) as pdf:
            count = randomize_font_subset_prefixes(pdf, TOKEN)
            pdf.save(sample_pdf_with_fonts)
        assert count >= 2  # /BaseFont and /FontName both rewritten

    def test_new_prefix_is_not_original(self, sample_pdf_with_fonts):
        with pikepdf.open(sample_pdf_with_fonts, allow_overwriting_input=True) as pdf:
            randomize_font_subset_prefixes(pdf, TOKEN)
            # Verify the old prefix ABCDEF is gone
            for obj in pdf.objects:
                try:
                    base = str(obj.get("/BaseFont", ""))
                except Exception:
                    continue
                assert not base.startswith("/ABCDEF+"), base

    def test_deterministic(self, sample_pdf_with_fonts, tmp_path):
        import shutil
        copy = tmp_path / "copy.pdf"
        shutil.copy(sample_pdf_with_fonts, copy)

        with pikepdf.open(sample_pdf_with_fonts, allow_overwriting_input=True) as pdf1:
            randomize_font_subset_prefixes(pdf1, TOKEN)
            names1 = [str(obj.get("/BaseFont", "")) for obj in pdf1.objects
                      if hasattr(obj, "get")]

        with pikepdf.open(copy, allow_overwriting_input=True) as pdf2:
            randomize_font_subset_prefixes(pdf2, TOKEN)
            names2 = [str(obj.get("/BaseFont", "")) for obj in pdf2.objects
                      if hasattr(obj, "get")]

        assert names1 == names2

    def test_different_tokens_differ(self, sample_pdf_with_fonts, tmp_path):
        import shutil
        copy = tmp_path / "copy.pdf"
        shutil.copy(sample_pdf_with_fonts, copy)

        def _get_basefont(pdf):
            for obj in pdf.objects:
                try:
                    v = str(obj.get("/BaseFont", ""))
                    if v.startswith("/") and "+" in v:
                        return v
                except Exception:
                    pass
            return None

        with pikepdf.open(sample_pdf_with_fonts, allow_overwriting_input=True) as pdf1:
            randomize_font_subset_prefixes(pdf1, "a" * 64)
            name1 = _get_basefont(pdf1)

        with pikepdf.open(copy, allow_overwriting_input=True) as pdf2:
            randomize_font_subset_prefixes(pdf2, "b" * 64)
            name2 = _get_basefont(pdf2)

        assert name1 != name2

    def test_noop_on_pdf_without_subset_fonts(self, sample_pdf):
        with pikepdf.open(sample_pdf) as pdf:
            assert randomize_font_subset_prefixes(pdf, TOKEN) == 0


class TestDeepClean:
    def test_returns_report(self, tmp_path):
        p = tmp_path / "c.pdf"
        _pdf_with_catalog_keys(p)
        with pikepdf.open(p, allow_overwriting_input=True) as pdf:
            report = deep_clean(pdf, TOKEN)
        assert "removed_catalog_keys" in report
        assert "font_names_rewritten" in report
        assert "page_artifacts_removed" in report
        assert len(report["removed_catalog_keys"]) >= 3
