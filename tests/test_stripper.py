"""Tests for entropy_inject.stripper."""
from __future__ import annotations

import pikepdf
import pytest

from entropy_inject.stripper import StripResult, inject_entropy


class TestInjectEntropy:
    def test_basic(self, sample_pdf, tmp_path):
        out = tmp_path / "out.pdf"
        result = inject_entropy(sample_pdf, out)
        assert isinstance(result, StripResult)
        assert out.exists()
        assert len(result.token) == 64
        assert len(result.input_hash) == 64
        assert len(result.output_hash) == 64
        assert result.output_hash != result.input_hash

    def test_metadata_stripped(self, sample_pdf, tmp_path):
        out = tmp_path / "out.pdf"
        inject_entropy(sample_pdf, out)
        with pikepdf.open(out) as pdf:
            info = pdf.docinfo
            assert "/Author" not in info
            assert "/Title" not in info
            assert "/Creator" not in info

    def test_entropy_fields_injected(self, sample_pdf, tmp_path):
        out = tmp_path / "out.pdf"
        result = inject_entropy(sample_pdf, out)
        with pikepdf.open(out) as pdf:
            info = pdf.docinfo
            assert str(info["/EntropyID"]) == result.token
            assert str(info["/EntropyBinding"]) == result.binding
            assert str(info["/EntropyInputHash"]) == result.input_hash
            assert info.get("/EntropyTimestamp") is not None

    def test_original_metadata_captured(self, sample_pdf, tmp_path):
        out = tmp_path / "out.pdf"
        result = inject_entropy(sample_pdf, out)
        assert result.original_metadata["info"]["/Author"] == "Test Author"
        assert result.original_metadata["info"]["/Title"] == "Test Title"

    def test_missing_input_raises(self, tmp_path):
        with pytest.raises(FileNotFoundError):
            inject_entropy(tmp_path / "nope.pdf", tmp_path / "out.pdf")

    def test_existing_output_raises(self, sample_pdf, tmp_path):
        out = tmp_path / "out.pdf"
        out.write_bytes(b"exists")
        with pytest.raises(FileExistsError):
            inject_entropy(sample_pdf, out)

    def test_force_overwrites(self, sample_pdf, tmp_path):
        out = tmp_path / "out.pdf"
        inject_entropy(sample_pdf, out)
        result2 = inject_entropy(sample_pdf, out, force=True)
        assert result2.token != ""  # new injection succeeded

    def test_custom_token(self, sample_pdf, tmp_path):
        token = "f" * 64
        out = tmp_path / "out.pdf"
        result = inject_entropy(sample_pdf, out, token=token)
        assert result.token == token

    def test_with_sign(self, sample_pdf, tmp_path):
        out = tmp_path / "out.pdf"
        result = inject_entropy(
            sample_pdf, out,
            sign=True,
            signing_key_path=tmp_path / "sign.key",
        )
        assert result.signature != ""
        assert result.verify_key != ""
        with pikepdf.open(out) as pdf:
            info = pdf.docinfo
            assert str(info["/EntropySignature"]) == result.signature
            assert str(info["/EntropyVerifyKey"]) == result.verify_key

    def test_signature_is_valid(self, sample_pdf, tmp_path):
        from entropy_inject.signing import verify_injection_signature
        out = tmp_path / "out.pdf"
        result = inject_entropy(
            sample_pdf, out,
            sign=True,
            signing_key_path=tmp_path / "sign.key",
        )
        assert verify_injection_signature(
            result.verify_key,
            result.token,
            result.input_hash,
            result.timestamp,
            result.signature,
        )

    def test_with_deep_clean(self, sample_pdf_with_fonts, tmp_path):
        out = tmp_path / "out.pdf"
        result = inject_entropy(sample_pdf_with_fonts, out, deep_clean=True)
        assert result.deep_clean_report.get("font_names_rewritten", 0) >= 2

    def test_xmp_stripped(self, tmp_path):
        pdf_path = tmp_path / "with_xmp.pdf"
        with pikepdf.new() as pdf:
            page_obj = pdf.make_indirect(pikepdf.Dictionary(
                Type=pikepdf.Name.Page,
                MediaBox=[0, 0, 612, 792],
                Resources=pikepdf.Dictionary(),
            ))
            pdf.pages.append(pikepdf.Page(page_obj))
            xmp = b'<?xpacket begin="" ?><x:xmpmeta xmlns:x="adobe:ns:meta/"></x:xmpmeta><?xpacket end="w"?>'
            stream = pdf.make_stream(xmp)
            stream["/Type"] = pikepdf.Name("/Metadata")
            stream["/Subtype"] = pikepdf.Name("/XML")
            pdf.Root["/Metadata"] = stream
            pdf.save(pdf_path)

        out = tmp_path / "out.pdf"
        result = inject_entropy(pdf_path, out)
        assert result.original_metadata.get("xmp") is not None
        with pikepdf.open(out) as cleaned:
            xmp_content = bytes(cleaned.Root["/Metadata"].read_bytes()).decode()
            assert "entropy:id" in xmp_content
            assert "xmpmeta" in xmp_content
