"""Metadata stripping and entropy injection for PDFs.

Uses pikepdf (libqpdf bindings) for precise control over the document
catalog, the /Info dictionary, and the XMP /Metadata stream.

Design notes
------------
- /Info is the legacy document information dictionary.  Every common
  identifying field lives here: Author, Title, Producer, Creator,
  CreationDate, ModDate, Subject, Keywords.
- /Metadata is a stream in the document catalog holding XMP (XML) that
  duplicates and extends the /Info data.  Both must be cleaned.
- We snapshot whatever we wipe so the caller can persist it to the ledger.
- The following entropy fields are injected into /Info (and mirrored in XMP):
    /EntropyID         — 256-bit CSPRNG token (hex)
    /EntropyBinding    — SHA-256(token:input_hash) tamper-evidence link
    /EntropyInputHash  — SHA-256 of the original (pre-sanitisation) file
    /EntropyTimestamp  — ISO-8601 UTC timestamp of injection
    /EntropySignature  — Ed25519 signature (only when sign=True)
    /EntropyVerifyKey  — Ed25519 verify key   (only when sign=True)
"""
from __future__ import annotations

from dataclasses import dataclass, field
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

import pikepdf

from .tokens import bind_token_to_hash, generate_token, hash_file


STANDARD_INFO_KEYS = (
    "/Title",
    "/Author",
    "/Subject",
    "/Keywords",
    "/Creator",
    "/Producer",
    "/CreationDate",
    "/ModDate",
    "/Trapped",
)


@dataclass
class StripResult:
    """Outcome of an entropy-injection run."""

    token: str
    input_hash: str       # SHA-256 of original file
    output_hash: str      # SHA-256 of sanitised file
    binding: str          # SHA-256(token:input_hash) — tamper-evidence
    original_metadata: dict[str, Any] = field(default_factory=dict)
    output_path: str = ""
    timestamp: str = ""
    signature: str = ""   # Ed25519 hex signature (empty unless sign=True)
    verify_key: str = ""  # Ed25519 verify key hex (empty unless sign=True)
    deep_clean_report: dict[str, Any] = field(default_factory=dict)


# ---- metadata snapshot helpers -----------------------------------------


def _snapshot_info(pdf: pikepdf.Pdf) -> dict[str, Any]:
    """Capture existing /Info dictionary as a plain dict of strings."""
    snapshot: dict[str, Any] = {}
    try:
        docinfo = pdf.docinfo
    except Exception:
        return snapshot
    if docinfo is None:
        return snapshot
    for key, value in docinfo.items():
        try:
            snapshot[str(key)] = str(value)
        except Exception:
            snapshot[str(key)] = "<unrepresentable>"
    return snapshot


def _snapshot_xmp(pdf: pikepdf.Pdf) -> str | None:
    """Capture existing XMP metadata stream as a string, if present."""
    root = pdf.Root
    if "/Metadata" not in root:
        return None
    stream = root["/Metadata"]
    try:
        return bytes(stream.read_bytes()).decode("utf-8", errors="replace")
    except AttributeError:
        return "<non-stream /Metadata — unreadable>"
    except Exception:
        return "<XMP read error>"


# ---- mutation helpers --------------------------------------------------


def _wipe_info(pdf: pikepdf.Pdf) -> None:
    """Remove every key from the /Info dictionary."""
    try:
        docinfo = pdf.docinfo
    except Exception:
        return
    if docinfo is None:
        return
    for key in list(docinfo.keys()):
        del docinfo[key]


def _wipe_xmp(pdf: pikepdf.Pdf) -> None:
    """Remove the XMP metadata stream from the document catalog."""
    root = pdf.Root
    if "/Metadata" in root:
        del root["/Metadata"]


def _inject_entropy_marker(
    pdf: pikepdf.Pdf,
    token: str,
    binding: str,
    input_hash: str,
    timestamp: str,
    signature: str = "",
    verify_key: str = "",
) -> None:
    """Write entropy fields into /Info and a minimal XMP packet."""
    docinfo = pdf.docinfo
    docinfo["/EntropyID"] = token
    docinfo["/EntropyBinding"] = binding
    docinfo["/EntropyInputHash"] = input_hash
    docinfo["/EntropyTimestamp"] = timestamp
    if signature:
        docinfo["/EntropySignature"] = signature
    if verify_key:
        docinfo["/EntropyVerifyKey"] = verify_key

    sig_xml = ""
    if signature:
        sig_xml = (
            f"\n      <entropy:signature>{signature}</entropy:signature>"
            f"\n      <entropy:verifyKey>{verify_key}</entropy:verifyKey>"
        )

    xmp = (
        '<?xpacket begin="﻿" id="W5M0MpCehiHzreSzNTczkc9d"?>\n'
        '<x:xmpmeta xmlns:x="adobe:ns:meta/" x:xmptk="entropy-inject">\n'
        '  <rdf:RDF xmlns:rdf="http://www.w3.org/1999/02/22-rdf-syntax-ns#">\n'
        '    <rdf:Description rdf:about=""\n'
        '        xmlns:entropy="https://entropy-inject.local/ns/1.0/">\n'
        f"      <entropy:id>{token}</entropy:id>\n"
        f"      <entropy:binding>{binding}</entropy:binding>\n"
        f"      <entropy:inputHash>{input_hash}</entropy:inputHash>\n"
        f"      <entropy:timestamp>{timestamp}</entropy:timestamp>"
        f"{sig_xml}\n"
        "    </rdf:Description>\n"
        "  </rdf:RDF>\n"
        "</x:xmpmeta>\n"
        "<?xpacket end=\"w\"?>"
    )
    stream = pdf.make_stream(xmp.encode("utf-8"))
    stream["/Type"] = pikepdf.Name("/Metadata")
    stream["/Subtype"] = pikepdf.Name("/XML")
    pdf.Root["/Metadata"] = stream


# ---- public API --------------------------------------------------------


def inject_entropy(
    input_path: str | Path,
    output_path: str | Path,
    *,
    token: str | None = None,
    token_bytes: int = 32,
    sign: bool = False,
    signing_key_path: Path | str | None = None,
    deep_clean: bool = False,
    force: bool = False,
) -> StripResult:
    """Strip metadata from a PDF and inject an entropy token.

    Parameters
    ----------
    input_path : source PDF
    output_path : destination for the sanitised PDF
    token : optional pre-generated token (hex string).  If None, one is
        generated using a CSPRNG.
    token_bytes : size in bytes when generating a token.  Ignored when
        ``token`` is supplied.
    sign : if True, sign ``(token, input_hash, timestamp)`` with the
        owner's Ed25519 key and embed the signature in the PDF.
    signing_key_path : path to Ed25519 seed file.  Defaults to
        ``~/.entropy-ledger/signing.key``; created if absent.
    deep_clean : if True, run the deep-clean pass (catalog key removal,
        page artifact stripping, font subset-prefix randomisation).
    force : if True, overwrite an existing output file.

    Returns
    -------
    StripResult — the caller is responsible for persisting this to a
    ledger; this function does not touch the ledger.
    """
    input_path = Path(input_path)
    output_path = Path(output_path)

    if not input_path.exists():
        raise FileNotFoundError(f"input PDF not found: {input_path}")
    if output_path.exists() and not force:
        raise FileExistsError(
            f"output path already exists: {output_path} "
            f"(pass force=True or --force to overwrite)"
        )

    input_hash = hash_file(input_path)
    token = token or generate_token(token_bytes)
    binding = bind_token_to_hash(token, input_hash)
    timestamp = datetime.now(timezone.utc).isoformat()

    signature = ""
    verify_key_hex = ""
    if sign:
        from .signing import load_or_create_signing_key, sign_injection
        skey = load_or_create_signing_key(signing_key_path)
        signature, verify_key_hex = sign_injection(skey, token, input_hash, timestamp)

    clean_report: dict[str, Any] = {}
    with pikepdf.open(input_path) as pdf:
        original_info = _snapshot_info(pdf)
        original_xmp = _snapshot_xmp(pdf)

        _wipe_info(pdf)
        _wipe_xmp(pdf)

        if deep_clean:
            from . import cleaner as _cleaner
            clean_report = _cleaner.deep_clean(pdf, token)

        _inject_entropy_marker(
            pdf, token, binding, input_hash, timestamp,
            signature, verify_key_hex,
        )

        pdf.save(
            output_path,
            linearize=False,
            object_stream_mode=pikepdf.ObjectStreamMode.generate,
        )

    output_hash = hash_file(output_path)

    snapshot: dict[str, Any] = {"info": original_info}
    if original_xmp is not None:
        snapshot["xmp"] = original_xmp

    return StripResult(
        token=token,
        input_hash=input_hash,
        output_hash=output_hash,
        binding=binding,
        original_metadata=snapshot,
        output_path=str(output_path),
        timestamp=timestamp,
        signature=signature,
        verify_key=verify_key_hex,
        deep_clean_report=clean_report,
    )
