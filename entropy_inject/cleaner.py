"""Deep-clean pass to reduce PDF body fingerprinting.

Two-stage process:
  1. Strip document-catalog entries that carry authoring metadata beyond
     /Info and XMP: /StructTreeRoot, /MarkInfo, /Lang, /SpiderInfo, etc.
  2. Replace font subsetting prefixes (``ABCDEF+FontName``) with
     token-derived alternatives.  Replacement is deterministic given the
     token and the original 6-char prefix, so the output is reproducible
     from a known token without re-randomising on every open.
  3. Remove per-page thumbnails and PieceInfo blobs.

Note: this pass does *not* rewrite page content streams or ICC profiles.
"""
from __future__ import annotations

import hashlib
import re
from typing import Any

import pikepdf

# Catalog keys that typically carry authoring information or are
# application-specific private data, without affecting page rendering.
_CATALOG_LEAK_KEYS: frozenset[str] = frozenset((
    "/StructTreeRoot",  # accessibility tree — reveals document structure
    "/MarkInfo",        # marks PDF as tagged; authoring-tool fingerprint
    "/Lang",            # document language hint set by authoring tool
    "/SpiderInfo",      # Acrobat web-capture artefact
    "/PieceInfo",       # application-specific private data blobs
    "/Legal",           # Acrobat legal-attestation extension
))

_SUBSET_RE = re.compile(r"^/([A-Z]{6})\+(.+)$")
_ALPHABET = "ABCDEFGHIJKLMNOPQRSTUVWXYZ"


def _derive_prefix(token: str, original: str, cache: dict[str, str]) -> str:
    if original not in cache:
        h = hashlib.sha256(f"{token}:{original}".encode()).digest()
        cache[original] = "".join(_ALPHABET[b % 26] for b in h[:6])
    return cache[original]


def strip_catalog_fingerprints(pdf: pikepdf.Pdf) -> list[str]:
    """Remove identifying document-catalog entries.

    Returns a list of the keys that were removed.
    """
    removed: list[str] = []
    root = pdf.Root
    for key in _CATALOG_LEAK_KEYS:
        if key in root:
            del root[key]
            removed.append(key)
    return removed


def strip_page_artifacts(pdf: pikepdf.Pdf) -> int:
    """Remove per-page artefacts that can carry authoring fingerprints.

    Strips embedded thumbnail images (``/Thumb``) and application-specific
    piece-info blobs (``/PieceInfo``) from every page.  Returns the total
    number of entries removed.
    """
    count = 0
    for page in pdf.pages:
        for key in ("/Thumb", "/PieceInfo"):
            if key in page:
                del page[key]
                count += 1
    return count


def randomize_font_subset_prefixes(pdf: pikepdf.Pdf, token: str) -> int:
    """Replace font subsetting prefixes with token-derived alternatives.

    Font subset names look like ``/ABCDEF+Arial-MT`` in ``/BaseFont`` and
    ``/FontName`` entries.  This function walks all indirect objects and
    rewrites every matching name so the 6-char prefix is deterministically
    derived from ``token`` and the original prefix.  Same original prefix
    always maps to the same replacement (within one injection), keeping
    cross-references consistent.

    Returns the number of font-name fields rewritten.
    """
    cache: dict[str, str] = {}
    count = 0
    for obj in pdf.objects:
        try:
            keys = list(obj.keys())
        except AttributeError:
            continue
        for key in keys:
            if key not in ("/BaseFont", "/FontName"):
                continue
            try:
                name_str = str(obj[key])
            except Exception:
                continue
            m = _SUBSET_RE.match(name_str)
            if not m:
                continue
            orig_prefix, rest = m.group(1), m.group(2)
            new_prefix = _derive_prefix(token, orig_prefix, cache)
            try:
                obj[key] = pikepdf.Name(f"/{new_prefix}+{rest}")
                count += 1
            except Exception:
                pass
    return count


def deep_clean(pdf: pikepdf.Pdf, token: str) -> dict[str, Any]:
    """Run all deep-clean passes against an open pikepdf document.

    Returns a summary dict describing what was changed.  The caller is
    responsible for saving the PDF after this call.
    """
    removed_catalog = strip_catalog_fingerprints(pdf)
    page_artifacts = strip_page_artifacts(pdf)
    font_rewrites = randomize_font_subset_prefixes(pdf, token)
    return {
        "removed_catalog_keys": removed_catalog,
        "page_artifacts_removed": page_artifacts,
        "font_names_rewritten": font_rewrites,
    }
