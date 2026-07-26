"""PDF Metadata Entropy Injector.

Strip identifying metadata from a PDF and replace it with a random entropy
token bound to the file's content hash.  The owner keeps a local encrypted
ledger mapping tokens back to real provenance.
"""
from .cleaner import deep_clean
from .ledger import Ledger, LedgerEntry
from .signing import (
    load_or_create_signing_key,
    sign_injection,
    verify_injection_signature,
)
from .stripper import StripResult, inject_entropy
from .tokens import generate_token, hash_file

__all__ = [
    "inject_entropy",
    "StripResult",
    "Ledger",
    "LedgerEntry",
    "generate_token",
    "hash_file",
    "deep_clean",
    "load_or_create_signing_key",
    "sign_injection",
    "verify_injection_signature",
]

__version__ = "0.2.0"
