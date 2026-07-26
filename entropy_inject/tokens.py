"""CSPRNG token generation and content hashing."""
from __future__ import annotations

import hashlib
import secrets
from pathlib import Path


def generate_token(nbytes: int = 32) -> str:
    """Generate a CSPRNG entropy token as a hex string.

    256 bits (32 bytes) is the default and is more than sufficient for
    uniqueness and unpredictability.
    """
    if nbytes < 16:
        raise ValueError("token must be at least 128 bits (16 bytes)")
    return secrets.token_hex(nbytes)


def hash_file(path: str | Path, chunk_size: int = 1 << 20) -> str:
    """SHA-256 of a file's contents, streamed. Returned as hex."""
    h = hashlib.sha256()
    with open(path, "rb") as f:
        for chunk in iter(lambda: f.read(chunk_size), b""):
            h.update(chunk)
    return h.hexdigest()


def bind_token_to_hash(token: str, file_hash: str) -> str:
    """Compute a tamper-evidence binding of token || file_hash.

    If the file is later modified, recomputing this binding will not match
    what the ledger stored, so the link to provenance breaks cleanly.
    """
    return hashlib.sha256(f"{token}:{file_hash}".encode()).hexdigest()
