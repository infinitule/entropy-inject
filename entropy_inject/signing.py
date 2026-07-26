"""Ed25519 signing key management for injection attestation.

The private key (raw 32-byte seed) lives at ~/.entropy-ledger/signing.key
with mode 0o600.  The corresponding verify key is safe to publish: anyone
holding it can confirm that a given (token, input_hash, timestamp) triple
was attested by the keyholder — without access to the ledger.

Message format (UTF-8): "{token}:{input_hash}:{timestamp}"
"""
from __future__ import annotations

import os
from pathlib import Path

import nacl.signing

DEFAULT_KEY_PATH = Path.home() / ".entropy-ledger" / "signing.key"


def load_or_create_signing_key(
    key_path: Path | str | None = None,
) -> nacl.signing.SigningKey:
    """Return the persisted Ed25519 signing key, creating one on first use."""
    path = Path(key_path) if key_path else DEFAULT_KEY_PATH
    path.parent.mkdir(parents=True, exist_ok=True)

    if path.exists():
        return nacl.signing.SigningKey(path.read_bytes())

    key = nacl.signing.SigningKey.generate()
    try:
        fd = os.open(str(path), os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
        try:
            os.write(fd, bytes(key))
        finally:
            os.close(fd)
    except OSError:
        path.write_bytes(bytes(key))
        try:
            path.chmod(0o600)
        except Exception:
            pass
    return key


def sign_injection(
    key: nacl.signing.SigningKey,
    token: str,
    input_hash: str,
    timestamp: str,
) -> tuple[str, str]:
    """Sign the injection record.

    Returns (signature_hex, verify_key_hex).  The signature covers
    ``"{token}:{input_hash}:{timestamp}"`` — binding the token to the
    original file's hash and the moment of injection.
    """
    msg = f"{token}:{input_hash}:{timestamp}".encode("utf-8")
    signed = key.sign(msg)
    return signed.signature.hex(), key.verify_key.encode().hex()


def verify_injection_signature(
    verify_key_hex: str,
    token: str,
    input_hash: str,
    timestamp: str,
    signature_hex: str,
) -> bool:
    """Verify an Ed25519 injection signature without the private key.

    Returns True iff the signature is valid for the given triple.
    """
    try:
        vk = nacl.signing.VerifyKey(bytes.fromhex(verify_key_hex))
        msg = f"{token}:{input_hash}:{timestamp}".encode("utf-8")
        vk.verify(msg, bytes.fromhex(signature_hex))
        return True
    except Exception:
        return False
