"""Tests for entropy_inject.signing."""
from __future__ import annotations

import pytest

from entropy_inject.signing import (
    load_or_create_signing_key,
    sign_injection,
    verify_injection_signature,
)


TOKEN = "a" * 64
INPUT_HASH = "b" * 64
TIMESTAMP = "2024-01-01T00:00:00+00:00"


class TestLoadOrCreate:
    def test_creates_key(self, tmp_path):
        key_path = tmp_path / "test.key"
        key = load_or_create_signing_key(key_path)
        assert key_path.exists()
        assert len(bytes(key)) == 32

    def test_file_permissions(self, tmp_path):
        import stat
        key_path = tmp_path / "test.key"
        load_or_create_signing_key(key_path)
        mode = key_path.stat().st_mode
        assert not (mode & stat.S_IRGRP)
        assert not (mode & stat.S_IROTH)

    def test_reloads_same_key(self, tmp_path):
        key_path = tmp_path / "test.key"
        k1 = load_or_create_signing_key(key_path)
        k2 = load_or_create_signing_key(key_path)
        assert bytes(k1) == bytes(k2)


class TestSignAndVerify:
    def test_valid_signature(self, tmp_path):
        key = load_or_create_signing_key(tmp_path / "k.key")
        sig, vk = sign_injection(key, TOKEN, INPUT_HASH, TIMESTAMP)
        assert verify_injection_signature(vk, TOKEN, INPUT_HASH, TIMESTAMP, sig)

    def test_wrong_token_fails(self, tmp_path):
        key = load_or_create_signing_key(tmp_path / "k.key")
        sig, vk = sign_injection(key, TOKEN, INPUT_HASH, TIMESTAMP)
        assert not verify_injection_signature(vk, "x" * 64, INPUT_HASH, TIMESTAMP, sig)

    def test_wrong_hash_fails(self, tmp_path):
        key = load_or_create_signing_key(tmp_path / "k.key")
        sig, vk = sign_injection(key, TOKEN, INPUT_HASH, TIMESTAMP)
        assert not verify_injection_signature(vk, TOKEN, "x" * 64, TIMESTAMP, sig)

    def test_wrong_timestamp_fails(self, tmp_path):
        key = load_or_create_signing_key(tmp_path / "k.key")
        sig, vk = sign_injection(key, TOKEN, INPUT_HASH, TIMESTAMP)
        assert not verify_injection_signature(vk, TOKEN, INPUT_HASH, "wrong", sig)

    def test_wrong_verify_key_fails(self, tmp_path):
        key = load_or_create_signing_key(tmp_path / "k.key")
        key2 = load_or_create_signing_key(tmp_path / "k2.key")
        sig, _ = sign_injection(key, TOKEN, INPUT_HASH, TIMESTAMP)
        _, vk2 = sign_injection(key2, TOKEN, INPUT_HASH, TIMESTAMP)
        assert not verify_injection_signature(vk2, TOKEN, INPUT_HASH, TIMESTAMP, sig)

    def test_bad_hex_returns_false(self):
        assert not verify_injection_signature(
            "notvalidhex", TOKEN, INPUT_HASH, TIMESTAMP, "also-not-hex"
        )

    def test_returns_hex_strings(self, tmp_path):
        key = load_or_create_signing_key(tmp_path / "k.key")
        sig, vk = sign_injection(key, TOKEN, INPUT_HASH, TIMESTAMP)
        int(sig, 16)
        int(vk, 16)
