"""Tests for entropy_inject.tokens."""
from __future__ import annotations

import hashlib
from pathlib import Path

import pytest

from entropy_inject.tokens import bind_token_to_hash, generate_token, hash_file


class TestGenerateToken:
    def test_default_length(self):
        t = generate_token()
        assert len(t) == 64  # 32 bytes → 64 hex chars

    def test_custom_length(self):
        t = generate_token(16)
        assert len(t) == 32

    def test_is_hex(self):
        t = generate_token()
        int(t, 16)  # raises if not valid hex

    def test_uniqueness(self):
        tokens = {generate_token() for _ in range(20)}
        assert len(tokens) == 20

    def test_too_short_raises(self):
        with pytest.raises(ValueError):
            generate_token(8)


class TestHashFile:
    def test_known_hash(self, tmp_path: Path):
        f = tmp_path / "data.bin"
        f.write_bytes(b"hello")
        expected = hashlib.sha256(b"hello").hexdigest()
        assert hash_file(f) == expected

    def test_empty_file(self, tmp_path: Path):
        f = tmp_path / "empty.bin"
        f.write_bytes(b"")
        expected = hashlib.sha256(b"").hexdigest()
        assert hash_file(f) == expected

    def test_large_file_chunked(self, tmp_path: Path):
        data = b"x" * (3 << 20)  # 3 MB
        f = tmp_path / "big.bin"
        f.write_bytes(data)
        expected = hashlib.sha256(data).hexdigest()
        assert hash_file(f) == expected


class TestBindToken:
    def test_deterministic(self):
        b1 = bind_token_to_hash("abc", "def")
        b2 = bind_token_to_hash("abc", "def")
        assert b1 == b2

    def test_different_inputs(self):
        b1 = bind_token_to_hash("aaa", "bbb")
        b2 = bind_token_to_hash("aaa", "ccc")
        assert b1 != b2

    def test_returns_hex(self):
        b = bind_token_to_hash("token", "hash")
        int(b, 16)
        assert len(b) == 64
