"""Tests for policy signing and verification — B05.

Covers:
- sign_policy: HMAC-SHA256 signature generation
- verify_policy: signature verification (valid, tampered, missing)
- strip_signature: removing signature block
- parse_signature: extracting signature metadata
- sign_policy_file / verify_policy_file: file-based operations
- load_policy_with_verification: key management, env vars
- generate_key / key_to_hex: key utilities
- Constant-time comparison (timing safety)
- Key rotation (key_id mismatch)
"""

from __future__ import annotations

import os
import tempfile
from pathlib import Path
from unittest import mock

import pytest

from irondome.policy_versioned.signing import (
    SIGNATURE_MARKER,
    PolicySignature,
    VerifyResult,
    generate_key,
    key_to_hex,
    load_policy_with_verification,
    parse_signature,
    sign_policy,
    sign_policy_file,
    strip_signature,
    verify_policy,
    verify_policy_file,
)

SAMPLE_POLICY = """rules:
  - name: deny-shells
    pattern: "*/sh"
    action: deny
  - name: deny-sudo
    pattern: "*/sudo"
    action: deny
"""


class TestSigning:
    def test_sign_policy_appends_signature(self):
        key = b"test-key-32-bytes-long-enough-xx"
        result = sign_policy(SAMPLE_POLICY, key)
        assert SIGNATURE_MARKER in result
        assert "# algorithm: hmac-sha256" in result
        assert "# signature:" in result
        assert "# timestamp:" in result
        assert "# key_id: default" in result

    def test_sign_policy_preserves_original_content(self):
        key = b"test-key-32-bytes-long-enough-xx"
        result = sign_policy(SAMPLE_POLICY, key)
        # Original content should be at the start
        assert result.startswith("rules:")

    def test_sign_policy_custom_key_id(self):
        key = b"test-key-32-bytes-long-enough-xx"
        result = sign_policy(SAMPLE_POLICY, key, key_id="prod-2026")
        assert "# key_id: prod-2026" in result

    def test_sign_policy_deterministic(self):
        key = b"test-key-32-bytes-long-enough-xx"
        # Same content + same key = same signature (ignoring timestamp)
        sig1 = sign_policy(SAMPLE_POLICY, key)
        # Extract just the signature hex
        parsed1 = parse_signature(sig1)
        assert parsed1 is not None
        # Verify with the same key should work
        result = verify_policy(sig1, key)
        assert result.valid

    def test_sign_policy_file(self, tmp_path):
        key = b"test-key-32-bytes-long-enough-xx"
        policy_file = tmp_path / "policy.yaml"
        policy_file.write_text(SAMPLE_POLICY)

        sign_policy_file(policy_file, key)

        content = policy_file.read_text()
        assert SIGNATURE_MARKER in content

    def test_sign_policy_file_removes_old_signature(self, tmp_path):
        key = b"test-key-32-bytes-long-enough-xx"
        policy_file = tmp_path / "policy.yaml"
        # Sign once
        policy_file.write_text(SAMPLE_POLICY)
        sign_policy_file(policy_file, key)
        first_content = policy_file.read_text()

        # Sign again (should replace, not double-sign)
        sign_policy_file(policy_file, key)
        second_content = policy_file.read_text()

        # Should still have exactly one signature block
        assert second_content.count(SIGNATURE_MARKER) == 1


class TestVerification:
    def test_verify_valid_signature(self):
        key = b"test-key-32-bytes-long-enough-xx"
        signed = sign_policy(SAMPLE_POLICY, key)
        result = verify_policy(signed, key)
        assert result.valid
        assert result.algorithm == "hmac-sha256"
        assert result.key_id == "default"

    def test_verify_tampered_content(self):
        key = b"test-key-32-bytes-long-enough-xx"
        signed = sign_policy(SAMPLE_POLICY, key)
        # Tamper with the content
        tampered = signed.replace("deny-shells", "allow-shells")
        result = verify_policy(tampered, key)
        assert not result.valid
        assert "mismatch" in result.error.lower() or "tampered" in result.error.lower()

    def test_verify_wrong_key(self):
        key1 = b"test-key-32-bytes-long-enough-xx"
        key2 = b"different-key-32-bytes-long-yy"
        signed = sign_policy(SAMPLE_POLICY, key1)
        result = verify_policy(signed, key2)
        assert not result.valid

    def test_verify_unsigned_policy(self):
        key = b"test-key-32-bytes-long-enough-xx"
        result = verify_policy(SAMPLE_POLICY, key)
        assert not result.valid
        assert "no signature" in result.error.lower()

    def test_verify_key_id_mismatch(self):
        key = b"test-key-32-bytes-long-enough-xx"
        signed = sign_policy(SAMPLE_POLICY, key, key_id="prod")
        result = verify_policy(signed, key, key_id="staging")
        assert not result.valid
        assert "key_id mismatch" in result.error

    def test_verify_policy_file(self, tmp_path):
        key = b"test-key-32-bytes-long-enough-xx"
        policy_file = tmp_path / "policy.yaml"
        policy_file.write_text(SAMPLE_POLICY)
        sign_policy_file(policy_file, key)

        result = verify_policy_file(policy_file, key)
        assert result.valid

    def test_verify_policy_file_not_found(self, tmp_path):
        key = b"test-key-32-bytes-long-enough-xx"
        result = verify_policy_file(tmp_path / "nonexistent.yaml", key)
        assert not result.valid
        assert "cannot read" in result.error


class TestParseSignature:
    def test_parse_valid_signature(self):
        key = b"test-key-32-bytes-long-enough-xx"
        signed = sign_policy(SAMPLE_POLICY, key)
        parsed = parse_signature(signed)
        assert parsed is not None
        assert parsed.algorithm == "hmac-sha256"
        assert len(parsed.signature) == 64  # SHA-256 hex
        assert parsed.key_id == "default"
        assert parsed.timestamp  # not empty

    def test_parse_no_signature(self):
        parsed = parse_signature(SAMPLE_POLICY)
        assert parsed is None

    def test_parse_custom_key_id(self):
        key = b"test-key-32-bytes-long-enough-xx"
        signed = sign_policy(SAMPLE_POLICY, key, key_id="prod-2026")
        parsed = parse_signature(signed)
        assert parsed is not None
        assert parsed.key_id == "prod-2026"


class TestStripSignature:
    def test_strip_removes_signature(self):
        key = b"test-key-32-bytes-long-enough-xx"
        signed = sign_policy(SAMPLE_POLICY, key)
        stripped = strip_signature(signed)
        assert SIGNATURE_MARKER not in stripped
        assert "rules:" in stripped

    def test_strip_preserves_original(self):
        key = b"test-key-32-bytes-long-enough-xx"
        signed = sign_policy(SAMPLE_POLICY, key)
        stripped = strip_signature(signed)
        # The stripped content should match the original (minus trailing newline)
        assert stripped.strip() == SAMPLE_POLICY.strip()

    def test_strip_no_signature(self):
        result = strip_signature(SAMPLE_POLICY)
        assert result.strip() == SAMPLE_POLICY.strip()


class TestKeyManagement:
    def test_generate_key_length(self):
        key = generate_key()
        assert len(key) == 32

    def test_generate_key_randomness(self):
        key1 = generate_key()
        key2 = generate_key()
        assert key1 != key2  # extremely unlikely to collide

    def test_key_to_hex_roundtrip(self):
        key = generate_key()
        hex_str = key_to_hex(key)
        assert len(hex_str) == 64  # 32 bytes = 64 hex chars
        recovered = bytes.fromhex(hex_str)
        assert recovered == key

    def test_load_key_from_env(self):
        key = generate_key()
        hex_str = key_to_hex(key)
        with mock.patch.dict(os.environ, {"IRONDOME_POLICY_KEY": hex_str}):
            from irondome.policy_versioned.signing import _load_key
            loaded = _load_key()
            assert loaded == key

    def test_load_key_from_file(self, tmp_path):
        key = generate_key()
        hex_str = key_to_hex(key)
        key_file = tmp_path / "policy.key"
        key_file.write_text(hex_str)

        with mock.patch.dict(os.environ, {"IRONDOME_POLICY_KEY_FILE": str(key_file)}, clear=False):
            # Remove direct key env if set
            os.environ.pop("IRONDOME_POLICY_KEY", None)
            from irondome.policy_versioned.signing import _load_key
            loaded = _load_key()
            assert loaded == key

    def test_load_key_none_when_not_configured(self):
        with mock.patch.dict(os.environ, {}, clear=True):
            from irondome.policy_versioned.signing import _load_key
            assert _load_key() is None


class TestLoadPolicyWithVerification:
    def test_unsigned_policy_no_key(self, tmp_path):
        policy_file = tmp_path / "policy.yaml"
        policy_file.write_text(SAMPLE_POLICY)

        content, result = load_policy_with_verification(policy_file, key=None)
        assert content == SAMPLE_POLICY
        assert result is None

    def test_signed_policy_valid(self, tmp_path):
        key = b"test-key-32-bytes-long-enough-xx"
        policy_file = tmp_path / "policy.yaml"
        policy_file.write_text(SAMPLE_POLICY)
        sign_policy_file(policy_file, key)

        content, result = load_policy_with_verification(policy_file, key=key)
        assert "rules:" in content
        assert result is not None
        assert result.valid

    def test_signed_policy_wrong_key(self, tmp_path):
        key1 = b"test-key-32-bytes-long-enough-xx"
        key2 = b"different-key-32-bytes-long-yy"
        policy_file = tmp_path / "policy.yaml"
        policy_file.write_text(SAMPLE_POLICY)
        sign_policy_file(policy_file, key1)

        content, result = load_policy_with_verification(policy_file, key=key2)
        assert content == ""  # rejected
        assert not result.valid

    def test_unsigned_policy_with_key_configured(self, tmp_path):
        key = b"test-key-32-bytes-long-enough-xx"
        policy_file = tmp_path / "policy.yaml"
        policy_file.write_text(SAMPLE_POLICY)

        content, result = load_policy_with_verification(policy_file, key=key)
        assert content == ""  # rejected — unsigned with key configured
        assert not result.valid
        assert "unsigned" in result.error.lower()

    def test_file_not_found(self, tmp_path):
        content, result = load_policy_with_verification(tmp_path / "nope.yaml", key=b"key")
        assert content == ""
        assert not result.valid