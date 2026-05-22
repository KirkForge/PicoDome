"""Tests for mTLS module."""

import os

import pytest

from irondome.mtls import MTLSConfig, create_ssl_context


class TestMTLSConfig:
    def test_default_not_configured(self):
        config = MTLSConfig()
        assert config.is_configured is False

    def test_dev_mode_configured(self):
        config = MTLSConfig(dev_mode=True)
        assert config.is_configured is True

    def test_cert_key_configured(self):
        config = MTLSConfig(cert_path="/tmp/cert.pem", key_path="/tmp/key.pem")
        assert config.is_configured is True

    def test_from_env(self):
        os.environ["IRONDOME_TLS_CERT"] = "/tmp/test.pem"
        os.environ["IRONDOME_TLS_KEY"] = "/tmp/test-key.pem"
        try:
            config = MTLSConfig.from_env()
            assert config.cert_path == "/tmp/test.pem"
        finally:
            del os.environ["IRONDOME_TLS_CERT"]
            del os.environ["IRONDOME_TLS_KEY"]

    def test_to_dict(self):
        config = MTLSConfig(cert_path="c", key_path="k", ca_path="a")
        d = config.to_dict()
        assert d["cert_path"] == "c"
        assert d["key_path"] == "k"


class TestCreateSSLContext:
    def test_no_config_returns_none(self):
        ctx = create_ssl_context(MTLSConfig())
        assert ctx is None

    def test_dev_mode_creates_context(self):
        # This test requires openssl on PATH
        import shutil

        if not shutil.which("openssl"):
            pytest.skip("openssl not available")
        ctx = create_ssl_context(MTLSConfig(dev_mode=True))  # noqa: F841
        # Dev SSL context should be created (or raise if openssl fails)
        # We just verify it doesn't crash
