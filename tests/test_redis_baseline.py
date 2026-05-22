"""Tests for Redis-backed baseline store — B14.

Covers:
- Fallback to shipped baselines when Redis unavailable
- Custom baseline CRUD with mock Redis
- List all (shipped + custom)
- Serialization/deserialization roundtrip
- Config from environment
"""

from __future__ import annotations

import os
from unittest import mock

import pytest

from irondome.l4.baseline import SHIPPED_BASELINES
from irondome.l4.models import Baseline
from irondome.l4.redis_baseline import RedisBaselineStore


class TestFallbackToShipped:
    """When Redis is unavailable, fall back to shipped baselines."""

    def test_gets_shipped_baseline(self):
        store = RedisBaselineStore(redis_url="redis://localhost:1/0")
        baseline = store.get("npm-install")
        assert baseline is not None
        assert baseline.name == "npm-install"

    def test_returns_none_for_unknown(self):
        store = RedisBaselineStore(redis_url="redis://localhost:1/0")
        assert store.get("nonexistent-baseline") is None

    def test_list_custom_empty(self):
        store = RedisBaselineStore(redis_url="redis://localhost:1/0")
        assert store.list_custom() == []

    def test_list_all_includes_shipped(self):
        store = RedisBaselineStore(redis_url="redis://localhost:1/0")
        all_names = store.list_all()
        assert "npm-install" in all_names
        assert "python-pip-install" in all_names


class MockRedisForBaseline:
    """In-memory mock Redis for baseline testing."""

    def __init__(self):
        self._data: dict[str, str] = {}

    def ping(self):
        return True

    def get(self, key):
        return self._data.get(key)

    def set(self, key, value, **kwargs):
        self._data[key] = value

    def delete(self, *keys):
        count = 0
        for key in keys:
            if key in self._data:
                del self._data[key]
                count += 1
        return count

    def scan_iter(self, pattern):
        import fnmatch
        for key in list(self._data.keys()):
            if fnmatch.fnmatch(key, pattern):
                yield key

    def from_url(self, url, **kwargs):
        return self


class TestRedisBaselineWithMock:
    """Test Redis baseline store with mock Redis."""

    @pytest.fixture
    def store(self):
        s = RedisBaselineStore()
        mock_redis = MockRedisForBaseline()
        s._client = mock_redis
        s._available = True
        return s

    def test_set_and_get_custom(self, store):
        custom = Baseline(
            name="custom-test",
            package="custom-pkg",
            version="1.0",
            expected_network_calls=5,
            expected_dns_queries=2,
            expected_fs_ops=100,
            expected_spawns=0,
            expected_runtime_ms_range=(100, 5000),
            allowed_domains=["example.com"],
            allowed_paths=["/tmp/**"],
            notes="Custom test baseline",
        )
        store.set(custom)
        result = store.get("custom-test")
        assert result is not None
        assert result.name == "custom-test"
        assert result.package == "custom-pkg"
        assert result.expected_network_calls == 5
        assert result.allowed_domains == ["example.com"]

    def test_delete_custom(self, store):
        custom = Baseline(
            name="to-delete",
            package="pkg",
            version="1.0",
            expected_network_calls=0,
            expected_dns_queries=0,
            expected_fs_ops=0,
            expected_spawns=0,
            expected_runtime_ms_range=(0, 1000),
            allowed_domains=[],
            allowed_paths=[],
        )
        store.set(custom)
        assert store.delete("to-delete")
        assert store.get("to-delete") is None

    def test_list_custom(self, store):
        for name in ["custom-a", "custom-b"]:
            store.set(Baseline(
                name=name,
                package="pkg",
                version="1.0",
                expected_network_calls=0,
                expected_dns_queries=0,
                expected_fs_ops=0,
                expected_spawns=0,
                expected_runtime_ms_range=(0, 1000),
                allowed_domains=[],
                allowed_paths=[],
            ))
        custom = store.list_custom()
        assert "custom-a" in custom
        assert "custom-b" in custom

    def test_list_all_merges_shipped_and_custom(self, store):
        store.set(Baseline(
            name="my-custom",
            package="pkg",
            version="1.0",
            expected_network_calls=0,
            expected_dns_queries=0,
            expected_fs_ops=0,
            expected_spawns=0,
            expected_runtime_ms_range=(0, 1000),
            allowed_domains=[],
            allowed_paths=[],
        ))
        all_names = store.list_all()
        assert "npm-install" in all_names  # shipped
        assert "my-custom" in all_names  # custom

    def test_custom_overrides_shipped(self, store):
        """Custom baseline in Redis takes precedence over shipped."""
        custom = Baseline(
            name="npm-install",  # same name as shipped
            package="npm-custom",
            version="2.0",
            expected_network_calls=99,
            expected_dns_queries=0,
            expected_fs_ops=0,
            expected_spawns=0,
            expected_runtime_ms_range=(0, 1000),
            allowed_domains=[],
            allowed_paths=[],
        )
        store.set(custom)
        result = store.get("npm-install")
        assert result is not None
        assert result.package == "npm-custom"  # custom, not shipped

    def test_serialization_roundtrip(self, store):
        original = Baseline(
            name="roundtrip-test",
            package="test-pkg",
            version="3.0",
            expected_network_calls=7,
            expected_dns_queries=3,
            expected_fs_ops=42,
            expected_spawns=1,
            expected_runtime_ms_range=(500, 10000),
            allowed_domains=["a.com", "b.com"],
            allowed_paths=["/opt/**", "/var/**"],
            notes="Roundtrip test",
        )
        store.set(original)
        loaded = store.get("roundtrip-test")
        assert loaded is not None
        assert loaded.name == original.name
        assert loaded.package == original.package
        assert loaded.version == original.version
        assert loaded.expected_network_calls == original.expected_network_calls
        assert loaded.allowed_domains == original.allowed_domains
        assert loaded.allowed_paths == original.allowed_paths
        assert loaded.notes == original.notes


class TestRedisBaselineConfig:
    def test_url_from_env(self):
        with mock.patch.dict(os.environ, {"IRONDOME_REDIS_URL": "redis://custom:6379/5"}):
            store = RedisBaselineStore()
            assert store.redis_url == "redis://custom:6379/5"