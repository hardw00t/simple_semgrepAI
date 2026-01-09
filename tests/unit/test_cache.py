"""Unit tests for validation cache."""
import pytest
import json
import hashlib
from pathlib import Path

from semgrepai.cache import ValidationCache


def _make_cache_key(finding: dict) -> str:
    """Create a cache key from a finding dict."""
    key_data = json.dumps(finding, sort_keys=True)
    return hashlib.sha256(key_data.encode()).hexdigest()


@pytest.mark.unit
def test_cache_creation(temp_dir: Path):
    """Test cache can be created in temp directory."""
    cache_dir = temp_dir / "cache"
    cache = ValidationCache(cache_dir)
    assert cache is not None
    assert cache.cache_dir.exists()


@pytest.mark.unit
def test_cache_set_and_get(temp_dir: Path):
    """Test cache set and get operations."""
    cache_dir = temp_dir / "cache"
    cache = ValidationCache(cache_dir)

    # Create a test finding and its cache key
    finding = {
        "rule_id": "test-rule",
        "code": "test code",
        "path": "test.py",
    }
    cache_key = _make_cache_key(finding)

    validation_result = {
        "verdict": "True Positive",
        "confidence": 0.9,
        "risk_score": 8,
    }

    # Set and retrieve using string key
    cache.set(cache_key, validation_result)
    retrieved = cache.get(cache_key)

    assert retrieved is not None
    assert retrieved["verdict"] == "True Positive"


@pytest.mark.unit
def test_cache_miss(temp_dir: Path):
    """Test cache returns None for missing entries."""
    cache_dir = temp_dir / "cache"
    cache = ValidationCache(cache_dir)

    # Use a string key that doesn't exist
    missing_key = "nonexistent-key-12345"

    result = cache.get(missing_key)
    assert result is None


@pytest.mark.unit
def test_cache_clear(temp_dir: Path):
    """Test cache clearing."""
    cache_dir = temp_dir / "cache"
    cache = ValidationCache(cache_dir)

    # Add some data
    cache.set("test-key", {"data": "value"})
    assert cache.get("test-key") is not None

    # Clear and verify
    cache.clear()
    assert cache.get("test-key") is None
