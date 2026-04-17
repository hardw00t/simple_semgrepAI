"""Unit tests for LLM provider helpers."""
import pytest

from semgrepai.llm.providers import _clean_api_key


@pytest.mark.unit
def test_clean_api_key_strips_whitespace():
    assert _clean_api_key("  sk-ant-123  ") == "sk-ant-123"
    assert _clean_api_key("sk-ant-123\n") == "sk-ant-123"


@pytest.mark.unit
def test_clean_api_key_passes_plain_ascii():
    key = "sk-ant-api03-abcDEF0123456789"
    assert _clean_api_key(key) == key


@pytest.mark.unit
@pytest.mark.parametrize(
    "bad_key",
    [
        "\u201ckey\u201d",        # smart quotes wrapping
        "\ufeffsk-ant-123",       # BOM prefix
        "sk-ant\u00a0123",        # non-breaking space
        "sk\u2013ant-123",        # en-dash instead of hyphen
    ],
)
def test_clean_api_key_rejects_non_ascii(bad_key):
    with pytest.raises(ValueError, match="non-ASCII"):
        _clean_api_key(bad_key)
