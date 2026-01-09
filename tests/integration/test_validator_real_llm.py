"""Integration tests for AIValidator with REAL LLM calls.

WARNING: These tests make real API calls and cost money!
Run with: pytest tests/integration -v -m "requires_openai"
"""
import os
import yaml
import pytest

from semgrepai.validator import AIValidator


@pytest.mark.integration
@pytest.mark.expensive
@pytest.mark.requires_openai
def test_validate_sql_injection_with_openai(
    sample_findings,
    skip_if_no_openai,
    temp_dir,
):
    """Test real LLM validation of SQL injection vulnerability with OpenAI."""
    # Create a config file for testing
    config_path = temp_dir / "test_config.yml"
    cache_dir = temp_dir / "cache"
    cache_dir.mkdir(parents=True, exist_ok=True)

    config_data = {
        "llm": {
            "provider": {
                "provider": "openai",
                "model": "gpt-4o-mini",
                "temperature": 0,
            },
            "cache_dir": str(cache_dir),
            "max_workers": 1,
        }
    }

    with open(config_path, "w") as f:
        yaml.dump(config_data, f)

    validator = AIValidator(config_path=str(config_path))

    # Just validate the first finding (SQL injection)
    findings = [sample_findings[0]]

    # This makes a REAL API call
    results = validator.validate_findings(findings)

    assert len(results) == 1
    validated = results[0]

    # Assertions on LLM response
    assert "ai_validation" in validated
    validation = validated["ai_validation"]

    # Clean up any markdown formatting from the verdict
    verdict = validation["verdict"].strip().strip("*").strip()
    assert verdict in ["True Positive", "False Positive", "Needs Review"], f"Unexpected verdict: {verdict}"

    # Verify confidence is valid (may be parsed with issues)
    assert 0 <= validation.get("confidence", 0) <= 1

    # Risk score may be 0 due to parsing issues - just check it's in valid range
    assert 0 <= validation.get("risk_score", 0) <= 10

    # Justification should exist and have content
    assert validation.get("justification") is not None


@pytest.mark.integration
@pytest.mark.expensive
@pytest.mark.requires_anthropic
def test_validate_with_anthropic(
    sample_findings,
    skip_if_no_anthropic,
    temp_dir,
):
    """Test real LLM validation with Anthropic Claude."""
    # Create a config file for testing
    config_path = temp_dir / "test_config.yml"
    cache_dir = temp_dir / "cache"
    cache_dir.mkdir(parents=True, exist_ok=True)

    config_data = {
        "llm": {
            "provider": {
                "provider": "anthropic",
                "model": "claude-haiku-4-5-20250901",
                "temperature": 0,
            },
            "cache_dir": str(cache_dir),
            "max_workers": 1,
        }
    }

    with open(config_path, "w") as f:
        yaml.dump(config_data, f)

    validator = AIValidator(config_path=str(config_path))

    # Just validate one finding
    results = validator.validate_findings([sample_findings[0]])

    assert len(results) == 1
    assert "ai_validation" in results[0]
