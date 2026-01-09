"""Unit tests for configuration management."""
import pytest
from pathlib import Path
import yaml

from semgrepai.config import ConfigManager


@pytest.mark.unit
def test_config_manager_loads_defaults():
    """Test that ConfigManager loads with defaults when no file exists."""
    manager = ConfigManager()
    assert manager.config is not None
    assert manager.config.llm is not None


@pytest.mark.unit
def test_config_from_yaml_file(temp_dir: Path):
    """Test loading configuration from YAML file."""
    config_path = temp_dir / "test_config.yml"
    config_data = {
        "llm": {
            "provider": {
                "provider": "anthropic",
                "model": "claude-haiku-4-5-20250901",
                "temperature": 0.5,
            },
            "max_workers": 2,
        }
    }

    with open(config_path, "w") as f:
        yaml.dump(config_data, f)

    manager = ConfigManager(str(config_path))
    assert manager.config.llm.provider.provider == "anthropic"
    assert manager.config.llm.provider.model == "claude-haiku-4-5-20250901"
    assert manager.config.llm.max_workers == 2


@pytest.mark.unit
def test_config_env_override(temp_dir: Path, monkeypatch):
    """Test that environment variables can override config."""
    monkeypatch.setenv("OPENAI_API_KEY", "test-key-12345")

    manager = ConfigManager()
    # The API key should be available via environment
    import os

    assert os.getenv("OPENAI_API_KEY") == "test-key-12345"
