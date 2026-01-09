"""Shared pytest fixtures for SemgrepAI tests."""
import os
import tempfile
import shutil
import pytest
from pathlib import Path
from typing import Generator


# ============================================================================
# PYTEST CONFIGURATION
# ============================================================================


def pytest_configure(config):
    """Configure custom markers."""
    config.addinivalue_line("markers", "unit: Fast unit tests (no external deps)")
    config.addinivalue_line("markers", "integration: Integration tests (may use external deps)")
    config.addinivalue_line("markers", "e2e: End-to-end tests with REAL LLM calls (slow, costs money)")
    config.addinivalue_line("markers", "expensive: Tests that cost money (real LLM API calls)")
    config.addinivalue_line("markers", "slow: Tests that take >10 seconds")
    config.addinivalue_line("markers", "requires_openai: Requires OpenAI API key")
    config.addinivalue_line("markers", "requires_anthropic: Requires Anthropic API key")
    config.addinivalue_line("markers", "requires_ollama: Requires local Ollama server")


def pytest_collection_modifyitems(config, items):
    """Auto-mark tests based on path."""
    for item in items:
        rel_path = str(item.fspath)

        if "/unit/" in rel_path:
            item.add_marker(pytest.mark.unit)
        elif "/integration/" in rel_path:
            item.add_marker(pytest.mark.integration)
        elif "/e2e/" in rel_path:
            item.add_marker(pytest.mark.e2e)
            item.add_marker(pytest.mark.expensive)
            item.add_marker(pytest.mark.slow)


# ============================================================================
# ENVIRONMENT & CONFIGURATION FIXTURES
# ============================================================================


@pytest.fixture(scope="session")
def test_env_vars():
    """Ensure required environment variables for tests."""
    return {
        "OPENAI_API_KEY": os.getenv("OPENAI_API_KEY"),
        "ANTHROPIC_API_KEY": os.getenv("ANTHROPIC_API_KEY"),
        "OLLAMA_BASE_URL": os.getenv("OLLAMA_BASE_URL", "http://localhost:11434"),
    }


@pytest.fixture(scope="session")
def test_models():
    """Define cheaper models for testing."""
    return {
        "openai": "gpt-4o-mini",
        "anthropic": "claude-haiku-4-5-20250901",
        "ollama": "llama3.2:latest",
    }


@pytest.fixture
def temp_dir() -> Generator[Path, None, None]:
    """Create a temporary directory for test isolation."""
    temp_path = Path(tempfile.mkdtemp(prefix="semgrepai_test_"))
    yield temp_path
    shutil.rmtree(temp_path, ignore_errors=True)


@pytest.fixture
def project_root() -> Path:
    """Get the project root directory."""
    return Path(__file__).parent.parent


# ============================================================================
# SAMPLE DATA FIXTURES
# ============================================================================


@pytest.fixture
def sample_vulnerable_code(temp_dir: Path) -> Path:
    """Create sample vulnerable Python code for testing."""
    code_dir = temp_dir / "sample_code"
    code_dir.mkdir()

    # SQL Injection vulnerability
    sql_injection = code_dir / "sql_injection.py"
    sql_injection.write_text('''
import sqlite3

def get_user(username):
    conn = sqlite3.connect('users.db')
    cursor = conn.cursor()
    # VULNERABLE: SQL injection
    query = f"SELECT * FROM users WHERE username = '{username}'"
    cursor.execute(query)
    return cursor.fetchone()
''')

    # XSS vulnerability
    xss_vuln = code_dir / "xss.py"
    xss_vuln.write_text('''
from flask import Flask, request, render_template_string

app = Flask(__name__)

@app.route('/search')
def search():
    query = request.args.get('q', '')
    # VULNERABLE: XSS via template injection
    return render_template_string(f"<h1>Results for: {query}</h1>")
''')

    # Safe code (false positive test)
    safe_code = code_dir / "safe.py"
    safe_code.write_text('''
import sqlite3

def get_user_safe(user_id):
    conn = sqlite3.connect('users.db')
    cursor = conn.cursor()
    # SAFE: Parameterized query
    query = "SELECT * FROM users WHERE id = ?"
    cursor.execute(query, (user_id,))
    return cursor.fetchone()
''')

    return code_dir


@pytest.fixture
def sample_findings():
    """Sample Semgrep findings for testing."""
    return [
        {
            "rule_id": "python.lang.security.injection.sql.sql-injection",
            "severity": "ERROR",
            "message": "Potential SQL injection vulnerability",
            "path": "test.py",
            "line": 5,
            "code": "query = f\"SELECT * FROM users WHERE username = '{username}'\"",
            "metadata": {
                "cwe": ["CWE-89"],
                "owasp": "A03:2021",
                "vulnerability_class": ["SQL Injection"],
            },
        },
        {
            "rule_id": "python.flask.security.xss.template-injection",
            "severity": "ERROR",
            "message": "Template injection leading to XSS",
            "path": "app.py",
            "line": 8,
            "code": 'return render_template_string(f"<h1>Results for: {query}</h1>")',
            "metadata": {
                "cwe": ["CWE-79"],
                "owasp": "A03:2021",
                "vulnerability_class": ["XSS"],
            },
        },
    ]


# ============================================================================
# SKIP HELPERS
# ============================================================================


@pytest.fixture
def skip_if_no_openai(test_env_vars):
    """Skip test if OpenAI API key is not set."""
    if not test_env_vars["OPENAI_API_KEY"]:
        pytest.skip("OPENAI_API_KEY not set")


@pytest.fixture
def skip_if_no_anthropic(test_env_vars):
    """Skip test if Anthropic API key is not set."""
    if not test_env_vars["ANTHROPIC_API_KEY"]:
        pytest.skip("ANTHROPIC_API_KEY not set")
