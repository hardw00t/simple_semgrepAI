"""End-to-end tests for CLI scan workflow.

WARNING: These tests make real API calls, run semgrep, and cost money!
Run with: pytest tests/e2e -v
"""
import subprocess
import pytest
from pathlib import Path


@pytest.mark.e2e
@pytest.mark.expensive
@pytest.mark.slow
@pytest.mark.requires_openai
def test_full_cli_scan_workflow(
    sample_vulnerable_code: Path,
    temp_dir: Path,
    skip_if_no_openai,
):
    """Test complete CLI workflow: scan -> validate -> report."""
    output_dir = temp_dir / "reports"
    output_dir.mkdir(exist_ok=True)

    # Run semgrepai scan command
    cmd = [
        "semgrepai",
        "scan",
        str(sample_vulnerable_code),
        "--output-dir",
        str(output_dir),
    ]

    result = subprocess.run(
        cmd,
        capture_output=True,
        text=True,
        timeout=300,  # 5 minute timeout
        cwd=str(temp_dir),
    )

    # Check command succeeded
    assert result.returncode == 0, f"CLI failed: {result.stderr}"

    # Verify output files created
    # Note: Actual file names may vary based on implementation
    report_files = list(output_dir.glob("*"))
    assert len(report_files) > 0, "No report files generated"


@pytest.mark.e2e
@pytest.mark.expensive
def test_cli_help_command():
    """Test that CLI help command works."""
    result = subprocess.run(
        ["semgrepai", "--help"],
        capture_output=True,
        text=True,
        timeout=30,
    )

    assert result.returncode == 0
    assert "semgrepai" in result.stdout.lower() or "usage" in result.stdout.lower()


@pytest.mark.e2e
def test_cli_version_command():
    """Test that CLI version command works."""
    result = subprocess.run(
        ["semgrepai", "version"],
        capture_output=True,
        text=True,
        timeout=30,
    )

    # Version command should work
    assert result.returncode == 0
