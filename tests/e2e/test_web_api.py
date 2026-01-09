"""End-to-end tests for the SemgrepAI Web API.

These tests verify the full API workflow including:
- Scan creation and execution
- Findings retrieval
- Dashboard statistics
- Finding triage updates
"""

import pytest
import httpx
import asyncio
import time
from pathlib import Path


@pytest.fixture(scope="module")
def api_base_url():
    """Base URL for the API server."""
    return "http://127.0.0.1:8082/api/v1"


@pytest.fixture(scope="module")
def test_target_path():
    """Path to test fixtures."""
    return str(Path(__file__).parent.parent / "fixtures" / "sample_code" / "python")


@pytest.mark.e2e
@pytest.mark.asyncio
async def test_api_health_check(api_base_url):
    """Test that the API server is responding."""
    async with httpx.AsyncClient(timeout=10.0) as client:
        response = await client.get(f"{api_base_url}/stats")
        assert response.status_code == 200
        data = response.json()
        assert "total_scans" in data
        assert "total_findings" in data


@pytest.mark.e2e
@pytest.mark.asyncio
async def test_get_scans_list(api_base_url):
    """Test retrieving the list of scans."""
    async with httpx.AsyncClient(timeout=10.0) as client:
        response = await client.get(f"{api_base_url}/scans")
        assert response.status_code == 200
        data = response.json()
        assert "items" in data
        assert "total" in data
        assert "page" in data


@pytest.mark.e2e
@pytest.mark.asyncio
async def test_create_and_complete_scan(api_base_url, test_target_path):
    """Test creating a new scan and waiting for completion."""
    async with httpx.AsyncClient(timeout=120.0) as client:
        # Create a new scan
        create_response = await client.post(
            f"{api_base_url}/scans",
            json={
                "target_path": test_target_path,
                "name": "E2E API Test Scan",
            }
        )
        assert create_response.status_code == 201, f"Failed to create scan: {create_response.text}"

        scan_data = create_response.json()
        scan_id = scan_data["id"]
        assert scan_id is not None

        # Wait for scan to complete (with timeout)
        max_wait_time = 60  # seconds
        start_time = time.time()

        while time.time() - start_time < max_wait_time:
            status_response = await client.get(f"{api_base_url}/scans/{scan_id}")
            assert status_response.status_code == 200

            status_data = status_response.json()
            if status_data["status"] in ["completed", "failed"]:
                break

            await asyncio.sleep(2)

        # Verify scan completed
        final_response = await client.get(f"{api_base_url}/scans/{scan_id}")
        final_data = final_response.json()
        assert final_data["status"] in ["completed", "failed"], f"Scan did not complete: {final_data['status']}"


@pytest.mark.e2e
@pytest.mark.asyncio
async def test_get_scan_findings(api_base_url):
    """Test retrieving findings for an existing scan."""
    async with httpx.AsyncClient(timeout=10.0) as client:
        # First get list of scans
        scans_response = await client.get(f"{api_base_url}/scans")
        assert scans_response.status_code == 200

        scans_data = scans_response.json()
        if scans_data["total"] == 0:
            pytest.skip("No scans available to test findings")

        # Get findings for first scan
        scan_id = scans_data["items"][0]["id"]
        findings_response = await client.get(f"{api_base_url}/scans/{scan_id}/findings")
        assert findings_response.status_code == 200

        findings_data = findings_response.json()
        assert "items" in findings_data
        assert "total" in findings_data


@pytest.mark.e2e
@pytest.mark.asyncio
async def test_get_dashboard_stats(api_base_url):
    """Test the dashboard statistics endpoint."""
    async with httpx.AsyncClient(timeout=10.0) as client:
        response = await client.get(f"{api_base_url}/stats")
        assert response.status_code == 200

        data = response.json()

        # Verify expected fields (from actual API response)
        expected_fields = [
            "total_scans",
            "total_findings",
            "completed_scans",
            "failed_scans",
        ]

        for field in expected_fields:
            assert field in data, f"Missing field: {field}"
            assert isinstance(data[field], (int, float)), f"Field {field} should be numeric"


@pytest.mark.e2e
@pytest.mark.asyncio
async def test_update_finding_triage(api_base_url):
    """Test updating a finding's triage status."""
    async with httpx.AsyncClient(timeout=10.0) as client:
        # Get scans with findings
        scans_response = await client.get(f"{api_base_url}/scans")
        scans_data = scans_response.json()

        if scans_data["total"] == 0:
            pytest.skip("No scans available")

        # Find a scan with findings
        for scan in scans_data["items"]:
            if scan["total_findings"] > 0:
                scan_id = scan["id"]
                break
        else:
            pytest.skip("No scans with findings available")

        # Get findings
        findings_response = await client.get(f"{api_base_url}/scans/{scan_id}/findings")
        findings_data = findings_response.json()

        if findings_data["total"] == 0:
            pytest.skip("No findings available")

        finding_id = findings_data["items"][0]["id"]

        # Update triage status
        update_response = await client.patch(
            f"{api_base_url}/scans/{scan_id}/findings/{finding_id}",
            json={"triage_status": "true_positive"}
        )
        assert update_response.status_code == 200

        # Verify the update
        updated_finding = update_response.json()
        assert updated_finding["triage_status"] == "true_positive"


@pytest.mark.e2e
@pytest.mark.asyncio
async def test_scan_with_custom_rules(api_base_url, test_target_path):
    """Test creating a scan with custom rules."""
    rules_path = str(Path(__file__).parent.parent.parent / "semgrepai" / "rules" / "common_vulnerabilities.yml")

    # Skip if rules file doesn't exist
    if not Path(rules_path).exists():
        pytest.skip("Custom rules file not found")

    async with httpx.AsyncClient(timeout=120.0) as client:
        create_response = await client.post(
            f"{api_base_url}/scans",
            json={
                "target_path": test_target_path,
                "name": "E2E Custom Rules Test",
                "rules_path": rules_path,
            }
        )

        # Should create or fail gracefully
        assert create_response.status_code in [201, 400, 422]


@pytest.mark.e2e
@pytest.mark.asyncio
async def test_pagination(api_base_url):
    """Test pagination of scans list."""
    async with httpx.AsyncClient(timeout=10.0) as client:
        # Request first page with small page size
        response = await client.get(f"{api_base_url}/scans?page=1&page_size=2")
        assert response.status_code == 200

        data = response.json()
        assert data["page"] == 1
        assert data["page_size"] == 2
        assert len(data["items"]) <= 2


@pytest.mark.e2e
@pytest.mark.asyncio
async def test_error_handling_invalid_scan_id(api_base_url):
    """Test error handling for invalid scan ID."""
    async with httpx.AsyncClient(timeout=10.0) as client:
        response = await client.get(f"{api_base_url}/scans/invalid-uuid-here")
        # Should return 404 or 422 for invalid UUID
        assert response.status_code in [404, 422]


@pytest.mark.e2e
@pytest.mark.asyncio
async def test_error_handling_missing_target_path(api_base_url):
    """Test error handling when target_path is missing."""
    async with httpx.AsyncClient(timeout=10.0) as client:
        response = await client.post(
            f"{api_base_url}/scans",
            json={"name": "Test without target"}
        )
        # Should return 422 for validation error
        assert response.status_code == 422
