"""
Tests for the FastAPI routes.
"""
import os
import shutil
import tempfile


def test_health(client):
    response = client.get("/health")
    assert response.status_code == 200
    assert response.json()["status"] == "ok"


def test_demo_scan_returns_findings(client):
    response = client.post("/api/scan/demo")
    assert response.status_code == 200
    data = response.json()
    assert data["total_findings"] > 0
    assert data["files_scanned"] > 0
    assert "scan_id" in data
    assert "findings" in data


def test_demo_scan_matched_value_absent(client):
    """matched_value must NEVER appear in any API response."""
    response = client.post("/api/scan/demo")
    assert response.status_code == 200
    data = response.json()
    # Check top-level
    assert "matched_value" not in data
    # Check every finding
    for finding in data["findings"]:
        assert "matched_value" not in finding, (
            f"matched_value found in finding: {finding.get('pii_type')}"
        )


def test_get_scan_by_id(client):
    scan_resp = client.post("/api/scan/demo")
    scan_id = scan_resp.json()["scan_id"]

    get_resp = client.get(f"/api/scan/{scan_id}")
    assert get_resp.status_code == 200
    assert get_resp.json()["scan_id"] == scan_id


def test_get_scan_not_found(client):
    response = client.get("/api/scan/nonexistent-id")
    assert response.status_code == 404


def test_fix_and_rescan(client, demo_app_path):
    """Fix should reduce findings; rescan should match fix result.

    IMPORTANT: This test modifies demo_vulnerable_app files.
    It must restore them after running.
    """
    demo_files = ["customer_service.py", "payments.py", "errors.py", "utils.py"]

    # Backup originals
    backup_dir = tempfile.mkdtemp()
    for fname in demo_files:
        src = str(demo_app_path / fname)
        if os.path.exists(src):
            shutil.copy2(src, os.path.join(backup_dir, fname))

    try:
        # Initial scan
        scan_resp = client.post("/api/scan/demo")
        assert scan_resp.status_code == 200
        scan_id = scan_resp.json()["scan_id"]
        initial_count = scan_resp.json()["total_findings"]
        assert initial_count > 0

        # Apply fix
        fix_resp = client.post(f"/api/scan/{scan_id}/fix")
        assert fix_resp.status_code == 200
        fixed_data = fix_resp.json()
        assert fixed_data["total_findings"] == 0, (
            f"Expected 0 findings after fix, got {fixed_data['total_findings']}"
        )

        # Rescan
        new_scan_id = fixed_data["scan_id"]
        rescan_resp = client.post(f"/api/scan/{new_scan_id}/rescan")
        assert rescan_resp.status_code == 200
        assert rescan_resp.json()["total_findings"] == 0

        # matched_value must be absent from fix response too
        for finding in fixed_data["findings"]:
            assert "matched_value" not in finding

    finally:
        # Always restore originals
        for fname in demo_files:
            backed_up = os.path.join(backup_dir, fname)
            if os.path.exists(backed_up):
                shutil.copy2(backed_up, str(demo_app_path / fname))
        shutil.rmtree(backup_dir)


def test_security_headers(client):
    response = client.get("/health")
    assert "x-content-type-options" in response.headers
    assert "x-frame-options" in response.headers


def test_fix_not_found(client):
    """Fix on non-existent scan_id returns 404."""
    response = client.post("/api/scan/nonexistent-id/fix")
    assert response.status_code == 404


def test_rescan_not_found(client):
    """Rescan on non-existent scan_id returns 404."""
    response = client.post("/api/scan/nonexistent-id/rescan")
    assert response.status_code == 404


def test_demo_scan_findings_have_required_fields(client):
    """Every finding must have the expected fields."""
    response = client.post("/api/scan/demo")
    assert response.status_code == 200
    for finding in response.json()["findings"]:
        assert "pii_type" in finding
        assert "masked_value" in finding
        assert "file" in finding
        assert "line_number" in finding
        assert "severity" in finding
