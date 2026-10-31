"""
API endpoint integration tests for CyberTrace.
"""

from httpx import ASGITransport, AsyncClient
import pytest
from app.main import app


@pytest.mark.asyncio
async def test_health_check_endpoint():
    transport = ASGITransport(app=app)
    async with AsyncClient(transport=transport, base_url="http://test") as client:
        response = await client.get("/api/v1/health")
        assert response.status_code == 200
        data = response.json()
        assert data["status"] == "healthy"
        assert data["service"] == "CyberTrace"


@pytest.mark.asyncio
async def test_list_incidents_endpoint():
    transport = ASGITransport(app=app)
    async with AsyncClient(transport=transport, base_url="http://test") as client:
        response = await client.get("/api/v1/incidents")
        assert response.status_code == 200
        assert isinstance(response.json(), list)


@pytest.mark.asyncio
async def test_upload_valid_json_log():
    sample_json = """
    [
        {
            "event_id": "evt_api_001",
            "timestamp": "2026-11-01T08:00:00Z",
            "category": "authentication",
            "action": "logon_failure",
            "user_identity": "jdoe",
            "source_ip": "192.168.1.10"
        }
    ]
    """
    transport = ASGITransport(app=app)
    async with AsyncClient(transport=transport, base_url="http://test") as client:
        files = {"file": ("auth.json", sample_json.encode("utf-8"), "application/json")}
        response = await client.post("/api/v1/logs/upload", files=files)
        assert response.status_code == 200
        data = response.json()
        assert data["filename"] == "auth.json"
        assert data["parsed_events_count"] == 1
        assert data["persisted_events_count"] == 1
        assert data["status"] == "success"


@pytest.mark.asyncio
async def test_upload_valid_csv_log():
    sample_csv = "timestamp,user,action,src_ip\n2026-11-01T08:00:00Z,jdoe,logon_success,192.168.1.10\n"
    transport = ASGITransport(app=app)
    async with AsyncClient(transport=transport, base_url="http://test") as client:
        files = {"file": ("auth.csv", sample_csv.encode("utf-8"), "text/csv")}
        response = await client.post("/api/v1/logs/upload", files=files)
        assert response.status_code == 200
        data = response.json()
        assert data["filename"] == "auth.csv"
        assert data["parsed_events_count"] == 1
        assert data["detected_format"] == "generic_csv"


@pytest.mark.asyncio
async def test_upload_empty_or_malformed_log():
    transport = ASGITransport(app=app)
    async with AsyncClient(transport=transport, base_url="http://test") as client:
        # Empty file
        empty_files = {"file": ("empty.log", b"", "text/plain")}
        res_empty = await client.post("/api/v1/logs/upload", files=empty_files)
        assert res_empty.status_code == 400

        # Unparseable binary or garbage
        garbage_files = {"file": ("corrupt.bin", b"\x00\x01\x02\x03\x04\x05", "application/octet-stream")}
        res_garbage = await client.post("/api/v1/logs/upload", files=garbage_files)
        assert res_garbage.status_code == 400


@pytest.mark.asyncio
async def test_upload_oversized_file_limit():
    from app.core.config import settings
    # Temporarily set a small size limit to test chunked enforcement
    original_limit = settings.MAX_UPLOAD_SIZE_BYTES
    settings.MAX_UPLOAD_SIZE_BYTES = 100  # 100 bytes limit

    oversized_data = b"A" * 500  # 500 bytes exceeds 100
    transport = ASGITransport(app=app)
    try:
        async with AsyncClient(transport=transport, base_url="http://test") as client:
            files = {"file": ("big.log", oversized_data, "text/plain")}
            response = await client.post("/api/v1/logs/upload", files=files)
            assert response.status_code == 413
            assert "exceeds maximum size" in response.json()["detail"]
    finally:
        settings.MAX_UPLOAD_SIZE_BYTES = original_limit


@pytest.mark.asyncio
async def test_upload_benign_logs_zero_detections():
    from pathlib import Path
    sample_path = Path(__file__).resolve().parent.parent / "app" / "data" / "sample_logs" / "benign_activity.json"
    with open(sample_path, "rb") as f:
        benign_bytes = f.read()

    transport = ASGITransport(app=app)
    async with AsyncClient(transport=transport, base_url="http://test") as client:
        files = {"file": ("benign.json", benign_bytes, "application/json")}
        response = await client.post("/api/v1/logs/upload", files=files)
        assert response.status_code == 200
        data = response.json()
        assert data["parsed_events_count"] == 6
        assert data["detections_count"] == 0
        assert data["incidents_count"] == 0


@pytest.mark.asyncio
async def test_upload_multi_stage_attack_creates_incident():
    from pathlib import Path
    sample_path = Path(__file__).resolve().parent.parent / "app" / "data" / "sample_logs" / "multi_stage_attack.json"
    with open(sample_path, "rb") as f:
        attack_bytes = f.read()

    transport = ASGITransport(app=app)
    async with AsyncClient(transport=transport, base_url="http://test") as client:
        files = {"file": ("attack.json", attack_bytes, "application/json")}
        response = await client.post("/api/v1/logs/upload", files=files)
        assert response.status_code == 200
        data = response.json()
        assert data["parsed_events_count"] == 9
        assert data["detections_count"] >= 4
        assert data["incidents_count"] == 1

        # Check incidents endpoint returns this incident
        inc_res = await client.get("/api/v1/incidents")
        assert inc_res.status_code == 200
        inc_list = inc_res.json()
        assert len(inc_list) >= 1
        assert any(i["severity"] in ("critical", "high") for i in inc_list)


@pytest.mark.asyncio
async def test_upload_idempotency_repeated_upload():
    from pathlib import Path
    sample_path = Path(__file__).resolve().parent.parent / "app" / "data" / "sample_logs" / "multi_stage_attack.json"
    with open(sample_path, "rb") as f:
        attack_bytes = f.read()

    transport = ASGITransport(app=app)
    async with AsyncClient(transport=transport, base_url="http://test") as client:
        files1 = {"file": ("attack.json", attack_bytes, "application/json")}
        res1 = await client.post("/api/v1/logs/upload", files=files1)
        assert res1.status_code == 200

        # Upload exact same file second time
        files2 = {"file": ("attack.json", attack_bytes, "application/json")}
        res2 = await client.post("/api/v1/logs/upload", files=files2)
        assert res2.status_code == 200
        assert res2.json()["parsed_events_count"] == 9

