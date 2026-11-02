"""
Tests for demo_lifecycle.py standalone runner.
Verifies that the demo script completes under genuine detection conditions,
and strictly fails (SystemExit(1)) if detection or incident correlation is missing.
"""

import pytest
import httpx
from unittest.mock import patch
from sqlalchemy.ext.asyncio import create_async_engine, async_sessionmaker, AsyncSession
from app.db.models import Base
from app.db.session import get_db_session
from app.main import app
from demo_lifecycle import _run_lifecycle


@pytest.fixture
async def demo_client():
    engine = create_async_engine("sqlite+aiosqlite:///:memory:", echo=False)
    async with engine.begin() as conn:
        await conn.run_sync(Base.metadata.create_all)

    session_factory = async_sessionmaker(engine, class_=AsyncSession, expire_on_commit=False)

    async def _override_get_db_session():
        async with session_factory() as session:
            yield session

    app.dependency_overrides[get_db_session] = _override_get_db_session

    transport = httpx.ASGITransport(app=app)
    async with httpx.AsyncClient(transport=transport, base_url="http://test", timeout=15.0) as client:
        yield client

    app.dependency_overrides.pop(get_db_session, None)
    await engine.dispose()


@pytest.mark.asyncio
async def test_demo_lifecycle_script_runs_successfully(demo_client):
    """Verify that demo_lifecycle completes end-to-end when detections trigger normally."""
    # Should not raise SystemExit
    await _run_lifecycle(demo_client)


@pytest.mark.asyncio
async def test_demo_lifecycle_fails_when_detection_absent(demo_client):
    """Verify that demo_lifecycle terminates with exit code 1 if no detection is generated."""
    original_get = demo_client.get

    async def mock_get(url, *args, **kwargs):
        if "/api/v1/detections" in str(url):
            # Simulate detection engine failing to match any event
            return httpx.Response(200, json=[], request=httpx.Request("GET", url))
        return await original_get(url, *args, **kwargs)

    with patch.object(demo_client, "get", side_effect=mock_get):
        with pytest.raises(SystemExit) as exc_info:
            await _run_lifecycle(demo_client)
        assert exc_info.value.code == 1


@pytest.mark.asyncio
async def test_demo_lifecycle_fails_when_incident_correlation_absent(demo_client):
    """Verify that demo_lifecycle terminates with exit code 1 if incident correlation fails."""
    original_get = demo_client.get

    async def mock_get(url, *args, **kwargs):
        if str(url).endswith("/api/v1/incidents"):
            # Simulate no incidents produced
            return httpx.Response(200, json=[], request=httpx.Request("GET", url))
        return await original_get(url, *args, **kwargs)

    with patch.object(demo_client, "get", side_effect=mock_get):
        with pytest.raises(SystemExit) as exc_info:
            await _run_lifecycle(demo_client)
        assert exc_info.value.code == 1
