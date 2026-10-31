"""
Pytest configuration and async database fixtures for CyberTrace tests.
"""

from typing import AsyncGenerator
import pytest
from sqlalchemy.ext.asyncio import (
    AsyncEngine,
    AsyncSession,
    async_sessionmaker,
    create_async_engine,
)
from app.db.session import Base


@pytest.fixture
async def async_test_engine() -> AsyncGenerator[AsyncEngine, None]:
    """Provide an isolated in-memory SQLite engine for tests."""
    engine = create_async_engine(
        "sqlite+aiosqlite:///:memory:",
        echo=False,
        future=True,
    )
    async with engine.begin() as conn:
        await conn.run_sync(Base.metadata.create_all)

    yield engine

    async with engine.begin() as conn:
        await conn.run_sync(Base.metadata.drop_all)
    await engine.dispose()


@pytest.fixture
async def db_session(async_test_engine: AsyncEngine) -> AsyncGenerator[AsyncSession, None]:
    """Provide a clean AsyncSession per test."""
    session_factory = async_sessionmaker(
        bind=async_test_engine,
        expire_on_commit=False,
        class_=AsyncSession,
    )
    async with session_factory() as session:
        yield session

