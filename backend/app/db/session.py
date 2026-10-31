"""
Database Session and Engine Management for CyberTrace.
Provides asynchronous SQLAlchemy 2.0 connection lifecycle management.
"""

from contextlib import asynccontextmanager
from typing import AsyncGenerator
from sqlalchemy.ext.asyncio import (
    AsyncEngine,
    AsyncSession,
    async_sessionmaker,
    create_async_engine,
)
from sqlalchemy.orm import DeclarativeBase
from app.core.config import settings


class Base(DeclarativeBase):
    """Base declarative class for all SQLAlchemy 2.0 models."""
    pass


# Global engine and sessionmaker
engine: AsyncEngine = create_async_engine(
    settings.DATABASE_URL,
    echo=False,
    future=True,
)

async_session_factory = async_sessionmaker(
    bind=engine,
    expire_on_commit=False,
    class_=AsyncSession,
)


async def init_db(custom_engine: AsyncEngine = None) -> None:
    """Initialize database tables. Supports in-memory test engines."""
    eng = custom_engine or engine
    async with eng.begin() as conn:
        await conn.run_sync(Base.metadata.create_all)


async def drop_db(custom_engine: AsyncEngine = None) -> None:
    """Drop database tables (used in test teardown)."""
    eng = custom_engine or engine
    async with eng.begin() as conn:
        await conn.run_sync(Base.metadata.drop_all)


async def get_db_session() -> AsyncGenerator[AsyncSession, None]:
    """Async generator for FastAPI dependency injection."""
    async with async_session_factory() as session:
        try:
            yield session
            await session.commit()
        except Exception:
            await session.rollback()
            raise


@asynccontextmanager
async def get_async_session() -> AsyncGenerator[AsyncSession, None]:
    """Context manager for standalone async sessions with automatic rollback."""
    async for session in get_db_session():
        yield session
