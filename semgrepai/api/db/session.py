"""Async SQLAlchemy database session configuration."""

from sqlalchemy.ext.asyncio import AsyncSession, create_async_engine, async_sessionmaker
from sqlalchemy.orm import DeclarativeBase
from pathlib import Path
from typing import AsyncGenerator

from ...config import ConfigManager


class Base(DeclarativeBase):
    """Base class for SQLAlchemy models."""
    pass


# Create config manager to get database URL
_config = ConfigManager()
_db_url = _config.config.api.db_url

# Ensure the database directory exists
if _db_url.startswith("sqlite"):
    db_path = _db_url.split("///")[-1]
    if db_path and db_path != ":memory:":
        Path(db_path).parent.mkdir(parents=True, exist_ok=True)

# Create async engine
engine = create_async_engine(
    _db_url,
    echo=_config.config.api.debug,
    future=True,
)

# Create async session factory
AsyncSessionLocal = async_sessionmaker(
    engine,
    class_=AsyncSession,
    expire_on_commit=False,
    autocommit=False,
    autoflush=False,
)


async def get_db() -> AsyncGenerator[AsyncSession, None]:
    """Dependency to get database session."""
    async with AsyncSessionLocal() as session:
        try:
            yield session
            await session.commit()
        except Exception:
            await session.rollback()
            raise
        finally:
            await session.close()


async def init_db():
    """Initialize the database schema."""
    # Import models to ensure they are registered
    from ..models import scan, finding  # noqa: F401

    async with engine.begin() as conn:
        await conn.run_sync(Base.metadata.create_all)
