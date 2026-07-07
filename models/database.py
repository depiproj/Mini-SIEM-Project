"""
models/database.py — Async SQLAlchemy engine + session factory.
Supports SQLite (dev) and PostgreSQL (production) via DATABASE_URL.
"""
import logging

from sqlalchemy import text
from sqlalchemy.ext.asyncio import AsyncSession, async_sessionmaker, create_async_engine
from sqlalchemy.orm import DeclarativeBase
from config import DATABASE_URL

logger = logging.getLogger(__name__)

# ── Engine ────────────────────────────────────────────────────────────────────
# `check_same_thread=False` is only relevant for SQLite; harmless on Postgres.
connect_args = {"check_same_thread": False} if "sqlite" in DATABASE_URL else {}

engine = create_async_engine(
    DATABASE_URL,
    echo=False,           # Set True to log raw SQL during development
    connect_args=connect_args,
)

AsyncSessionLocal = async_sessionmaker(
    bind=engine,
    class_=AsyncSession,
    expire_on_commit=False,
    autoflush=False,
    autocommit=False,
)


class Base(DeclarativeBase):
    """All ORM models inherit from this base."""
    pass


# SQLAlchemy's create_all() only creates missing TABLES — it will never add a
# column to a table that already exists, which is exactly what breaks an
# existing dev database after a model gains a new field (e.g. content_hash on
# LogUpload). This is not a substitute for real migrations (Alembic) on
# Postgres/production, but for SQLite dev databases it closes the gap with a
# few lines instead of leaving people to hit an OperationalError and delete
# their db file every time a column is added.
def _column_map() -> dict[str, set[str]]:
    return {
        table.name: {col.name for col in table.columns}
        for table in Base.metadata.sorted_tables
    }


async def _add_missing_columns(conn) -> None:
    if "sqlite" not in DATABASE_URL:
        return  # Real migrations (Alembic) required for Postgres — see README.

    for table in Base.metadata.sorted_tables:
        result = await conn.execute(text(f"PRAGMA table_info('{table.name}')"))
        existing_cols = {row[1] for row in result.fetchall()}
        if not existing_cols:
            continue  # table doesn't exist yet — create_all() will handle it

        for column in table.columns:
            if column.name in existing_cols:
                continue
            col_type = column.type.compile(dialect=conn.dialect)
            ddl = f'ALTER TABLE "{table.name}" ADD COLUMN "{column.name}" {col_type}'
            logger.warning("Auto-migrating: %s", ddl)
            await conn.execute(text(ddl))


async def init_db() -> None:
    """Create all tables on startup (idempotent), then patch in any new columns."""
    async with engine.begin() as conn:
        await conn.run_sync(Base.metadata.create_all)
        await _add_missing_columns(conn)


async def get_db():
    """FastAPI dependency — yields an async DB session."""
    async with AsyncSessionLocal() as session:
        try:
            yield session
            await session.commit()
        except Exception:
            await session.rollback()
            raise