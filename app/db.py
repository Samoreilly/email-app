from collections.abc import Iterator
from contextlib import contextmanager
from datetime import UTC, datetime
from pathlib import Path

from sqlalchemy import create_engine, event
from sqlalchemy.orm import DeclarativeBase, Session, sessionmaker

from app.config import get_settings


class Base(DeclarativeBase):
    pass


def utcnow() -> datetime:
    """Naive UTC timestamp; every datetime in the database is naive UTC."""
    return datetime.now(UTC).replace(tzinfo=None)


_engine = None
_SessionLocal: sessionmaker[Session] | None = None


def init_engine(url: str | None = None):
    global _engine, _SessionLocal
    url = url or get_settings().database_url
    kwargs = {}
    if url.startswith("sqlite"):
        path = url.removeprefix("sqlite:///")
        if path and path != ":memory:":
            Path(path).parent.mkdir(parents=True, exist_ok=True)
        kwargs["connect_args"] = {"check_same_thread": False}
    _engine = create_engine(url, pool_pre_ping=True, **kwargs)
    if url.startswith("sqlite"):

        @event.listens_for(_engine, "connect")
        def _sqlite_pragmas(conn, _):
            cur = conn.cursor()
            cur.execute("PRAGMA foreign_keys=ON")
            cur.execute("PRAGMA journal_mode=WAL")
            cur.close()

    _SessionLocal = sessionmaker(bind=_engine, expire_on_commit=False)
    return _engine


def get_engine():
    if _engine is None:
        init_engine()
    return _engine


def create_all() -> None:
    from app import models  # noqa: F401  (registers tables)

    Base.metadata.create_all(get_engine())


def new_session() -> Session:
    if _SessionLocal is None:
        init_engine()
    return _SessionLocal()


@contextmanager
def session_scope() -> Iterator[Session]:
    s = new_session()
    try:
        yield s
        s.commit()
    except Exception:
        s.rollback()
        raise
    finally:
        s.close()


def get_db() -> Iterator[Session]:
    """FastAPI dependency."""
    s = new_session()
    try:
        yield s
    finally:
        s.close()
