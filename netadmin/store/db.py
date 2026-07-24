"""SQLite connection factory, pragmas, migration runner, and the write-txn guard.

This module owns everything about *how* the database file is opened and kept
honest; :mod:`netadmin.store.repository` owns *what* SQL runs against it. The
non-negotiable pragmas and the ``BEGIN IMMEDIATE`` discipline come straight from
``docs/ARCHITECTURE.md`` section 4:

- ``journal_mode=WAL`` -- readers never block the single writer.
- ``synchronous=NORMAL`` -- the WAL-safe durability/throughput trade.
- ``busy_timeout=5000`` -- wait up to 5 s for a lock instead of failing instantly.
- ``foreign_keys=ON`` -- enforced per connection.

Connections run with ``isolation_level=None`` (autocommit): Python's implicit
transaction management is disabled so we control every transaction by hand.
Writers open with :func:`begin_immediate`, which takes the write lock up front.
A read-then-upgrade transaction (plain ``BEGIN`` then a write) fails instantly
regardless of ``busy_timeout`` -- that is the known trap this module exists to
avoid.
"""

from __future__ import annotations

import re
import sqlite3
from contextlib import contextmanager
from pathlib import Path
from typing import Iterator, Union

__all__ = [
    "MIGRATIONS_DIR",
    "connect",
    "begin_immediate",
    "apply_migrations",
    "schema_version",
]

MIGRATIONS_DIR = Path(__file__).resolve().parent / "migrations"

# Applied verbatim on every new connection, in order.
_PRAGMAS: tuple[tuple[str, object], ...] = (
    ("journal_mode", "WAL"),
    ("synchronous", "NORMAL"),
    ("foreign_keys", "ON"),
)

_MIGRATION_RE = re.compile(r"^(\d+)_.*\.sql$")


def connect(
    db_path: Union[str, Path],
    *,
    busy_timeout_ms: int = 5000,
) -> sqlite3.Connection:
    """Open a connection with the non-negotiable pragmas applied.

    ``busy_timeout_ms`` is exposed (default 5000, per the architecture doc) so
    tests can dial it down to make lock-contention assertions fail fast instead
    of blocking for five seconds.
    """
    path = Path(db_path)
    if path.parent and not path.parent.exists():
        path.parent.mkdir(parents=True, exist_ok=True)

    # isolation_level=None -> autocommit; we manage transactions explicitly.
    conn = sqlite3.connect(str(path), isolation_level=None)
    conn.row_factory = sqlite3.Row
    for name, value in _PRAGMAS:
        conn.execute(f"PRAGMA {name}={value}")
    conn.execute(f"PRAGMA busy_timeout={int(busy_timeout_ms)}")
    return conn


@contextmanager
def begin_immediate(conn: sqlite3.Connection) -> Iterator[sqlite3.Connection]:
    """Run a write transaction, taking the write lock up front.

    ``BEGIN IMMEDIATE`` acquires SQLite's RESERVED lock at transaction start, so
    two writers contend immediately (the loser waits out ``busy_timeout`` then
    raises ``OperationalError``) while WAL readers proceed unblocked. Commits on
    clean exit, rolls back on any exception. If the ``BEGIN`` itself fails
    (another writer holds the lock), the exception propagates and no rollback is
    attempted -- there is no open transaction to unwind.
    """
    conn.execute("BEGIN IMMEDIATE")
    try:
        yield conn
    except BaseException:
        conn.execute("ROLLBACK")
        raise
    else:
        conn.execute("COMMIT")


def schema_version(conn: sqlite3.Connection) -> int:
    """Current schema version from ``PRAGMA user_version`` (0 = fresh db)."""
    return int(conn.execute("PRAGMA user_version").fetchone()[0])


def _discover_migrations(migrations_dir: Path) -> list[tuple[int, Path]]:
    """Return ``(version, path)`` for every ``NNNN_*.sql`` file, sorted."""
    found: list[tuple[int, Path]] = []
    for path in sorted(migrations_dir.glob("*.sql")):
        match = _MIGRATION_RE.match(path.name)
        if match:
            found.append((int(match.group(1)), path))
    found.sort(key=lambda item: item[0])
    return found


def _iter_statements(script: str) -> Iterator[str]:
    """Yield individual executable statements from a migration script.

    Line comments (``--`` to end of line) are stripped first -- some carry a
    semicolon inside the prose -- then the remainder is split on ``;``. The
    schema files hold no semicolons inside statements, no ``--`` inside string
    literals, and no triggers, so this is correct and lets each statement run in
    one explicit transaction (``executescript`` cannot -- it force-commits first).
    """
    lines: list[str] = []
    for line in script.splitlines():
        comment_at = line.find("--")
        lines.append(line if comment_at == -1 else line[:comment_at])
    for chunk in "\n".join(lines).split(";"):
        if chunk.strip():
            yield chunk.strip()


def apply_migrations(
    conn: sqlite3.Connection,
    migrations_dir: Path = MIGRATIONS_DIR,
) -> list[int]:
    """Apply every migration newer than ``PRAGMA user_version``; return applied versions.

    Idempotent: already-applied versions are skipped, so calling this repeatedly
    (e.g. on every daemon start) is a no-op once the schema is current. Each
    migration runs in its own ``BEGIN IMMEDIATE`` transaction together with the
    ``user_version`` bump, so a failure leaves the version untouched.
    """
    current = schema_version(conn)
    applied: list[int] = []
    for version, path in _discover_migrations(migrations_dir):
        if version <= current:
            continue
        sql = path.read_text(encoding="utf-8")
        with begin_immediate(conn):
            for statement in _iter_statements(sql):
                conn.execute(statement)
            # PRAGMA cannot be parameterized; version is a validated int.
            conn.execute(f"PRAGMA user_version={version}")
        applied.append(version)
    return applied
