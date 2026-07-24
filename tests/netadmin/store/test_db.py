"""Tests for the connection factory, pragmas, migration runner, and txn guard."""

from __future__ import annotations

import sqlite3
from pathlib import Path

import pytest

from netadmin.store import db


def test_pragmas_applied(tmp_db_path: Path) -> None:
    conn = db.connect(tmp_db_path)
    assert conn.execute("PRAGMA journal_mode").fetchone()[0].lower() == "wal"
    assert int(conn.execute("PRAGMA synchronous").fetchone()[0]) == 1  # NORMAL
    assert int(conn.execute("PRAGMA foreign_keys").fetchone()[0]) == 1
    assert int(conn.execute("PRAGMA busy_timeout").fetchone()[0]) == 5000
    conn.close()


def test_connect_creates_parent_dir(tmp_path: Path) -> None:
    nested = tmp_path / "sub" / "dir" / "netadmin.db"
    conn = db.connect(nested)
    assert nested.parent.is_dir()
    conn.close()


def test_migration_sets_user_version(tmp_db_path: Path) -> None:
    conn = db.connect(tmp_db_path)
    assert db.schema_version(conn) == 0
    applied = db.apply_migrations(conn)
    assert applied == [1, 2, 3, 4]
    assert db.schema_version(conn) == 4
    conn.close()


def test_migration_creates_all_tables(tmp_db_path: Path) -> None:
    conn = db.connect(tmp_db_path)
    db.apply_migrations(conn)
    names = {
        r[0] for r in conn.execute("SELECT name FROM sqlite_master WHERE type='table'").fetchall()
    }
    expected = {
        "entities",
        "state_changes",
        "series",
        "samples",
        "samples_hourly",
        "samples_daily",
        "events",
        "poll_runs",
        "issues",
        "issue_events",
        "sle_minutes",
        "changes",
        "baselines",
        "investigations",
        "incidents",
        "incident_members",
    }
    assert expected <= names
    conn.close()


def test_without_rowid_and_partial_index(tmp_db_path: Path) -> None:
    conn = db.connect(tmp_db_path)
    db.apply_migrations(conn)
    # WITHOUT ROWID tables carry their PK as the table's rowid replacement.
    for table in ("samples", "samples_hourly", "samples_daily", "sle_minutes", "baselines"):
        sql = conn.execute(
            "SELECT sql FROM sqlite_master WHERE type='table' AND name=?", (table,)
        ).fetchone()[0]
        assert "WITHOUT ROWID" in sql.upper()
    # Partial unique index only over non-resolved issues.
    idx_sql = conn.execute(
        "SELECT sql FROM sqlite_master WHERE type='index' AND name='idx_issues_open_fp'"
    ).fetchone()[0]
    assert "WHERE" in idx_sql.upper() and "RESOLVED" in idx_sql.upper()
    # The reopen lookup index (migration 0002) is present over (fingerprint, resolved_ts).
    resolved_idx = conn.execute(
        "SELECT sql FROM sqlite_master WHERE type='index' AND name='idx_issues_fp_resolved'"
    ).fetchone()
    assert resolved_idx is not None
    assert "RESOLVED_TS" in resolved_idx[0].upper()
    # Migration 0003 raw-tier read indexes.
    poll_idx = conn.execute(
        "SELECT sql FROM sqlite_master WHERE type='index' AND name='idx_poll_runs_job_ts'"
    ).fetchone()
    assert poll_idx is not None
    native_idx = conn.execute(
        "SELECT sql FROM sqlite_master WHERE type='index' AND name='idx_events_native_id'"
    ).fetchone()
    assert native_idx is not None
    # Partial: only rows that carry a native_id are indexed.
    assert "WHERE" in native_idx[0].upper() and "NATIVE_ID" in native_idx[0].upper()
    conn.close()


def test_migration_idempotent(tmp_db_path: Path) -> None:
    conn = db.connect(tmp_db_path)
    first = db.apply_migrations(conn)
    second = db.apply_migrations(conn)
    third = db.apply_migrations(conn)
    assert first == [1, 2, 3, 4]
    assert second == []  # nothing re-applied
    assert third == []
    assert db.schema_version(conn) == 4
    conn.close()


def test_partial_unique_index_enforced(tmp_db_path: Path) -> None:
    conn = db.connect(tmp_db_path)
    db.apply_migrations(conn)
    # Two open issues with the same fingerprint must collide...
    with db.begin_immediate(conn):
        conn.execute(
            "INSERT INTO issues (fingerprint, detector_key, severity, state, "
            "first_seen_ts, last_seen_ts, title) VALUES ('fp','k','p2','active',1,1,'t')"
        )
    with pytest.raises(sqlite3.IntegrityError):
        with db.begin_immediate(conn):
            conn.execute(
                "INSERT INTO issues (fingerprint, detector_key, severity, state, "
                "first_seen_ts, last_seen_ts, title) VALUES ('fp','k','p2','pending',1,1,'t')"
            )
    # ...but a resolved issue with the same fingerprint is allowed.
    with db.begin_immediate(conn):
        conn.execute(
            "INSERT INTO issues (fingerprint, detector_key, severity, state, "
            "first_seen_ts, last_seen_ts, title) VALUES ('fp','k','p2','resolved',1,1,'t')"
        )
    conn.close()


def test_begin_immediate_commits_and_rolls_back(tmp_db_path: Path) -> None:
    conn = db.connect(tmp_db_path)
    db.apply_migrations(conn)
    with db.begin_immediate(conn):
        conn.execute("INSERT INTO poll_runs (ts, job, ok) VALUES (1, 'x', 1)")
    assert conn.execute("SELECT COUNT(*) FROM poll_runs").fetchone()[0] == 1

    with pytest.raises(RuntimeError):
        with db.begin_immediate(conn):
            conn.execute("INSERT INTO poll_runs (ts, job, ok) VALUES (2, 'y', 1)")
            raise RuntimeError("boom")
    # rolled back: still only the first row
    assert conn.execute("SELECT COUNT(*) FROM poll_runs").fetchone()[0] == 1
    conn.close()


def test_begin_immediate_blocks_writer_not_reader(tmp_db_path: Path) -> None:
    """Two connections: a held BEGIN IMMEDIATE blocks a second writer but not a reader."""
    writer_a = db.connect(tmp_db_path)
    db.apply_migrations(writer_a)
    writer_a.execute("INSERT INTO poll_runs (ts, job, ok) VALUES (1, 'seed', 1)")

    # Short busy_timeout so the contended writer fails fast instead of waiting 5 s.
    other = db.connect(tmp_db_path, busy_timeout_ms=100)

    with db.begin_immediate(writer_a):
        writer_a.execute("INSERT INTO poll_runs (ts, job, ok) VALUES (2, 'held', 1)")

        # Second writer cannot take the write lock -> OperationalError (locked).
        with pytest.raises(sqlite3.OperationalError):
            with db.begin_immediate(other):
                other.execute("INSERT INTO poll_runs (ts, job, ok) VALUES (3, 'blocked', 1)")

        # A reader on the other connection still sees committed data (WAL).
        seen = other.execute("SELECT COUNT(*) FROM poll_runs").fetchone()[0]
        assert seen == 1  # only the committed 'seed' row; the held write is uncommitted

    # After the writer commits, the reader sees both committed rows.
    assert other.execute("SELECT COUNT(*) FROM poll_runs").fetchone()[0] == 2
    writer_a.close()
    other.close()
