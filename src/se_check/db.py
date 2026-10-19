"""Database connection used by the audit."""

from __future__ import annotations

import psycopg


def connect(dsn: str) -> psycopg.Connection:
    """Open a connection for auditing.

    Every transaction on it is read-only: the audit never writes. Server-side prepared
    statements are disabled so Supabase's transaction pooler (port 6543) works too.
    """
    conn = psycopg.connect(
        dsn,
        application_name="se-check",
        connect_timeout=10,
        prepare_threshold=None,
    )
    conn.read_only = True
    return conn


def connect_for_probe(dsn: str) -> psycopg.Connection:
    """Open a connection for the dynamic probe, which writes.

    Not read-only, but every transaction the probe opens on it is rolled back
    (`conn.transaction(force_rollback=True)`); nothing else should use it.
    """
    return psycopg.connect(
        dsn,
        application_name="se-check probe",
        connect_timeout=10,
        prepare_threshold=None,
    )
