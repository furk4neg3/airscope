from __future__ import annotations

import sqlite3
from contextlib import contextmanager
from pathlib import Path
from typing import Iterable

import pandas as pd

from .models import APRecord, Finding, utc_now_iso
from .utils import DB_PATH, ensure_directories, json_dumps, json_loads


class StorageManager:
    def __init__(self, db_path: str | Path = DB_PATH) -> None:
        ensure_directories()
        self.db_path = str(db_path)
        self.init_db()

    def clear_mapping_points(self) -> None:
        with self.connect() as conn:
            conn.execute("DELETE FROM mapping_points")

    @contextmanager
    def connect(self):
        conn = sqlite3.connect(self.db_path)
        conn.row_factory = sqlite3.Row
        try:
            yield conn
            conn.commit()
        finally:
            conn.close()

    def init_db(self) -> None:
        with self.connect() as conn:
            conn.executescript(
                """
                CREATE TABLE IF NOT EXISTS scan_snapshots (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    snapshot_name TEXT NOT NULL,
                    captured_at TEXT NOT NULL,
                    backend TEXT NOT NULL,
                    mode TEXT NOT NULL,
                    metadata_json TEXT
                );

                CREATE TABLE IF NOT EXISTS scan_records (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    snapshot_id INTEGER NOT NULL,
                    ssid TEXT,
                    bssid TEXT,
                    signal_dbm REAL,
                    signal_percent REAL,
                    channel INTEGER,
                    band TEXT,
                    security TEXT,
                    timestamp TEXT,
                    backend TEXT,
                    frequency_mhz REAL,
                    raw_json TEXT,
                    FOREIGN KEY(snapshot_id) REFERENCES scan_snapshots(id)
                );

                CREATE TABLE IF NOT EXISTS mapping_points (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    point_label TEXT,
                    x REAL NOT NULL,
                    y REAL NOT NULL,
                    ssid TEXT,
                    bssid TEXT,
                    signal_dbm REAL,
                    timestamp TEXT,
                    source_snapshot_id INTEGER,
                    FOREIGN KEY(source_snapshot_id) REFERENCES scan_snapshots(id)
                );

                CREATE TABLE IF NOT EXISTS findings (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    created_at TEXT NOT NULL,
                    context TEXT NOT NULL,
                    finding_type TEXT,
                    severity TEXT,
                    confidence REAL,
                    ssid TEXT,
                    bssid TEXT,
                    details TEXT,
                    recommendation TEXT,
                    extra_json TEXT
                );
                """
            )

    def save_scan_snapshot(
        self,
        snapshot_name: str,
        records: Iterable[APRecord],
        backend: str,
        mode: str,
        metadata: dict | None = None,
    ) -> int:
        captured_at = utc_now_iso()
        with self.connect() as conn:
            cursor = conn.execute(
                """
                INSERT INTO scan_snapshots (snapshot_name, captured_at, backend, mode, metadata_json)
                VALUES (?, ?, ?, ?, ?)
                """,
                (snapshot_name, captured_at, backend, mode, json_dumps(metadata or {})),
            )
            snapshot_id = int(cursor.lastrowid)
            conn.executemany(
                """
                INSERT INTO scan_records (
                    snapshot_id, ssid, bssid, signal_dbm, signal_percent, channel, band,
                    security, timestamp, backend, frequency_mhz, raw_json
                )
                VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                """,
                [
                    (
                        snapshot_id,
                        record.ssid,
                        record.bssid,
                        record.signal_dbm,
                        record.signal_percent,
                        record.channel,
                        record.band,
                        record.security,
                        record.timestamp,
                        record.backend,
                        record.frequency_mhz,
                        json_dumps(record.raw),
                    )
                    for record in records
                ],
            )
        return snapshot_id

    def list_snapshots(self) -> pd.DataFrame:
        with self.connect() as conn:
            return pd.read_sql_query(
                """
                SELECT id, snapshot_name, captured_at, backend, mode, metadata_json
                FROM scan_snapshots
                ORDER BY id DESC
                """,
                conn,
            )

    def load_scan_records(self, snapshot_id: int | None = None) -> pd.DataFrame:
        with self.connect() as conn:
            if snapshot_id is None:
                query = """
                    SELECT r.*, s.snapshot_name, s.captured_at, s.mode
                    FROM scan_records r
                    JOIN scan_snapshots s ON s.id = r.snapshot_id
                    WHERE r.snapshot_id = (SELECT id FROM scan_snapshots ORDER BY id DESC LIMIT 1)
                """
                return pd.read_sql_query(query, conn)
            return pd.read_sql_query(
                """
                SELECT r.*, s.snapshot_name, s.captured_at, s.mode
                FROM scan_records r
                JOIN scan_snapshots s ON s.id = r.snapshot_id
                WHERE r.snapshot_id = ?
                ORDER BY r.signal_dbm DESC NULLS LAST
                """,
                conn,
                params=(snapshot_id,),
            )


    def load_all_scan_records(self) -> pd.DataFrame:
        with self.connect() as conn:
            return pd.read_sql_query(
                """
                SELECT r.*, s.snapshot_name, s.captured_at, s.mode
                FROM scan_records r
                JOIN scan_snapshots s ON s.id = r.snapshot_id
                ORDER BY s.id DESC, r.signal_dbm DESC
                """,
                conn,
            )

    def save_mapping_points(
        self,
        x: float,
        y: float,
        point_label: str,
        records: Iterable[APRecord],
        source_snapshot_id: int | None = None,
    ) -> int:
        rows = [
            (
                point_label,
                x,
                y,
                record.ssid,
                record.bssid,
                record.signal_dbm,
                record.timestamp,
                source_snapshot_id,
            )
            for record in records
        ]
        with self.connect() as conn:
            conn.executemany(
                """
                INSERT INTO mapping_points (
                    point_label, x, y, ssid, bssid, signal_dbm, timestamp, source_snapshot_id
                )
                VALUES (?, ?, ?, ?, ?, ?, ?, ?)
                """,
                rows,
            )
            return len(rows)

    def load_mapping_points(self, ssid: str | None = None) -> pd.DataFrame:
        with self.connect() as conn:
            if ssid:
                return pd.read_sql_query(
                    """
                    SELECT * FROM mapping_points
                    WHERE ssid = ?
                    ORDER BY timestamp ASC
                    """,
                    conn,
                    params=(ssid,),
                )
            return pd.read_sql_query(
                "SELECT * FROM mapping_points ORDER BY timestamp ASC",
                conn,
            )

    def save_findings(self, findings: Iterable[Finding], context: str) -> int:
        rows = [
            (
                finding.created_at,
                context,
                finding.finding_type,
                finding.severity,
                finding.confidence,
                finding.ssid,
                finding.bssid,
                finding.details,
                finding.recommendation,
                json_dumps(finding.extra),
            )
            for finding in findings
        ]
        with self.connect() as conn:
            conn.executemany(
                """
                INSERT INTO findings (
                    created_at, context, finding_type, severity, confidence,
                    ssid, bssid, details, recommendation, extra_json
                )
                VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                """,
                rows,
            )
        return len(rows)

    def load_findings(self, limit: int = 200) -> pd.DataFrame:
        with self.connect() as conn:
            return pd.read_sql_query(
                """
                SELECT * FROM findings
                ORDER BY id DESC
                LIMIT ?
                """,
                conn,
                params=(limit,),
            )

    def clear_all(self) -> None:
        with self.connect() as conn:
            conn.executescript(
                "DELETE FROM scan_records; DELETE FROM scan_snapshots; DELETE FROM mapping_points; DELETE FROM findings;"
            )

    def latest_snapshot_id(self) -> int | None:
        snapshots = self.list_snapshots()
        if snapshots.empty:
            return None
        return int(snapshots.iloc[0]["id"])
