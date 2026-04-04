from __future__ import annotations

from pathlib import Path

import pandas as pd

from .models import APRecord
from .utils import DATA_DIR

SAMPLE_SCAN_PATH = DATA_DIR / "sample_scans.csv"
SAMPLE_MAPPING_PATH = DATA_DIR / "sample_mapping_points.csv"


def load_demo_scan_df(snapshot_name: str | None = None) -> pd.DataFrame:
    df = pd.read_csv(SAMPLE_SCAN_PATH)
    if snapshot_name:
        filtered = df[df["snapshot_name"] == snapshot_name].copy()
        if not filtered.empty:
            return filtered
    latest_snapshot = df["snapshot_name"].iloc[-1]
    return df[df["snapshot_name"] == latest_snapshot].copy()


def load_demo_scan_records(snapshot_name: str | None = None) -> list[APRecord]:
    df = load_demo_scan_df(snapshot_name=snapshot_name)
    records: list[APRecord] = []
    for _, row in df.iterrows():
        records.append(
            APRecord(
                ssid=row["ssid"],
                bssid=row["bssid"],
                signal_dbm=float(row["signal_dbm"]),
                signal_percent=float(row["signal_percent"]),
                channel=int(row["channel"]),
                band=row["band"],
                security=row["security"],
                timestamp=row["timestamp"],
                backend=row["backend"],
                frequency_mhz=float(row["frequency_mhz"]) if not pd.isna(row["frequency_mhz"]) else None,
                raw={},
            )
        )
    return records


def list_demo_snapshots() -> list[str]:
    df = pd.read_csv(SAMPLE_SCAN_PATH)
    return df["snapshot_name"].drop_duplicates().tolist()


def load_demo_mapping_df(ssid: str | None = None) -> pd.DataFrame:
    df = pd.read_csv(SAMPLE_MAPPING_PATH)
    if ssid:
        return df[df["ssid"] == ssid].copy()
    return df.copy()
