from __future__ import annotations

import numpy as np
import pandas as pd

from .utils import dbm_to_quality_bucket, score_from_dbm, security_category

DEFAULT_THRESHOLDS = {
    "excellent": -55,
    "good": -65,
    "fair": -72,
    "weak": -80,
}


def calculate_security_score(scan_df: pd.DataFrame, findings_df: pd.DataFrame | None = None) -> tuple[float, dict]:
    if scan_df.empty:
        return 0.0, {"reason": "No scan data available."}

    n = max(len(scan_df), 1)
    categories = scan_df["security"].map(security_category)
    open_ratio = (categories == "open").sum() / n
    wep_ratio = (categories == "wep").sum() / n
    weak_ratio = categories.isin(["wpa", "unknown"]).sum() / n

    mismatch_ratio = 0.0
    rogue_ratio = 0.0
    anomaly_ratio = 0.0
    if findings_df is not None and not findings_df.empty:
        mismatch_ratio = (findings_df["finding_type"] == "Security Mismatch / Possible Rogue").sum() / max(1, scan_df["ssid"].nunique())
        rogue_ratio = findings_df["finding_type"].isin(["Signal Spike / Possible Evil Twin", "Historical Profile Drift"]).sum() / max(1, scan_df["ssid"].nunique())
        anomaly_ratio = (findings_df["finding_type"] == "ML Anomaly").sum() / n

    penalty = (
        (35 * open_ratio)
        + (28 * wep_ratio)
        + (18 * weak_ratio)
        + (22 * mismatch_ratio)
        + (18 * rogue_ratio)
        + (10 * anomaly_ratio)
    )
    score = float(np.clip(100 - penalty, 0, 100))
    breakdown = {
        "open_ratio": round(open_ratio, 3),
        "wep_ratio": round(wep_ratio, 3),
        "weak_ratio": round(weak_ratio, 3),
        "mismatch_ratio": round(mismatch_ratio, 3),
        "rogue_ratio": round(rogue_ratio, 3),
        "anomaly_ratio": round(anomaly_ratio, 3),
        "penalty": round(penalty, 2),
    }
    return round(score, 1), breakdown


def _channel_congestion_score(scan_df: pd.DataFrame) -> float:
    if scan_df.empty or "channel" not in scan_df:
        return 50.0
    channel_counts = scan_df.groupby(["band", "channel"], dropna=False)["bssid"].nunique().reset_index(name="count")
    if channel_counts.empty:
        return 50.0
    worst = channel_counts["count"].max()
    mean_count = channel_counts["count"].mean()
    congestion_penalty = min(45.0, (worst - 1) * 8 + max(0.0, mean_count - 1) * 5)
    return round(float(np.clip(100 - congestion_penalty, 0, 100)), 1)


def calculate_coverage_score(
    scan_df: pd.DataFrame,
    mapping_df: pd.DataFrame | None = None,
    thresholds: dict[str, float] | None = None,
) -> tuple[float, dict]:
    thresholds = thresholds or DEFAULT_THRESHOLDS
    if scan_df.empty and (mapping_df is None or mapping_df.empty):
        return 0.0, {"reason": "No signal data available."}

    if mapping_df is not None and not mapping_df.empty:
        basis = mapping_df.groupby(["x", "y"], as_index=False)["signal_dbm"].max()
        basis_name = "mapping"
    else:
        basis = scan_df[["signal_dbm"]].copy()
        basis["x"] = np.arange(len(basis))
        basis["y"] = 0
        basis_name = "scan"

    basis = basis.dropna(subset=["signal_dbm"]).copy()
    basis["quality_bucket"] = basis["signal_dbm"].apply(lambda v: dbm_to_quality_bucket(v, thresholds))

    avg_signal_score = float(basis["signal_dbm"].apply(score_from_dbm).mean()) if not basis.empty else 0.0
    weak_fraction = float((basis["quality_bucket"] == "weak").mean()) if not basis.empty else 1.0
    dead_fraction = float((basis["quality_bucket"] == "dead zone").mean()) if not basis.empty else 1.0
    congestion_score = _channel_congestion_score(scan_df)

    score = (
        0.55 * avg_signal_score
        + 0.2 * (100 - weak_fraction * 100)
        + 0.15 * (100 - dead_fraction * 100)
        + 0.1 * congestion_score
    )
    score = round(float(np.clip(score, 0, 100)), 1)
    breakdown = {
        "basis": basis_name,
        "avg_signal_score": round(avg_signal_score, 2),
        "weak_fraction": round(weak_fraction, 3),
        "dead_fraction": round(dead_fraction, 3),
        "congestion_score": congestion_score,
    }
    return score, breakdown


def calculate_overall_score(security_score: float, coverage_score: float) -> float:
    return round((0.55 * security_score) + (0.45 * coverage_score), 1)
