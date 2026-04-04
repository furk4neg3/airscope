from __future__ import annotations

from collections import Counter
from dataclasses import asdict

import numpy as np
import pandas as pd
from sklearn.cluster import DBSCAN
from sklearn.ensemble import IsolationForest
from sklearn.preprocessing import StandardScaler

from .models import APRecord, Finding
from .utils import (
    confidence_label,
    infer_band,
    is_unusual_channel,
    security_category,
    security_risk_weight,
)


def records_to_dataframe(records: list[APRecord]) -> pd.DataFrame:
    if not records:
        return pd.DataFrame(
            columns=[
                "ssid",
                "bssid",
                "signal_dbm",
                "signal_percent",
                "channel",
                "band",
                "security",
                "timestamp",
                "backend",
                "frequency_mhz",
            ]
        )
    return pd.DataFrame([record.to_dict() for record in records])


def _prepare_features(df: pd.DataFrame) -> pd.DataFrame:
    features = df.copy()
    features["security_risk"] = features["security"].map(security_risk_weight)
    features["band_code"] = features["band"].map({"2.4 GHz": 2.4, "5 GHz": 5.0, "6 GHz": 6.0}).fillna(0)
    ssid_counts = features.groupby("ssid")["bssid"].transform("nunique")
    features["ssid_bssid_count"] = ssid_counts
    features["signal_dbm"] = features["signal_dbm"].fillna(-90)
    features["channel"] = features["channel"].fillna(0)
    return features[["signal_dbm", "channel", "band_code", "security_risk", "ssid_bssid_count"]]


def run_anomaly_detection(df: pd.DataFrame) -> pd.DataFrame:
    if df.empty:
        return df.assign(anomaly_score=[], is_anomaly=[])
    working = df.copy()
    if len(working) < 5:
        working["anomaly_score"] = 0.0
        working["is_anomaly"] = False
        return working
    features = _prepare_features(working)
    scaler = StandardScaler()
    scaled = scaler.fit_transform(features)
    contamination = min(0.25, max(0.1, round(2 / len(working), 2)))
    model = IsolationForest(random_state=42, contamination=contamination)
    labels = model.fit_predict(scaled)
    scores = model.decision_function(scaled)
    working["anomaly_score"] = scores
    working["is_anomaly"] = labels == -1
    return working


def run_clustering(df: pd.DataFrame) -> pd.DataFrame:
    if df.empty:
        return df.assign(cluster=[])
    working = df.copy()
    if len(working) < 3:
        working["cluster"] = -1
        return working
    features = _prepare_features(working)
    scaled = StandardScaler().fit_transform(features)
    clustering = DBSCAN(eps=1.15, min_samples=2)
    labels = clustering.fit_predict(scaled)
    working["cluster"] = labels
    return working


def summarize_channels(df: pd.DataFrame) -> pd.DataFrame:
    if df.empty:
        return pd.DataFrame(columns=["band", "channel", "ap_count"])
    summary = (
        df.groupby(["band", "channel"], dropna=False)["bssid"]
        .nunique()
        .reset_index(name="ap_count")
        .sort_values(["band", "ap_count", "channel"], ascending=[True, False, True])
    )
    return summary


def analyze_scan(records: list[APRecord], history_df: pd.DataFrame | None = None) -> dict[str, pd.DataFrame | list[Finding] | dict]:
    df = records_to_dataframe(records)
    if df.empty:
        return {
            "df": df,
            "findings": [],
            "findings_df": pd.DataFrame(),
            "anomaly_df": df,
            "clustered_df": df,
            "channel_summary": pd.DataFrame(),
            "summary": {},
        }

    df["security_category"] = df["security"].map(security_category)
    df["band"] = df.apply(lambda row: row["band"] or infer_band(row["channel"], row.get("frequency_mhz")), axis=1)

    anomaly_df = run_anomaly_detection(df)
    clustered_df = run_clustering(anomaly_df)
    channel_summary = summarize_channels(df)
    findings: list[Finding] = []

    for _, row in clustered_df.iterrows():
        if row["security_category"] == "open":
            findings.append(
                Finding(
                    finding_type="Open Network",
                    severity="medium",
                    confidence=0.9,
                    ssid=row["ssid"],
                    bssid=row["bssid"],
                    details=f"{row['ssid']} is broadcasting without encryption.",
                    recommendation="Move this SSID to WPA2 or WPA3 and limit unauthenticated access.",
                )
            )
        elif row["security_category"] in {"wep", "wpa", "unknown"}:
            findings.append(
                Finding(
                    finding_type="Weak Encryption",
                    severity="high" if row["security_category"] == "wep" else "medium",
                    confidence=0.88 if row["security_category"] == "wep" else 0.72,
                    ssid=row["ssid"],
                    bssid=row["bssid"],
                    details=f"{row['ssid']} uses {row['security']} which is considered legacy or weak.",
                    recommendation="Upgrade this AP to WPA2/WPA3 and retire legacy ciphers.",
                )
            )
        if is_unusual_channel(row["channel"], row["band"]):
            findings.append(
                Finding(
                    finding_type="Unexpected Channel/Band",
                    severity="low",
                    confidence=0.6,
                    ssid=row["ssid"],
                    bssid=row["bssid"],
                    details=f"{row['ssid']} reported channel {row['channel']} for band {row['band']}.",
                    recommendation="Verify the AP configuration and confirm the band/channel are expected.",
                )
            )

    ssid_groups = clustered_df.groupby("ssid", dropna=False)
    for ssid, group in ssid_groups:
        unique_bssids = group["bssid"].nunique()
        security_types = set(group["security_category"].tolist())
        bands = set(group["band"].dropna().tolist())
        channels = set(int(c) for c in group["channel"].dropna().tolist())
        signal_median = group["signal_dbm"].median()
        strongest = group.loc[group["signal_dbm"].idxmax()] if not group["signal_dbm"].isna().all() else None
        multi_cluster = group["cluster"].nunique() > 1

        if unique_bssids > 1:
            findings.append(
                Finding(
                    finding_type="Duplicate SSID",
                    severity="low",
                    confidence=0.65,
                    ssid=ssid,
                    bssid="multiple",
                    details=f"{ssid} appears on {unique_bssids} BSSIDs across channels {sorted(channels)}.",
                    recommendation="Maintain a trusted BSSID inventory so duplicate SSIDs can be verified quickly.",
                    extra={"bssid_count": int(unique_bssids)},
                )
            )

        if len(security_types) > 1 and unique_bssids > 1:
            confidence = 0.82 + (0.05 if multi_cluster else 0.0)
            findings.append(
                Finding(
                    finding_type="Security Mismatch / Possible Rogue",
                    severity="high",
                    confidence=min(confidence, 0.95),
                    ssid=ssid,
                    bssid="multiple",
                    details=f"{ssid} is advertising multiple security profiles: {', '.join(sorted(security_types))}.",
                    recommendation="Verify every BSSID for this SSID. Mismatched security on the same SSID is a classic rogue or evil twin signal.",
                    extra={"clusters": group["cluster"].tolist()},
                )
            )

        if strongest is not None and unique_bssids > 1:
            if strongest["signal_dbm"] >= signal_median + 12 and len(security_types) > 1:
                findings.append(
                    Finding(
                        finding_type="Signal Spike / Possible Evil Twin",
                        severity="high",
                        confidence=0.86,
                        ssid=ssid,
                        bssid=strongest["bssid"],
                        details=(
                            f"{ssid} has a much stronger AP ({strongest['signal_dbm']} dBm) than the group median "
                            f"({round(signal_median, 1)} dBm) alongside inconsistent security settings."
                        ),
                        recommendation="Physically verify the strongest BSSID and compare it against your approved inventory.",
                    )
                )

        if unique_bssids > 2 and len(bands) > 1 and len(security_types) > 1:
            findings.append(
                Finding(
                    finding_type="Band/Channel Inconsistency",
                    severity="medium",
                    confidence=0.75,
                    ssid=ssid,
                    bssid="multiple",
                    details=f"{ssid} spans multiple bands {sorted(bands)} with inconsistent security or clustering patterns.",
                    recommendation="Confirm that band steering and multi-band APs are configured intentionally for this SSID.",
                )
            )

    if history_df is not None and not history_df.empty:
        history_group = history_df.groupby("ssid")
        for ssid, group in clustered_df.groupby("ssid"):
            if ssid not in history_group.groups:
                continue
            historical = history_group.get_group(ssid)
            expected_security = Counter(historical["security"].dropna().tolist()).most_common(1)
            if not expected_security:
                continue
            expected_security_name = expected_security[0][0]
            current_security_types = set(group["security"].dropna().tolist())
            if expected_security_name not in current_security_types:
                findings.append(
                    Finding(
                        finding_type="Historical Profile Drift",
                        severity="medium",
                        confidence=0.7,
                        ssid=ssid,
                        bssid="multiple",
                        details=f"{ssid} previously appeared as {expected_security_name}, but the latest snapshot differs.",
                        recommendation="Compare the latest scan to trusted historical baselines before allowing clients to connect.",
                    )
                )

    anomaly_rows = clustered_df[clustered_df["is_anomaly"]]
    for _, row in anomaly_rows.iterrows():
        findings.append(
            Finding(
                finding_type="ML Anomaly",
                severity="medium",
                confidence=0.68,
                ssid=row["ssid"],
                bssid=row["bssid"],
                details=(
                    f"Isolation Forest marked this AP as anomalous based on signal, channel, band, and security features. "
                    f"Anomaly score: {row['anomaly_score']:.3f}."
                ),
                recommendation="Review this AP in context with your approved AP list and recent environment changes.",
            )
        )

    findings_df = pd.DataFrame([finding.to_dict() for finding in findings]) if findings else pd.DataFrame(
        columns=["finding_type", "severity", "confidence", "ssid", "bssid", "details", "recommendation", "created_at", "extra"]
    )

    suspicious_ap_count = findings_df[findings_df["severity"].isin(["medium", "high"])]["bssid"].nunique() if not findings_df.empty else 0
    summary = {
        "total_aps": int(df["bssid"].nunique()),
        "unique_ssids": int(df["ssid"].nunique()),
        "open_networks": int((df["security_category"] == "open").sum()),
        "weak_networks": int(df["security_category"].isin(["wep", "wpa", "unknown"]).sum()),
        "suspicious_findings": int(len(findings_df[findings_df["severity"].isin(["medium", "high"])])) if not findings_df.empty else 0,
        "suspicious_aps": int(suspicious_ap_count),
        "average_signal_dbm": float(df["signal_dbm"].fillna(-90).mean()),
    }

    return {
        "df": df,
        "findings": findings,
        "findings_df": findings_df.sort_values(["severity", "confidence"], ascending=[True, False]) if not findings_df.empty else findings_df,
        "anomaly_df": anomaly_df,
        "clustered_df": clustered_df,
        "channel_summary": channel_summary,
        "summary": summary,
    }
