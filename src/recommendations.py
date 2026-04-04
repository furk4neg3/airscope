from __future__ import annotations

import pandas as pd

from .heatmap import weak_zone_summary
from .utils import security_category


def build_recommendations(
    scan_df: pd.DataFrame,
    findings_df: pd.DataFrame,
    mapping_df: pd.DataFrame | None,
    scores: dict[str, float],
) -> pd.DataFrame:
    recommendations: list[dict] = []

    if not scan_df.empty:
        categories = scan_df["security"].map(security_category)
        if (categories == "open").any():
            recommendations.append(
                {
                    "priority": "High",
                    "category": "Security",
                    "recommendation": "Replace open SSIDs with WPA2 or WPA3.",
                    "rationale": "Open networks were detected and materially lower the security score.",
                }
            )
        if categories.isin(["wep", "wpa", "unknown"]).any():
            recommendations.append(
                {
                    "priority": "High",
                    "category": "Security",
                    "recommendation": "Retire WEP/WPA or unknown-security APs and standardize on WPA2/WPA3.",
                    "rationale": "Legacy encryption remains one of the clearest preventable Wi-Fi risks.",
                }
            )

        channel_counts = (
            scan_df.dropna(subset=["channel"])
            .groupby(["band", "channel"], dropna=False)["bssid"]
            .nunique()
            .reset_index(name="ap_count")
        )
        congested = channel_counts[channel_counts["ap_count"] >= 3]
        if not congested.empty:
            top = congested.sort_values(["ap_count", "channel"], ascending=[False, True]).iloc[0]
            channel_value = int(top["channel"]) if pd.notna(top.get("channel")) else None
            band_value = top.get("band") if pd.notna(top.get("band")) else "unknown band"
            channel_label = f"channel {channel_value}" if channel_value is not None else "the busiest visible channel"
            recommendations.append(
                {
                    "priority": "Medium",
                    "category": "Coverage",
                    "recommendation": f"Reduce congestion on {channel_label} ({band_value}).",
                    "rationale": f"That channel currently carries {int(top['ap_count'])} visible APs, which can hurt throughput and roaming quality.",
                }
            )

    if findings_df is not None and not findings_df.empty:
        if (findings_df["finding_type"] == "Security Mismatch / Possible Rogue").any():
            suspicious_ssids = ", ".join(findings_df.loc[findings_df["finding_type"] == "Security Mismatch / Possible Rogue", "ssid"].drop_duplicates().tolist()[:3])
            recommendations.append(
                {
                    "priority": "High",
                    "category": "Rogue AP",
                    "recommendation": f"Verify duplicate SSIDs immediately: {suspicious_ssids}.",
                    "rationale": "The same SSID advertised with different security settings is consistent with rogue or evil twin behavior.",
                }
            )
        if (findings_df["finding_type"] == "ML Anomaly").any():
            recommendations.append(
                {
                    "priority": "Medium",
                    "category": "Monitoring",
                    "recommendation": "Maintain a trusted SSID/BSSID baseline and review anomalous APs after each survey.",
                    "rationale": "The anomaly detector found APs whose signal, channel, and security profile differ from peers.",
                }
            )

    if mapping_df is not None and not mapping_df.empty:
        weak_summary = weak_zone_summary(mapping_df)
        if weak_summary["dead_points"] > 0 or weak_summary["weak_points"] > 0:
            worst = weak_summary["weak_locations"][0] if weak_summary["weak_locations"] else None
            location_text = f" around ({worst['x']:.1f}, {worst['y']:.1f})" if worst else ""
            recommendations.append(
                {
                    "priority": "High",
                    "category": "Coverage",
                    "recommendation": f"Consider moving or adding an AP near the weakest surveyed area{location_text}.",
                    "rationale": f"The survey contains {weak_summary['weak_points']} weak points and {weak_summary['dead_points']} dead-zone points.",
                }
            )

    if scores.get("security_score", 100) < 70:
        recommendations.append(
            {
                "priority": "High",
                "category": "Security",
                "recommendation": "Prioritize security hardening before expanding coverage.",
                "rationale": "The security score is below 70, indicating avoidable risk in the current Wi-Fi environment.",
            }
        )
    if scores.get("coverage_score", 100) < 70:
        recommendations.append(
            {
                "priority": "Medium",
                "category": "Coverage",
                "recommendation": "Repeat the survey after AP repositioning or channel updates to confirm the weak areas are resolved.",
                "rationale": "The coverage score is below 70, suggesting persistent signal quality or congestion issues.",
            }
        )

    if not recommendations:
        recommendations.append(
            {
                "priority": "Low",
                "category": "Baseline",
                "recommendation": "Environment looks stable. Save this snapshot as a trusted baseline and repeat surveys after major changes.",
                "rationale": "No major risk or coverage issues were detected in the current dataset.",
            }
        )

    result = pd.DataFrame(recommendations).drop_duplicates(subset=["recommendation"]).reset_index(drop=True)
    priority_order = {"High": 0, "Medium": 1, "Low": 2}
    return result.sort_values(by="priority", key=lambda s: s.map(priority_order)).reset_index(drop=True)
