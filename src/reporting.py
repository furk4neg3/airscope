from __future__ import annotations

from pathlib import Path

import pandas as pd

from .utils import REPORTS_DIR, timestamp_filename


def build_markdown_report(
    title: str,
    scan_df: pd.DataFrame,
    findings_df: pd.DataFrame,
    recommendations_df: pd.DataFrame,
    scores: dict[str, float],
    metadata: dict[str, str] | None = None,
) -> str:
    metadata = metadata or {}
    lines = [f"# {title}", ""]
    if metadata:
        lines.append("## Context")
        for key, value in metadata.items():
            lines.append(f"- **{key}**: {value}")
        lines.append("")

    lines.extend(
        [
            "## Executive Summary",
            f"- Total APs: **{scan_df['bssid'].nunique() if not scan_df.empty else 0}**",
            f"- Security score: **{scores.get('security_score', 0):.1f}/100**",
            f"- Coverage score: **{scores.get('coverage_score', 0):.1f}/100**",
            f"- Overall score: **{scores.get('overall_score', 0):.1f}/100**",
            f"- Suspicious findings: **{len(findings_df)}**",
            "",
        ]
    )

    lines.append("## Key Findings")
    if findings_df.empty:
        lines.append("No suspicious findings were detected in the selected dataset.")
    else:
        for _, row in findings_df.iterrows():
            lines.append(
                f"- **{row['finding_type']}** | severity={row['severity']} | confidence={row['confidence']:.2f} | {row['details']}"
            )
    lines.append("")

    lines.append("## Recommendations")
    for _, row in recommendations_df.iterrows():
        lines.append(f"- **{row['priority']} / {row['category']}**: {row['recommendation']} — {row['rationale']}")
    lines.append("")

    lines.append("## Access Point Inventory")
    if scan_df.empty:
        lines.append("No scan data available.")
    else:
        inventory = scan_df[["ssid", "bssid", "signal_dbm", "channel", "band", "security"]].copy()
        lines.append(inventory.to_markdown(index=False))
    lines.append("")

    return "\n".join(lines)


def build_html_report(markdown_text: str, title: str = "Wi-Fi Assessment Report") -> str:
    escaped = markdown_text.replace("&", "&amp;").replace("<", "&lt;").replace(">", "&gt;")
    body = escaped.replace("\n", "<br>")
    return f"""
<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="UTF-8" />
  <meta name="viewport" content="width=device-width, initial-scale=1.0" />
  <title>{title}</title>
  <style>
    body {{ font-family: Arial, sans-serif; margin: 2rem auto; max-width: 1000px; color: #111827; line-height: 1.5; }}
    h1, h2 {{ color: #0f172a; }}
    code, pre {{ background: #f3f4f6; padding: 0.2rem 0.4rem; border-radius: 6px; }}
  </style>
</head>
<body>
{body}
</body>
</html>
""".strip()


def save_report(content: str, stem: str, suffix: str) -> Path:
    REPORTS_DIR.mkdir(parents=True, exist_ok=True)
    filename = timestamp_filename(stem, suffix)
    path = REPORTS_DIR / filename
    path.write_text(content, encoding="utf-8")
    return path
