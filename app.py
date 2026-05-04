from __future__ import annotations

from dataclasses import replace
from datetime import datetime
import base64
from pathlib import Path

import pandas as pd
import plotly.express as px
import plotly.graph_objects as go
import streamlit as st
from PIL import Image

from src.analyzer import analyze_scan
from src.demo_data import list_demo_snapshots, load_demo_mapping_df, load_demo_scan_records
from src.heatmap import DEFAULT_THRESHOLDS, build_heatmap_figure, weak_zone_summary
from src.models import APRecord
from src.recommendations import build_recommendations
from src.reporting import build_html_report, build_markdown_report, save_report
from src.scanner import WiFiScanner
from src.scoring import calculate_coverage_score, calculate_overall_score, calculate_security_score
from src.storage import StorageManager
from src.utils import ASSETS_DIR, environment_summary, ensure_directories, pretty_backend_name

st.set_page_config(
    page_title="Secure Wi-Fi Signal Mapper",
    page_icon="📶",
    layout="wide",
    initial_sidebar_state="expanded",
)


CSS = """
<style>
    .block-container {padding-top: 1.2rem; padding-bottom: 2rem;}
    .hero {
        background: linear-gradient(135deg, #0f172a 0%, #1d4ed8 60%, #0ea5e9 100%);
        color: white;
        border-radius: 20px;
        padding: 1.4rem 1.6rem;
        margin-bottom: 1rem;
        box-shadow: 0 20px 40px rgba(2, 6, 23, 0.18);
    }
    .hero h1 { margin: 0 0 0.2rem 0; font-size: 2rem; }
    .hero p { margin: 0; opacity: 0.95; }
    .small-muted { color: #475569; font-size: 0.95rem; }
    .pill {
        display: inline-block;
        padding: 0.22rem 0.6rem;
        border-radius: 999px;
        background: #eff6ff;
        color: #1d4ed8;
        font-size: 0.85rem;
        margin-right: 0.35rem;
        margin-bottom: 0.35rem;
        border: 1px solid #bfdbfe;
    }
    .card {
    border: 1px solid #334155;
    border-radius: 18px;
    padding: 1rem 1rem 0.85rem;
    background: #1e293b;
    color: #f8fafc;
    box-shadow: 0 6px 18px rgba(15, 23, 42, 0.20);
    }
    .card strong {
        color: #ffffff;
    }
    .card span {
        color: #e2e8f0;
    }
    .small-muted {
        color: #cbd5e1;
        font-size: 0.95rem;
    }
</style>
"""


def apply_styles() -> None:
    st.markdown(CSS, unsafe_allow_html=True)


@st.cache_resource(show_spinner=False)
def get_storage() -> StorageManager:
    ensure_directories()
    return StorageManager()


@st.cache_resource(show_spinner=False)
def get_scanner() -> WiFiScanner:
    return WiFiScanner()


def records_from_dataframe(df: pd.DataFrame) -> list[APRecord]:
    records: list[APRecord] = []
    if df.empty:
        return records
    for _, row in df.iterrows():
        records.append(
            APRecord(
                ssid=row.get("ssid", "<hidden>"),
                bssid=row.get("bssid", ""),
                signal_dbm=float(row["signal_dbm"]) if pd.notna(row.get("signal_dbm")) else None,
                signal_percent=float(row["signal_percent"]) if pd.notna(row.get("signal_percent")) else None,
                channel=int(row["channel"]) if pd.notna(row.get("channel")) else None,
                band=row.get("band"),
                security=row.get("security", "Unknown"),
                timestamp=row.get("timestamp", datetime.utcnow().isoformat() + "Z"),
                backend=row.get("backend", "unknown"),
                frequency_mhz=float(row["frequency_mhz"]) if pd.notna(row.get("frequency_mhz")) else None,
                raw={},
            )
        )
    return records


def initialize_state() -> None:
    if "current_records" not in st.session_state:
        records = load_demo_scan_records()
        set_current_scan(records, backend="demo", mode="demo", source_label="Bundled demo dataset")
    if "selected_snapshot_id" not in st.session_state:
        st.session_state.selected_snapshot_id = None
    if "mapping_width" not in st.session_state:
        st.session_state.mapping_width = 10.0
    if "mapping_height" not in st.session_state:
        st.session_state.mapping_height = 8.0


def historical_context(mode: str, current_snapshot_id: int | None) -> pd.DataFrame:
    if mode == "demo":
        demo_rows = pd.read_csv(Path(__file__).resolve().parent / "data" / "sample_scans.csv")
        return demo_rows
    all_rows = get_storage().load_all_scan_records()
    if current_snapshot_id is not None and not all_rows.empty:
        return all_rows[all_rows["snapshot_id"] != current_snapshot_id].copy()
    return all_rows


def active_mapping_df(mode: str) -> pd.DataFrame:
    if mode == "demo":
        # Demo mode shows only the bundled demo points so the demonstration
        # is reproducible and not contaminated by real survey data the user
        # may have captured in previous live sessions.
        return load_demo_mapping_df()
    return get_storage().load_mapping_points()


def set_current_scan(
    records: list[APRecord],
    backend: str,
    mode: str,
    source_label: str,
    snapshot_id: int | None = None,
) -> None:
    try:
        analysis = analyze_scan(records, history_df=historical_context(mode, snapshot_id))
        scan_df = analysis["df"]
        mapping_df = active_mapping_df(mode)
        security_score, security_breakdown = calculate_security_score(scan_df, analysis["findings_df"])
        coverage_score, coverage_breakdown = calculate_coverage_score(scan_df, mapping_df)
        overall_score = calculate_overall_score(security_score, coverage_score)
        scores = {
            "security_score": security_score,
            "coverage_score": coverage_score,
            "overall_score": overall_score,
        }
        recommendations_df = build_recommendations(scan_df, analysis["findings_df"], mapping_df, scores)
    except Exception as exc:  # noqa: BLE001 - surface any analysis failure to the UI
        st.error(
            f"Could not analyze scan ({type(exc).__name__}): {exc}. "
            "Previous dataset kept; check the input source for malformed or missing fields."
        )
        return

    st.session_state.current_records = records
    st.session_state.current_scan_df = scan_df
    st.session_state.current_findings_df = analysis["findings_df"]
    st.session_state.current_analysis = analysis
    st.session_state.current_mapping_df = mapping_df
    st.session_state.current_scores = scores
    st.session_state.current_score_breakdown = {
        "security": security_breakdown,
        "coverage": coverage_breakdown,
    }
    st.session_state.current_recommendations_df = recommendations_df
    st.session_state.current_backend = backend
    st.session_state.current_mode = mode
    st.session_state.current_source_label = source_label
    st.session_state.current_snapshot_id = snapshot_id


apply_styles()
initialize_state()
scanner = get_scanner()
storage = get_storage()

st.markdown(
    """<br>
    <br>
""",
    unsafe_allow_html=True,
)

with st.sidebar:
    st.header("Control Panel")
    mode_choice = st.radio("Data source", ["Demo Mode", "Live Scan"], index=0 if st.session_state.current_mode == "demo" else 1)
    demo_snapshots = list_demo_snapshots()
    selected_demo_snapshot = st.selectbox("Demo snapshot", demo_snapshots, index=len(demo_snapshots) - 1)
    if st.button("Load selected demo snapshot", use_container_width=True):
        records = load_demo_scan_records(selected_demo_snapshot)
        set_current_scan(records, backend="demo", mode="demo", source_label=f"Demo snapshot: {selected_demo_snapshot}")
        st.success(f"Loaded {selected_demo_snapshot}.")

    st.markdown("### Live-scan capability")
    env = environment_summary()
    pills = [f"OS: {env['os']}"]
    for name in ["netsh", "nmcli", "iw", "airport", "system_profiler", "pyobjc_corewlan", "pyobjc_corelocation"]:
        pills.append(f"{name}: {'yes' if env[name] else 'no'}")
    st.markdown("".join([f"<span class='pill'>{p}</span>" for p in pills]), unsafe_allow_html=True)
    for note in scanner.live_scan_capability_notes():
        st.caption(note)

    st.markdown("### Current dataset")
    st.write(f"**Source:** {st.session_state.current_source_label}")
    st.write(f"**Backend:** {pretty_backend_name(st.session_state.current_backend)}")
    st.write(f"**Mode:** {st.session_state.current_mode}")

    if mode_choice == "Live Scan" and st.button("Run live scan now", type="primary", use_container_width=True):
        result = scanner.scan()
        if result.success:
            set_current_scan(result.records, backend=result.backend, mode="live", source_label=f"Live scan via {result.backend}")
            st.success(f"{result.message} Captured {len(result.records)} AP records using {result.backend}.")
            if result.warning:
                st.info(result.warning)
        else:
            st.error(result.message)
            attempts_summary = (result.metadata or {}).get("attempts_summary") if hasattr(result, "metadata") else None
            if attempts_summary:
                st.caption(f"Tried backends — {attempts_summary}")
            elif result.stderr:
                st.caption(result.stderr)
            if scanner.os_name == "darwin":
                st.info("On recent macOS versions, the app prefers CoreWLAN via PyObjC for full nearby-network RSSI data, then falls back to airport and finally system_profiler. If CoreWLAN metadata is missing, allow Location Services for Terminal / iTerm / Python and restart Streamlit from a new terminal window.")
            demo_records = load_demo_scan_records(selected_demo_snapshot)
            set_current_scan(demo_records, backend="demo", mode="demo", source_label=f"Fallback demo snapshot: {selected_demo_snapshot}")
            st.info("The app switched to Demo Mode so the rest of the workflow stays fully usable.")

    if st.button("Save current scan snapshot", use_container_width=True):
        if st.session_state.current_records:
            # Fingerprint = (number of records, source label, current snapshot id).
            # If the user clicks twice in a row without changing the dataset, the
            # second click would just create an identical row in the snapshot
            # list, which is confusing. Skip saving in that case and tell them.
            fingerprint = (
                len(st.session_state.current_records),
                st.session_state.current_source_label,
                st.session_state.get("current_snapshot_id"),
            )
            if st.session_state.get("last_saved_fingerprint") == fingerprint:
                st.info("This dataset is already saved as the most recent snapshot.")
            else:
                name = f"Snapshot {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}"
                snapshot_id = storage.save_scan_snapshot(
                    snapshot_name=name,
                    records=st.session_state.current_records,
                    backend=st.session_state.current_backend,
                    mode=st.session_state.current_mode,
                    metadata={"source_label": st.session_state.current_source_label},
                )
                storage.save_findings(st.session_state.current_analysis["findings"], context=f"snapshot:{snapshot_id}")
                st.session_state.selected_snapshot_id = snapshot_id
                st.session_state.last_saved_fingerprint = fingerprint
                st.success(f"Saved snapshot #{snapshot_id}.")

    snapshots_df = storage.list_snapshots()
    if not snapshots_df.empty:
        snapshot_options = {
            f"#{row['id']} · {row['snapshot_name']} · {row['captured_at']}": int(row["id"])
            for _, row in snapshots_df.iterrows()
        }
        selected_label = st.selectbox("Load saved snapshot", list(snapshot_options.keys()))
        if st.button("Open saved snapshot", use_container_width=True):
            snapshot_id = snapshot_options[selected_label]
            snapshot_df = storage.load_scan_records(snapshot_id)
            records = records_from_dataframe(snapshot_df)
            set_current_scan(
                records,
                backend=str(snapshot_df["backend"].iloc[0]) if not snapshot_df.empty else "stored",
                mode=str(snapshot_df["mode"].iloc[0]) if not snapshot_df.empty else "stored",
                source_label=f"Saved snapshot #{snapshot_id}",
                snapshot_id=snapshot_id,
            )
            st.success(f"Loaded saved snapshot #{snapshot_id}.")

scan_df = st.session_state.current_scan_df.copy()
findings_df = st.session_state.current_findings_df.copy()
mapping_df = st.session_state.current_mapping_df.copy()
scores = st.session_state.current_scores.copy()
analysis = st.session_state.current_analysis
recommendations_df = st.session_state.current_recommendations_df.copy()


overview_tab, scan_tab, mapping_tab, rogue_tab, recommendations_tab, reports_tab = st.tabs(
    [
        "Overview",
        "Visible APs",
        "Signal Mapping",
        "Rogue AP Detection",
        "Recommendations",
        "Reports / Export",
    ]
)

with overview_tab:
    st.subheader("Executive overview")
    summary = analysis.get("summary", {})
    c1, c2, c3, c4, c5, c6 = st.columns(6)
    c1.metric("Total APs", summary.get("total_aps", 0))
    c2.metric("Suspicious findings", summary.get("suspicious_findings", 0))
    c3.metric("Open / weak", summary.get("open_networks", 0) + summary.get("weak_networks", 0))
    c4.metric("Avg signal", f"{summary.get('average_signal_dbm', -90):.1f} dBm")
    c5.metric("Security score", f"{scores['security_score']:.1f}")
    c6.metric("Coverage score", f"{scores['coverage_score']:.1f}")

    left, right = st.columns([1.05, 0.95])
    with left:
        if not scan_df.empty:
            categories = scan_df.copy()
            categories["security_category"] = categories["security"].str.lower()
            fig_security = px.histogram(
                categories,
                x="security",
                y=None,
                color="band",
                title="Visible AP inventory by security type and band",
                template="plotly_white",
            )
            st.plotly_chart(fig_security, use_container_width=True)
        else:
            st.info("No scan dataset is currently loaded.")

    with right:
        channel_summary = analysis.get("channel_summary", pd.DataFrame())
        if not channel_summary.empty:
            fig_channels = px.bar(
                channel_summary,
                x="channel",
                y="ap_count",
                color="band",
                barmode="group",
                title="Channel congestion snapshot",
                template="plotly_white",
            )
            st.plotly_chart(fig_channels, use_container_width=True)
        else:
            st.info("Channel congestion appears once scan data is loaded.")

    st.markdown("### Score summary")
    score_df = pd.DataFrame(
        [
            {"Score": "Security", "Value": scores["security_score"]},
            {"Score": "Coverage", "Value": scores["coverage_score"]},
            {"Score": "Overall", "Value": scores["overall_score"]},
        ]
    )
    score_fig = px.bar(score_df, x="Score", y="Value", text="Value", range_y=[0, 100], template="plotly_white")
    st.plotly_chart(score_fig, use_container_width=True)

with scan_tab:
    st.subheader("Scan nearby Wi-Fi access points")
    st.caption("Passive scanning only. No credential capture, packet injection, deauthentication, or exploitation features are included.")

    if not scan_df.empty:
        scan_filters_left, scan_filters_right = st.columns([1.2, 1])
        with scan_filters_left:
            ssid_options = ["All"] + sorted(scan_df["ssid"].dropna().unique().tolist())
            selected_ssid = st.selectbox("Filter by SSID", ssid_options)
            band_options = ["All"] + sorted(scan_df["band"].dropna().unique().tolist())
            selected_band = st.selectbox("Filter by band", band_options)
        with scan_filters_right:
            security_options = ["All"] + sorted(scan_df["security"].dropna().unique().tolist())
            selected_security = st.selectbox("Filter by security", security_options)
            suspicious_only = st.checkbox("Show suspicious only")

        filtered = scan_df.copy()
        suspicious_ssids = set(findings_df["ssid"].dropna().tolist()) if not findings_df.empty else set()
        suspicious_bssids = set(findings_df["bssid"].dropna().tolist()) if not findings_df.empty else set()
        if selected_ssid != "All":
            filtered = filtered[filtered["ssid"] == selected_ssid]
        if selected_band != "All":
            filtered = filtered[filtered["band"] == selected_band]
        if selected_security != "All":
            filtered = filtered[filtered["security"] == selected_security]
        if suspicious_only:
            filtered = filtered[(filtered["ssid"].isin(suspicious_ssids)) | (filtered["bssid"].isin(suspicious_bssids))]

        st.dataframe(
            filtered[["ssid", "bssid", "signal_dbm", "signal_percent", "channel", "band", "security", "backend", "timestamp"]],
            use_container_width=True,
            hide_index=True,
        )
    else:
        st.warning("No scan records are loaded yet. Use the sidebar to run a live scan or load demo data.")

with mapping_tab:
    st.subheader("Signal Mapping")
    controls_left, controls_right = st.columns([1, 1])
    with controls_left:
        st.session_state.mapping_width = st.number_input("Survey width", min_value=1.0, value=float(st.session_state.mapping_width), step=1.0)
        st.session_state.mapping_height = st.number_input("Survey height", min_value=1.0, value=float(st.session_state.mapping_height), step=1.0)
        interpolation_method = st.selectbox("Interpolation method", ["linear", "nearest"])
    with controls_right:
        threshold_excellent = st.slider("Excellent threshold (dBm)", -70, -40, int(DEFAULT_THRESHOLDS["excellent"]))
        threshold_good = st.slider("Good threshold (dBm)", -80, -45, int(DEFAULT_THRESHOLDS["good"]))
        threshold_fair = st.slider("Fair threshold (dBm)", -85, -50, int(DEFAULT_THRESHOLDS["fair"]))
        threshold_weak = st.slider("Weak threshold (dBm)", -90, -55, int(DEFAULT_THRESHOLDS["weak"]))
    ordered = sorted([threshold_excellent, threshold_good, threshold_fair, threshold_weak], reverse=True)
    thresholds = {
        "excellent": ordered[0],
        "good": ordered[1],
        "fair": ordered[2],
        "weak": ordered[3],
    }

    bg_option = st.radio("Background", ["None", "Upload floor plan", "Use bundled sample floor plan"], horizontal=True)
    background_image = None
    if bg_option == "Upload floor plan":
        uploaded_image = st.file_uploader("Upload PNG/JPG/SVG floor plan", type=["png", "jpg", "jpeg", "svg"])
        if uploaded_image:
            suffix = Path(uploaded_image.name).suffix.lower()
            if suffix == ".svg":
                svg_data = uploaded_image.getvalue()
                background_image = "data:image/svg+xml;base64," + base64.b64encode(svg_data).decode("utf-8")
            else:
                background_image = Image.open(uploaded_image)
    elif bg_option == "Use bundled sample floor plan":
        sample_floorplan = ASSETS_DIR / "sample_floorplan.svg"
        if sample_floorplan.exists():
            background_image = "data:image/svg+xml;base64," + base64.b64encode(sample_floorplan.read_bytes()).decode("utf-8")

    capture_left, capture_right = st.columns([1.3, 1])
    with capture_left:
        st.markdown("### Add survey point")
        x_value = st.number_input("X coordinate", min_value=0.0, max_value=float(st.session_state.mapping_width), value=0.0, step=0.5)
        y_value = st.number_input("Y coordinate", min_value=0.0, max_value=float(st.session_state.mapping_height), value=0.0, step=0.5)
        point_label = st.text_input("Point label", value=f"P-{datetime.now().strftime('%H%M%S')}")
    with capture_right:
        st.markdown("### Capture source")
        capture_source = st.selectbox("Use data from", ["Current dataset", "Fresh live scan", "Selected demo snapshot"])
        sample_count = st.number_input(
            "Samples per point (Fresh live scan)",
            min_value=1,
            max_value=10,
            value=3,
            step=1,
            help="Number of consecutive live scans to average per AP. Only used with 'Fresh live scan'.",
        )
        if st.button("Clear saved survey points", use_container_width=True):
            storage.clear_mapping_points()
            st.session_state.current_mapping_df = active_mapping_df(st.session_state.current_mode)
            st.success("Saved survey points cleared.")
            st.rerun()
        if st.button("Capture measurement point", use_container_width=True):
            if capture_source == "Fresh live scan":
                samples: list[list] = []
                last_error: str | None = None
                last_stderr: str | None = None
                progress = st.progress(0.0, text="Running live scans...")
                for i in range(int(sample_count)):
                    result = scanner.scan()
                    if result.success:
                        samples.append(result.records)
                    else:
                        last_error = result.message
                        last_stderr = result.stderr
                    progress.progress((i + 1) / int(sample_count), text=f"Scan {i + 1}/{int(sample_count)} complete")
                progress.empty()

                if samples:
                    aggregated: dict[str, dict] = {}
                    for records in samples:
                        for rec in records:
                            entry = aggregated.setdefault(
                                rec.bssid,
                                {"record": rec, "dbm": [], "percent": []},
                            )
                            if rec.signal_dbm is not None:
                                entry["dbm"].append(rec.signal_dbm)
                            if rec.signal_percent is not None:
                                entry["percent"].append(rec.signal_percent)
                            # Keep the most recent record as template
                            entry["record"] = rec

                    records_to_save = []
                    for entry in aggregated.values():
                        base = entry["record"]
                        avg_dbm = sum(entry["dbm"]) / len(entry["dbm"]) if entry["dbm"] else None
                        avg_pct = sum(entry["percent"]) / len(entry["percent"]) if entry["percent"] else None
                        averaged = replace(
                            base,
                            signal_dbm=round(avg_dbm, 2) if avg_dbm is not None else None,
                            signal_percent=round(avg_pct, 2) if avg_pct is not None else None,
                        )
                        records_to_save.append(averaged)
                    st.success(
                        f"Captured {len(records_to_save)} APs for point {point_label} "
                        f"(averaged across {len(samples)}/{int(sample_count)} successful scans)."
                    )
                    if last_error and len(samples) < int(sample_count):
                        st.warning(f"Some scans failed: {last_error}")
                else:
                    records_to_save = []
                    if last_error:
                        st.error(last_error)
                    if last_stderr:
                        st.caption(last_stderr)
                    st.error("Live capture failed. No survey point was saved.")
            elif capture_source == "Selected demo snapshot":
                records_to_save = load_demo_scan_records(selected_demo_snapshot)
            else:
                records_to_save = st.session_state.current_records

            if records_to_save:
                storage.save_mapping_points(x=x_value, y=y_value, point_label=point_label, records=records_to_save, source_snapshot_id=st.session_state.current_snapshot_id)
                st.session_state.current_mapping_df = active_mapping_df(st.session_state.current_mode)
                mapping_df = st.session_state.current_mapping_df.copy()
                coverage_score, coverage_breakdown = calculate_coverage_score(scan_df, mapping_df)
                st.session_state.current_scores["coverage_score"] = coverage_score
                st.session_state.current_scores["overall_score"] = calculate_overall_score(st.session_state.current_scores["security_score"], coverage_score)
                st.session_state.current_score_breakdown["coverage"] = coverage_breakdown
                st.session_state.current_recommendations_df = build_recommendations(scan_df, findings_df, mapping_df, st.session_state.current_scores)
                st.success(f"Saved measurement point '{point_label}'.")

    mapping_df = st.session_state.current_mapping_df.copy()
    if not mapping_df.empty:
        st.markdown("### Visualize an SSID")
        ssid_options = sorted(mapping_df["ssid"].dropna().unique().tolist())
        selected_map_ssid = st.selectbox("SSID to plot", ssid_options)
        selected_points = mapping_df[mapping_df["ssid"] == selected_map_ssid].copy()
        fig, heatmap_result = build_heatmap_figure(
            selected_points,
            width=float(st.session_state.mapping_width),
            height=float(st.session_state.mapping_height),
            thresholds=thresholds,
            background_image=background_image,
            interpolation_method=interpolation_method,
        )
        st.plotly_chart(fig, use_container_width=True)
        if heatmap_result.mode == "scatter":
            st.warning(heatmap_result.message)
        weak_summary = weak_zone_summary(selected_points, thresholds)
        m1, m2, m3 = st.columns(3)
        m1.metric("Weak points", weak_summary["weak_points"])
        m2.metric("Dead-zone points", weak_summary["dead_points"])
        m3.metric("Survey samples", len(selected_points[["x", "y"]].drop_duplicates()))
        st.info("Each survey point stores a full Wi-Fi snapshot at that coordinate. For the map, the app uses the strongest non-empty signal for the selected SSID at each coordinate.")
        st.dataframe(selected_points[["point_label", "x", "y", "ssid", "bssid", "signal_dbm", "timestamp"]], use_container_width=True, hide_index=True)
    else:
        st.info("No mapping points exist yet. Add a point above or use Demo Mode.")

with rogue_tab:
    st.subheader("Rogue AP Detection & Explainable Findings")
    if findings_df.empty:
        st.success("No suspicious or insecure patterns are currently flagged in the active dataset.")
    else:
        severity_order = ["high", "medium", "low"]
        findings_view = findings_df.copy()
        findings_view["severity"] = pd.Categorical(findings_view["severity"], categories=severity_order, ordered=True)
        st.dataframe(
            findings_view[["finding_type", "severity", "confidence", "ssid", "bssid", "details", "recommendation"]].sort_values(["severity", "confidence"]),
            use_container_width=True,
            hide_index=True,
        )

        col_a, col_b = st.columns(2)
        with col_a:
            sev_chart = px.histogram(
                findings_df,
                x="severity",
                color="finding_type",
                title="Finding severity distribution",
                template="plotly_white",
            )
            st.plotly_chart(sev_chart, use_container_width=True)
        with col_b:
            clustered_df = analysis.get("clustered_df", pd.DataFrame())
            if not clustered_df.empty:
                anomaly_chart = px.scatter(
                    clustered_df,
                    x="channel",
                    y="signal_dbm",
                    color="cluster",
                    symbol="is_anomaly",
                    hover_data=["ssid", "bssid", "security"],
                    title="DBSCAN clusters with Isolation Forest outliers",
                    template="plotly_white",
                )
                st.plotly_chart(anomaly_chart, use_container_width=True)

with recommendations_tab:
    st.subheader("Recommendations")
    st.markdown(
        f"**Overall score:** {scores['overall_score']:.1f}/100 &nbsp;&nbsp;|&nbsp;&nbsp; "
        f"**Security:** {scores['security_score']:.1f}/100 &nbsp;&nbsp;|&nbsp;&nbsp; "
        f"**Coverage:** {scores['coverage_score']:.1f}/100"
    )

    recs = st.session_state.current_recommendations_df.copy()
    for _, row in recs.iterrows():
        st.markdown(
            f"""
<div class="card">
  <strong>{row['priority']} · {row['category']}</strong><br>
  <span style="font-size:1.05rem;">{row['recommendation']}</span><br>
  <span class="small-muted">{row['rationale']}</span>
</div>
""",
            unsafe_allow_html=True,
        )
        st.write("")

    st.markdown("### Score breakdown")
    score_breakdown_df = pd.DataFrame(
        [
            {"metric": f"security::{k}", "value": v}
            for k, v in st.session_state.current_score_breakdown["security"].items()
            if isinstance(v, (int, float))
        ]
        + [
            {"metric": f"coverage::{k}", "value": v}
            for k, v in st.session_state.current_score_breakdown["coverage"].items()
            if isinstance(v, (int, float))
        ]
    )
    if not score_breakdown_df.empty:
        breakdown_chart = px.bar(score_breakdown_df, x="metric", y="value", title="Scoring model inputs", template="plotly_white")
        st.plotly_chart(breakdown_chart, use_container_width=True)

with reports_tab:
    st.subheader("Reports & Export")
    report_title = st.text_input("Report title", value="Wi-Fi Assessment Summary")
    metadata = {
        "Data source": st.session_state.current_source_label,
        "Backend": pretty_backend_name(st.session_state.current_backend),
        "Mode": st.session_state.current_mode,
        "Generated": datetime.now().isoformat(timespec="seconds"),
    }
    markdown_report = build_markdown_report(report_title, scan_df, findings_df, recommendations_df, scores, metadata)
    html_report = build_html_report(markdown_report, title=report_title)

    export_col1, export_col2, export_col3 = st.columns(3)
    with export_col1:
        st.download_button(
            "Download scan CSV",
            data=scan_df.to_csv(index=False).encode("utf-8"),
            file_name="scan_results.csv",
            mime="text/csv",
            use_container_width=True,
        )
        st.download_button(
            "Download findings CSV",
            data=findings_df.to_csv(index=False).encode("utf-8"),
            file_name="findings.csv",
            mime="text/csv",
            use_container_width=True,
        )
    with export_col2:
        st.download_button(
            "Download mapping CSV",
            data=mapping_df.to_csv(index=False).encode("utf-8"),
            file_name="mapping_points.csv",
            mime="text/csv",
            use_container_width=True,
        )
        st.download_button(
            "Download Markdown report",
            data=markdown_report.encode("utf-8"),
            file_name="wifi_assessment_report.md",
            mime="text/markdown",
            use_container_width=True,
        )
    with export_col3:
        st.download_button(
            "Download HTML report",
            data=html_report.encode("utf-8"),
            file_name="wifi_assessment_report.html",
            mime="text/html",
            use_container_width=True,
        )
        if st.button("Save Markdown + HTML into reports/", use_container_width=True):
            md_path = save_report(markdown_report, "wifi_assessment_report", "md")
            html_path = save_report(html_report, "wifi_assessment_report", "html")
            st.success(f"Saved reports to {md_path.name} and {html_path.name}.")

    st.markdown("### Report preview")
    st.text_area("Markdown preview", value=markdown_report, height=360)
