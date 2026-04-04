# Secure Wi-Fi Signal Strength Mapping and Rogue AP Detection Tool

A polished Streamlit application for **authorized, defensive Wi-Fi assessment**. The tool passively scans nearby access points when live scan backends are available, normalizes Wi-Fi metadata into a common schema, maps signal strength across a surveyed area, flags risky or suspicious patterns, scores security and coverage, and exports concise reports.

> Scope boundary: this project is **passive and defensive only**. It does **not** perform credential capture, deauthentication, packet injection, cracking, exploitation, or offensive actions.

---

## What the project does

The app helps you:

- scan nearby Wi-Fi access points
- inspect SSIDs, BSSIDs, channels, bands, signal, and security types
- detect open or legacy-encrypted networks
- flag suspicious duplicate SSIDs and possible rogue / evil twin behavior
- record survey measurements on an X/Y grid or floor-plan-backed view
- generate interpolated signal heatmaps
- identify weak zones and dead zones
- compute explainable **security**, **coverage**, and **overall** scores
- generate short, actionable recommendations
- export CSV and Markdown/HTML reports

---

## Features

### Dashboard / Overview
- total AP count
- suspicious finding count
- open / weak network count
- average signal strength
- security score
- coverage score
- channel congestion chart
- security distribution chart

### Live Scan
- Windows backend via `netsh`
- Linux backend via `nmcli`, with `iw` fallback
- macOS backend via `CoreWLAN` (preferred), `airport`, and `system_profiler`
- automatic OS / backend detection
- normalized scan table
- filtering by SSID, band, security, suspicious-only
- snapshot saving with timestamps

### Signal Mapping
- manual X/Y survey point workflow
- optional uploaded floor plan background
- bundled sample floor plan for instant demos
- capture points from:
  - current dataset
  - fresh live scan
  - bundled demo snapshot
- interpolated heatmaps using SciPy `griddata`
- scatter fallback when there are too few points
- weak / dead-zone highlighting through thresholds

### Rogue AP Detection
- duplicate SSID detection
- security mismatch detection within the same SSID
- strong signal spike detection within duplicate SSID groups
- anomaly detection using **Isolation Forest**
- clustering using **DBSCAN**
- plain-language explanations with confidence levels

### Recommendations Engine
- AP placement hints
- encryption hardening advice
- channel congestion reduction suggestions
- suspicious SSID verification suggestions
- baseline inventory guidance

### Persistence
- SQLite database for:
  - saved scan snapshots
  - mapping points
  - stored findings

### Demo Mode
- bundled realistic sample scan data
- bundled realistic mapping points
- bundled floor-plan image
- app remains fully usable even when live scan is unavailable

---

## Architecture

```text
app.py                     Streamlit UI and orchestration
src/scanner.py             OS/backend detection and passive Wi-Fi scanning
src/parsers.py             Parsing for netsh, nmcli, iw, airport outputs
src/models.py              Dataclasses for AP records, mapping points, findings
src/storage.py             SQLite persistence layer
src/analyzer.py            Heuristics, clustering, anomaly detection
src/heatmap.py             Interpolation, heatmap generation, weak-zone logic
src/scoring.py             Security / coverage / overall scoring
src/recommendations.py     Recommendation engine
src/demo_data.py           Bundled demo loaders
src/reporting.py           Markdown and HTML report generation
src/utils.py               Shared helpers and normalization utilities
```

---

## Project structure

```text
Secure-WiFi-Signal-Mapping-Tool/
├── app.py
├── README.md
├── requirements.txt
├── assets/
│   └── sample_floorplan.svg
├── data/
│   ├── sample_mapping_points.csv
│   ├── sample_scans.csv
│   └── wifi_assessment.db
├── reports/
├── src/
│   ├── __init__.py
│   ├── analyzer.py
│   ├── demo_data.py
│   ├── heatmap.py
│   ├── models.py
│   ├── parsers.py
│   ├── recommendations.py
│   ├── reporting.py
│   ├── scanner.py
│   ├── scoring.py
│   ├── storage.py
│   └── utils.py
└── tests/
    └── test_core.py
```

> `wifi_assessment.db` is created automatically on first run if it does not already exist.

---

## Prerequisites

- Python **3.11+**
- A local machine with Wi-Fi hardware if you want live scanning
- On Linux, one of:
  - `nmcli` (NetworkManager)
  - `iw`
- On macOS, PyObjC/CoreWLAN first, then Apple’s `airport` utility if available
- On Windows, `netsh` (normally included)

---

## Installation

### 1) Create and activate a virtual environment

#### Windows (PowerShell)
```powershell
python -m venv .venv
.\.venv\Scripts\Activate.ps1
```

#### macOS / Linux
```bash
python3 -m venv .venv
source .venv/bin/activate
```

### 2) Install dependencies
```bash
pip install -r requirements.txt
```

### 3) Run the app
```bash
streamlit run app.py
```

Open the local URL shown by Streamlit in your browser.

---

## How to use the app

### Demo Mode
Demo Mode works immediately with no hardware requirements.

1. Start the app with:
   ```bash
   streamlit run app.py
   ```
2. In the sidebar, keep **Data source = Demo Mode**
3. Choose a bundled demo snapshot
4. Review the Overview, Rogue AP Detection, Recommendations, and Reports tabs
5. Open the Signal Mapping tab to view the bundled coverage survey and heatmap

### Live Scan Mode
1. Start the app
2. In the sidebar, switch to **Live Scan**
3. Click **Run live scan now**
4. If scanning works, results appear in the Live Scan tab and update the rest of the app
5. Save the snapshot if you want persistence across app restarts

If live scanning fails, the app will:
- explain the failure
- show the backend stderr when available
- automatically switch to Demo Mode so the workflow remains usable

### Survey / Signal Mapping workflow
1. Go to **Signal Mapping**
2. Set the survey width and height
3. Optionally upload a floor plan or use the bundled sample floor plan
4. Enter an `(x, y)` point and a label
5. Choose capture source:
   - current dataset
   - fresh live scan
   - selected demo snapshot
6. Click **Capture measurement point**
7. Pick an SSID to visualize
8. Review the heatmap and weak/dead-zone metrics

### Save and export
- Save scan snapshots from the sidebar
- Export scan, findings, and mapping data as CSV in the Reports / Export tab
- Download Markdown or HTML summaries
- Save reports directly into the `reports/` folder

---

## Live scan notes by OS

### Windows
Backend used:
- `netsh wlan show networks mode=bssid`

Requirements / notes:
- Wi-Fi must be enabled
- a WLAN adapter must be present
- some managed or virtualized environments may expose no scan results

### Linux
Preferred backends:
- `nmcli`
- `iw dev <iface> scan` fallback

Requirements / notes:
- `nmcli` usually works best on desktops/laptops using NetworkManager
- `iw` may require additional permissions on some distributions
- results inside VMs often fail or reflect no real wireless adapter

### macOS
Backend used:
- `airport -s`

Requirements / notes:
- the airport utility path is checked automatically
- some managed systems or newer OS builds may restrict or hide the command

---

## Data model

Each AP is normalized into a schema that may include:
- `ssid`
- `bssid`
- `signal_dbm`
- `signal_percent`
- `channel`
- `band`
- `security`
- `timestamp`
- `backend`
- `frequency_mhz` when available

Different OS outputs are normalized into this internal model before analysis.

---

## Scoring model

### Security score (0–100)
Penalizes:
- open networks
- WEP
- WPA / unknown / legacy security
- duplicate SSIDs with mismatched security
- suspicious rogue-like signal spikes
- ML anomalies

### Coverage score (0–100)
Uses:
- mean signal strength
- fraction of weak points
- fraction of dead-zone points
- channel congestion estimate

### Overall score
Weighted combination:
- 55% security
- 45% coverage

---

## Data science components

This project includes real analysis, not dummy labels:

- **Isolation Forest** for AP anomaly detection
- **DBSCAN** for pattern clustering
- **SciPy griddata** for signal interpolation
- explainable scoring model for risk and coverage

---

## Running tests

```bash
pytest -q
```

---

## Troubleshooting

### Live scan says no backend found
Cause:
- required OS command is missing
- the environment is unsupported

What to do:
- use Demo Mode immediately
- on Linux, install NetworkManager / nmcli or ensure `iw` is present
- on macOS, verify the airport utility exists

### Live scan returns empty results
Cause:
- Wi-Fi disabled
- unsupported adapter
- insufficient permissions
- VM / remote session limitations

What to do:
- confirm the machine has an active Wi-Fi interface
- retry outside the VM if possible
- use Demo Mode for the rest of the workflow

### Floor-plan upload does not render for SVG
Cause:
- local Pillow build may not decode SVG directly

What to do:
- use PNG/JPG uploads for maximum compatibility
- or use the bundled sample floor plan

### Heatmap falls back to scatter mode
Cause:
- too few unique survey points

What to do:
- capture at least four unique `(x, y)` points
- distribute measurements across the area instead of only along one edge

### Coverage score seems low even with a decent scan
Cause:
- saved mapping points may contain weak/dead zones
- crowded channels can reduce the coverage score

What to do:
- review the Signal Mapping and Overview tabs together
- verify thresholds match your environment

---

## Limitations

- live scanning depends on platform utilities and local permissions
- 6 GHz identification depends on frequency visibility from the backend
- channel heuristics are intentionally conservative to reduce false positives
- signal mapping is based on sampled points, not a physical RF propagation model
- the rogue / evil twin detection is **heuristic and probabilistic**, not proof of compromise

---

## Future improvements

- historical drift dashboard across many saved snapshots
- trusted SSID/BSSID baseline management UI
- authenticated multi-user persistence
- richer PDF report generation
- optional floor-plan calibration using image click-to-coordinate mapping
- stronger channel planning logic per regulatory domain

---

## Exact quick-start commands

### Windows (PowerShell)
```powershell
python -m venv .venv
.\.venv\Scripts\Activate.ps1
pip install -r requirements.txt
streamlit run app.py
```

### macOS / Linux
```bash
python3 -m venv .venv
source .venv/bin/activate
pip install -r requirements.txt
streamlit run app.py
```

On macOS, `pip install -r requirements.txt` also installs the PyObjC bindings used for CoreWLAN and CoreLocation.



## macOS airport note

On macOS Sonoma 14.4 and later, `airport -s` can return only a deprecation warning instead of nearby networks. This project now prefers `CoreWLAN` via PyObjC for live scans because it can return RSSI values for nearby networks, then falls back to `airport`, and finally to `system_profiler SPAirPortDataType`. `system_profiler` is a limited fallback and often omits RSSI for unconnected networks. If CoreWLAN shows hidden or incomplete metadata, enable Location Services for the Python interpreter or terminal host app, then restart Streamlit from a new terminal window.
