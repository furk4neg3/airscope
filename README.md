# AirScope

**AirScope** is a Streamlit-based Python application for **passive, defensive Wi-Fi assessment**. It helps you inspect nearby access points, map signal strength across a surveyed space, flag risky or suspicious wireless patterns, score security and coverage, and export short assessment reports.

> Scope boundary: AirScope is **passive and defensive only**. It does **not** perform credential capture, deauthentication, packet injection, cracking, exploitation, or any other offensive action.

---

## What AirScope does

AirScope lets you:

- run a **live passive Wi-Fi scan** when a supported local backend is available
- inspect **SSID, BSSID, signal, channel, band, frequency, and security** values in a normalized table
- flag **open networks**, **weak encryption**, **duplicate SSIDs**, **security mismatches**, **signal spikes**, and **other anomaly-based findings**
- save scan snapshots to a local **SQLite** database
- capture survey points on an **X/Y grid** for coverage analysis
- generate **signal heatmaps** or scatter fallback views when there are too few points to interpolate
- identify **weak** and **dead-zone** areas using configurable thresholds
- compute **security**, **coverage**, and **overall** scores
- generate **recommendations** based on the current scan and mapping data
- export **CSV**, **Markdown**, and **HTML** reports

---

## Current feature set

### Overview tab
- total AP count
- suspicious findings count
- open / weak network count
- average signal strength
- security score
- coverage score
- security inventory chart
- channel congestion chart
- overall score chart

### Live Scan tab
- passive scan workflow
- normalized AP table
- filters by **SSID**, **band**, **security**, and **suspicious-only**
- backend-aware status messages
- demo fallback when live scanning cannot collect usable AP data

### Signal Mapping tab
- manual X/Y survey point capture
- optional uploaded floor plan background
- bundled sample floor plan
- capture points from:
  - current dataset
  - fresh live scan
  - selected demo snapshot
- interpolated heatmap view
- scatter fallback when interpolation is not possible
- configurable thresholds for excellent / good / fair / weak coverage

### Rogue AP Detection tab
- open network detection
- weak encryption detection
- duplicate SSID detection
- security mismatch / possible rogue detection
- signal spike / possible evil twin detection
- unexpected channel / band checks
- historical profile drift checks when saved data exists
- DBSCAN clustering and Isolation Forest anomaly analysis

### Recommendations tab
- prioritized recommendations
- rationale for each recommendation
- score breakdown chart for explainable scoring inputs

### Reports / Export tab
- scan CSV download
- findings CSV download
- mapping CSV download
- Markdown report download
- HTML report download
- save Markdown + HTML into `reports/`
- in-app Markdown preview

### Persistence
AirScope stores data locally in SQLite for:
- saved scan snapshots
- mapping points
- stored findings

### Demo mode
The app includes bundled demo data so the interface remains usable even if live scanning is unavailable on the host system.

---

## Live scan backends

AirScope uses best-effort passive Wi-Fi scanning based on the current OS.

### Windows
- `netsh wlan show networks mode=bssid`

### Linux
- `nmcli` (preferred)
- `iw` fallback

### macOS
- **CoreWLAN via PyObjC** (preferred)
- Apple `airport` utility fallback
- `system_profiler SPAirPortDataType` final fallback

### Important macOS note
Recent macOS builds may still expose the `airport` binary while returning **no usable scan rows**. In that case, AirScope can detect the backend but still be unable to collect AP data. The app then shows a scan error and switches back to demo data so the rest of the workflow still works.

CoreWLAN also depends on macOS privacy permissions. If scan metadata is incomplete, enable **Location Services** for the Python host / Terminal app and restart Streamlit from a fresh terminal window.

---

## Architecture

```text
app.py                     Streamlit UI and orchestration
src/scanner.py             OS/backend detection and passive Wi-Fi scanning
src/parsers.py             Parsing and normalization for supported scan outputs
src/models.py              Dataclasses for AP records, mapping points, and findings
src/storage.py             SQLite persistence layer
src/analyzer.py            Heuristics, clustering, anomaly detection, and findings
src/heatmap.py             Interpolation, visualization, and weak-zone logic
src/scoring.py             Security / coverage / overall scoring
src/recommendations.py     Recommendation engine
src/demo_data.py           Bundled demo loaders
src/reporting.py           Markdown and HTML report generation
src/utils.py               Shared helpers and normalization utilities
```

---

## Project structure

```text
airscope/
├── app.py
├── README.md
├── requirements.txt
├── assets/
│   └── sample_floorplan.svg
├── data/
│   ├── sample_mapping_points.csv
│   ├── sample_scans.csv
│   └── wifi_assessment.db        # created automatically on first run
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
    ├── conftest.py
    └── test_core.py
```

---

## Requirements

- Python **3.11+**
- a local machine with Wi-Fi hardware for live scanning
- Streamlit-compatible desktop/browser environment
- for Linux live scan: `nmcli` or `iw`
- for macOS live scan: PyObjC / CoreWLAN support is preferred; `airport` and `system_profiler` are fallback paths
- for Windows live scan: `netsh`

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

### 3) Run AirScope
```bash
streamlit run app.py
```

Open the local Streamlit URL shown in the terminal.

---

## How to use AirScope

### Demo Mode
Demo Mode works immediately and does not require working Wi-Fi scan backends.

1. Start the app:
   ```bash
   streamlit run app.py
   ```
2. In the sidebar, keep **Data source = Demo Mode**
3. Choose a bundled demo snapshot
4. Click **Load selected demo snapshot**
5. Review the **Overview**, **Rogue AP Detection**, **Recommendations**, and **Reports / Export** tabs
6. Open **Signal Mapping** to inspect the bundled coverage workflow

### Live Scan Mode
1. Start the app locally on the host machine
2. In the sidebar, switch **Data source** to **Live Scan**
3. Click **Run live scan now**
4. If a supported backend returns usable AP data, the active dataset updates across the app
5. Save the snapshot if you want to keep it in SQLite

If live scanning fails, AirScope:
- shows the failure message
- displays backend stderr when available
- loads the selected demo snapshot so the rest of the workflow remains usable

### Signal Mapping workflow
1. Open **Signal Mapping**
2. Set the survey width and height
3. Optionally upload a floor plan or use the bundled sample floor plan
4. Add an `(x, y)` point and label
5. Choose the capture source:
   - **Current dataset**
   - **Fresh live scan**
   - **Selected demo snapshot**
6. Click **Capture measurement point**
7. Pick the **SSID to plot**
8. Review the map, weak/dead-zone metrics, and the stored per-point scan rows

### Reports and export
Use **Reports / Export** to:
- download scan, findings, and mapping CSV files
- download Markdown and HTML reports
- save both report formats into the local `reports/` directory

---

## Running tests

```bash
pytest -q
```

The current project state passes the included test suite.

---

## Known limitations

- Live scanning is **best effort** and depends on OS support, local hardware, permissions, and backend output format.
- A detected backend is not always a usable backend. For example, on some recent macOS builds, `airport` exists but returns only a deprecation warning and no AP rows.
- `system_profiler` can act as a macOS fallback, but it may omit RSSI for neighboring networks, which reduces mapping accuracy.
- Virtual machines, remote sessions, containers, and some managed systems often do not expose real Wi-Fi hardware to the app.
- Signal mapping quality depends on the number and spread of saved survey points.

---

## Safety and intended use

AirScope is intended for:
- authorized wireless assessments
- lab environments
- home or enterprise Wi-Fi visibility
- defensive analysis and reporting

It is **not** intended for offensive wireless operations.
