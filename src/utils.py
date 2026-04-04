from __future__ import annotations

import base64
import importlib.util
import json
import math
import os
import platform
import re
import shutil
import subprocess
from io import BytesIO
from pathlib import Path
from typing import Any

import numpy as np

PROJECT_ROOT = Path(__file__).resolve().parent.parent
DATA_DIR = PROJECT_ROOT / "data"
REPORTS_DIR = PROJECT_ROOT / "reports"
ASSETS_DIR = PROJECT_ROOT / "assets"
DB_PATH = DATA_DIR / "wifi_assessment.db"


SECURITY_RANK = {
    "open": 0,
    "wep": 1,
    "wpa": 2,
    "wpa2": 3,
    "wpa2/wpa3": 4,
    "wpa3": 5,
    "enterprise": 4,
    "unknown": 2,
}


def ensure_directories() -> None:
    for directory in (DATA_DIR, REPORTS_DIR, ASSETS_DIR):
        directory.mkdir(parents=True, exist_ok=True)


def current_os() -> str:
    return platform.system().lower()


def command_exists(command: str) -> bool:
    return shutil.which(command) is not None


def module_exists(module_name: str) -> bool:
    return importlib.util.find_spec(module_name) is not None


def safe_run(command: list[str], timeout: int = 20) -> tuple[bool, str, str]:
    try:
        completed = subprocess.run(
            command,
            capture_output=True,
            text=True,
            timeout=timeout,
            check=False,
        )
        return completed.returncode == 0, completed.stdout, completed.stderr
    except (FileNotFoundError, subprocess.TimeoutExpired, PermissionError) as exc:
        return False, "", str(exc)


def signal_percent_to_dbm(percent: float | int | None) -> float | None:
    if percent is None:
        return None
    try:
        percent = float(percent)
    except (TypeError, ValueError):
        return None
    percent = max(0.0, min(100.0, percent))
    return round((percent / 2.0) - 100.0, 1)


def infer_band(channel: int | None = None, frequency_mhz: float | None = None) -> str | None:
    if frequency_mhz:
        if 2400 <= frequency_mhz < 2500:
            return "2.4 GHz"
        if 4900 <= frequency_mhz < 5925:
            return "5 GHz"
        if 5925 <= frequency_mhz < 7125:
            return "6 GHz"
    if channel is None:
        return None
    if 1 <= channel <= 14:
        return "2.4 GHz"
    if 32 <= channel <= 177:
        return "5 GHz"
    if 1 <= channel <= 233:
        return "6 GHz"
    return None


def parse_channel_value(value: str | None) -> int | None:
    if not value:
        return None
    match = re.search(r"(\d+)", str(value))
    return int(match.group(1)) if match else None


def clean_ssid(ssid: str | None) -> str:
    if ssid is None:
        return "<hidden>"
    value = str(ssid).strip()
    return value if value else "<hidden>"


def normalize_security(security: str | None) -> str:
    if not security:
        return "Unknown"
    raw = str(security).strip()
    upper = raw.upper()

    if "OPEN" in upper or upper in {"--", "NONE", "NOPASS", "UNSECURED"}:
        return "Open"
    if "WEP" in upper:
        return "WEP"
    if "WPA3" in upper and "WPA2" in upper:
        return "WPA2/WPA3"
    if "WPA3" in upper:
        return "WPA3"
    if "WPA2" in upper:
        return "WPA2"
    if "WPA" in upper:
        return "WPA"
    if "802.1X" in upper or "ENTERPRISE" in upper or "EAP" in upper:
        return "Enterprise"
    return raw


def security_category(security: str | None) -> str:
    normalized = normalize_security(security).lower()
    if normalized.startswith("open"):
        return "open"
    if normalized.startswith("wep"):
        return "wep"
    if normalized == "wpa":
        return "wpa"
    if normalized == "wpa2/wpa3":
        return "wpa2/wpa3"
    if normalized == "wpa3":
        return "wpa3"
    if normalized == "wpa2":
        return "wpa2"
    if normalized == "enterprise":
        return "enterprise"
    return "unknown"


def security_risk_weight(security: str | None) -> int:
    category = security_category(security)
    if category == "open":
        return 100
    if category == "wep":
        return 85
    if category == "wpa":
        return 60
    if category == "unknown":
        return 50
    if category == "enterprise":
        return 20
    if category == "wpa2":
        return 18
    if category == "wpa2/wpa3":
        return 10
    if category == "wpa3":
        return 5
    return 40


def dbm_to_quality_bucket(signal_dbm: float | None, thresholds: dict[str, float]) -> str:
    if signal_dbm is None or (isinstance(signal_dbm, float) and np.isnan(signal_dbm)):
        return "unknown"
    if signal_dbm >= thresholds["excellent"]:
        return "excellent"
    if signal_dbm >= thresholds["good"]:
        return "good"
    if signal_dbm >= thresholds["fair"]:
        return "fair"
    if signal_dbm >= thresholds["weak"]:
        return "weak"
    return "dead zone"


def score_from_dbm(signal_dbm: float | None) -> float:
    if signal_dbm is None:
        return 0.0
    return float(np.clip((signal_dbm + 90) / 40 * 100, 0, 100))


def json_dumps(data: Any) -> str:
    return json.dumps(data, ensure_ascii=False, default=str)


def json_loads(data: str | None, default: Any = None) -> Any:
    if not data:
        return default
    try:
        return json.loads(data)
    except json.JSONDecodeError:
        return default


def encode_image_to_data_url(image_bytes: bytes, mime: str = "image/png") -> str:
    return f"data:{mime};base64," + base64.b64encode(image_bytes).decode("utf-8")


def pil_image_to_data_url(image: Any, mime: str = "image/png") -> str:
    buffer = BytesIO()
    image.save(buffer, format="PNG")
    return encode_image_to_data_url(buffer.getvalue(), mime=mime)


def pretty_backend_name(backend: str) -> str:
    return backend.replace("_", " ").title()


def confidence_label(value: float) -> str:
    if value >= 0.85:
        return "High"
    if value >= 0.65:
        return "Medium"
    return "Low"


def expected_channel_range(band: str | None) -> tuple[int, int] | None:
    if band == "2.4 GHz":
        return (1, 14)
    if band == "5 GHz":
        return (32, 177)
    if band == "6 GHz":
        return (1, 233)
    return None


def is_unusual_channel(channel: int | None, band: str | None) -> bool:
    if channel is None or band is None:
        return False
    bounds = expected_channel_range(band)
    if not bounds:
        return False
    low, high = bounds
    return not (low <= channel <= high)


def floor_round(value: float, base: float = 1.0) -> float:
    return math.floor(value / base) * base


def ceil_round(value: float, base: float = 1.0) -> float:
    return math.ceil(value / base) * base


def timestamp_filename(stem: str, suffix: str) -> str:
    from datetime import datetime

    return f"{stem}_{datetime.now().strftime('%Y%m%d_%H%M%S')}.{suffix.lstrip('.')}"


def environment_summary() -> dict[str, Any]:
    airport_path = "/System/Library/PrivateFrameworks/Apple80211.framework/Versions/Current/Resources/airport"
    return {
        "os": current_os(),
        "netsh": command_exists("netsh"),
        "nmcli": command_exists("nmcli"),
        "iw": command_exists("iw"),
        "airport": os.path.exists(airport_path),
        "system_profiler": command_exists("system_profiler"),
        "pyobjc_corewlan": module_exists("CoreWLAN"),
        "pyobjc_corelocation": module_exists("CoreLocation"),
    }
