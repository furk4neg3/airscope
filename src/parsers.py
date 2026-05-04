from __future__ import annotations

import re
from typing import Iterable

from .models import APRecord
from .utils import clean_ssid, infer_band, normalize_security, parse_channel_value, signal_percent_to_dbm


MAC_REGEX = r"(?:[0-9A-Fa-f]{2}:){5}[0-9A-Fa-f]{2}"


def parse_netsh_output(text: str) -> list[APRecord]:
    records: list[APRecord] = []
    current_ssid = "<hidden>"
    current_auth = "Unknown"
    current_encryption = "Unknown"
    current_radio = ""

    for raw_line in text.splitlines():
        line = raw_line.strip()
        if not line:
            continue
        ssid_match = re.match(r"SSID\s+\d+\s*:\s*(.*)$", line)
        if ssid_match:
            current_ssid = clean_ssid(ssid_match.group(1))
            current_auth = "Unknown"
            current_encryption = "Unknown"
            current_radio = ""
            continue
        auth_match = re.match(r"Authentication\s*:\s*(.*)$", line)
        if auth_match:
            current_auth = auth_match.group(1).strip()
            continue
        enc_match = re.match(r"Encryption\s*:\s*(.*)$", line)
        if enc_match:
            current_encryption = enc_match.group(1).strip()
            continue
        radio_match = re.match(r"Radio type\s*:\s*(.*)$", line)
        if radio_match:
            current_radio = radio_match.group(1).strip()
            continue

        bssid_match = re.match(rf"BSSID\s+\d+\s*:\s*({MAC_REGEX})$", line)
        if bssid_match:
            bssid = bssid_match.group(1).lower()
            security = normalize_security(f"{current_auth} / {current_encryption}")
            record = APRecord(
                ssid=current_ssid,
                bssid=bssid,
                signal_dbm=None,
                signal_percent=None,
                channel=None,
                band=None,
                security=security,
                backend="netsh",
                raw={"radio_type": current_radio, "authentication": current_auth, "encryption": current_encryption},
            )
            records.append(record)
            continue
        if not records:
            continue

        signal_match = re.match(r"Signal\s*:\s*(\d+)%", line)
        if signal_match:
            percent = float(signal_match.group(1))
            records[-1].signal_percent = percent
            records[-1].signal_dbm = signal_percent_to_dbm(percent)
            continue
        channel_match = re.match(r"Channel\s*:\s*(.*)$", line)
        if channel_match:
            channel = parse_channel_value(channel_match.group(1))
            records[-1].channel = channel
            records[-1].band = infer_band(channel)
            continue

    return records


_NMCLI_FIELD_SPLIT = re.compile(r"(?<!\\):")


def _split_nmcli_terse_line(line: str) -> list[str]:
    """Split a nmcli '-t' line on unescaped ':' and unescape '\\:' in fields."""
    parts = _NMCLI_FIELD_SPLIT.split(line)
    return [p.replace("\\:", ":") for p in parts]


def parse_nmcli_output(text: str) -> list[APRecord]:
    records: list[APRecord] = []
    for raw_line in text.splitlines():
        line = raw_line.strip()
        if not line:
            continue
        parts = _split_nmcli_terse_line(line)
        if len(parts) < 6:
            continue
        ssid, bssid, channel, freq, signal, security = parts[:6]
        channel_int = parse_channel_value(channel)
        freq_match = re.search(r"\d+(?:\.\d+)?", freq)
        freq_val = float(freq_match.group(0)) if freq_match else None
        signal_match = re.search(r"\d+(?:\.\d+)?", signal)
        percent = float(signal_match.group(0)) if signal_match else None
        records.append(
            APRecord(
                ssid=clean_ssid(ssid),
                bssid=bssid.strip().lower(),
                signal_dbm=signal_percent_to_dbm(percent),
                signal_percent=percent,
                channel=channel_int,
                band=infer_band(channel_int, freq_val),
                security=normalize_security(security),
                backend="nmcli",
                frequency_mhz=freq_val,
                raw={},
            )
        )
    return records


def parse_airport_output(text: str) -> list[APRecord]:
    records: list[APRecord] = []
    lines = [line.rstrip() for line in text.splitlines() if line.strip()]
    if len(lines) <= 1:
        return records

    pattern = re.compile(
        rf"^(?P<ssid>.*?)\s+(?P<bssid>{MAC_REGEX})\s+(?P<rssi>-?\d+)\s+(?P<channel>[\d,]+)\s+(?P<ht>\S+)\s+(?P<cc>\S+)\s+(?P<security>.+)$"
    )
    for line in lines[1:]:
        match = pattern.match(line)
        if not match:
            continue
        channel = parse_channel_value(match.group("channel"))
        signal_dbm = float(match.group("rssi"))
        records.append(
            APRecord(
                ssid=clean_ssid(match.group("ssid")),
                bssid=match.group("bssid").lower(),
                signal_dbm=signal_dbm,
                signal_percent=max(0.0, min(100.0, round((signal_dbm + 100) * 2, 1))),
                channel=channel,
                band=infer_band(channel),
                security=normalize_security(match.group("security")),
                backend="airport",
                raw={"country": match.group("cc"), "ht": match.group("ht")},
            )
        )
    return records


def parse_iw_output(text: str) -> list[APRecord]:
    records: list[APRecord] = []
    current: dict[str, str] = {}
    security_markers: set[str] = set()

    def flush_current() -> None:
        if not current.get("bssid"):
            return
        channel = parse_channel_value(current.get("channel"))
        freq_val = float(current["freq"]) if current.get("freq") else None
        signal_dbm = float(current["signal"]) if current.get("signal") else None
        security = " / ".join(sorted(security_markers)) if security_markers else "Open"
        records.append(
            APRecord(
                ssid=clean_ssid(current.get("ssid")),
                bssid=current["bssid"].lower(),
                signal_dbm=signal_dbm,
                signal_percent=max(0.0, min(100.0, round((signal_dbm + 100) * 2, 1))) if signal_dbm is not None else None,
                channel=channel,
                band=infer_band(channel, freq_val),
                security=normalize_security(security),
                backend="iw",
                frequency_mhz=freq_val,
                raw={},
            )
        )

    for raw_line in text.splitlines():
        line = raw_line.strip()
        if not line:
            continue
        bss_match = re.match(rf"BSS\s+({MAC_REGEX})", line)
        if bss_match:
            if current:
                flush_current()
            current = {"bssid": bss_match.group(1)}
            security_markers = set()
            continue
        if line.startswith("SSID:"):
            current["ssid"] = line.split(":", 1)[1].strip()
        elif line.startswith("freq:"):
            current["freq"] = line.split(":", 1)[1].strip()
        elif line.startswith("signal:"):
            current["signal"] = line.split(":", 1)[1].split()[0].strip()
        elif "DS Parameter set: channel" in line:
            current["channel"] = line.rsplit("channel", 1)[1].strip()
        elif line.startswith("primary channel:"):
            current["channel"] = line.split(":", 1)[1].strip()
        elif "RSN:" in line:
            security_markers.add("WPA2")
        elif "WPA:" in line:
            security_markers.add("WPA")
        elif "WEP" in line.upper():
            security_markers.add("WEP")
        elif "SAE" in line.upper():
            security_markers.add("WPA3")
        elif "802.1X" in line.upper() or "EAP" in line.upper():
            security_markers.add("Enterprise")

    if current:
        flush_current()
    return records


def dedupe_records(records: Iterable[APRecord]) -> list[APRecord]:
    deduped: dict[tuple[str, str, int | None], APRecord] = {}
    for record in records:
        key = (record.ssid, record.bssid, record.channel)
        previous = deduped.get(key)
        if previous is None:
            deduped[key] = record
            continue
        if (record.signal_dbm or -999) > (previous.signal_dbm or -999):
            deduped[key] = record
    return list(deduped.values())


def parse_system_profiler_output(text: str) -> list[APRecord]:
    """Parse `system_profiler SPAirPortDataType` text output on macOS."""
    records: list[APRecord] = []
    lines = [line.rstrip("\n") for line in text.splitlines() if line.strip()]
    if not lines:
        return records

    mode: str | None = None
    current_ssid: str | None = None
    current_fields: dict[str, str] = {}
    reserved_headers = {
        "Wi-Fi",
        "Interfaces",
        "Software Versions",
        "Current Network Information",
        "Other Local Wi-Fi Networks",
    }
    property_keys = {"Channel", "Security", "Signal / Noise", "PHY Mode", "Network Type"}

    def flush_current(active_mode: str | None) -> None:
        nonlocal current_ssid, current_fields
        if not current_ssid:
            current_fields = {}
            return
        channel_text = current_fields.get("channel", "")
        signal_text = current_fields.get("signal", "")
        security_text = current_fields.get("security", "Unknown")

        channel = parse_channel_value(channel_text)
        if "6GHZ" in channel_text.upper():
            band = "6 GHz"
        elif "5GHZ" in channel_text.upper():
            band = "5 GHz"
        elif "2GHZ" in channel_text.upper() or "2.4GHZ" in channel_text.upper():
            band = "2.4 GHz"
        else:
            band = infer_band(channel)

        signal_match = re.search(r"(-?\d+)\s*dBm", signal_text, flags=re.IGNORECASE)
        signal_dbm = float(signal_match.group(1)) if signal_match else None
        signal_percent = None
        if signal_dbm is not None:
            signal_percent = max(0.0, min(100.0, round((signal_dbm + 100) * 2, 1)))

        records.append(
            APRecord(
                ssid=clean_ssid(current_ssid),
                bssid="",
                signal_dbm=signal_dbm,
                signal_percent=signal_percent,
                channel=channel,
                band=band,
                security=normalize_security(security_text),
                backend="system_profiler",
                raw={"mode": active_mode or "unknown"},
            )
        )
        current_ssid = None
        current_fields = {}

    for line in lines:
        stripped = line.strip()
        if stripped == "Current Network Information:":
            flush_current(mode)
            mode = "current"
            continue
        if stripped == "Other Local Wi-Fi Networks:":
            flush_current(mode)
            mode = "other"
            continue

        if mode is None:
            continue

        if stripped.endswith(":") and stripped[:-1] not in reserved_headers and stripped[:-1] not in property_keys:
            flush_current(mode)
            current_ssid = stripped[:-1].strip()
            continue

        if current_ssid:
            field_match = re.match(r"^(?P<key>Channel|Security|Signal / Noise|PHY Mode|Network Type):\s*(?P<value>.+)$", stripped)
            if field_match:
                key = field_match.group("key")
                value = field_match.group("value").strip()
                if key == "Channel":
                    current_fields["channel"] = value
                elif key == "Security":
                    current_fields["security"] = value
                elif key == "Signal / Noise":
                    current_fields["signal"] = value
                else:
                    current_fields[key.lower().replace(" / ", "_").replace(" ", "_")] = value
                continue

        # Leave section on unrelated top-level headings after parsing current entries.
        if stripped.endswith(":") and stripped[:-1] in reserved_headers - {"Current Network Information", "Other Local Wi-Fi Networks"}:
            flush_current(mode)
            mode = None

    flush_current(mode)
    return records

