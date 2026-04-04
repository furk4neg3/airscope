from __future__ import annotations

import pandas as pd

from src.heatmap import prepare_points_for_mapping
from src.parsers import parse_system_profiler_output
from src.scanner import WiFiScanner


def test_system_profiler_parser_reads_current_and_neighbor_networks() -> None:
    sample = """
Wi-Fi:

    Current Network Information:

      OfficeNet:
          PHY Mode: 802.11ac
          Channel: 149 (5GHz, 80MHz)
          Security: WPA2 Personal
          Signal / Noise: -54 dBm / -92 dBm

    Other Local Wi-Fi Networks:

      GuestNet:
          PHY Mode: 802.11n
          Channel: 6 (2GHz, 20MHz)
          Security: Open

      Warehouse:
          PHY Mode: 802.11ax
          Channel: 37 (6GHz, 80MHz)
          Security: WPA3 Personal
"""
    records = parse_system_profiler_output(sample)
    assert len(records) == 3
    assert records[0].ssid == "OfficeNet"
    assert records[0].signal_dbm == -54.0
    assert records[1].ssid == "GuestNet"
    assert records[1].signal_dbm is None
    assert records[1].security == "Open"
    assert records[2].band == "6 GHz"


def test_mapping_summary_ignores_nan_and_keeps_strongest_signal() -> None:
    df = pd.DataFrame(
        [
            {"point_label": "P1", "x": 0, "y": 0, "ssid": "OfficeNet", "signal_dbm": -60},
            {"point_label": "P1", "x": 0, "y": 0, "ssid": "OfficeNet", "signal_dbm": None},
            {"point_label": "P2", "x": 2, "y": 2, "ssid": "OfficeNet", "signal_dbm": -67},
            {"point_label": "P2", "x": 2, "y": 2, "ssid": "OfficeNet", "signal_dbm": -63},
        ]
    )
    office = df[df["ssid"] == "OfficeNet"].copy()
    summary = prepare_points_for_mapping(office)
    assert len(summary) == 2
    strongest = summary.sort_values(["x", "y"]).reset_index(drop=True)
    assert strongest.loc[0, "signal_dbm"] == -60
    assert strongest.loc[1, "signal_dbm"] == -63


class DummyChannel:
    def __init__(self, channel: int) -> None:
        self._channel = channel

    def channelNumber(self) -> int:
        return self._channel


class DummyNetwork:
    def __init__(self, ssid: str, bssid: str | None, rssi: int, channel: int, security: str) -> None:
        self._ssid = ssid
        self._bssid = bssid
        self._rssi = rssi
        self._channel = DummyChannel(channel)
        self._security = security

    def ssid(self) -> str:
        return self._ssid

    def bssid(self) -> str | None:
        return self._bssid

    def rssiValue(self) -> int:
        return self._rssi

    def channel(self) -> DummyChannel:
        return self._channel

    def __str__(self) -> str:
        return f"<CWNetwork [ssid={self._ssid}, bssid={self._bssid}, security={self._security}, rssi={self._rssi}]>"


def test_corewlan_record_conversion_preserves_rssi_for_each_network() -> None:
    scanner = WiFiScanner()
    records = scanner._corewlan_networks_to_records(
        [
            DummyNetwork("Net-A", "aa:bb:cc:dd:ee:01", -55, 1, "WPA2 Personal"),
            DummyNetwork("Net-B", None, -71, 44, "Open"),
        ]
    )
    assert len(records) == 2
    assert records[0].signal_dbm == -55.0
    assert records[0].security == "WPA2"
    assert records[1].signal_dbm == -71.0
    assert records[1].security == "Open"


def test_recommendations_ignore_missing_channel_values() -> None:
    from src.recommendations import build_recommendations

    scan_df = pd.DataFrame(
        [
            {"ssid": "Net-A", "bssid": "aa:aa:aa:aa:aa:01", "security": "WPA2", "channel": None, "band": None},
            {"ssid": "Net-B", "bssid": "aa:aa:aa:aa:aa:02", "security": "WPA2", "channel": None, "band": None},
            {"ssid": "Net-C", "bssid": "aa:aa:aa:aa:aa:03", "security": "WPA2", "channel": None, "band": None},
        ]
    )
    result = build_recommendations(scan_df, pd.DataFrame(), None, {"security_score": 90, "coverage_score": 90})
    assert not result.empty
