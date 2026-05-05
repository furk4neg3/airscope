from __future__ import annotations

import os
import re
import time
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Iterable

from .models import APRecord
from .parsers import (
    dedupe_records,
    parse_airport_output,
    parse_iw_output,
    parse_netsh_output,
    parse_nmcli_output,
    parse_system_profiler_output,
)
from .utils import clean_ssid, current_os, infer_band, module_exists, normalize_security, safe_run

AIRPORT_PATH = "/System/Library/PrivateFrameworks/Apple80211.framework/Versions/Current/Resources/airport"


@dataclass(slots=True)
class ScanResult:
    success: bool
    records: list[APRecord]
    backend: str
    mode: str
    message: str
    stderr: str = ""
    warning: str = ""
    metadata: dict[str, Any] = field(default_factory=dict)


class WiFiScanner:
    """Best-effort passive Wi-Fi scanner with per-OS backends."""

    def __init__(self) -> None:
        self.os_name = current_os()

    def available_backends(self) -> list[str]:
        if self.os_name == "windows":
            return ["netsh"]
        if self.os_name == "linux":
            backends: list[str] = []
            if self._has_command("nmcli"):
                backends.append("nmcli")
            if self._has_command("iw"):
                backends.append("iw")
            return backends
        if self.os_name == "darwin":
            backends: list[str] = []
            if module_exists("CoreWLAN"):
                backends.append("corewlan")
            if os.path.exists(AIRPORT_PATH):
                backends.append("airport")
            if self._has_command("system_profiler"):
                backends.append("system_profiler")
            return backends
        return []

    def scan(self) -> ScanResult:
        backends = self.available_backends()
        if not backends:
            return ScanResult(
                success=False,
                records=[],
                backend="none",
                mode="demo-required",
                message="No supported live scan backend was detected on this system.",
            )

        last_error = ""
        last_warning = ""
        attempts: list[tuple[str, str]] = []  # (backend, short reason)
        for backend in backends:
            if backend == "netsh":
                result = self._scan_windows_netsh()
            elif backend == "nmcli":
                result = self._scan_linux_nmcli()
            elif backend == "iw":
                result = self._scan_linux_iw()
            elif backend == "corewlan":
                result = self._scan_macos_corewlan()
            elif backend == "airport":
                result = self._scan_macos_airport()
            elif backend == "system_profiler":
                result = self._scan_macos_system_profiler()
            else:
                continue

            if result.success and result.records:
                result.records = dedupe_records(result.records)
                return result
            last_error = result.stderr or result.message
            last_warning = result.warning or last_warning
            reason = (result.stderr or result.message or "no records").strip().splitlines()[0][:160]
            attempts.append((backend, reason))

        summary = "; ".join(f"{name}: {reason}" for name, reason in attempts) if attempts else ""
        return ScanResult(
            success=False,
            records=[],
            backend=backends[0],
            mode="demo-required",
            message="Live scan could not collect Wi-Fi data with the available backend(s).",
            stderr=last_error,
            warning=last_warning,
            metadata={"attempts": attempts, "attempts_summary": summary},
        )

    def live_scan_capability_notes(self) -> list[str]:
        notes = []
        if self.os_name == "windows":
            notes.append("Windows live scanning uses 'netsh wlan show networks mode=bssid'.")
            notes.append("If results are empty, verify Wi-Fi is enabled and the adapter supports WLAN scans.")
        elif self.os_name == "linux":
            notes.append("Linux prefers 'nmcli' and falls back to 'iw dev <iface> scan'.")
            notes.append("'iw' scans can require root privileges or NetworkManager permissions on some distributions.")
        elif self.os_name == "darwin":
            notes.append("macOS now prefers CoreWLAN via PyObjC, because it can return RSSI for nearby networks instead of only the connected SSID.")
            notes.append("If CoreWLAN is unavailable, the app tries Apple's legacy 'airport' utility and finally 'system_profiler SPAirPortDataType'.")
            notes.append("system_profiler is a limited fallback on macOS and often omits RSSI for neighboring networks. Enable Location Services for Python / Terminal to improve SSID and BSSID visibility.")
        else:
            notes.append("This OS is not supported for live scanning in the current build.")
        return notes

    @staticmethod
    def _has_command(command: str) -> bool:
        from shutil import which

        return which(command) is not None

    def _scan_windows_netsh(self) -> ScanResult:
        ok, stdout, stderr = safe_run(["netsh", "wlan", "show", "networks", "mode=bssid"])
        records = parse_netsh_output(stdout) if ok else []
        return ScanResult(
            success=ok and bool(records),
            records=records,
            backend="netsh",
            mode="live",
            message="Windows scan completed." if ok else "Windows scan failed.",
            stderr=stderr,
        )

    def _scan_linux_nmcli(self) -> ScanResult:
        # Use nmcli's default terse output (':' separator with '\:' escapes).
        # The '--separator' flag was removed in newer nmcli releases, so relying
        # on the default keeps this compatible across versions.
        #
        # '--rescan auto' lets NetworkManager decide whether to trigger a fresh
        # radio scan or return its recent cache. Forcing 'yes' on every call
        # (including back-to-back captures from the multi-sample mapping flow)
        # can hit NM's rate-limit and cause 'Scanning not allowed immediately
        # following previous scan' errors.
        command = [
            "nmcli",
            "-t",
            "-f",
            "SSID,BSSID,CHAN,FREQ,SIGNAL,SECURITY",
            "dev",
            "wifi",
            "list",
            "--rescan",
            "auto",
        ]
        ok, stdout, stderr = safe_run(command)
        records = parse_nmcli_output(stdout) if ok else []
        return ScanResult(
            success=ok and bool(records),
            records=records,
            backend="nmcli",
            mode="live",
            message="Linux NetworkManager scan completed." if ok else "nmcli scan failed.",
            stderr=stderr,
        )

    def _scan_linux_iw(self) -> ScanResult:
        ok, stdout, stderr = safe_run(["iw", "dev"])
        if not ok:
            return ScanResult(False, [], "iw", "live", "Unable to enumerate wireless interfaces.", stderr)

        iface = None
        for line in stdout.splitlines():
            stripped = line.strip()
            if stripped.startswith("Interface "):
                iface = stripped.split()[-1]
                break
        if not iface:
            return ScanResult(False, [], "iw", "live", "No wireless interface was found for 'iw'.", stderr)

        ok, scan_out, scan_err = safe_run(["iw", "dev", iface, "scan"], timeout=30)
        records = parse_iw_output(scan_out) if ok else []
        return ScanResult(
            success=ok and bool(records),
            records=records,
            backend="iw",
            mode="live",
            message=f"Linux iw scan completed on interface {iface}." if ok else f"iw scan failed on interface {iface}.",
            stderr=scan_err,
        )

    def _scan_macos_airport(self) -> ScanResult:
        if not Path(AIRPORT_PATH).exists():
            return ScanResult(False, [], "airport", "live", "airport utility was not found.")
        ok, stdout, stderr = safe_run([AIRPORT_PATH, "-s"])
        records = parse_airport_output(stdout) if ok else []

        warning_text = (stdout + "\n" + stderr).lower()
        if ok and not records and "deprecated" in warning_text and "wireless diagnostics" in warning_text:
            return ScanResult(
                success=False,
                records=[],
                backend="airport",
                mode="live",
                message="macOS airport is present but no longer returns scan results on this macOS build. Falling back to another backend is required.",
                stderr=(stderr or stdout).strip(),
            )

        return ScanResult(
            success=ok and bool(records),
            records=records,
            backend="airport",
            mode="live",
            message="macOS airport scan completed." if ok else "airport scan failed.",
            stderr=stderr,
        )

    def _scan_macos_system_profiler(self) -> ScanResult:
        ok, stdout, stderr = safe_run(["system_profiler", "SPAirPortDataType"], timeout=60)
        records = parse_system_profiler_output(stdout) if ok else []
        missing_signal_count = sum(1 for record in records if record.signal_dbm is None)
        warning = ""
        if records and missing_signal_count:
            warning = "system_profiler is a limited macOS fallback. It may show neighboring SSIDs without RSSI values, which makes mapping less accurate for unconnected networks."
        return ScanResult(
            success=ok and bool(records),
            records=records,
            backend="system_profiler",
            mode="live",
            message="macOS System Profiler scan completed." if ok else "system_profiler scan failed.",
            stderr=stderr,
            warning=warning,
            metadata={"missing_signal_count": missing_signal_count},
        )

    def _scan_macos_corewlan(self) -> ScanResult:
        try:
            import CoreWLAN  # type: ignore
        except Exception as exc:
            return ScanResult(False, [], "corewlan", "live", "PyObjC CoreWLAN is not available.", stderr=str(exc))

        auth_note = self._prime_location_services()

        try:
            client = CoreWLAN.CWWiFiClient.sharedWiFiClient()
            interface = client.interface() if hasattr(client, "interface") else None
            if interface is None and hasattr(client, "interfaces"):
                interfaces = list(client.interfaces() or [])
                interface = interfaces[0] if interfaces else None
            if interface is None:
                return ScanResult(False, [], "corewlan", "live", "No macOS Wi-Fi interface was available through CoreWLAN.", warning=auth_note)

            response = interface.scanForNetworksWithName_includeHidden_error_(None, True, None)
            networks, error = self._unpack_scan_response(response)
            records = self._corewlan_networks_to_records(networks)
            warning_parts: list[str] = []
            if auth_note:
                warning_parts.append(auth_note)
            if records and all(record.signal_dbm is not None for record in records):
                pass
            elif records:
                warning_parts.append("CoreWLAN returned some networks without RSSI, SSID, or BSSID details. This usually means macOS privacy restrictions are still hiding part of the scan metadata.")

            location_blocked = records and all((record.ssid == "<hidden>" and not record.bssid) for record in records)
            if location_blocked:
                warning_parts.append("CoreWLAN saw nearby radios but macOS hid SSID/BSSID values. Enable Location Services for the Python interpreter and restart Streamlit from a new terminal window.")

            error_text = str(error) if error else ""
            return ScanResult(
                success=bool(records),
                records=records,
                backend="corewlan",
                mode="live",
                message="macOS CoreWLAN scan completed." if records else "CoreWLAN scan returned no nearby networks.",
                stderr=error_text,
                warning=" ".join(part for part in warning_parts if part).strip(),
                metadata={"interface": self._safe_call(interface, "interfaceName") or ""},
            )
        except Exception as exc:
            return ScanResult(
                False,
                [],
                "corewlan",
                "live",
                "CoreWLAN scan failed.",
                stderr=str(exc),
                warning=auth_note,
            )

    def _prime_location_services(self) -> str:
        if self.os_name != "darwin" or not module_exists("CoreLocation"):
            return ""
        try:
            import CoreLocation  # type: ignore

            manager = CoreLocation.CLLocationManager.alloc().init()
            request = getattr(manager, "requestWhenInUseAuthorization", None)
            if callable(request):
                try:
                    request()
                except Exception:
                    pass
            manager.startUpdatingLocation()
            time.sleep(0.2)
            status_method = getattr(manager, "authorizationStatus", None)
            status = status_method() if callable(status_method) else None
            if status in {0, 1, 2}:
                return "macOS Location Services access has not been granted yet for this Python host. Nearby SSIDs and BSSIDs may be hidden until you allow access in System Settings → Privacy & Security → Location Services."
        except Exception:
            return ""
        return ""

    @staticmethod
    def _unpack_scan_response(response: Any) -> tuple[Iterable[Any], Any]:
        if isinstance(response, tuple):
            if len(response) == 2:
                return response[0] or [], response[1]
            if len(response) == 1:
                return response[0] or [], None
        return response or [], None

    @staticmethod
    def _safe_call(obj: Any, method_name: str, default: Any = None) -> Any:
        if obj is None:
            return default
        method = getattr(obj, method_name, None)
        if not callable(method):
            return default
        try:
            return method()
        except Exception:
            return default

    @staticmethod
    def _corewlan_channel_number(channel_obj: Any) -> int | None:
        """Return a CoreWLAN channel number across PyObjC/macOS variants.

        On some Macs, CWNetwork.channel() returns a CWChannel object.
        On your Mac, it can return an integer-like NSNumber directly.
        This helper supports both.
        """
        if channel_obj is None:
            return None

        channel_number = WiFiScanner._safe_call(channel_obj, "channelNumber")
        if channel_number is not None:
            try:
                return int(channel_number)
            except (TypeError, ValueError):
                return None

        try:
            return int(channel_obj)
        except (TypeError, ValueError):
            return None

    def _corewlan_networks_to_records(self, networks: Iterable[Any]) -> list[APRecord]:
        records: list[APRecord] = []
        for network in list(networks or []):
            ssid = clean_ssid(self._safe_call(network, "ssid"))
            bssid = (self._safe_call(network, "bssid") or "").strip().lower()
            signal_dbm_raw = self._safe_call(network, "rssiValue")
            try:
                signal_dbm = float(signal_dbm_raw) if signal_dbm_raw is not None else None
            except (TypeError, ValueError):
                signal_dbm = None
            signal_percent = None
            if signal_dbm is not None:
                signal_percent = max(0.0, min(100.0, round((signal_dbm + 100) * 2, 1)))

            channel_obj = self._safe_call(network, "channel")
            channel = self._corewlan_channel_number(channel_obj)

            band = infer_band(channel)
            security = self._corewlan_security_label(network)

            if ssid == "<hidden>" and not bssid and signal_dbm is None and channel is None:
                continue

            records.append(
                APRecord(
                    ssid=ssid,
                    bssid=bssid,
                    signal_dbm=signal_dbm,
                    signal_percent=signal_percent,
                    channel=channel,
                    band=band,
                    security=security,
                    backend="corewlan",
                    raw={"repr": str(network)},
                )
            )
        return records

    @staticmethod
    def _corewlan_security_label(network: Any) -> str:
        network_text = str(network)
        match = re.search(r"security=([^,\]]+)", network_text)
        if match:
            return normalize_security(match.group(1).strip())
        return "Unknown"
