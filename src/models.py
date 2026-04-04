from __future__ import annotations

from dataclasses import dataclass, field, asdict
from datetime import datetime, timezone
from typing import Any


def utc_now_iso() -> str:
    return datetime.now(timezone.utc).replace(microsecond=0).isoformat().replace("+00:00", "Z")


@dataclass(slots=True)
class APRecord:
    ssid: str
    bssid: str
    signal_dbm: float | None
    signal_percent: float | None
    channel: int | None
    band: str | None
    security: str
    timestamp: str = field(default_factory=utc_now_iso)
    backend: str = "unknown"
    frequency_mhz: float | None = None
    raw: dict[str, Any] = field(default_factory=dict)

    def to_dict(self) -> dict[str, Any]:
        data = asdict(self)
        data["ssid"] = self.ssid or "<hidden>"
        return data


@dataclass(slots=True)
class MappingPoint:
    x: float
    y: float
    ssid: str
    bssid: str
    signal_dbm: float | None
    timestamp: str = field(default_factory=utc_now_iso)
    source_snapshot_id: int | None = None
    point_label: str = ""

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)


@dataclass(slots=True)
class Finding:
    finding_type: str
    severity: str
    confidence: float
    ssid: str
    bssid: str
    details: str
    recommendation: str
    created_at: str = field(default_factory=utc_now_iso)
    extra: dict[str, Any] = field(default_factory=dict)

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)
