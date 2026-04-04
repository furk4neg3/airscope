from __future__ import annotations

from dataclasses import dataclass

import numpy as np
import pandas as pd
import plotly.graph_objects as go
from scipy.interpolate import griddata

from .utils import dbm_to_quality_bucket


@dataclass(slots=True)
class HeatmapResult:
    mode: str
    grid_x: np.ndarray | None
    grid_y: np.ndarray | None
    grid_z: np.ndarray | None
    message: str


def inverse_distance_weighting(
    x: np.ndarray,
    y: np.ndarray,
    values: np.ndarray,
    grid_x: np.ndarray,
    grid_y: np.ndarray,
    power: float = 2.0,
) -> np.ndarray:
    result = np.empty_like(grid_x, dtype=float)
    for i in range(grid_x.shape[0]):
        for j in range(grid_x.shape[1]):
            distances = np.sqrt((x - grid_x[i, j]) ** 2 + (y - grid_y[i, j]) ** 2)
            if np.any(distances == 0):
                result[i, j] = values[np.argmin(distances)]
                continue
            weights = 1 / np.power(distances, power)
            result[i, j] = np.sum(weights * values) / np.sum(weights)
    return result


def build_interpolated_grid(
    points_df: pd.DataFrame,
    width: float,
    height: float,
    resolution: int = 70,
    method: str = "linear",
) -> HeatmapResult:
    if points_df.empty or len(points_df[["x", "y"]].drop_duplicates()) < 4:
        return HeatmapResult(
            mode="scatter",
            grid_x=None,
            grid_y=None,
            grid_z=None,
            message="At least four unique survey points are needed for interpolation. Falling back to scatter mode.",
        )

    x = points_df["x"].to_numpy(dtype=float)
    y = points_df["y"].to_numpy(dtype=float)
    z = points_df["signal_dbm"].to_numpy(dtype=float)

    grid_x, grid_y = np.mgrid[0:width:complex(resolution), 0:height:complex(resolution)]

    try:
        grid_z = griddata((x, y), z, (grid_x, grid_y), method=method)
        if np.isnan(grid_z).any():
            nearest = griddata((x, y), z, (grid_x, grid_y), method="nearest")
            grid_z = np.where(np.isnan(grid_z), nearest, grid_z)
    except Exception:
        grid_z = inverse_distance_weighting(x, y, z, grid_x, grid_y)

    if np.isnan(grid_z).all():
        grid_z = inverse_distance_weighting(x, y, z, grid_x, grid_y)

    return HeatmapResult(
        mode="interpolated",
        grid_x=grid_x,
        grid_y=grid_y,
        grid_z=grid_z,
        message="Interpolated heatmap generated.",
    )


DEFAULT_THRESHOLDS = {
    "excellent": -55,
    "good": -65,
    "fair": -72,
    "weak": -80,
}


def prepare_points_for_mapping(points_df: pd.DataFrame) -> pd.DataFrame:
    if points_df.empty:
        return points_df.copy()

    prepared = points_df.copy()
    prepared["signal_dbm"] = pd.to_numeric(prepared["signal_dbm"], errors="coerce")
    prepared = prepared.dropna(subset=["x", "y", "signal_dbm"]).copy()
    if prepared.empty:
        return prepared

    prepared = prepared.sort_values("signal_dbm", ascending=False)
    subset = [col for col in ["ssid", "x", "y"] if col in prepared.columns]
    if subset:
        prepared = prepared.drop_duplicates(subset=subset, keep="first")
    return prepared.reset_index(drop=True)


def classify_points(points_df: pd.DataFrame, thresholds: dict[str, float] | None = None) -> pd.DataFrame:
    thresholds = thresholds or DEFAULT_THRESHOLDS
    classified = prepare_points_for_mapping(points_df)
    classified["quality_bucket"] = classified["signal_dbm"].apply(lambda value: dbm_to_quality_bucket(value, thresholds))
    return classified


def weak_zone_summary(points_df: pd.DataFrame, thresholds: dict[str, float] | None = None) -> dict:
    thresholds = thresholds or DEFAULT_THRESHOLDS
    if points_df.empty:
        return {"weak_points": 0, "dead_points": 0, "weak_locations": []}
    classified = classify_points(points_df, thresholds)
    if classified.empty:
        return {"weak_points": 0, "dead_points": 0, "weak_locations": []}
    weak = classified[classified["quality_bucket"] == "weak"]
    dead = classified[classified["quality_bucket"] == "dead zone"]
    worst = classified.sort_values("signal_dbm").head(3)
    return {
        "weak_points": int(len(weak)),
        "dead_points": int(len(dead)),
        "weak_locations": worst[["x", "y", "signal_dbm"]].to_dict(orient="records"),
    }


def build_heatmap_figure(
    points_df: pd.DataFrame,
    width: float,
    height: float,
    thresholds: dict[str, float] | None = None,
    background_image=None,
    interpolation_method: str = "linear",
) -> tuple[go.Figure, HeatmapResult]:
    thresholds = thresholds or DEFAULT_THRESHOLDS
    classified = classify_points(points_df, thresholds)
    heatmap = build_interpolated_grid(classified, width, height, method=interpolation_method)

    fig = go.Figure()
    if heatmap.mode == "interpolated" and heatmap.grid_z is not None:
        fig.add_trace(
            go.Heatmap(
                x=np.linspace(0, width, heatmap.grid_z.shape[0]),
                y=np.linspace(0, height, heatmap.grid_z.shape[1]),
                z=heatmap.grid_z.T,
                colorbar=dict(title="Signal (dBm)"),
                zmin=-90,
                zmax=-35,
                hovertemplate="x=%{x:.1f}<br>y=%{y:.1f}<br>Signal=%{z:.1f} dBm<extra></extra>",
                opacity=0.78,
            )
        )

    fig.add_trace(
        go.Scatter(
            x=classified["x"],
            y=classified["y"],
            mode="markers+text",
            text=classified["quality_bucket"],
            textposition="top center",
            marker=dict(
                size=12,
                color=classified["signal_dbm"],
                colorscale="Viridis",
                cmin=-90,
                cmax=-35,
                line=dict(width=1, color="#111827"),
                showscale=False,
            ),
            customdata=classified[["ssid", "signal_dbm", "quality_bucket"]],
            hovertemplate=(
                "SSID=%{customdata[0]}<br>x=%{x}<br>y=%{y}<br>Signal=%{customdata[1]} dBm"
                "<br>Bucket=%{customdata[2]}<extra></extra>"
            ),
            name="Survey Points",
        )
    )

    if background_image is not None:
        fig.add_layout_image(
            dict(
                source=background_image,
                x=0,
                y=height,
                sizex=width,
                sizey=height,
                xref="x",
                yref="y",
                sizing="stretch",
                opacity=0.28,
                layer="below",
            )
        )

    fig.update_layout(
        title="Wi-Fi Signal Map",
        template="plotly_white",
        xaxis_title="X",
        yaxis_title="Y",
        xaxis=dict(range=[0, width]),
        yaxis=dict(range=[0, height], scaleanchor="x", scaleratio=1),
        margin=dict(l=20, r=20, t=50, b=20),
        height=620,
        legend=dict(orientation="h", yanchor="bottom", y=1.02, xanchor="right", x=1),
    )
    return fig, heatmap
