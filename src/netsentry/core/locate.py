"""Where is a WiFi device? — position from signal strength at known points.

Several receivers ("anchors") at known positions each report how strongly they
hear a device. Signal strength falls with distance, so each reading suggests a
distance, and three or more of them suggest a position.

Radio indoors is rough: walls, furniture and people move a reading by several
dB, and a few dB is a metre or more. So this module never returns a bare point.
It returns an estimate *with its spread*, computed as a probability map over
the floor (each grid cell is weighted by how well it explains every reading),
and with fewer than three anchors it says "near X, about N m" instead of
inventing coordinates. Expect room-level answers, not centimetres.

Pure functions, no I/O.
"""

from __future__ import annotations

import math
from dataclasses import dataclass

# How much a reading typically wobbles indoors, in dB. Sets how wide the
# probability map is; 5–7 dB is the usual figure for indoor shadowing.
SIGMA_DB = 6.0
_MIN_M, _MAX_M = 0.3, 60.0


@dataclass(frozen=True)
class Anchor:
    """A receiver at a known place on the floor (metres from the plan's corner)."""
    id: str
    name: str
    x: float
    y: float


@dataclass(frozen=True)
class PathLoss:
    """Log-distance model: ``rssi = rssi_at_1m - 10 * exponent * log10(metres)``.

    ``exponent`` is 2 in free space and 2.5–4 through walls.
    """
    rssi_at_1m: float = -45.0
    exponent: float = 3.0

    def distance(self, rssi: float) -> float:
        metres = 10 ** ((self.rssi_at_1m - rssi) / (10 * self.exponent))
        return min(max(metres, _MIN_M), _MAX_M)

    def rssi(self, metres: float) -> float:
        return self.rssi_at_1m - 10 * self.exponent * math.log10(max(metres, _MIN_M))


@dataclass(frozen=True)
class Estimate:
    """Where a device probably is.

    ``kind`` is ``"area"`` when three or more anchors agree on a region
    (``x``/``y`` is its centre, ``radius_m`` its spread), and ``"near"`` when
    only one or two anchors hear the device (no coordinates: ``nearest`` and
    ``nearest_m`` are all that can honestly be said).
    """
    kind: str
    nearest: str                  # id of the anchor that hears it best
    nearest_m: float              # distance that anchor's reading suggests
    anchors: int                  # how many anchors heard it
    x: float | None = None
    y: float | None = None
    radius_m: float | None = None


def fit_path_loss(samples: list[tuple[float, float]]) -> PathLoss | None:
    """Fit the model to ``(metres, rssi)`` pairs measured between known points.

    Returns None when the samples cannot pin the model down: too few, all at
    about the same distance, or a fit outside what radio physically does.
    """
    points = [(math.log10(d), r) for d, r in samples if d >= _MIN_M and -100 <= r <= 0]
    if len(points) < 3:
        return None
    xs = [p[0] for p in points]
    if 10 ** (max(xs) - min(xs)) < 1.5:           # farthest < 1.5× nearest: slope unknowable
        return None
    n = len(points)
    mean_x = sum(xs) / n
    mean_y = sum(p[1] for p in points) / n
    spread = sum((x - mean_x) ** 2 for x in xs)
    slope = sum((x - mean_x) * (y - mean_y) for x, y in points) / spread
    exponent = -slope / 10
    if not 1.5 <= exponent <= 5.0:
        return None
    return PathLoss(rssi_at_1m=round(mean_y - slope * mean_x, 1), exponent=round(exponent, 2))


def fit_level(samples: list[tuple[float, float]], exponent: float = 3.0) -> PathLoss | None:
    """Fit only the level (signal at 1 m), taking the fall-off as given.

    For when the known points are all about equally far apart — the usual case
    with a few sensors in the corners of a home — so the fall-off cannot be
    measured but the level still can.
    """
    levels = [r + 10 * exponent * math.log10(d) for d, r in samples
              if d >= _MIN_M and -100 <= r <= 0]
    if len(levels) < 2:
        return None
    level = sum(levels) / len(levels)
    if not -75 <= level <= -15:
        return None
    return PathLoss(rssi_at_1m=round(level, 1), exponent=exponent)


def locate(readings: dict[str, float], anchors: dict[str, Anchor],
           models: dict[str, PathLoss] | PathLoss, *,
           width_m: float, height_m: float, step_m: float = 0.25) -> Estimate | None:
    """Estimate a device's position from ``{anchor_id: rssi}``.

    ``models`` is one model for every anchor, or one per anchor id (anchors
    missing from the dict use the default model).
    """
    heard = {a: float(r) for a, r in readings.items() if a in anchors and -100 <= r <= 0}
    if not heard:
        return None

    def model(anchor_id: str) -> PathLoss:
        if isinstance(models, PathLoss):
            return models
        return models.get(anchor_id) or PathLoss()

    nearest = min(heard, key=lambda a: model(a).distance(heard[a]))
    nearest_m = round(model(nearest).distance(heard[nearest]), 1)
    if len(heard) < 3:
        return Estimate("near", nearest, nearest_m, len(heard))

    # Probability map: every cell scored by how well it explains all readings.
    cols = max(2, int(width_m / step_m) + 1)
    rows = max(2, int(height_m / step_m) + 1)
    total = sum_x = sum_y = 0.0
    cells: list[tuple[float, float, float]] = []
    for row in range(rows):
        y = row * step_m
        for col in range(cols):
            x = col * step_m
            cost = 0.0
            for anchor_id, rssi in heard.items():
                a = anchors[anchor_id]
                expected = model(anchor_id).rssi(math.hypot(x - a.x, y - a.y))
                cost += (rssi - expected) ** 2
            cells.append((x, y, cost))
    best = min(c[2] for c in cells)
    for x, y, cost in cells:
        weight = math.exp(-(cost - best) / (2 * SIGMA_DB ** 2))
        total += weight
        sum_x += weight * x
        sum_y += weight * y
    cx, cy = sum_x / total, sum_y / total
    variance = sum(math.exp(-(cost - best) / (2 * SIGMA_DB ** 2))
                   * ((x - cx) ** 2 + (y - cy) ** 2) for x, y, cost in cells) / total
    return Estimate("area", nearest, nearest_m, len(heard),
                    x=round(cx, 1), y=round(cy, 1),
                    radius_m=round(max(math.sqrt(variance), step_m), 1))
