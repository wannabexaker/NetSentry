"""Draw the floor map for the locator: anchors, devices and how unsure each is."""

from __future__ import annotations

from pathlib import Path

from ...core.locate import Anchor, Estimate

_MARGIN = 40
_MAX_SIDE = 900
_INK = (30, 34, 44)
_FAINT = (224, 228, 236)
_ANCHOR = (60, 90, 200)
_DEVICE = (214, 72, 60)
# Device names are the owner's own labels and may be in any script; the font
# bundled with Pillow only covers Latin. Use a wide system font when there is one.
_FONTS = (
    "/usr/share/fonts/truetype/dejavu/DejaVuSans.ttf",
    "/usr/share/fonts/truetype/noto/NotoSans-Regular.ttf",
    "/usr/share/fonts/truetype/liberation/LiberationSans-Regular.ttf",
    "C:/Windows/Fonts/segoeui.ttf",
    "/System/Library/Fonts/Supplemental/Arial Unicode.ttf",
)


def _font(size: int):
    from PIL import ImageFont

    for candidate in _FONTS:
        try:
            return ImageFont.truetype(candidate, size)
        except OSError:
            continue
    try:
        return ImageFont.load_default(size=size)
    except TypeError:                        # older Pillow: fixed-size bitmap font
        return ImageFont.load_default()


def draw_map(path: Path, width_m: float, height_m: float, anchors: list[Anchor],
             devices: list[tuple[str, Estimate]], floor_image: str = "") -> Path:
    """Write a PNG of the floor to ``path``; (0, 0) is the top-left corner."""
    from PIL import Image, ImageDraw

    scale = _MAX_SIDE / max(width_m, height_m, 1.0)
    w, h = int(width_m * scale), int(height_m * scale)
    image = Image.new("RGB", (w + 2 * _MARGIN, h + 2 * _MARGIN), "white")

    def px(x: float, y: float) -> tuple[int, int]:
        return _MARGIN + int(x * scale), _MARGIN + int(y * scale)

    if floor_image:
        try:
            plan = Image.open(floor_image).convert("RGB").resize((w, h))
            image.paste(plan, (_MARGIN, _MARGIN))
        except OSError:
            floor_image = ""                 # unreadable plan: fall back to the grid
    draw = ImageDraw.Draw(image, "RGBA")
    font = _font(15)

    def label(cx: int, cy: int, text: str, colour) -> None:
        """Write beside a mark — to its left when the right edge is too close."""
        length = int(draw.textlength(text, font=font))
        x = cx + 11 if cx + 11 + length < image.width - 4 else cx - 11 - length
        draw.text((x, cy - 9), text, fill=colour, font=font)

    if not floor_image:
        for metre in range(int(width_m) + 1):
            draw.line([px(metre, 0), px(metre, height_m)], fill=_FAINT)
        for metre in range(int(height_m) + 1):
            draw.line([px(0, metre), px(width_m, metre)], fill=_FAINT)
    draw.rectangle([px(0, 0), px(width_m, height_m)], outline=_INK, width=2)
    # Legend, drawn rather than typed so it never depends on the font's symbols.
    size_text = f"{width_m:g} m x {height_m:g} m"
    draw.text((_MARGIN, 11), size_text, fill=_INK, font=font)
    x = _MARGIN + int(draw.textlength(size_text, font=font)) + 28
    draw.rectangle([x, 14, x + 12, 26], fill=_ANCHOR)
    draw.text((x + 18, 11), "sensor", fill=_INK, font=font)
    x += 18 + int(draw.textlength("sensor", font=font)) + 24
    draw.ellipse([x, 14, x + 12, 26], fill=_DEVICE)
    draw.text((x + 18, 11), "device (circle = how unsure)", fill=_INK, font=font)

    # Uncertainty first, so labels stay readable on top of it.
    for _name, est in devices:
        cx, cy = px(est.x, est.y)
        r = int((est.radius_m or 0) * scale)
        draw.ellipse([cx - r, cy - r, cx + r, cy + r], fill=(*_DEVICE, 36),
                     outline=(*_DEVICE, 110))
    for anchor in anchors:
        cx, cy = px(anchor.x, anchor.y)
        draw.rectangle([cx - 7, cy - 7, cx + 7, cy + 7], fill=_ANCHOR)
        label(cx, cy, anchor.name[:28], _ANCHOR)
    for name, est in devices:
        cx, cy = px(est.x, est.y)
        draw.ellipse([cx - 6, cy - 6, cx + 6, cy + 6], fill=_DEVICE, outline="white")
        label(cx, cy, name[:28], _INK)

    path.parent.mkdir(parents=True, exist_ok=True)
    image.save(path, "PNG")
    return path
