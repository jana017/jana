"""Dynamic OG image generator for CyberLab shared analyses.

Renders a 1200x630 PNG when Twitter/LinkedIn/Slack unfurls
`/cyberlab/share/{share_id}`. No external deps — uses Pillow only.

Layout
------
    ┌──────────────────────────────────────────────────────┐
    │ NivX · CyberLab                                      │
    │                                                      │
    │   MALICIOUS   ▓▓▓▓▓▓▓▓▓▓░░  85 / 100                │
    │                                                      │
    │   Ransomware family observed · 3 rule matches        │
    │                                                      │
    │   Top TTPs:  T1486 · T1490 · T1059.001               │
    │                                                      │
    │                             nivxmachines.com/cyberlab│
    └──────────────────────────────────────────────────────┘
"""
from __future__ import annotations
import io
from typing import Dict, Any, List

from PIL import Image, ImageDraw, ImageFont


W, H = 1200, 630

# Verdict colors
VERDICT_COLORS = {
    "malicious":  {"bg": (17, 24, 39), "bar": (220, 38, 38), "text": (248, 113, 113), "label": "MALICIOUS"},
    "suspicious": {"bg": (17, 24, 39), "bar": (217, 119, 6), "text": (252, 211, 77), "label": "SUSPICIOUS"},
    "clean":      {"bg": (17, 24, 39), "bar": ( 16, 185, 129), "text": (110, 231, 183), "label": "CLEAN"},
}

CYAN   = (34, 211, 238)
SLATE  = (148, 163, 184)
WHITE  = (241, 245, 249)
DARK   = (2, 6, 23)


def _font(size: int, bold: bool = False) -> ImageFont.FreeTypeFont | ImageFont.ImageFont:
    """Try DejaVu system font (bundled with Pillow), fall back to default."""
    candidates = (
        "/usr/share/fonts/truetype/dejavu/DejaVuSans-Bold.ttf" if bold
        else "/usr/share/fonts/truetype/dejavu/DejaVuSans.ttf",
        "/usr/share/fonts/dejavu/DejaVuSans-Bold.ttf" if bold else "/usr/share/fonts/dejavu/DejaVuSans.ttf",
    )
    for p in candidates:
        try:
            return ImageFont.truetype(p, size)
        except OSError:
            continue
    return ImageFont.load_default()


def render(payload: Dict[str, Any]) -> bytes:
    """Return PNG bytes for a share document's `payload` field."""
    analysis = payload.get("analysis") or {}
    verdict = analysis.get("verdict", "clean")
    risk = int(analysis.get("risk_score") or 0)
    summary = analysis.get("summary") or "No suspicious indicators observed."
    mitre = analysis.get("mitre") or []
    rules = analysis.get("rules") or []
    iocs = analysis.get("iocs") or []

    style = VERDICT_COLORS.get(verdict, VERDICT_COLORS["clean"])

    im = Image.new("RGB", (W, H), style["bg"])
    dr = ImageDraw.Draw(im)

    # --- background grid pattern (subtle) ---
    grid = (30, 41, 59)
    for x in range(0, W, 60):
        dr.line([(x, 0), (x, H)], fill=grid, width=1)
    for y in range(0, H, 60):
        dr.line([(0, y), (W, y)], fill=grid, width=1)

    # --- left accent stripe with verdict color ---
    dr.rectangle([(0, 0), (18, H)], fill=style["bar"])

    # --- brand row ---
    brand_font = _font(28, bold=True)
    sub_font = _font(20)
    dr.text((60, 50), "NivX", fill=WHITE, font=brand_font)
    dr.text((136, 55), "·  CyberLab", fill=CYAN, font=sub_font)

    # --- verdict label pill ---
    label_font = _font(46, bold=True)
    label_w = int(dr.textlength(style["label"], font=label_font))
    dr.rounded_rectangle([(60, 130), (60 + label_w + 60, 200)],
                         radius=14, fill=style["bar"])
    dr.text((90, 138), style["label"], fill=WHITE, font=label_font)

    # --- risk score gauge ---
    gauge_x, gauge_y, gauge_w, gauge_h = 60, 240, 500, 32
    dr.rounded_rectangle(
        [(gauge_x, gauge_y), (gauge_x + gauge_w, gauge_y + gauge_h)],
        radius=16, fill=(30, 41, 59),
    )
    fill_w = max(1, int(gauge_w * min(risk, 100) / 100))
    dr.rounded_rectangle(
        [(gauge_x, gauge_y), (gauge_x + fill_w, gauge_y + gauge_h)],
        radius=16, fill=style["bar"],
    )
    dr.text((gauge_x + gauge_w + 30, gauge_y - 4),
            f"{risk}/100", fill=style["text"], font=_font(36, bold=True))
    dr.text((gauge_x, gauge_y + gauge_h + 8),
            "RISK SCORE", fill=SLATE, font=_font(14, bold=True))

    # --- summary line (truncate to fit) ---
    summary_font = _font(22)
    text = _truncate(dr, summary, summary_font, W - 120)
    dr.text((60, 330), text, fill=WHITE, font=summary_font)

    # --- stats row: rules · mitre · iocs ---
    stats_font = _font(18, bold=True)
    stats_label = _font(13)
    y = 380
    _stat(dr, 60,  y, "MITRE",    str(len(mitre)),  CYAN,   stats_font, stats_label)
    _stat(dr, 260, y, "RULES",    str(len(rules)),  style["text"], stats_font, stats_label)
    _stat(dr, 460, y, "IOCs",     str(len(iocs)),   (147, 197, 253), stats_font, stats_label)

    # --- top TTPs strip ---
    if mitre:
        top: List[str] = [m.get("id", "") for m in mitre[:5]]
        ttp_font = _font(20, bold=True)
        dr.text((60, 480), "TOP TTPs", fill=SLATE, font=_font(14, bold=True))
        chip_x = 60
        for tid in top:
            if not tid:
                continue
            chip_w = int(dr.textlength(tid, font=ttp_font)) + 24
            dr.rounded_rectangle(
                [(chip_x, 510), (chip_x + chip_w, 552)],
                radius=8, outline=CYAN, width=2, fill=(15, 23, 42),
            )
            dr.text((chip_x + 12, 518), tid, fill=CYAN, font=ttp_font)
            chip_x += chip_w + 12

    # --- footer URL ---
    footer_font = _font(18, bold=True)
    url = "nivxmachines.com/cyberlab"
    url_w = int(dr.textlength(url, font=footer_font))
    dr.text((W - url_w - 60, H - 45), url, fill=SLATE, font=footer_font)

    buf = io.BytesIO()
    im.save(buf, format="PNG", optimize=True)
    return buf.getvalue()


def _stat(dr: ImageDraw.ImageDraw, x: int, y: int, label: str, value: str,
          color, big_font, small_font) -> None:
    dr.text((x, y), value, fill=color, font=big_font)
    dr.text((x, y + 26), label, fill=SLATE, font=small_font)


def _truncate(dr: ImageDraw.ImageDraw, text: str, font, max_px: int) -> str:
    if int(dr.textlength(text, font=font)) <= max_px:
        return text
    while text and int(dr.textlength(text + "…", font=font)) > max_px:
        text = text[:-1]
    return text + "…"
