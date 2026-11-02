"""WCAG AA contrast audit (PL-2) for the UI's orange/amber palette (vapt_agent/static/index.html).

Standalone and dependency-free on purpose: a reviewer can run `python3 scripts/contrast_audit.py`
without installing anything, and get a pass/fail against the WCAG 2.1 4.5:1 (normal text) /
3:1 (large text, >=18.66px bold or >=24px regular) thresholds for every text/background pair that
matters in the UI, computed with the standard relative-luminance formula (WCAG 2.1 §1.4.3).

Colors with alpha are pre-composited onto the background they actually sit on (e.g. the hero
section's rgba() chips over #000) before measuring -- contrast only means something against the
color a pixel actually renders as.
"""
from __future__ import annotations

AA_NORMAL = 4.5
AA_LARGE = 3.0


def _hex_to_rgb(h: str) -> tuple[int, int, int]:
    h = h.lstrip("#")
    return int(h[0:2], 16), int(h[2:4], 16), int(h[4:6], 16)


def _composite(fg_hex: str, alpha: float, bg_hex: str) -> tuple[int, int, int]:
    fr, fg, fb = _hex_to_rgb(fg_hex)
    br, bgc, bb = _hex_to_rgb(bg_hex)
    return (round(fr * alpha + br * (1 - alpha)),
            round(fg * alpha + bgc * (1 - alpha)),
            round(fb * alpha + bb * (1 - alpha)))


def _linearize(c: int) -> float:
    c = c / 255
    return c / 12.92 if c <= 0.03928 else ((c + 0.055) / 1.055) ** 2.4


def _luminance(rgb: tuple[int, int, int]) -> float:
    r, g, b = rgb
    return 0.2126 * _linearize(r) + 0.7152 * _linearize(g) + 0.0722 * _linearize(b)


def contrast(fg_hex: str, bg_hex: str) -> float:
    l1, l2 = _luminance(_hex_to_rgb(fg_hex)), _luminance(_hex_to_rgb(bg_hex))
    l1, l2 = max(l1, l2), min(l1, l2)
    return (l1 + 0.05) / (l2 + 0.05)


# (label, foreground hex, background hex, "normal"|"large")
PAIRS = [
    ("body text on app background", "#f3eade", "#120d09", "normal"),
    ("muted label/placeholder on app background", "#b9a589", "#120d09", "normal"),
    ("muted label/placeholder on input field", "#b9a589", "#0d0906", "normal"),
    ("accent2 link on app background", "#facc15", "#120d09", "normal"),
    ("accent2 link on panel/card", "#facc15", "#1d150e", "normal"),
    ("decision-level event text on app background", "#facc15", "#120d09", "normal"),
    ("warn-level event text on app background", "#fb923c", "#120d09", "normal"),
    ("error-level event text on app background", "#f87171", "#120d09", "normal"),
    # Buttons: bold 13px text over a gradient that animates between --accent and --accent2 --
    # check both endpoints, since the midpoint is always >= the darker of the two.
    ("button text at the --accent end of the gradient", "#1a0f02", "#f97316", "normal"),
    ("button text at the --accent2 end of the gradient", "#1a0f02", "#facc15", "normal"),
    # Severity pills: small bold text on a solid fill.
    ("critical-pill text on critical fill", "#220000", "#f87171", "normal"),
    ("high-pill text on high fill", "#220000", "#fb923c", "normal"),
    ("medium-pill text on medium fill", "#220000", "#facc15", "normal"),
    ("low-pill text on low fill", "#000022", "#4ade80", "normal"),
    ("info-pill text on info fill", "#000022", "#94a3b8", "normal"),
]

# (label, foreground hex, alpha, the solid color it's actually composited over, "normal"|"large")
HERO_PAIRS = [
    ("hero scroll-hint on hero background", "#a8785a", 1.0, "#000000", "normal"),
    ("hero chip text on its translucent orange fill", "#fed7aa", 1.0, "#000000", "normal"),
    ("hero badge text on its translucent orange fill", "#ffedd5", 1.0, "#000000", "normal"),
    ("hero subtitle (90% alpha) on hero background", "#ffedd5", 0.9, "#000000", "normal"),
]


def main() -> int:
    failures = 0
    for label, fg, bg, size in PAIRS:
        ratio = contrast(fg, bg)
        threshold = AA_NORMAL if size == "normal" else AA_LARGE
        ok = ratio >= threshold
        failures += not ok
        print(f"{'PASS' if ok else 'FAIL'}  {ratio:5.2f}:1  (need {threshold}:1)  {label}")
    for label, fg, alpha, bg, size in HERO_PAIRS:
        composited_fg = "#%02x%02x%02x" % _composite(fg, alpha, bg) if alpha < 1.0 else fg
        ratio = contrast(composited_fg, bg)
        threshold = AA_NORMAL if size == "normal" else AA_LARGE
        ok = ratio >= threshold
        failures += not ok
        print(f"{'PASS' if ok else 'FAIL'}  {ratio:5.2f}:1  (need {threshold}:1)  {label}")
    print(f"\n{len(PAIRS) + len(HERO_PAIRS) - failures}/{len(PAIRS) + len(HERO_PAIRS)} pairs meet WCAG AA.")
    return 1 if failures else 0


if __name__ == "__main__":
    raise SystemExit(main())
