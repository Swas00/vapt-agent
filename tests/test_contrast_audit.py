"""Regression coverage for PL-2: every text/background pair in the UI's orange/amber palette
(scripts/contrast_audit.py) must keep clearing WCAG AA (4.5:1 for normal-size text). Run as a test,
not just a standalone script, so a future palette change that regresses contrast fails CI instead
of only being caught by someone remembering to re-run the script."""
from __future__ import annotations

from scripts.contrast_audit import AA_NORMAL, HERO_PAIRS, PAIRS, contrast, _composite


def test_every_static_text_background_pair_clears_aa_normal_text():
    for label, fg, bg, _size in PAIRS:
        ratio = contrast(fg, bg)
        assert ratio >= AA_NORMAL, f"{label}: {ratio:.2f}:1 < {AA_NORMAL}:1"


def test_every_hero_translucent_pair_clears_aa_normal_text():
    for label, fg, alpha, bg, _size in HERO_PAIRS:
        composited_fg = "#%02x%02x%02x" % _composite(fg, alpha, bg) if alpha < 1.0 else fg
        ratio = contrast(composited_fg, bg)
        assert ratio >= AA_NORMAL, f"{label}: {ratio:.2f}:1 < {AA_NORMAL}:1"


def test_contrast_formula_matches_a_known_wcag_reference_pair():
    # Black on white is the textbook 21:1 maximum.
    assert round(contrast("#000000", "#ffffff"), 2) == 21.0
