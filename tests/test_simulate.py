"""A fast smoke of the simulation harness. The full million-input run is offline (too slow for
CI); this gates the harness itself: a small seeded run must never crash, never hang, and never
spuriously flag the randomly generated benign text.
"""
from __future__ import annotations

import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "tools"))
import simulate  # noqa: E402


def test_a_small_seeded_run_is_robust_and_clean() -> None:
    stats = simulate.run(n=3000, seed=1)
    assert stats["crashes"] == 0, "the scanner crashed on a generated input"
    assert stats["slow"] == 0, "a scan exceeded the hang bound"
    # Randomly generated benign config text must not spuriously flag.
    assert stats["benign_flagged"] == 0, (
        f"benign false positives: {stats['benign_flagged']}/{stats['benign_n']}")
    # Sanity: the run actually exercised all three input kinds.
    assert stats["benign_n"] and stats["attack_n"] and stats["junk_n"]
