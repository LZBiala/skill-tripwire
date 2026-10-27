"""The tripwire-hardening-1 QA wave: one test per must-fix, each seen failing on the branch first.

This file holds no backslash byte: every backslash and line end is built with chr(). Every
credential-shaped string is made up and joined from pieces at run time, never whole in the file,
and every host is made up under .invalid.
"""
from __future__ import annotations

from pathlib import Path

import test_action_inputs

ROOT = Path(__file__).resolve().parents[1]
NL = chr(10)


# ---- W3: the read-only token pin --------------------------------------------------------------

def test_the_read_only_token_pin_refuses_a_second_permissions_key_or_a_wider_block() -> None:
    text = (ROOT / ".github" / "workflows" / "ci.yml").read_text(encoding="utf-8")
    pin = test_action_inputs._assert_read_only_token
    pin(text)  # the control: the shipped workflow passes the pin
    top = "permissions:" + NL + "  contents: read" + NL
    job = "  test:" + NL
    assert text.count(top) == 1 and text.count(job) == 1, "the anchors the mutants edit (the precondition)"
    quoted = chr(34) + "permissions" + chr(34) + ":"
    changes = [
        ("a job-level write-all", job, "    permissions: write-all" + NL),
        ("a quoted job-level block with a write scope", job, "    " + quoted + NL + "      contents: write" + NL),
        ("an id-token write scope under contents: read", top, "  id-token: write" + NL),
        ("a pull-requests write scope under contents: read", top, "  pull-requests: write" + NL),
    ]
    passed = []
    for label, anchor, change in changes:
        mutant = text.replace(anchor, anchor + change)
        assert anchor + change in mutant and change not in text, "the mutant holds its change: " + label
        try:
            pin(mutant)
        except AssertionError:
            continue
        passed.append(label)
    assert passed == [], "the token pin passes " + "; ".join(passed)
