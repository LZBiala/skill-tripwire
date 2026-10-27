"""The composite Action and the CI workflow, read as text (no YAML library: the core is stdlib only).

A GitHub expression inside a run script is pasted into the shell before bash reads it, so an
input such as `x; curl ... | sh` would run as code. The inputs must reach bash only through
env, the threshold must be checked before use, and the paths must be split with globbing off.
The workflow runs with a read-only token, pins each action by full commit SHA, and lets the
step that runs the Action fail.
"""
from __future__ import annotations

import re
from pathlib import Path

from skill_tripwire import cli

ROOT = Path(__file__).resolve().parents[1]
EXPR = "${" + "{"


def _run_blocks(text: str) -> list[str]:
    """Every run script: the value after `run:` plus the lines indented deeper than the key."""
    lines = text.splitlines()
    blocks: list[str] = []
    for i, line in enumerate(lines):
        m = re.match(r"^(\s*)(?:-\s+)?run:\s?(.*)$", line)
        if not m:
            continue
        indent = len(m.group(1))
        body = [m.group(2)]
        for nxt in lines[i + 1:]:
            if nxt.strip() and len(nxt) - len(nxt.lstrip()) <= indent:
                break
            body.append(nxt)
        blocks.append("\n".join(body))
    return blocks


def test_no_run_script_in_the_action_holds_an_expression() -> None:
    text = (ROOT / "action.yml").read_text(encoding="utf-8")
    blocks = _run_blocks(text)
    assert len(blocks) == 2, "the Action has two run steps, install and scan (the precondition)"
    for block in blocks:
        assert EXPR not in block, "a run script holds an expression: " + block


def test_the_action_takes_its_inputs_through_env() -> None:
    text = (ROOT / "action.yml").read_text(encoding="utf-8")
    assert "TRIPWIRE_ACTION_PATH: " + EXPR + " github.action_path }}" in text
    assert "TRIPWIRE_FAIL_ON: " + EXPR + " inputs.fail-on }}" in text
    assert "TRIPWIRE_PATHS: " + EXPR + " inputs.paths }}" in text
    assert 'run: python -m pip install "$TRIPWIRE_ACTION_PATH"' in text
    assert ("no shell expansion, so quotes, escapes, variables, ~, braces and globs are literal"
            in text), "the paths input says what the split does not do"


def test_the_scan_script_checks_the_threshold_and_splits_paths_with_globbing_off() -> None:
    scan = _run_blocks((ROOT / "action.yml").read_text(encoding="utf-8"))[1]
    assert "set -f" in scan and "tripwire_paths=($TRIPWIRE_PATHS)" in scan, scan
    assert scan.index("set -f") < scan.index("tripwire_paths=("), "globbing off before the split"
    assert "review|quarantine) ;;" in scan and "exit 3" in scan, "a bad threshold is a usage error"
    assert scan.index("review|quarantine") < scan.index("skill-tripwire scan"), "the threshold is checked first"
    assert 'skill-tripwire scan --fail-on "$TRIPWIRE_FAIL_ON" -- "${tripwire_paths[@]}"' in scan


def test_the_workflow_has_a_read_only_token_and_pins_actions_by_sha() -> None:
    text = (ROOT / ".github" / "workflows" / "ci.yml").read_text(encoding="utf-8")
    assert re.search(r"(?m)^permissions:\n  contents: read$", text)
    assert "uses: actions/checkout@11d5960a326750d5838078e36cf38b85af677262  # v4" in text
    assert "uses: actions/setup-python@a26af69be951a213d495a4c3e4e4022e16d87065  # v5" in text
    for m in re.finditer(r"uses:\s*([^\s#]+)", text):
        ref = m.group(1)
        if ref == "./":
            continue
        assert re.fullmatch(r"[\w.-]+/[\w.-]+@[0-9a-f]{40}", ref), "not pinned by full SHA: " + ref


def test_the_ci_step_that_runs_the_action_can_fail_and_its_scan_of_examples_exits_0() -> None:
    assert cli.main(["scan", "--fail-on", "quarantine", "--", str(ROOT / "examples")]) == 0, (
        "the walk finds no file of the kinds it scans under examples/, so the step exits 0 (the precondition)")
    text = (ROOT / ".github" / "workflows" / "ci.yml").read_text(encoding="utf-8")
    step = text.split("- name: The composite Action scans this repo (Linux only)\n", 1)[1]
    assert "uses: ./\n" in step and "paths: examples\n" in step, step
    assert "continue-on-error" not in text, "nothing hides a failure of the step that runs the Action"
