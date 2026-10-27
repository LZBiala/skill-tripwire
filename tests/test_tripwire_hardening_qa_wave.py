"""The tripwire-hardening-1 QA wave: one test per must-fix, each seen failing on the branch first.

This file holds no backslash byte: every backslash and line end is built with chr(). Every
credential-shaped string is made up and joined from pieces at run time, never whole in the file,
and every host is made up under .invalid.
"""
from __future__ import annotations

import os
from pathlib import Path

import pytest
import test_action_inputs

from skill_tripwire import server

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


# ---- W5: a --root that names no folder exits 2 with the rule line, never the value typed -------

_ROOT_LINE = "--root must name an existing folder"


def _exit_of_main(argv: list[str], monkeypatch: pytest.MonkeyPatch) -> tuple[object, list[object]]:
    """server.main in process, with serve replaced by a recorder and the root globals put back after."""
    served: list[object] = []
    monkeypatch.setattr(server, "serve", lambda: served.append(server._ROOT))
    monkeypatch.setattr(server, "_ROOT", None)
    monkeypatch.setattr(server, "_ROOT_AS_GIVEN", None)
    with pytest.raises(SystemExit) as stop:
        server.main(argv)
        raise AssertionError("main served in place of exiting 2 (serve calls: " + str(len(served)) + ")")
    return stop.value.code, served


def _a_link_loop(tmp_path: Path) -> Path:
    """loop-a and loop-b, each a link to the other: junctions on Windows, symlinks elsewhere."""
    first, second = tmp_path / "loop-a", tmp_path / "loop-b"
    try:
        if os.name == "nt":
            import _winapi

            second.mkdir()  # a junction's target must exist when the junction is made
            _winapi.CreateJunction(str(second), str(first))
            second.rmdir()
            _winapi.CreateJunction(str(first), str(second))
        else:
            os.symlink(second, first)
            os.symlink(first, second)
    except (OSError, ImportError, AttributeError) as exc:
        pytest.skip("neither a junction nor a symlink can be made here: " + type(exc).__name__)
    return first


def test_a_root_flag_whose_resolve_cannot_finish_exits_2_with_the_rule_and_no_path(
        tmp_path: Path, monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]) -> None:
    loop = _a_link_loop(tmp_path)
    with pytest.raises((RuntimeError, OSError)):
        loop.resolve()  # the precondition: this resolve cannot finish
    code, served = _exit_of_main(["--root", str(loop)], monkeypatch)
    err = capsys.readouterr().err
    assert code == 2 and served == [], "a --root whose resolve cannot finish stops the server before it serves"
    assert _ROOT_LINE in err
    assert "Traceback" not in err and "loop-" not in err, "the refusal names the rule, never the folder typed"


_BLANK_ROOTS = [pytest.param("", id="empty")] + ([pytest.param(" ", id="blank")] if os.name == "nt" else [])


@pytest.mark.parametrize("typed", _BLANK_ROOTS)
def test_an_empty_or_blank_root_flag_exits_2_in_place_of_serving_the_start_folder(
        typed: str, tmp_path: Path, monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]) -> None:
    monkeypatch.chdir(tmp_path)
    assert Path(typed).resolve().is_dir(), "the old folder test reads it as the start folder (the precondition)"
    code, served = _exit_of_main(["--root", typed], monkeypatch)
    err = capsys.readouterr().err
    assert code == 2 and served == [], "an empty or blank --root names no folder"
    assert _ROOT_LINE in err
    code, served = _exit_of_main(["--root", str(tmp_path / "missing")], monkeypatch)
    err = capsys.readouterr().err
    assert code == 2 and served == [] and _ROOT_LINE in err and "missing" not in err, "the control still exits 2"


# ---- W6: the root check compares the names on disk exactly, never through str.lower() ----------

_BENIGN = "# Date Formatter" + NL + "Formats a date. No tools." + NL

# Each pair: a root and a folder beside it whose name lower-cases onto the root name in Python
# (U+212A KELVIN SIGN to k, U+2126 OHM SIGN to U+03C9) while NTFS keeps the two names apart.
_LOOKALIKE_PAIRS = [
    pytest.param("r" + chr(0x212A), "rk", id="kelvin-sign-root"),
    pytest.param("rk", "r" + chr(0x212A), id="kelvin-sign-outside"),
    pytest.param("r" + chr(0x2126), "r" + chr(0x03C9), id="ohm-sign-root"),
]


@pytest.mark.parametrize("root_name,outside_name", _LOOKALIKE_PAIRS)
def test_a_folder_outside_the_root_whose_name_python_lower_cases_into_the_root_is_refused(
        root_name: str, outside_name: str, tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    base = tmp_path.resolve()
    root, outside, sibling = base / root_name, base / outside_name, base / "plain-sibling"
    for folder in (root, outside, sibling):
        folder.mkdir()
    (root / "INSIDE.md").write_text(_BENIGN, encoding="utf-8")
    (outside / "SKILL.md").write_text(_BENIGN, encoding="utf-8")
    (sibling / "SKILL.md").write_text(_BENIGN, encoding="utf-8")
    target = outside / "SKILL.md"
    assert not os.path.samefile(outside, root), "two folders on disk (the precondition)"
    assert all(str(parent) != str(root) for parent in target.parents), "the root holds no part of the outside file"
    if os.name == "nt":
        assert Path(outside) == Path(root), "the case-blind compare reads the two as one (the precondition)"
    monkeypatch.setattr(server, "_ROOT", root.resolve())
    monkeypatch.setattr(server, "_ROOT_AS_GIVEN", None)
    monkeypatch.chdir(root)
    for typed in (str(target), "../" + outside_name + "/SKILL.md"):
        body = server.dispatch("scan_skill_file", {"path": typed})
        assert [found["rule"] for found in body["findings"]] == ["path-outside-root"], (
            "a folder outside the root was read, verdict " + body["verdict"])
        for field in ("message", "evidence", "location"):
            assert typed not in body["findings"][0][field] and "SKILL.md" not in body["findings"][0][field]
    assert server.dispatch("scan_skill_file", {"path": str(root / "INSIDE.md")})["verdict"] == "PASS", (
        "a file inside the root is still read (the guard)")
    plain = server.dispatch("scan_skill_file", {"path": str(sibling / "SKILL.md")})
    assert [found["rule"] for found in plain["findings"]] == ["path-outside-root"], "a plain sibling is refused (the guard)"
