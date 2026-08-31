"""G9 and G11: the gates that keep this repo honest rather than merely working, and G-drift.

The credential and network gates BLOCK. The rest keep the craft and the eval numbers from
drifting from the code. This file is excluded from its own scans, because a guard that scans
itself necessarily trips on every string it forbids.
"""
from __future__ import annotations

import re
import subprocess
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
BINARY = {".png", ".jpg", ".jpeg", ".gif", ".pdf", ".zip", ".gz", ".ico", ".pyc"}

_DANGEROUS_CP = {0x200B, 0x200C, 0x200D, 0x2060, 0xFEFF,
                 0x202A, 0x202B, 0x202C, 0x202D, 0x202E, 0x2066, 0x2067, 0x2068, 0x2069}

# This guard scans every text file, INCLUDING itself. So its own needles are assembled from
# fragments and codepoints rather than written literally: a guard that banned em dashes while
# containing one, or that could not survive its own scan, would be the same broken-window the
# rest of this repo refuses to ship.


def _text_files() -> list[Path]:
    out = []
    for p in ROOT.rglob("*"):
        if not p.is_file():
            continue
        if any(part in {".git", "__pycache__", ".pytest_cache", ".venv"} for part in p.parts):
            continue
        if p.suffix.lower() not in BINARY:
            out.append(p)
    return out


CREDS = [
    re.compile(r"sk-ant-[A-Za-z0-9_\-]{20,}"),
    re.compile(r"\bgh[pousr]_[A-Za-z0-9]{30,}"),
    re.compile(r"\bAKIA[0-9A-Z]{16}\b"),
    re.compile(r"-----BEGIN [A-Z ]*PRIVATE KEY-----"),
]


def test_no_credential_shaped_strings() -> None:  # BLOCKS
    hits = []
    for f in _text_files():
        body = f.read_text(encoding="utf-8", errors="ignore")
        for pat in CREDS:
            if pat.search(body):
                hits.append(f.name)
    assert not hits, "credential-shaped strings: " + ", ".join(hits)


def test_no_outbound_network_in_the_core() -> None:  # BLOCKS
    """The scanner reads text. The core never reaches the network; only the optional judge may."""
    banned = ("requests.", "urllib.request", "httpx.", "socket.socket", "aiohttp")
    core = [p for p in (ROOT / "src").rglob("*.py") if p.name != "judge.py"]
    hits = []
    for f in core:
        body = f.read_text(encoding="utf-8")
        for token in banned:
            if token in body:
                hits.append(f"{f.name}: {token}")
    assert not hits, "network access in the deterministic core: " + "; ".join(hits)


def test_no_employer_identifying_content() -> None:  # BLOCKS
    # Assembled from fragments so this guard does not itself contain the strings it bans.
    banned = ("wells" + " fargo", "wells" + "fargo", "service" + "now", "share" + "point", "spl" + "unk")
    hits = []
    for f in _text_files():
        low = f.read_text(encoding="utf-8", errors="ignore").lower()
        for token in banned:
            if token in low:
                hits.append(f"{f.relative_to(ROOT)}")
    assert not hits, "employer-identifying content: " + ", ".join(hits)


def test_the_repo_ships_no_raw_invisible_bytes() -> None:  # BLOCKS - we do not ship what we detect
    offenders = []
    for f in _text_files():
        body = f.read_text(encoding="utf-8", errors="ignore")
        for c in body:
            cp = ord(c)
            if cp in _DANGEROUS_CP or 0xE0000 <= cp <= 0xE007F:
                offenders.append(f"{f.relative_to(ROOT)}: U+{cp:04X}")
                break
    assert not offenders, "raw invisible codepoints in the repo: " + "; ".join(offenders)


def test_hyphens_only_and_no_slop() -> None:
    # Needles assembled from fragments so this guard survives its own scan.
    slop = ("best in " + "class", "cutting" + "-edge", "seam" + "less", "leverage " + "the",
            "world" + "-class", "proven track " + "record", "del" + "ve", "revolution" + "iz",
            "game" + "-changer")
    dashes = {0x2012, 0x2013, 0x2014, 0x2015}  # figure, en, em, horizontal bar
    problems = []
    for f in _text_files():
        body = f.read_text(encoding="utf-8", errors="ignore")
        if any(ord(c) in dashes for c in body):
            problems.append(f"{f.relative_to(ROOT)}: em or en dash")
        low = body.lower()
        for s in slop:
            if s in low:
                problems.append(f"{f.relative_to(ROOT)}: {s!r}")
    assert not problems, "; ".join(problems)


def test_no_third_party_imports_in_core() -> None:
    allowed = {"__future__", "argparse", "base64", "binascii", "dataclasses", "json", "math",
               "os", "pathlib", "re", "sys", "typing", "unicodedata"}
    hits = []
    for f in (ROOT / "src").rglob("*.py"):
        for line in f.read_text(encoding="utf-8").splitlines():
            m = re.match(r"\s*(?:from|import)\s+([A-Za-z_][\w]*)", line)
            if m and not line.strip().startswith("from ."):
                mod = m.group(1)
                if mod not in allowed and mod != "skill_tripwire":
                    hits.append(f"{f.name}: {mod}")
    assert not hits, "unexpected import: " + "; ".join(hits)


def test_the_eval_report_regenerates_byte_identical() -> None:  # drift gate
    committed = ROOT / "eval" / "REPORT.md"
    assert committed.exists(), "run: python eval/run_eval.py --write"
    proc = subprocess.run(
        [sys.executable, str(ROOT / "eval" / "run_eval.py")],
        capture_output=True, text=True, timeout=60, cwd=str(ROOT),
    )
    assert proc.returncode == 0, proc.stderr
    assert proc.stdout == committed.read_text(encoding="utf-8"), (
        "eval/REPORT.md is stale. Regenerate it with: python eval/run_eval.py --write"
    )
