"""Orchestration: canonicalize, run the rules, aggregate to a fail-closed verdict.

The verdict is the worst finding's severity. Block dominates warn, warn dominates a clean
pass, and anything the scanner cannot read becomes QUARANTINE rather than passing by omission,
because a file the tool could not inspect is exactly the file you should not load blind.
"""
from __future__ import annotations

from dataclasses import dataclass
from pathlib import Path

from .canon import CanonResult, canonicalize
from .rules import Finding, run_rules

_ORDER = {"QUARANTINE": 2, "REVIEW": 1, "PASS": 0}
_TIER_VERDICT = {"block": "QUARANTINE", "warn": "REVIEW"}

# A scanner that parses attacker-controlled input needs a ceiling, or a crafted file is a
# denial of service: NFKC can expand text several-fold and every stage is linear in size. Five
# million characters is far above any real skill file and well below a cost that matters.
MAX_INPUT_BYTES = 5_000_000


def _too_large(size: int, where: str, surface: str) -> "ScanResult":
    return ScanResult(
        "QUARANTINE",
        (Finding("input-too-large", "block", "ASI:obfuscation",
                 f"Input is {size} bytes, over the {MAX_INPUT_BYTES}-byte limit, and was not "
                 "inspected. A file too large to scan safely fails closed.",
                 f"{size} bytes", where),),
        surface, None,
    )


@dataclass(frozen=True)
class ScanResult:
    verdict: str
    findings: tuple[Finding, ...]
    surface: str
    canon: CanonResult | None


def _verdict_of(findings: "list[Finding] | tuple[Finding, ...]") -> str:
    v = "PASS"
    for f in findings:
        # An unrecognized tier is an internal-invariant break; fail closed to QUARANTINE
        # rather than downgrading it to a REVIEW nobody may act on.
        cand = _TIER_VERDICT.get(f.tier, "QUARANTINE")
        if _ORDER[cand] > _ORDER[v]:
            v = cand
    return v


def scan(content: str, surface: str = "skill") -> ScanResult:
    if len(content) > MAX_INPUT_BYTES:
        return _too_large(len(content), "input", surface)
    canon = canonicalize(content)
    findings = run_rules(canon, surface)
    findings.sort(key=lambda f: 0 if f.tier == "block" else 1)
    return ScanResult(_verdict_of(findings), tuple(findings), surface, canon)


def scan_file(path: str | Path, surface: str = "skill") -> ScanResult:
    p = Path(path)
    try:
        size = p.stat().st_size
    except OSError as exc:
        return _unreadable(p, type(exc).__name__, surface)
    # Check size before reading, so an oversized file never reaches memory.
    if size > MAX_INPUT_BYTES:
        return _too_large(size, str(p.name), surface)
    try:
        content = p.read_text(encoding="utf-8")
    except (OSError, UnicodeDecodeError) as exc:
        return _unreadable(p, type(exc).__name__, surface)
    return scan(content, surface)


def _unreadable(p: Path, reason: str, surface: str) -> ScanResult:
    return ScanResult(
        "QUARANTINE",
        (Finding(
            "unreadable-file", "block", "ASI:obfuscation",
            f"The file could not be read as UTF-8 text ({reason}); a config file that "
            "will not decode is not one to load blind.",
            reason, str(p.name),
        ),),
        surface, None,
    )
