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


@dataclass(frozen=True)
class ScanResult:
    verdict: str
    findings: tuple[Finding, ...]
    surface: str
    canon: CanonResult | None


def _verdict_of(findings: list[Finding]) -> str:
    v = "PASS"
    for f in findings:
        # An unrecognized tier is an internal-invariant break; fail closed to QUARANTINE
        # rather than downgrading it to a REVIEW nobody may act on.
        cand = _TIER_VERDICT.get(f.tier, "QUARANTINE")
        if _ORDER[cand] > _ORDER[v]:
            v = cand
    return v


def scan(content: str, surface: str = "skill") -> ScanResult:
    canon = canonicalize(content)
    findings = run_rules(canon, surface)
    findings.sort(key=lambda f: 0 if f.tier == "block" else 1)
    return ScanResult(_verdict_of(findings), tuple(findings), surface, canon)


def scan_file(path: str | Path, surface: str = "skill") -> ScanResult:
    p = Path(path)
    try:
        content = p.read_text(encoding="utf-8")
    except (OSError, UnicodeDecodeError) as exc:
        reason = type(exc).__name__
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
    return scan(content, surface)
