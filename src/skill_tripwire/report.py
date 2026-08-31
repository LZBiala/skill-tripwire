"""Turn a ScanResult into the two shapes callers need: a JSON object and a human summary."""
from __future__ import annotations

from typing import Any

from .scan import ScanResult

EXIT_CODE = {"PASS": 0, "REVIEW": 1, "QUARANTINE": 2}


def to_dict(result: ScanResult) -> dict[str, Any]:
    return {
        "verdict": result.verdict,
        "surface": result.surface,
        "findings": [
            {
                "rule": f.rule_id,
                "tier": f.tier,
                "owasp": f.owasp,
                "message": f.message,
                "evidence": f.evidence,
                "location": f.location,
            }
            for f in result.findings
        ],
        "invisibles_removed": len(result.canon.invisibles) if result.canon else 0,
        "blobs_decoded": len(result.canon.decodings) if result.canon else 0,
    }


def to_text(result: ScanResult) -> str:
    lines = [f"verdict: {result.verdict}  ({result.surface})"]
    if not result.findings:
        lines.append("  no findings")
    for f in result.findings:
        lines.append(f"  [{f.tier.upper()}] {f.rule_id} ({f.owasp}) - {f.location}")
        lines.append(f"      {f.message}")
        lines.append(f"      evidence: {f.evidence}")
    return "\n".join(lines)
