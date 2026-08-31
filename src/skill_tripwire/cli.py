"""Command line: scan a file before you install it, with the verdict in the exit code.

    skill-tripwire scan path/to/SKILL.md        # human summary, exit 0/1/2
    skill-tripwire scan --json path/to/tool.json

PASS exits 0, REVIEW exits 1, QUARANTINE exits 2, so this drops into a pre-commit hook or a
CI step with no output parsing.
"""
from __future__ import annotations

import argparse
import json
import sys

from . import report
from .scan import scan_file


def main(argv: list[str] | None = None) -> int:
    ap = argparse.ArgumentParser(
        prog="skill-tripwire",
        description="Scan an agent skill or config file for the shapes of poisoned instructions.",
    )
    sub = ap.add_subparsers(dest="command", required=True)
    scan_p = sub.add_parser("scan", help="scan a file and report a verdict")
    scan_p.add_argument("path", help="path to a SKILL.md, MCP tool JSON, or CLAUDE.md/AGENTS.md")
    scan_p.add_argument("--json", action="store_true", help="emit a JSON object instead of text")
    scan_p.add_argument("--surface", default="skill",
                        choices=["skill", "mcp-tool", "agent-config"],
                        help="what kind of file this is (affects nothing yet; reserved)")
    ns = ap.parse_args(argv)

    result = scan_file(ns.path, surface=ns.surface)
    if ns.json:
        sys.stdout.write(json.dumps(report.to_dict(result), indent=2) + "\n")
    else:
        sys.stdout.write(report.to_text(result) + "\n")
    return report.EXIT_CODE[result.verdict]


if __name__ == "__main__":
    raise SystemExit(main())
