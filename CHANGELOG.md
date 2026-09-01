# Changelog

All notable changes to skill-tripwire are recorded here. The published numbers in the README
and eval/ are regenerated in CI, so this file tracks capability and interface changes, not
metrics.

## 0.1.1 - 2026-08-31

### Added
- Incident-grounded detection rules (agent-subversion taxonomy: transcript falsification,
  monitor evasion, covert coordination, persistence, evade-detection), warn-tier.
- A 1,000,000-input seeded robustness simulation (`tools/simulate.py`, `eval/SIMULATION.md`):
  0 crashes, 0 hangs, 0 false positives on 450,360 generated benign files, reproducible from a
  fixed seed.
- `GEMINI.md` covered by the pre-commit hook, matching the CLI directory walk.
- CI now exercises the integration surface: `pip install`, the console scripts, and the
  composite Action itself.
- A cross-file drift gate: the README must quote the simulation's own benign count, and its
  headline example block must reproduce the live scan output.

### Fixed
- README benign-file count corrected (450,346 -> 450,360) and gated.
- README example output block regenerated to match the current scanner.
- The GitHub Action snippet now shows `actions/checkout` first: without it the workspace is
  empty and the gate passes green while scanning nothing.
- The MCP setup section now names the destination config file per client.

## 0.1.0 - 2026-08-30

- First public release: fail-closed, stdlib-only scanner for poisoned agent config files
  (SKILL.md, MCP tool descriptions, CLAUDE.md/AGENTS.md); CLI + MCP stdio server + optional
  off-by-default fenced LLM judge. Published detection and false-positive rates with misses
  on the scorecard.
