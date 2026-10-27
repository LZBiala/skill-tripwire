# Changelog

## Unreleased

- eval: a pre-registered live-judge study on the same 60-sample corpus (tools/judge_live.py, 22 tests, raw record and report under eval/), published as a partial run with the two refused ids named; the README links it with the caveat in the same sentence and a test pins the README's figures to the report.
- security: the composite Action takes its inputs through env only (no expression inside a run script), checks fail-on against review or quarantine before use (exit 3 otherwise) and splits paths on spaces, tabs or line ends with no shell expansion, passed after `--`: quotes, escapes, variables, `~`, braces and globs in paths are now literal (so a path holding a space cannot be named), an option word is a path, and a paths list may put one path on each line; CI runs with a read-only token, pins actions/checkout and actions/setup-python by full commit SHA, and its Action step no longer hides a failure; tools/judge_live.py calls the CLI with every built-in tool off and no MCP server (the 2026-09 run predates both flags) and refuses a .cmd or .bat launcher, which cmd.exe would re-parse; the MCP server reads a path only inside the folder it started in or the one named by `--root`, checks the text before any file system call and then resolves that same text, refuses any other with a QUARANTINE naming the rule, shows a file's location from the root, and ignores arguments other than `--root` with a line saying so; on Windows a UNC or device spelling, one that starts with two slashes or backslashes or with the NT prefix (a backslash, two question marks and a backslash, each slash read as a backslash), is never stat-ed: as a `path` it is refused under any root, a drive root too, and as a one-line `content` it now reads REVIEW path-as-content, where master's stat of it opened an SMB connection with the caller's NTLM credentials; evidence masks credential-shaped runs, keeping the class and the length (a UUID-shaped run among them, so a UUID that is no secret is masked too; a run holding / or - only above a higher spread floor, so URL paths and hyphenated names still show, and so does any other run of hex digits and hyphens, a key- prefix on 32 hex digits among them, which never reaches that floor). No version bump and no tag: the published v0.1.1 Action keeps its old run lines until a new tag.

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
