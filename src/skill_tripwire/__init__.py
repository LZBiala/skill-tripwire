"""skill-tripwire: a fail-closed scanner for poisoned agent skill and config files.

The core is deterministic, stdlib-only, keyless, and network-free. It is a measured
triage floor, never a boundary: static detection collapses under payload-preserving
obfuscation, and this package says so with numbers. See README.md and eval/REPORT.md.
"""
__version__ = "0.1.0"
