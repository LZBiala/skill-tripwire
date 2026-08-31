"""The detection rules, split into two tiers by their false-positive economics.

Block-tier rules hunt shapes with no legitimate use in a config file: invisible codepoints,
download-and-execute one-liners, shell that runs before the model's defenses, an unrestricted
shell grant on a narrow skill, and a read-then-send-it-out instruction. These can raise
QUARANTINE because their false-positive rate is near zero by construction.

Warn-tier rules hunt shapes that are suspicious but also occur in honest files: agent-directed
imperative phrasing, and opaque high-entropy blobs. These can only ever raise REVIEW, because
at the ~2% real-world base rate a noisy rule that hard-blocks destroys more trust than it
saves. The eval report publishes each rule's measured precision and recall so this split is a
tested claim, not an assertion.
"""
from __future__ import annotations

import math
import re
import unicodedata
from dataclasses import dataclass

from .canon import CanonResult


@dataclass(frozen=True)
class Finding:
    rule_id: str
    tier: str  # "block" | "warn"
    owasp: str
    message: str
    evidence: str
    location: str


def _defang(s: str, limit: int = 80) -> str:
    """Trim and neutralize a matched shape for safe display in a report or a client.

    A scanner echoes attacker-controlled text back as evidence, so that text is sanitized
    before it leaves: control characters are removed, not shown, because a raw ESC in a
    matched span would be a terminal-escape-injection channel through the scanner's own
    output, and the same bytes handed to a calling agent are untrusted content. Newlines and
    tabs become visible markers; every other C-category codepoint is dropped.
    """
    s = s.replace("\n", "\\n").replace("\r", "\\r").replace("\t", " ")
    s = "".join(ch for ch in s if unicodedata.category(ch) not in {"Cc", "Cf", "Co"})
    s = s.strip()
    if len(s) > limit:
        s = s[:limit] + "..."
    return s


# --------------------------------------------------------------------------- block tier

def _rule_invisible_codepoints(canon: CanonResult, surface: str) -> list[Finding]:
    if not canon.invisibles:
        return []
    classes = sorted({inv.category for inv in canon.invisibles})
    sample = canon.invisibles[0]
    return [Finding(
        "invisible-codepoints", "block", "ASI:hidden-instructions",
        f"{canon.invisible_count} invisible codepoint(s) ({', '.join(classes)}) - "
        "these render as nothing to a human but are read by the model.",
        _defang(f"{sample.name} at canonical offset {sample.offset}"),
        f"canonical offset {sample.offset}",
    )]


_EXEC = re.compile(
    r"""(?ix)
    # 1) a web fetch piped into a shell (curl|bash and the PowerShell fetch family)
    (?: curl|wget|iwr|invoke-webrequest|irm|invoke-restmethod )
    [^\n`]{0,200}? \| \s*
    (?: bash|sh|zsh|iex|invoke-expression|python\d? )
    |
    # 2) a decode piped into a shell
    (?: base64\s+-d|xxd\s+-r|openssl\s+enc ) [^\n`]{0,60}? \| \s* (?: bash|sh|python\d? )
    |
    # 3) functional Invoke-Expression wrapped around a web fetch (iex(irm ...), iex (iwr ...),
    #    IEX (New-Object ...).DownloadString(...)) - the no-pipe PowerShell cradle
    (?: iex|invoke-expression ) \s* \(? \s*
    (?: iwr|irm|invoke-\w+|curl|wget|new-object [^\n`]{0,60}? downloadstring )
    |
    # 4) a web fetch feeding iex in the other order
    (?: iwr|irm|invoke-webrequest|invoke-restmethod|curl|wget ) [^\n`]{0,200}? \| \s* iex
    |
    # 5) process or command substitution executed by a shell (source <(curl ...), bash <(...))
    (?: source|\.|bash|sh|zsh ) \s+ <\( \s* (?: curl|wget|iwr|irm )
    |
    # 6) eval of a command substitution that fetches (eval "$(curl ...)", eval `wget ...`)
    eval \s+ ["']? [$`] \(? [^\n`]{0,120}? (?: curl|wget|iwr|irm )
    |
    # 7) staged fetch to disk then run it (curl -o x && bash x, iwr -OutFile p ; ./p)
    (?: curl|wget|iwr|irm|invoke-webrequest|invoke-restmethod )
    [^\n`]{0,150}? (?: -o|-O|-outfile )\b [^\n`]{0,80}? (?: &&|;|\|\| ) [^\n`]{0,60}?
    (?: bash|sh|zsh|python\d?|node|source|iex|\./|\.\\ )
    |
    # 8) a Python interpreter running fetched code inline (python -c ... urlopen ... exec)
    python\d? \s+ -c\b [^\n`]{0,200}? (?: urlopen|urllib|requests|socket|http )
    [^\n`]{0,120}? (?: exec|eval|system|popen )
    |
    # 9) a Node interpreter running fetched code inline (node -e ... fetch ... eval)
    node \s+ -e\b [^\n`]{0,200}? fetch [^\n`]{0,120}? (?: eval|exec|function )
    """,
)


def _rule_download_and_execute(canon: CanonResult, surface: str) -> list[Finding]:
    m = _EXEC.search(canon.scan_text)
    if not m:
        return []
    return [Finding(
        "download-and-execute", "block", "ASI:code-execution",
        "A download-and-execute one-liner pipes fetched content straight into a shell.",
        _defang(m.group(0)), f"canonical offset {m.start()}",
    )]


_PRE_EXEC = re.compile(r"""(?m)^[^\n]*:\s*!`[^`]+`""")  # frontmatter value of the form  key: !`cmd`


def _rule_pre_execution_shell(canon: CanonResult, surface: str) -> list[Finding]:
    m = _PRE_EXEC.search(canon.text)
    if not m:
        return []
    return [Finding(
        "pre-execution-shell", "block", "ASI:code-execution",
        "Dynamic shell in front matter runs when the skill is rendered, before the model's "
        "injection defenses ever see it.",
        _defang(m.group(0)), f"front matter, canonical offset {m.start()}",
    )]


# Scope the capability scan to the first fenced front-matter block when one exists, so prose
# that merely mentions "allowed-tools: Bash" does not trigger a false quarantine. When there is
# no front matter (a bare config), fall back to the whole text so coverage still fails closed.
_FRONTMATTER = re.compile(r"(?s)\A\s*---[ \t]*\n(.*?)\n---[ \t]*(?:\n|\Z)")
_ALLOWED_TOOLS = re.compile(r"(?im)^allowed-tools[ \t]*:[ \t]*(.*)$")
_LIST_ITEM = re.compile(r"^[ \t]*-[ \t]*(.+?)[ \t]*$")
# A shell-granting tool token, optionally followed by its (scope). A token with no scope is a
# full shell grant; a scope of () or (*) is a wildcard grant; a scope like (git diff) is narrow.
_SHELL_TOKEN = re.compile(r"(?i)\b(bash|shell|exec|execute|terminal|run_command)\b([ \t]*\([^)]*\))?")


def _grant_text(text: str, m: re.Match) -> str:
    """The granted tools: the same-line value, or the following indented list if that is empty."""
    same = m.group(1).strip()
    if same:
        return same
    items = []
    for line in text[m.end():].splitlines():
        li = _LIST_ITEM.match(line)
        if li:
            items.append(li.group(1))
        elif line.strip() == "":
            continue
        else:
            break
    return ", ".join(items)


def _rule_broad_shell_capability(canon: CanonResult, surface: str) -> list[Finding]:
    fm = _FRONTMATTER.match(canon.text)
    scope_text = fm.group(1) if fm else canon.text
    # Iterate EVERY allowed-tools key, not just the first: a benign 'allowed-tools: Read' line
    # must not shadow a later 'allowed-tools: Bash(*)'.
    for m in _ALLOWED_TOOLS.finditer(scope_text):
        grant = _grant_text(scope_text, m)
        for tm in _SHELL_TOKEN.finditer(grant):
            scope = tm.group(2)
            inner = scope.strip()[1:-1].strip() if scope else None
            broad = inner is None or inner in ("", "*")  # bare token, or (), or (*)
            if broad:
                return [Finding(
                    "broad-shell-capability", "block", "ASI:excessive-capability",
                    "The skill grants unrestricted shell access. A narrow skill has no reason to.",
                    _defang(f"allowed-tools: {grant}"), "front matter",
                )]
    return []


_SECRET = r"(?:~/\.\w+|/etc/\w+|\bid_rsa\b|\btoken\b|\bsecret\b|\bkey\b|\benv\b|credentials)"
_EXFIL = re.compile(
    r"""(?ix)
    # read a secret, then send it to an http(s) URL
    (?:read|cat|contents?\s+of|send|post|upload|exfiltrate|leak)
    [^\n]{0,120}? """ + _SECRET + r""" [^\n]{0,120}? https?://[^\s`)]+
    |
    # send/post/upload ... to an http(s) URL
    (?:send|post|upload|exfiltrate)[^\n]{0,60}?\bto\b[^\n]{0,20}?https?://[^\s`)]+
    |
    # read a secret, then send it to an email address (gated on the secret so a plain "email
    # the report to team@x" stays clean)
    (?:read|cat|contents?\s+of|send|post|upload|email|exfiltrate|leak)
    [^\n]{0,120}? """ + _SECRET + r""" [^\n]{0,120}? [\w.+\-]+@[\w.\-]+\.\w+
    """,
)


def _rule_exfiltration(canon: CanonResult, surface: str) -> list[Finding]:
    m = _EXFIL.search(canon.scan_text)
    if not m:
        return []
    return [Finding(
        "exfiltration", "block", "ASI:data-exfiltration",
        "An instruction to read sensitive data and send it to an external URL.",
        _defang(m.group(0)), f"canonical offset {m.start()}",
    )]


# ---------------------------------------------------------------------------- warn tier

_IMPERATIVE = re.compile(
    r"""(?ix)
    ignore\s+(?:all\s+)?(?:previous|prior|above)\s+instructions
    | disregard\s+(?:all\s+)?(?:previous|prior|the\s+above)
    | do\s+not\s+(?:tell|mention|inform|reveal|disclose)[^\n]{0,40}?(?:user|human|operator)
    | without\s+(?:telling|informing|alerting)[^\n]{0,20}?(?:the\s+)?user
    | (?:you\s+are\s+now|from\s+now\s+on\s+you)\b
    | (?:system\s+override|admin\s+override|developer\s+mode)
    | this\s+is\s+(?:an?\s+)?(?:approved|trusted|official)\s+(?:skill|instruction|command)
    """,
)


def _rule_imperative_to_agent(canon: CanonResult, surface: str) -> list[Finding]:
    m = _IMPERATIVE.search(canon.scan_text)
    if not m:
        return []
    return [Finding(
        "imperative-to-agent", "warn", "ASI:social-engineering",
        "Phrasing aimed at the agent rather than the user (jailbreak or authority framing).",
        _defang(m.group(0)), f"canonical offset {m.start()}",
    )]


def _shannon(token: str) -> float:
    if not token:
        return 0.0
    counts: dict[str, int] = {}
    for c in token:
        counts[c] = counts.get(c, 0) + 1
    n = len(token)
    return -sum((c / n) * math.log2(c / n) for c in counts.values())


def _rule_high_entropy_blob(canon: CanonResult, surface: str) -> list[Finding]:
    for token in re.split(r"\s+", canon.text):
        if len(token) >= 40 and _shannon(token) >= 4.5:
            return [Finding(
                "high-entropy-blob", "warn", "ASI:obfuscation",
                "A long, high-entropy token that did not decode to text - an opaque blob in a "
                "config file is worth a human look.",
                _defang(token, 48), "matched in canonical text",
            )]
    return []


_RULES = (
    _rule_invisible_codepoints,
    _rule_download_and_execute,
    _rule_pre_execution_shell,
    _rule_broad_shell_capability,
    _rule_exfiltration,
    _rule_imperative_to_agent,
    _rule_high_entropy_blob,
)

# For the coverage gate: every rule id this module can emit, with its tier and owasp id.
RULE_REGISTRY = {
    "invisible-codepoints": ("block", "ASI:hidden-instructions"),
    "download-and-execute": ("block", "ASI:code-execution"),
    "pre-execution-shell": ("block", "ASI:code-execution"),
    "broad-shell-capability": ("block", "ASI:excessive-capability"),
    "exfiltration": ("block", "ASI:data-exfiltration"),
    "imperative-to-agent": ("warn", "ASI:social-engineering"),
    "high-entropy-blob": ("warn", "ASI:obfuscation"),
}


def run_rules(canon: CanonResult, surface: str = "skill") -> list[Finding]:
    findings: list[Finding] = []
    for rule in _RULES:
        findings.extend(rule(canon, surface))
    return findings
