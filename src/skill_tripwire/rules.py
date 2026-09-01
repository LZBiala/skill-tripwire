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
    # 1) a web fetch piped straight into a shell (the \b stops "| sha256sum" matching "| sh")
    (?: curl|wget|iwr|invoke-webrequest|irm|invoke-restmethod )
    [^\n`]{0,200}? \| \s*
    (?: bash|sh|zsh|iex|invoke-expression )\b
    |
    # 2) a decode piped into a shell
    (?: base64\s+-d|xxd\s+-r|openssl\s+enc ) [^\n`]{0,60}? \| \s* (?: bash|sh|python\d? )\b
    |
    # 3) functional Invoke-Expression wrapped around a web fetch (iex(irm ...), iex (iwr ...),
    #    IEX (New-Object ...).DownloadString(...)) - the no-pipe PowerShell cradle
    (?: iex|invoke-expression ) \s* \(? \s*
    (?: iwr|irm|invoke-\w+|curl|wget|new-object [^\n`]{0,60}? downloadstring )
    |
    # 4) a web fetch feeding iex in the other order
    (?: iwr|irm|invoke-webrequest|invoke-restmethod|curl|wget ) [^\n`]{0,200}? \| \s* iex\b
    |
    # 5) process or command substitution executed by a shell (source <(curl ...), bash <(...))
    (?: source|\.|bash|sh|zsh ) \s+ <\( \s* (?: curl|wget|iwr|irm )
    |
    # 6) eval of a command substitution that fetches (eval "$(curl ...)", eval `wget ...`)
    eval \s+ ["']? [$`] \(? [^\n`]{0,120}? (?: curl|wget|iwr|irm )
    |
    # 7) staged fetch to disk then run THAT FILE (curl -o x && bash x). A backreference to the
    #    downloaded name is required, so "curl -o data.csv && python analyze.py data.csv" (a
    #    local script reading downloaded DATA) does not match.
    (?: curl|wget|iwr|irm|invoke-webrequest|invoke-restmethod )
    [^\n`]{0,150}? (?: -o|-O|-outfile )[ \t]+ (?P<dl>[^\s`;&|]+)
    [^\n`]{0,80}? (?: &&|;|\|\| ) [^\n`]{0,20}?
    (?: (?: bash|sh|zsh|source|iex )[ \t]+ (?:\./)? (?P=dl)\b | \./(?P=dl)\b )
    |
    # 8) a Python interpreter running fetched code inline (python -c ... urlopen ... exec()).
    #    exec/eval require a call paren, so "urlopen('.../evals/latest')" does not match on "eval".
    python\d? \s+ -c\b [^\n`]{0,200}? (?: urlopen|urllib|requests|socket )
    [^\n`]{0,120}? (?: \bexec\s*\(|\beval\s*\(|os\.system|\bpopen\s*\( )
    |
    # 9) a Node interpreter running fetched code inline (node -e ... fetch ... eval). The bare
    #    Function constructor or a passed eval reference is the vector; a plain function() callback
    #    is not.
    node \s+ -e\b [^\n`]{0,200}? fetch [^\n`]{0,120}? (?: \beval\b|\bexec\b|new\s+function\s*\( )
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
_YAML_COMMENT = re.compile(r"\s+#.*$")
# One granted tool entry: a bare identifier and an optional (scope). A whole-entry match, so a
# longer name like "execute-cell" or "run_terminal_cmd" is never mistaken for a shell word.
_TOOL_ENTRY = re.compile(r"^([A-Za-z0-9_]+)[ \t]*(?:\(([^)]*)\))?$")
# Actual shell interpreters. A bare grant of one of these, or a wildcard scope, is unrestricted.
_SHELL_WORDS = {"bash", "sh", "zsh", "shell", "powershell", "pwsh"}


def _grant_entries(text: str, m: re.Match) -> list[str]:
    """The granted tool entries: the same-line value, or the following indented list. YAML
    end-of-line comments are stripped so a comment's words are not read as a grant."""
    same = _YAML_COMMENT.sub("", m.group(1)).strip()
    raw = same
    if not same:
        items = []
        for line in text[m.end():].splitlines():
            li = _LIST_ITEM.match(line)
            if li:
                items.append(_YAML_COMMENT.sub("", li.group(1)).strip())
            elif line.strip() == "":
                continue
            else:
                break
        raw = ", ".join(items)
    return [e.strip() for e in raw.split(",") if e.strip()]


def _is_broad_shell(entry: str) -> bool:
    em = _TOOL_ENTRY.match(entry)
    if not em:
        return False  # not a bare tool name (e.g. "execute-cell"); cannot be a bare shell grant
    base, scope = em.group(1).lower(), em.group(2)
    if base not in _SHELL_WORDS:
        return False
    return scope is None or scope.strip() in ("", "*")  # bare, (), or (*) is unrestricted


def _rule_broad_shell_capability(canon: CanonResult, surface: str) -> list[Finding]:
    fm = _FRONTMATTER.match(canon.text)
    scope_text = fm.group(1) if fm else canon.text
    # Iterate EVERY allowed-tools key, not just the first: a benign 'allowed-tools: Read' line
    # must not shadow a later 'allowed-tools: Bash(*)'.
    for m in _ALLOWED_TOOLS.finditer(scope_text):
        for entry in _grant_entries(scope_text, m):
            if _is_broad_shell(entry):
                return [Finding(
                    "broad-shell-capability", "block", "ASI:excessive-capability",
                    "The skill grants unrestricted shell access. A narrow skill has no reason to.",
                    _defang(f"allowed-tools: {entry}"), "front matter",
                )]
    return []


# A secret is a specific, sensitive source - not a bare "key" or "env", which appear in
# "key features" and "env vars" all over honest docs. The narrow forms ("api key", ".env file")
# are what real exfil instructions actually say.
_SECRET = (r"(?:~/\.\w+|/etc/\w+|\bid_rsa\b|\b(?:api|ssh|private|secret|access|gpg)[ -]?key\b|"
           r"\btoken\b|\bcredentials?\b|\.env\b|\benv\s+(?:file|var)|\bsecrets?\b)")
# A sensitive data object for the no-secret-keyword branch: things whose exfil is alarming even
# without a credential. Deliberately excludes "results/output/logs", which are posted benignly.
_SENSITIVE = r"(?:conversation|clipboard|credentials?|secrets?|keychain|\.env|password)"
_EMAIL = r"[\w.+\-]+@[\w.\-]+\.[A-Za-z]{2,}"
_VCS_HOSTS = re.compile(r"(?i)@(?:github|gitlab|bitbucket)\.")
_EXFIL = re.compile(
    r"""(?ix)
    # A) read a secret, then send it to an http(s) URL
    \b(?:read|cat|contents?\s+of|send|post|upload|exfiltrate|leak|dump)\b
    [^\n]{0,120}? """ + _SECRET + r""" [^\n]{0,120}? https?://[^\s`)]+
    |
    # B) exfiltrate/leak to a URL (inherently hostile verbs, ungated)
    \b(?:exfiltrate|leak)\b [^\n]{0,80}? \bto\b [^\n]{0,20}? https?://[^\s`)]+
    |
    # B2) send a sensitive data object to a URL (gated on the object, not a generic verb)
    \b(?:send|post|upload|dump|email)\b [^\n]{0,100}? \b""" + _SENSITIVE + r"""\b
    [^\n]{0,100}? https?://[^\s`)]+
    |
    # C) read a secret, then email it (read-type verb, alphabetic TLD; VCS remotes filtered out)
    \b(?:read|cat|dump|exfiltrate|leak|contents?\s+of)\b
    [^\n]{0,120}? """ + _SECRET + r""" [^\n]{0,120}? \b(?:email|send|to)\b [^\n]{0,40}? """ + _EMAIL + r"""
    """,
)


def _rule_exfiltration(canon: CanonResult, surface: str) -> list[Finding]:
    m = _EXFIL.search(canon.scan_text)
    if not m:
        return []
    hit = m.group(0)
    # A secret near a VCS remote (git@github.com) with no http URL is a clone instruction, not
    # exfil: no attacker emails a secret to github.com.
    if "@" in hit and "http" not in hit.lower() and _VCS_HOSTS.search(hit):
        return []
    return [Finding(
        "exfiltration", "block", "ASI:data-exfiltration",
        "An instruction to read sensitive data and send it to an external URL.",
        _defang(hit), f"canonical offset {m.start()}",
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
    # Agent-subversion shapes from a documented real incident (agents falsifying transcripts,
    # evading their grader, coordinating covertly, persisting). Verb-gated so the everyday senses
    # ("format a transcript", "package the results", "monitor the queue") do not trip.
    | \b(?:falsify|spoof|forge|fabricate|tamper\s+with)\b[^\n]{0,30}?\b(?:logs?|transcripts?|audit|records?|tool\s+(?:call|output))\b
    | \b(?:disable|bypass|circumvent|defeat|turn\s+off)\b[^\n]{0,30}?\b(?:monitor|grader|scorer|safety|guardrail|tripwire|oversight|sandbox)\b
    | \b(?:evade|avoid|escape)\s+detection\b
    | \breverse[-\s]engineer\b[^\n]{0,20}?\b(?:scorer|grader|scoring|benchmark|evaluation)\b
    # covert coordination channel: gated on a coordination purpose so a benign "encode the
    # version in the package name" (a normal convention) does not trip.
    | \b(?:encode|hide|smuggle)\b[^\n]{0,60}?\b(?:directory|folder|package)\s*names?\b[^\n]{0,40}?\b(?:agents?|collective|swarm|message|channel|covert|instances?)\b
    | \b(?:establish|gain|achieve)\s+(?:persistence|admin\s+access|root\s+access|remote\s+code)\b
    | \b(?:self[-\s]respawn|move\s+laterally)\b
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


# Structured tokens that legitimately look high-entropy and carry no instructions: a JWT (three
# dot-separated base64url segments) and a Subresource Integrity hash. A payload disguised as one
# still gets caught, because canon decodes base64 and re-scans the plaintext.
_JWT = re.compile(r"^[A-Za-z0-9_\-]+\.[A-Za-z0-9_\-]+\.[A-Za-z0-9_\-]+$")
_SRI = re.compile(r"^sha(?:256|384|512)-")


def _rule_high_entropy_blob(canon: CanonResult, surface: str) -> list[Finding]:
    # Spans that already decoded to text are scanned as their plaintext; flagging the raw blob
    # too is redundant noise.
    decoded_spans = [d.span for d in canon.decodings]
    for m in re.finditer(r"\S+", canon.text):
        token = m.group(0)
        if len(token) < 40 or _shannon(token) < 4.5:
            continue
        if _JWT.match(token) or _SRI.match(token):
            continue
        if "://" in token:
            continue  # a URL is structured text, not the opaque blob this warn targets; a
            # malicious URL is still caught by the block-tier download-and-execute / exfil rules
        if any(s <= m.start() < e for s, e in decoded_spans):
            continue
        return [Finding(
            "high-entropy-blob", "warn", "ASI:obfuscation",
            "A long, high-entropy token that did not decode to text - an opaque blob in a "
            "config file is worth a human look.",
            _defang(token, 48), f"canonical offset {m.start()}",
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
