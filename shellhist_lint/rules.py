"""Lint rules.

Each rule is a plain function: Command -> list[Finding]. That keeps adding
a new check to "write a function, append it to RULES" instead of growing a
class hierarchy nobody needs yet.
"""

from __future__ import annotations

import re
from dataclasses import dataclass

from .reader import Command


@dataclass
class Finding:
    lineno: int
    rule_id: str
    message: str
    snippet: str


# A var assignment whose name looks credential-ish and whose value is a
# literal (quoted or not) rather than a substitution like $VAR or ${VAR}.
# This will miss secrets built from string concatenation and will flag the
# occasional false positive (a var named "password_prompt" with real text)
# -- it's a heuristic, not a proof.
_SECRET_ASSIGNMENT_RE = re.compile(
    r"""(?ix)
    \b (?:api[_-]?key | secret | token | password | passwd | pwd)
    [a-z0-9_]* \s* = \s*
    (['"]?) (?!\$) (?!\{) \S{4,} \1
    """
)

_RM_RE = re.compile(r"\brm\b")
_RM_RF_FLAG_RE = re.compile(
    r"(?:^|\s)-[a-zA-Z]*r[a-zA-Z]*f[a-zA-Z]*(?:\s|$)"
    r"|(?:^|\s)-[a-zA-Z]*f[a-zA-Z]*r[a-zA-Z]*(?:\s|$)"
    r"|--recursive\b.*--force\b"
    r"|--force\b.*--recursive\b"
)
_DANGEROUS_TARGET_RE = re.compile(r"(?:^|\s)(/|~|~/\S*|\$HOME\S*|/\*|--no-preserve-root)(?:\s|$)")

_PIPE_TO_SHELL_RE = re.compile(r"\b(curl|wget)\b[^|]*\|\s*(sudo\s+)?(sh|bash|zsh)\b")

_CHMOD_777_RE = re.compile(r"\bchmod\s+(-R\s+)?0?777\b")


def rule_plaintext_secret(cmd: Command) -> list[Finding]:
    if _SECRET_ASSIGNMENT_RE.search(cmd.text):
        return [
            Finding(
                cmd.lineno,
                "secret-in-history",
                "possible plaintext credential in a shell variable assignment",
                cmd.text.strip(),
            )
        ]
    return []


def rule_dangerous_rm(cmd: Command) -> list[Finding]:
    text = cmd.text
    if _RM_RE.search(text) and _RM_RF_FLAG_RE.search(text) and _DANGEROUS_TARGET_RE.search(text):
        return [
            Finding(
                cmd.lineno,
                "dangerous-rm",
                "rm -rf against an absolute path, home directory, or with --no-preserve-root",
                text.strip(),
            )
        ]
    return []


def rule_pipe_to_shell(cmd: Command) -> list[Finding]:
    if _PIPE_TO_SHELL_RE.search(cmd.text):
        return [
            Finding(
                cmd.lineno,
                "curl-pipe-shell",
                "downloading a script and piping it straight into a shell",
                cmd.text.strip(),
            )
        ]
    return []


def rule_chmod_777(cmd: Command) -> list[Finding]:
    if _CHMOD_777_RE.search(cmd.text):
        return [
            Finding(
                cmd.lineno,
                "chmod-777",
                "chmod 777 grants world write access",
                cmd.text.strip(),
            )
        ]
    return []


RULES = [
    rule_plaintext_secret,
    rule_dangerous_rm,
    rule_pipe_to_shell,
    rule_chmod_777,
]


def lint_command(cmd: Command) -> list[Finding]:
    findings: list[Finding] = []
    for rule in RULES:
        findings.extend(rule(cmd))
    return findings
