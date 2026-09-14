"""Streaming parsers for shell history files.

Bash and zsh write a few different on-disk formats depending on shell
options (plain, bash with HISTTIMEFORMAT comments, zsh's ": start:elapsed;"
extended format). All three parsers below pull one physical line at a time
from the input and only ever hold the lines belonging to the *current*
logical command in memory. A multi-gigabyte history file never gets loaded
whole, which matters because these files are append-only and some people
have been typing into the same one for a decade.
"""

from __future__ import annotations

import re
from dataclasses import dataclass
from typing import IO, Iterator, Optional

_ZSH_EXTENDED_RE = re.compile(r"^: (\d+):(\d+);(.*)$")
_BASH_TIMESTAMP_RE = re.compile(r"^#(\d+)$")


@dataclass
class Command:
    """One logical history entry, possibly spanning several source lines."""

    lineno: int  # line the entry starts on (1-based)
    text: str  # the command, with embedded newlines if it was multi-line
    timestamp: Optional[int] = None


def iter_commands(stream: IO[str], style: str = "auto") -> Iterator[Command]:
    """Yield Command objects from an open, line-iterable text stream.

    style is one of "auto", "plain", "bash-timestamp", "zsh-extended".
    "auto" looks at the first non-blank line to pick a parser and then
    sticks with it for the rest of the stream.
    """
    numbered = _numbered_lines(stream)
    lineno = None
    first = None
    for n, line in numbered:
        if line.strip():
            lineno, first = n, line
            break
    if first is None:
        return

    if style == "auto":
        style = _detect_style(first)

    rest = _prepend(lineno, first, numbered)
    if style == "zsh-extended":
        yield from _iter_zsh_extended(rest)
    elif style == "bash-timestamp":
        yield from _iter_bash_timestamp(rest)
    else:
        yield from _iter_plain(rest)


def iter_commands_from_path(path: str, style: str = "auto") -> Iterator[Command]:
    """Convenience wrapper that opens path and streams commands from it."""
    with open(path, "r", encoding="utf-8", errors="replace") as fh:
        yield from iter_commands(fh, style=style)


def _detect_style(first_line: str) -> str:
    if _ZSH_EXTENDED_RE.match(first_line):
        return "zsh-extended"
    if _BASH_TIMESTAMP_RE.match(first_line):
        return "bash-timestamp"
    return "plain"


def _numbered_lines(stream: IO[str]):
    for i, raw in enumerate(stream, start=1):
        yield i, raw.rstrip("\n")


def _prepend(lineno: int, line: str, rest):
    yield lineno, line
    yield from rest


def _iter_plain(numbered) -> Iterator[Command]:
    # A plain HISTFILE has no way to mark where a multi-line command
    # started, so each non-blank line is treated as its own command.
    for n, line in numbered:
        if line:
            yield Command(n, line)


def _iter_bash_timestamp(numbered) -> Iterator[Command]:
    # Format: a "#<epoch>" line followed by one or more lines of command
    # text, running until the next "#<epoch>" marker or end of file.
    ts: Optional[int] = None
    start_lineno: Optional[int] = None
    buffer: list[str] = []

    for n, line in numbered:
        match = _BASH_TIMESTAMP_RE.match(line)
        if match:
            if buffer:
                yield Command(start_lineno, "\n".join(buffer), ts)
                buffer = []
            ts = int(match.group(1))
            start_lineno = None
            continue
        if not line and start_lineno is None:
            continue
        if start_lineno is None:
            start_lineno = n
        buffer.append(line)

    if buffer:
        yield Command(start_lineno, "\n".join(buffer), ts)


def _iter_zsh_extended(numbered) -> Iterator[Command]:
    # Format: ": <start>:<elapsed>;<command>", where zsh encodes a real
    # newline inside the command as a trailing backslash followed by a
    # literal newline (i.e. another physical line). A run of those
    # continuation lines belongs to one logical command.
    for n, line in numbered:
        match = _ZSH_EXTENDED_RE.match(line)
        if not match:
            # Not a well-formed entry header (e.g. a blank line between
            # entries); skip it rather than guess which command it
            # belongs to.
            continue
        ts = int(match.group(1))
        parts = [match.group(3)]
        while parts[-1].endswith("\\") and not parts[-1].endswith("\\\\"):
            try:
                _, cont = next(numbered)
            except StopIteration:
                break
            parts[-1] = parts[-1][:-1]
            parts.append(cont)
        yield Command(n, "\n".join(parts), ts)
