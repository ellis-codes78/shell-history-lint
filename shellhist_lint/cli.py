"""Command-line entry point: shellhist-lint FILE [FILE ...]"""

from __future__ import annotations

import argparse
import sys

from .reader import iter_commands, iter_commands_from_path
from .rules import lint_command


def _report(source_label: str, cmd_iter) -> int:
    count = 0
    for cmd in cmd_iter:
        for finding in lint_command(cmd):
            print(f"{source_label}:{finding.lineno}: [{finding.rule_id}] {finding.message}")
            print(f"    {finding.snippet}")
            count += 1
    return count


def main(argv=None) -> int:
    parser = argparse.ArgumentParser(
        prog="shellhist-lint",
        description="Scan shell history files for leaked secrets and risky commands.",
    )
    parser.add_argument(
        "paths",
        nargs="*",
        help="history file(s) to check; reads stdin if none are given",
    )
    parser.add_argument(
        "--style",
        choices=["auto", "plain", "bash-timestamp", "zsh-extended"],
        default="auto",
        help="history file format (default: auto-detect from the first line)",
    )
    args = parser.parse_args(argv)

    total = 0
    if args.paths:
        for path in args.paths:
            total += _report(path, iter_commands_from_path(path, style=args.style))
    else:
        total += _report("<stdin>", iter_commands(sys.stdin, style=args.style))

    return 1 if total else 0


if __name__ == "__main__":
    raise SystemExit(main())
