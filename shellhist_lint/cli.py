"""Command-line entry point: shellhist-lint FILE [FILE ...]"""

from __future__ import annotations

import argparse
import sys

from .config import SuppressionConfigError, is_suppressed, load_suppressions
from .reader import iter_commands, iter_commands_from_path
from .rules import lint_command


def _report(source_label: str, cmd_iter, suppressions) -> int:
    count = 0
    for cmd in cmd_iter:
        for finding in lint_command(cmd):
            if is_suppressed(finding, cmd.text, suppressions):
                continue
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
    parser.add_argument(
        "--config",
        metavar="PATH",
        help="suppression file: lines of '<rule-id or *> <regex>' matched against "
        "each command's raw text to silence known-fine findings",
    )
    args = parser.parse_args(argv)

    suppressions = []
    if args.config:
        try:
            suppressions = load_suppressions(args.config)
        except OSError as exc:
            parser.error(f"can't read suppression config: {exc}")
        except SuppressionConfigError as exc:
            parser.error(str(exc))

    total = 0
    if args.paths:
        for path in args.paths:
            total += _report(path, iter_commands_from_path(path, style=args.style), suppressions)
    else:
        total += _report("<stdin>", iter_commands(sys.stdin, style=args.style), suppressions)

    return 1 if total else 0


if __name__ == "__main__":
    raise SystemExit(main())
