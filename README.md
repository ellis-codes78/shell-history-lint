# shellhist-lint

Your shell history file is a log of everything you typed, kept forever,
usually world-readable, and never reviewed. It's where a `curl ... | sudo
bash` you ran once lives next to a `DB_PASSWORD=hunter2` you typed by hand
because the `.env` loader was broken that day. `shellhist-lint` reads a
history file and reports the lines worth a second look.

## Usage

```
$ shellhist-lint ~/.bash_history
/home/ellis/.bash_history:1842: [secret-in-history] possible plaintext credential in a shell variable assignment
    DB_PASSWORD=hunter2 psql -h prod-db -U admin
/home/ellis/.bash_history:2011: [curl-pipe-shell] downloading a script and piping it straight into a shell
    curl -fsSL https://get.example.com/install.sh | sudo bash
/home/ellis/.bash_history:2390: [dangerous-rm] rm -rf against an absolute path, home directory, or with --no-preserve-root
    rm -rf ~/old-project
```

Exit status is 1 if anything was found, 0 otherwise, so it's usable in a
pre-push hook or a cron job that mails you a diff of new findings.

It also reads from stdin, so you can point it at the shell's live history
instead of the file on disk:

```
$ history | shellhist-lint
```

## Supported formats

History files come in a few shapes depending on shell and settings.
`shellhist-lint` looks at the first line and picks a parser:

- **plain** -- one command per line (default `HISTFILE` for most setups).
- **bash-timestamp** -- a `#<epoch-seconds>` comment before each command,
  written when `HISTTIMEFORMAT` is set.
- **zsh-extended** -- `: <start>:<elapsed>;<command>` lines, written when
  `setopt EXTENDED_HISTORY` is on. Multi-line commands are decoded back
  into a single logical entry.

Pass `--style` to force one instead of relying on auto-detection.

## Why streaming matters here

A history file that's been appended to for years can be tens of megabytes,
and it's common to run this against several shell users' files at once.
The reader in `shellhist_lint/reader.py` never reads the file into a
string or a list of lines -- it pulls one physical line at a time from an
open file object and holds onto at most the lines that make up the
*current* logical command (relevant for the zsh multi-line format, where a
single history entry can span several physical lines). Line numbers are
tracked as the file is walked, so findings always point at the right spot
even for multi-line entries.

## Install

No dependencies, standard library only.

```
$ pip install -e .
$ shellhist-lint --help
```

Or just run it in place: `python -m shellhist_lint.cli ~/.zsh_history`.

## Tests

Standard library `unittest`, no test runner to install:

```
$ python -m unittest discover
```

## Status

Early. Four rules exist: leaked-looking credentials, `rm -rf` against a
root-ish path, `curl | sh` style pipes, and `chmod 777`. See the roadmap in
the project notes for what's planned next -- more rules, a config file for
suppressing known-fine lines, and JSON output for CI.

## License

MIT, see `LICENSE`.
