import io
import unittest

from shellhist_lint.reader import iter_commands


def commands(text, style="auto"):
    return list(iter_commands(io.StringIO(text), style=style))


class PlainFormatTests(unittest.TestCase):
    def test_one_command_per_line(self):
        cmds = commands("ls -la\ncd /tmp\n")
        self.assertEqual([c.text for c in cmds], ["ls -la", "cd /tmp"])
        self.assertEqual([c.lineno for c in cmds], [1, 2])

    def test_blank_lines_are_skipped(self):
        cmds = commands("ls\n\n\ncd /tmp\n")
        self.assertEqual([c.lineno for c in cmds], [1, 4])

    def test_no_trailing_newline(self):
        cmds = commands("ls -la")
        self.assertEqual([c.text for c in cmds], ["ls -la"])

    def test_empty_stream_yields_nothing(self):
        self.assertEqual(commands(""), [])

    def test_plain_has_no_timestamp(self):
        cmds = commands("ls -la\n")
        self.assertIsNone(cmds[0].timestamp)


class BashTimestampFormatTests(unittest.TestCase):
    def test_single_line_entries(self):
        cmds = commands("#1000000000\nls -la\n#1000000005\ncd /tmp\n")
        self.assertEqual([c.text for c in cmds], ["ls -la", "cd /tmp"])
        self.assertEqual([c.timestamp for c in cmds], [1000000000, 1000000005])
        self.assertEqual([c.lineno for c in cmds], [2, 4])

    def test_multi_line_command_joins_until_next_marker(self):
        text = "#1000000000\nfor f in *; do\n  echo $f\ndone\n#1000000010\nls\n"
        cmds = commands(text)
        self.assertEqual(len(cmds), 2)
        self.assertEqual(cmds[0].text, "for f in *; do\n  echo $f\ndone")
        self.assertEqual(cmds[0].lineno, 2)
        self.assertEqual(cmds[1].text, "ls")

    def test_trailing_buffer_without_next_marker_is_flushed(self):
        cmds = commands("#1000000000\nls -la\n")
        self.assertEqual(len(cmds), 1)
        self.assertEqual(cmds[0].text, "ls -la")

    def test_detected_from_leading_marker(self):
        cmds = commands("#1700000000\necho hi\n", style="auto")
        self.assertEqual(cmds[0].timestamp, 1700000000)


class ZshExtendedFormatTests(unittest.TestCase):
    def test_single_line_entry(self):
        cmds = commands(": 1700000000:0;ls -la\n")
        self.assertEqual(cmds[0].text, "ls -la")
        self.assertEqual(cmds[0].timestamp, 1700000000)
        self.assertEqual(cmds[0].lineno, 1)

    def test_continuation_lines_join_into_one_command(self):
        text = ": 1700000000:0;for f in *; do \\\necho $f; \\\ndone\n"
        cmds = commands(text)
        self.assertEqual(len(cmds), 1)
        self.assertEqual(cmds[0].text, "for f in *; do \necho $f; \ndone")

    def test_escaped_backslash_does_not_start_continuation(self):
        # The command text itself ends in two literal backslashes (an
        # escaped backslash), not zsh's single-backslash continuation
        # marker, so this must stay one entry rather than swallowing the
        # next header line as a continuation.
        cmds = commands(': 1700000000:0;echo foo\\\\\n: 1700000001:0;echo next\n')
        self.assertEqual(len(cmds), 2)
        self.assertEqual(cmds[0].text, "echo foo\\\\")
        self.assertEqual(cmds[1].text, "echo next")

    def test_malformed_header_line_is_skipped(self):
        text = ": 1700000000:0;ls\nnot a valid header\n: 1700000001:0;cd /tmp\n"
        cmds = commands(text)
        self.assertEqual([c.text for c in cmds], ["ls", "cd /tmp"])

    def test_detected_from_leading_marker(self):
        cmds = commands(": 1700000000:0;ls\n", style="auto")
        self.assertEqual(cmds[0].timestamp, 1700000000)


class StyleOverrideTests(unittest.TestCase):
    def test_forced_plain_style_ignores_zsh_markers(self):
        cmds = commands(": 1700000000:0;ls\n", style="plain")
        self.assertEqual(cmds[0].text, ": 1700000000:0;ls")
        self.assertIsNone(cmds[0].timestamp)


if __name__ == "__main__":
    unittest.main()
