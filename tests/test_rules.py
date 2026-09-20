import unittest

from shellhist_lint.reader import Command
from shellhist_lint.rules import (
    lint_command,
    rule_chmod_777,
    rule_dangerous_rm,
    rule_pipe_to_shell,
    rule_plaintext_secret,
)


def cmd(text, lineno=1):
    return Command(lineno, text)


class PlaintextSecretRuleTests(unittest.TestCase):
    def test_flags_literal_password_assignment(self):
        findings = rule_plaintext_secret(cmd("DB_PASSWORD=correcthorsebatterystaple psql"))
        self.assertEqual(len(findings), 1)
        self.assertEqual(findings[0].rule_id, "secret-in-history")
        self.assertEqual(findings[0].lineno, 1)

    def test_flags_quoted_api_key(self):
        findings = rule_plaintext_secret(cmd('export API_KEY="' + "x" * 32 + '"'))
        self.assertEqual(len(findings), 1)

    def test_does_not_flag_variable_substitution(self):
        findings = rule_plaintext_secret(cmd("export TOKEN=$SECRET_TOKEN"))
        self.assertEqual(findings, [])

    def test_does_not_flag_brace_substitution(self):
        findings = rule_plaintext_secret(cmd("export PASSWORD=${DB_PASSWORD}"))
        self.assertEqual(findings, [])

    def test_does_not_flag_unrelated_assignment(self):
        findings = rule_plaintext_secret(cmd("export PATH=/usr/local/bin:$PATH"))
        self.assertEqual(findings, [])

    def test_does_not_flag_short_value(self):
        findings = rule_plaintext_secret(cmd("pwd=x"))
        self.assertEqual(findings, [])


class DangerousRmRuleTests(unittest.TestCase):
    def test_flags_rm_rf_root(self):
        findings = rule_dangerous_rm(cmd("rm -rf /"))
        self.assertEqual(len(findings), 1)
        self.assertEqual(findings[0].rule_id, "dangerous-rm")

    def test_flags_rm_rf_home(self):
        findings = rule_dangerous_rm(cmd("rm -rf ~"))
        self.assertEqual(len(findings), 1)

    def test_flags_rm_rf_home_subdir(self):
        findings = rule_dangerous_rm(cmd("rm -rf ~/old-project"))
        self.assertEqual(len(findings), 1)

    def test_flags_long_flags_with_no_preserve_root(self):
        findings = rule_dangerous_rm(cmd("rm --recursive --force --no-preserve-root /"))
        self.assertEqual(len(findings), 1)

    def test_does_not_flag_relative_path(self):
        findings = rule_dangerous_rm(cmd("rm -rf build/artifacts"))
        self.assertEqual(findings, [])

    def test_does_not_flag_rm_without_force_flag(self):
        findings = rule_dangerous_rm(cmd("rm -r /tmp/scratch"))
        self.assertEqual(findings, [])

    def test_does_not_flag_unrelated_command(self):
        findings = rule_dangerous_rm(cmd("rmdir /tmp/empty"))
        self.assertEqual(findings, [])


class PipeToShellRuleTests(unittest.TestCase):
    def test_flags_curl_pipe_bash(self):
        findings = rule_pipe_to_shell(cmd("curl -fsSL https://example.com/install.sh | bash"))
        self.assertEqual(len(findings), 1)
        self.assertEqual(findings[0].rule_id, "curl-pipe-shell")

    def test_flags_curl_pipe_sudo_bash(self):
        findings = rule_pipe_to_shell(cmd("curl -fsSL https://example.com/install.sh | sudo bash"))
        self.assertEqual(len(findings), 1)

    def test_flags_wget_pipe_sh(self):
        findings = rule_pipe_to_shell(cmd("wget -qO- https://example.com/install.sh | sh"))
        self.assertEqual(len(findings), 1)

    def test_does_not_flag_curl_saved_to_file(self):
        findings = rule_pipe_to_shell(cmd("curl -fsSL https://example.com/install.sh -o install.sh"))
        self.assertEqual(findings, [])

    def test_does_not_flag_unrelated_pipe(self):
        findings = rule_pipe_to_shell(cmd("cat access.log | grep 500"))
        self.assertEqual(findings, [])


class Chmod777RuleTests(unittest.TestCase):
    def test_flags_chmod_777(self):
        findings = rule_chmod_777(cmd("chmod 777 deploy.sh"))
        self.assertEqual(len(findings), 1)
        self.assertEqual(findings[0].rule_id, "chmod-777")

    def test_flags_chmod_recursive_0777(self):
        findings = rule_chmod_777(cmd("chmod -R 0777 /var/www"))
        self.assertEqual(len(findings), 1)

    def test_does_not_flag_chmod_755(self):
        findings = rule_chmod_777(cmd("chmod 755 deploy.sh"))
        self.assertEqual(findings, [])


class LintCommandTests(unittest.TestCase):
    def test_aggregates_findings_from_multiple_rules(self):
        findings = lint_command(cmd("chmod 777 deploy.sh; rm -rf /"))
        rule_ids = {f.rule_id for f in findings}
        self.assertEqual(rule_ids, {"chmod-777", "dangerous-rm"})

    def test_clean_command_yields_no_findings(self):
        findings = lint_command(cmd("git status"))
        self.assertEqual(findings, [])

    def test_findings_carry_the_command_lineno(self):
        findings = lint_command(cmd("chmod 777 deploy.sh", lineno=42))
        self.assertTrue(all(f.lineno == 42 for f in findings))


if __name__ == "__main__":
    unittest.main()
