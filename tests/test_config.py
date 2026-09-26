import unittest

from shellhist_lint.config import SuppressionConfigError, is_suppressed, parse_suppressions
from shellhist_lint.rules import Finding


def finding(rule_id="secret-in-history"):
    return Finding(1, rule_id, "message", "snippet")


class ParseSuppressionsTests(unittest.TestCase):
    def test_parses_rule_scoped_pattern(self):
        suppressions = parse_suppressions(["secret-in-history TEST_PASSWORD="])
        self.assertEqual(len(suppressions), 1)
        self.assertEqual(suppressions[0].rule_id, "secret-in-history")
        self.assertTrue(suppressions[0].pattern.search("TEST_PASSWORD=xyz"))

    def test_parses_wildcard_pattern(self):
        suppressions = parse_suppressions(["* rm -rf /tmp/scratch"])
        self.assertEqual(suppressions[0].rule_id, "*")

    def test_skips_blank_and_comment_lines(self):
        suppressions = parse_suppressions(["", "  ", "# a comment", "  # indented comment"])
        self.assertEqual(suppressions, [])

    def test_pattern_may_contain_spaces(self):
        suppressions = parse_suppressions(["* rm -rf /tmp/scratch dir"])
        self.assertEqual(suppressions[0].pattern.pattern, "rm -rf /tmp/scratch dir")

    def test_missing_pattern_raises(self):
        with self.assertRaises(SuppressionConfigError):
            parse_suppressions(["secret-in-history"])

    def test_invalid_regex_raises(self):
        with self.assertRaises(SuppressionConfigError):
            parse_suppressions(["* ("])


class IsSuppressedTests(unittest.TestCase):
    def test_wildcard_rule_matches_any_finding(self):
        suppressions = parse_suppressions(["* TEST_PASSWORD="])
        self.assertTrue(is_suppressed(finding("secret-in-history"), "export TEST_PASSWORD=x", suppressions))
        self.assertTrue(is_suppressed(finding("chmod-777"), "TEST_PASSWORD=x; chmod 777 x", suppressions))

    def test_scoped_rule_only_matches_that_rule(self):
        suppressions = parse_suppressions(["secret-in-history TEST_PASSWORD="])
        self.assertTrue(is_suppressed(finding("secret-in-history"), "export TEST_PASSWORD=x", suppressions))
        self.assertFalse(is_suppressed(finding("chmod-777"), "export TEST_PASSWORD=x", suppressions))

    def test_no_match_is_not_suppressed(self):
        suppressions = parse_suppressions(["secret-in-history TEST_PASSWORD="])
        self.assertFalse(is_suppressed(finding("secret-in-history"), "export DB_PASSWORD=hunter2", suppressions))

    def test_empty_suppression_list_never_suppresses(self):
        self.assertFalse(is_suppressed(finding(), "export DB_PASSWORD=hunter2", []))


if __name__ == "__main__":
    unittest.main()
