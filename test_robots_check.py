import contextlib
import io
import json
import os
import tempfile
import unittest
from pathlib import Path

from robots_check import (RobotsError, canonicalize, check_robots, main,
                          parse_robots, pattern_matches, url_to_path)


class Base(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.file = Path(self.temp.name) / "robots.txt"

    def write(self, text):
        self.file.write_text(text, encoding="utf-8")

    def cli(self, *args, stdin=None):
        out, err = io.StringIO(), io.StringIO()
        if stdin is not None:
            old = sys_stdin()
        with contextlib.redirect_stdout(out), contextlib.redirect_stderr(err):
            code = main(list(args))
        return code, out.getvalue(), err.getvalue()


def sys_stdin():
    import sys
    return sys.stdin


class CanonicalizeTests(unittest.TestCase):
    def test_plain_unchanged(self):
        self.assertEqual(canonicalize("/a/b-c_d.html"), "/a/b-c_d.html")

    def test_unreserved_decoded(self):
        self.assertEqual(canonicalize("/foo/bar/%62%61%7A"), "/foo/bar/baz")

    def test_unreserved_lowercase_hex(self):
        self.assertEqual(canonicalize("/%7e%2e"), "/~.")

    def test_reserved_kept_uppercased(self):
        self.assertEqual(canonicalize("/a%2fb"), "/a%2Fb")

    def test_non_ascii_encoded(self):
        self.assertEqual(canonicalize("/é"), "/%C3%A9")

    def test_bare_percent_literal(self):
        self.assertEqual(canonicalize("/100%"), "/100%")

    def test_percent_at_end_literal(self):
        self.assertEqual(canonicalize("/a%4"), "/a%4")

    def test_wildcard_unchanged(self):
        self.assertEqual(canonicalize("/a*/b$", is_pattern=True), "/a*/b$")

    def test_uri_metacharacters_encoded(self):
        self.assertEqual(canonicalize("/a*b$"), "/a%2Ab%24")

    def test_pattern_mid_dollar_encoded(self):
        self.assertEqual(canonicalize("/a$b$", is_pattern=True), "/a%24b$")


class PatternMatchTests(unittest.TestCase):
    def test_prefix(self):
        self.assertTrue(pattern_matches("/foo", "/foo/bar"))

    def test_exact(self):
        self.assertTrue(pattern_matches("/foo", "/foo"))

    def test_no_match(self):
        self.assertFalse(pattern_matches("/foo", "/fobar/baz/quxfoo"))

    def test_case_sensitive(self):
        self.assertFalse(pattern_matches("/Foo", "/foo"))

    def test_dollar_anchor(self):
        self.assertTrue(pattern_matches("/foo$", "/foo"))
        self.assertFalse(pattern_matches("/foo$", "/foobar"))

    def test_dollar_mid_pattern_literal(self):
        self.assertTrue(pattern_matches("/a$b", "/a$b"))

    def test_star(self):
        self.assertTrue(pattern_matches("/a*/b", "/a/x/y/b"))
        self.assertTrue(pattern_matches("/a*/b", "/a/b"))
        self.assertTrue(pattern_matches("/*.gif$", "/x/y.gif"))
        self.assertFalse(pattern_matches("/*.gif$", "/x/y.gifx"))

    def test_multiple_stars(self):
        self.assertTrue(pattern_matches("/*foo*bar", "/x/foo/y/bar"))
        self.assertFalse(pattern_matches("/*foo*bar", "/x/bar/y"))

    def test_star_not_slash_limited(self):
        self.assertTrue(pattern_matches("/a*", "/a/b/c"))


class RfcExampleTests(unittest.TestCase):
    def test_merge_same_token_groups(self):
        # RFC 9309 Figure 2.
        robots = parse_robots(
            "user-agent: ExampleBot\ndisallow: /foo\ndisallow: /bar\n"
            "user-agent: ExampleBot\ndisallow: /baz\n")
        self.assertFalse(robots.check("examplebot", "/baz")["allowed"])

    def test_fallback_to_star_group(self):
        # RFC 9309 Figure 3.
        robots = parse_robots(
            "user-agent: *\ndisallow: /foo\ndisallow: /bar\n"
            "user-agent: BazBot\ndisallow: /baz\n")
        self.assertFalse(robots.check("ExampleBot", "/bar")["allowed"])
        self.assertTrue(robots.check("ExampleBot", "/baz")["allowed"])
        self.assertFalse(robots.check("bazbot", "/baz")["allowed"])
        self.assertTrue(robots.check("bazbot", "/bar")["allowed"])

    def test_no_matching_group_allows(self):
        robots = parse_robots("user-agent: FooBot\ndisallow: /x\n")
        self.assertTrue(robots.check("OtherBot", "/x")["allowed"])

    def test_empty_file_allows(self):
        self.assertTrue(parse_robots("").check("AnyBot", "/anything")["allowed"])

    def test_group_without_rules_allows(self):
        robots = parse_robots("user-agent: FooBot\n")
        self.assertTrue(robots.check("foobot", "/x")["allowed"])

    def test_user_agent_case_insensitive(self):
        robots = parse_robots("User-Agent: GOOGLEbot\nDisallow: /x\n")
        self.assertFalse(robots.check("googlebot", "/x")["allowed"])

    def test_percent_encoded_unreserved_matches_literal(self):
        # RFC 9309 Figure 4, last row.
        robots = parse_robots("user-agent: *\ndisallow: /foo/bar/baz\n")
        self.assertFalse(robots.check("bot", "/foo/bar/%62%61%7A")["allowed"])

    def test_non_ascii_rule_matches_encoded_url(self):
        # RFC 9309 Figure 4, middle rows.
        robots = parse_robots("user-agent: *\ndisallow: /foo/bar/\u30c4\n")
        self.assertFalse(robots.check("bot", "/foo/bar/%E3%83%84")["allowed"])

    def test_escaped_star_is_literal(self):
        # RFC 9309 Figure 6.
        robots = parse_robots("user-agent: *\ndisallow: /path/file-with-a-%2A.html\n")
        self.assertFalse(robots.check("bot", "/path/file-with-a-*.html")["allowed"])
        self.assertTrue(robots.check("bot", "/path/file-with-a-x.html")["allowed"])

    def test_robots_txt_itself_always_allowed(self):
        robots = parse_robots("user-agent: *\ndisallow: /\n")
        self.assertTrue(robots.check("bot", "/robots.txt")["allowed"])

    def test_rules_before_first_user_agent_ignored(self):
        robots = parse_robots("disallow: /ignored\nuser-agent: *\ndisallow: /x\n")
        self.assertTrue(robots.check("bot", "/ignored")["allowed"])
        self.assertIn("rule_outside_group", [f["code"] for f in robots.findings])


class MatchingPrecedenceTests(unittest.TestCase):
    def check(self, text, path, agent="bot"):
        return parse_robots(text).check(agent, path)

    def test_longest_match_wins_over_order(self):
        # urllib.robotparser uses first-match-in-order; RFC 9309 uses longest.
        verdict = self.check(
            "user-agent: *\ndisallow: /ab\nallow: /abcd\n", "/abcdef")
        self.assertTrue(verdict["allowed"])
        self.assertEqual(verdict["reason"], "tie_or_longer_allow")

    def test_longest_disallow_wins(self):
        verdict = self.check(
            "user-agent: *\nallow: /ab\ndisallow: /abcd\n", "/abcdef")
        self.assertFalse(verdict["allowed"])
        self.assertEqual(verdict["reason"], "longest_match_disallow")

    def test_equal_length_allow_wins(self):
        verdict = self.check(
            "user-agent: *\ndisallow: /ab\nallow: /ab\n", "/ab")
        self.assertTrue(verdict["allowed"])

    def test_wildcard_counts_toward_length(self):
        verdict = self.check(
            "user-agent: *\nallow: /ab\ndisallow: /a*c\n", "/abc")
        self.assertFalse(verdict["allowed"])  # 4 octets beats 3

    def test_dollar_vs_prefix(self):
        robots = parse_robots("user-agent: *\ndisallow: /admin$\n")
        self.assertFalse(robots.check("bot", "/admin")["allowed"])
        self.assertTrue(robots.check("bot", "/admin/panel")["allowed"])

    def test_suffix_block(self):
        robots = parse_robots("user-agent: *\ndisallow: /*.gif$\n")
        self.assertFalse(robots.check("bot", "/img/logo.gif")["allowed"])
        self.assertTrue(robots.check("bot", "/img/logo.png")["allowed"])

    def test_full_block(self):
        robots = parse_robots("user-agent: *\ndisallow: /\n")
        self.assertFalse(robots.check("bot", "/")["allowed"])
        self.assertFalse(robots.check("bot", "/anything")["allowed"])

    def test_empty_disallow_is_noop(self):
        robots = parse_robots("user-agent: *\ndisallow:\n")
        self.assertTrue(robots.check("bot", "/anything")["allowed"])
        self.assertIn("empty_disallow", [f["code"] for f in robots.findings])

    def test_query_included_in_match(self):
        robots = parse_robots("user-agent: *\ndisallow: /*?sort=*\n")
        self.assertFalse(robots.check("bot", "/list?sort=asc")["allowed"])
        self.assertTrue(robots.check("bot", "/list")["allowed"])

    def test_url_input_path_extracted(self):
        robots = parse_robots("user-agent: *\ndisallow: /x\n")
        verdict = robots.check("bot", url_to_path("https://ex.com/x?y=1#frag"))
        self.assertFalse(verdict["allowed"])

    def test_verdict_reports_rule_line(self):
        verdict = self.check(
            "user-agent: *\n\n# c\ndisallow: /sec\n", "/secret")
        self.assertEqual(verdict["matched_rule"]["line"], 4)

    def test_comments_stripped(self):
        robots = parse_robots("user-agent: * # all bots\ndisallow: /x # no\n")
        self.assertFalse(robots.check("bot", "/x")["allowed"])

    def test_crlf_and_tabs(self):
        robots = parse_robots("user-agent:\t*\r\ndisallow:\t/x\r\n")
        self.assertFalse(robots.check("bot", "/x")["allowed"])

    def test_bom(self):
        robots = parse_robots("\ufeffuser-agent: *\ndisallow: /x\n")
        self.assertFalse(robots.check("bot", "/x")["allowed"])
        self.assertIn("bom_prefix", [f["code"] for f in robots.findings])


class AuditTests(unittest.TestCase):
    def codes(self, text):
        return [f["code"] for f in parse_robots(text).findings]

    def test_duplicate_rule(self):
        text = "user-agent: *\ndisallow: /x\ndisallow: /x\n"
        self.assertIn("duplicate_rule", self.codes(text))

    def test_allow_disallow_same_pattern(self):
        text = "user-agent: *\nallow: /x\ndisallow: /x\n"
        self.assertIn("allow_disallow_same_pattern", self.codes(text))

    def test_missing_leading_slash(self):
        self.assertIn("pattern_missing_leading_slash",
                      self.codes("user-agent: *\ndisallow: x\n"))

    def test_unknown_field(self):
        self.assertIn("unknown_field",
                      self.codes("user-agent: *\ncrawl-delay: 10\n"))

    def test_unparseable_line(self):
        self.assertIn("unparseable_line", self.codes("user-agent: *\nhello\n"))

    def test_invalid_token(self):
        self.assertIn("invalid_product_token",
                      self.codes("user-agent: bad bot!\ndisallow: /x\n"))

    def test_wildcard_plus_text(self):
        self.assertIn("wildcard_plus_text",
                      self.codes("user-agent: *bot\ndisallow: /x\n"))

    def test_sitemaps_collected(self):
        robots = parse_robots(
            "user-agent: *\nsitemap: https://ex.com/s.xml\n")
        self.assertEqual(robots.sitemaps, ["https://ex.com/s.xml"])

    def test_oversized(self):
        self.assertIn("oversized_file", self.codes("u" * (501 * 1024)))

    def test_sitemap_does_not_terminate_group(self):
        robots = parse_robots(
            "user-agent: *\nsitemap: https://ex.com/s.xml\ndisallow: /x\n")
        self.assertFalse(robots.check("bot", "/x")["allowed"])

    def test_clean_file_no_findings(self):
        self.assertEqual(self.codes("user-agent: *\ndisallow: /admin\n"), [])


class UrlToPathTests(unittest.TestCase):
    def test_full_url(self):
        self.assertEqual(url_to_path("https://ex.com/a?b=1#c"), "/a?b=1")

    def test_no_path(self):
        self.assertEqual(url_to_path("https://ex.com"), "/")

    def test_bare_path(self):
        self.assertEqual(url_to_path("/a/b"), "/a/b")

    def test_relative_becomes_rooted(self):
        self.assertEqual(url_to_path("a/b"), "/a/b")


class CLITests(Base):
    def test_allowed_exit_zero(self):
        self.write("user-agent: *\n")
        code, out, _ = self.cli(str(self.file), "--agent", "bot", "--path", "/x")
        self.assertEqual(code, 0)
        self.assertIn("ALLOWED", out)

    def test_disallowed_exit_one(self):
        self.write("user-agent: *\ndisallow: /x\n")
        code, out, _ = self.cli(str(self.file), "--agent", "bot", "--path", "/x")
        self.assertEqual(code, 1)
        self.assertIn("DISALLOWED", out)
        self.assertIn("disallow_rule_matches", out)

    def test_json_shape(self):
        self.write("user-agent: *\ndisallow: /x\n")
        code, out, _ = self.cli(str(self.file), "--agent", "bot",
                                "--path", "/x", "--format", "json")
        report = json.loads(out)
        self.assertEqual(report["format_version"], 1)
        self.assertFalse(report["allowed"])
        self.assertEqual(report["matched_rule"]["line"], 2)

    def test_audit_text(self):
        self.write("user-agent: *\ndisallow: x\n")
        code, out, _ = self.cli(str(self.file), "--audit")
        self.assertEqual(code, 0)
        self.assertIn("pattern_missing_leading_slash", out)

    def test_audit_json(self):
        self.write("user-agent: *\nsitemap: https://ex.com/s.xml\n")
        _, out, _ = self.cli(str(self.file), "--audit", "--format", "json")
        report = json.loads(out)
        self.assertEqual(report["sitemaps"], ["https://ex.com/s.xml"])

    def test_missing_agent_path_error(self):
        self.write("user-agent: *\n")
        with self.assertRaises(SystemExit):
            self.cli(str(self.file))

    def test_missing_file(self):
        code, _, err = self.cli(str(self.file) + ".nope",
                                "--agent", "b", "--path", "/x")
        self.assertEqual(code, 2)
        self.assertIn("file_unreadable", err)

    def test_invalid_agent(self):
        self.write("user-agent: *\n")
        code, _, err = self.cli(str(self.file),
                                "--agent", "bad bot", "--path", "/x")
        self.assertEqual(code, 2)
        self.assertIn("invalid_agent_token", err)

    def test_stdin_input(self):
        import sys
        self.write("unused")
        old, sys.stdin = sys.stdin, io.StringIO("user-agent: *\ndisallow: /x\n")
        try:
            code, out, _ = self.cli("-", "--agent", "b", "--path", "/x")
        finally:
            sys.stdin = old
        self.assertEqual(code, 1)

    def test_no_file_mutation(self):
        self.write("user-agent: *\ndisallow: /x\n")
        before = self.file.read_bytes()
        self.cli(str(self.file), "--agent", "b", "--path", "/x")
        self.cli(str(self.file), "--audit")
        self.assertEqual(self.file.read_bytes(), before)


class StdlibDivergenceTests(unittest.TestCase):
    def test_robotparser_order_vs_rfc_longest(self):
        # urllib.robotparser returns the FIRST matching rule in file order;
        # RFC 9309 section 2.2.2 requires the longest match. This test pins
        # our RFC behavior; it does not depend on robotparser internals.
        text = "user-agent: *\ndisallow: /ab\nallow: /abcd\n"
        import urllib.robotparser as rp
        parser = rp.RobotFileParser()
        parser.parse(text.splitlines())
        ours = parse_robots(text).check("bot", "/abcd")
        self.assertTrue(ours["allowed"])
        self.assertFalse(parser.can_fetch("bot", "/abcd"))  # stdlib diverges


if __name__ == "__main__":
    unittest.main()
