# robots-check

An RFC 9309 ([Robots Exclusion Protocol]) parser, matcher, and auditor with
no dependencies and no network access. It answers two questions correctly:

- **Can agent X fetch path Y?** Evaluated with the real spec rules, and it
  shows you *which rule decided*.
- **Is this robots.txt doing what its author thinks?** Static audit findings
  for the mistakes that silently change crawl behavior.

## Why another robots.txt parser

Most hand-rolled matchers - and Python's own `urllib.robotparser` - do not
implement the matching algorithm the RFC requires:

- **Longest match wins, not first match.** RFC 9309 section 2.2.2: "The most
  specific match found MUST be used." On Python before 3.13,
  `urllib.robotparser` returns the first matching rule in file order (see
  `Entry.allowance` in the stdlib source), so `Disallow: /ab` followed by
  `Allow: /abcd` blocks `/abcd` there and allows it under the RFC. CPython
  [gh-138907] landed full RFC 9309 support in robotparser for 3.13 - this
  tool gives you the same semantics on any supported Python, plus the audit
  and per-rule explanations robotparser does not have. The divergence (and
  the 3.13 fix) is pinned in a test.
- **Wildcards are spec, not optional.** `*` (any run of characters) and `$`
  (end anchor) are MUST-support per section 2.2.3. The pre-3.13 stdlib
  matcher is a plain `str.startswith`.
- **Percent-encoding rules are subtle.** Section 2.2.2 requires decoding
  percent-encoded *unreserved* octets (`%62` is `b`), percent-encoding
  non-ASCII as UTF-8, and encoding literal `*`/`$` in URIs so escaped
  patterns like `/path/file-with-a-%2A.html` work (Figure 6). Google's own
  reference parser ([google/robotstxt]) normalizes escape casing and encodes
  non-ASCII octets, but the unreserved-decode step from Figure 4 is not
  visible in its `MaybeEscapePattern`; this tool implements the RFC rule.

Other real-world behavior encoded here, all from the RFC: groups with the
same product token merge (Figure 2), crawlers fall back to the `*` group
(Figure 3), rules before the first `user-agent` line are ignored, a group
with no rules allows everything, `/robots.txt` itself is always allowed,
and matching is anchored at the first octet of the path.

## Usage

```console
$ python3 robots_check.py robots.txt --agent googlebot --path /admin/panel
DISALLOWED
agent: googlebot
path: /admin/panel
reason: disallow_rule_matches
matched: disallow: /admin (line 2, length 6)

$ python3 robots_check.py robots.txt --audit
1 group(s), 3 rule(s), 1 sitemap(s), 109 byte(s)
FINDING: unknown_field (line 6): crawl-delay
```

Exit codes: `0` allowed, `1` disallowed, `2` input error. `--format json`
for scripting; `-` as the file reads stdin. Library use:

```python
from robots_check import parse_robots
robots = parse_robots(open("robots.txt").read())
verdict = robots.check("googlebot", "/shop/%62%61%72")  # decodes to /shop/bar
print(verdict["allowed"], verdict["reason"], verdict["matched_rule"])
```

## What the audit catches

Duplicate rules, allow/disallow pairs on the same pattern (allow SHOULD win),
rules outside any group, patterns missing the leading `/`, empty allow or
disallow values, unknown fields (e.g. the non-standard `Crawl-delay`),
invalid product tokens, `*` mixed with other text in a user-agent, BOMs,
control characters, unparseable lines, and files over the 500 KiB minimum
parsing limit from section 2.5. Sitemaps are collected and reported.

## Semantics notes and limits

- Priority = octet length of the full canonicalized pattern (counting `*`
  and `$`), equal length goes to allow. This matches the `pattern.length()`
  priority in Google's `LongestMatchRobotsMatchStrategy`.
- Matching is case-sensitive (the RFC's SHOULD); user-agent tokens are
  case-insensitive (MUST).
- This tool decides *from file content*. It does not fetch URLs, so the
  access-result rules in section 2.3.1 (4xx = allow all, 5xx/unreachable =
  assume full disallow, redirect following, 24 h caching) are documented
  here but out of scope for the matcher.
- robots.txt is not access control. Section 3: listing paths makes them
  discoverable; use real authentication for sensitive content.
- A pass means "the RFC says allowed", not "every crawler will fetch it";
  major crawlers also honor non-standard extensions this tool deliberately
  reports instead of obeying.

## Tests

```console
$ python3 -m unittest -v
```

70 tests, all offline: every worked example in RFC 9309 (Figures 2-6),
longest-match and tie-break precedence, percent-encoding edge cases, the
stdlib divergence, audit findings, CLI exit codes, and JSON shape. CI runs
the suite on Linux and Windows across Python 3.9 and 3.13.

## Sources

- [Robots Exclusion Protocol] - RFC 9309, the specification implemented here
  (matching in 2.2.2, special characters in 2.2.3, limits in 2.5)
- [google/robotstxt] - Google's reference C++ parser: pos[] match algorithm
  and `pattern.length()` priority ported from `robots.cc`
- [urllib.robotparser] - Python stdlib; `Entry.allowance` shows first-match
  semantics and `RuleLine.applies_to` shows prefix-only matching (pre-3.13)
- [gh-138907] - CPython PR adding RFC 9309 support to robotparser in 3.13
  (group merging, longest match, wildcard handling)
- [Google Search robots.txt reference] - production behavior the RFC
  codified (group merging, `*`/`$`, sitemap records)

[Robots Exclusion Protocol]: https://www.rfc-editor.org/rfc/rfc9309.html
[google/robotstxt]: https://github.com/google/robotstxt/blob/master/robots.cc
[urllib.robotparser]: https://docs.python.org/3/library/urllib.robotparser.html
[Google Search robots.txt reference]: https://developers.google.com/search/docs/crawling-indexing/robots/robots_txt
[gh-138907]: https://github.com/python/cpython/pull/138908

## License

MIT (see LICENSE).
