#!/usr/bin/env python3
"""RFC 9309 robots.txt parser, matcher, and auditor. No network access."""
import argparse
import json
import sys

__version__ = "0.1.0"
FORMAT_VERSION = 1
MAX_PARSE_BYTES = 500 * 1024  # RFC 9309 section 2.5 minimum parsing limit.
UNRESERVED = frozenset(
    "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_.~")
TOKEN_CHARS = frozenset(
    "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz_-")


class RobotsError(ValueError):
    """Unreadable input or bad options. Reports fixed codes only."""

    def __init__(self, code):
        self.code = code
        super().__init__(code)


def canonicalize(text, is_pattern=False):
    """Apply RFC 9309 section 2.2.2 octet normalization.

    Percent-encoded ASCII octets in the unreserved range are decoded;
    other escapes are kept with uppercase hex; non-ASCII characters are
    UTF-8 percent-encoded. In patterns, raw '*' stays a wildcard and a
    trailing '$' stays the end anchor, so literal metacharacters must be
    percent-encoded (RFC 9309 Figure 6); a non-trailing '$' is literal and
    is encoded. In URIs, raw '*' and '$' are encoded. Result is ASCII.
    """
    out = []
    i = 0
    while i < len(text):
        char = text[i]
        if (char == "%" and i + 2 < len(text)
                and all(c in "0123456789abcdefABCDEF" for c in text[i+1:i+3])):
            byte = int(text[i+1:i+3], 16)
            if chr(byte) in UNRESERVED:
                out.append(chr(byte))
            else:
                out.append("%" + text[i+1:i+3].upper())
            i += 3
        elif ord(char) > 127:
            for byte in char.encode("utf-8"):
                out.append("%%%02X" % byte)
            i += 1
        elif char == "*" and not is_pattern:
            out.append("%2A")
            i += 1
        elif char == "$" and not (is_pattern and i == len(text) - 1):
            out.append("%24")
            i += 1
        else:
            out.append(char)
            i += 1
    return "".join(out)


def pattern_matches(pattern, path):
    """Prefix match with '*' wildcards and an end-anchored '$'.

    Port of the pos[] algorithm in Google's LongestMatchRobotsMatchStrategy:
    O(len(pattern) * len(path)) worst case, anchored at the first octet.
    """
    positions = [0]
    for index, char in enumerate(pattern):
        if char == "$" and index == len(pattern) - 1:
            return bool(positions) and positions[-1] == len(path)
        if char == "*":
            if not positions:
                return False
            positions = list(range(positions[0], len(path) + 1))
        else:
            positions = [p + 1 for p in positions
                         if p < len(path) and path[p] == char]
            if not positions:
                return False
    return True


class Rule:
    __slots__ = ("kind", "pattern", "raw", "line")

    def __init__(self, kind, pattern, raw, line):
        self.kind = kind
        self.pattern = pattern
        self.raw = raw
        self.line = line

    def matches(self, path):
        return pattern_matches(self.pattern, path)

    def to_dict(self):
        return {"kind": self.kind, "pattern": self.raw, "line": self.line,
                "length": len(self.pattern)}


class RobotsFile:
    def __init__(self, groups, sitemaps, findings, size_bytes):
        self.groups = groups  # list of (agents:list[str], rules:list[Rule])
        self.sitemaps = sitemaps
        self.findings = findings
        self.size_bytes = size_bytes

    def rules_for(self, agent):
        """Merged rules for a product token per RFC 9309 section 2.2.1."""
        specific, global_ = [], []
        for agents, rules in self.groups:
            lowered = [a.lower() for a in agents]
            if agent.lower() in lowered:
                specific.extend(rules)
            elif "*" in lowered:
                global_.extend(rules)
        return specific if specific else global_

    def check(self, agent, path):
        """Return the verdict dict for an agent fetching path."""
        canon = canonicalize(path)
        best = {"allow": None, "disallow": None}
        for rule in self.rules_for(agent):
            if not rule.matches(canon):
                continue
            current = best[rule.kind]
            if current is None or len(rule.pattern) > len(current.pattern):
                best[rule.kind] = rule
        allow, disallow = best["allow"], best["disallow"]
        if path == "/robots.txt" or canon == "/robots.txt":
            return _verdict(True, "robots_txt_implicitly_allowed", allow, disallow)
        if disallow is None:
            reason = "no_matching_rule" if allow is None else "allow_rule_matches"
            return _verdict(True, reason, allow, disallow)
        if allow is None:
            return _verdict(False, "disallow_rule_matches", allow, disallow)
        if len(disallow.pattern) > len(allow.pattern):
            return _verdict(False, "longest_match_disallow", allow, disallow)
        return _verdict(True, "tie_or_longer_allow", allow, disallow)


def _verdict(allowed, reason, allow, disallow):
    matched = disallow if not allowed else allow
    return {
        "allowed": allowed,
        "reason": reason,
        "matched_rule": matched.to_dict() if matched else None,
        "allow_rule": allow.to_dict() if allow else None,
        "disallow_rule": disallow.to_dict() if disallow else None,
    }


def _finding(code, line=None, detail=None):
    item = {"code": code}
    if line is not None:
        item["line"] = line
    if detail is not None:
        item["detail"] = detail
    return item


def parse_robots(text):
    """Parse robots.txt text per RFC 9309 section 2.2. Never raises."""
    findings = []
    size_bytes = len(text.encode("utf-8", "replace"))
    if size_bytes > MAX_PARSE_BYTES:
        findings.append(_finding("oversized_file", detail=str(size_bytes)))
    if text.startswith("\ufeff"):
        findings.append(_finding("bom_prefix", line=1))
        text = text[1:]

    groups, sitemaps = [], []
    agents, rules = [], []
    seen_rule = False

    def flush():
        nonlocal agents, rules, seen_rule
        if agents:
            groups.append((agents, rules))
        agents, rules, seen_rule = [], [], False

    for number, raw_line in enumerate(text.splitlines(), start=1):
        line = raw_line.split("#", 1)[0].strip()
        if not line:
            continue
        key, sep, value = line.partition(":")
        if not sep:
            findings.append(_finding("unparseable_line", line=number))
            continue
        key, value = key.strip().lower(), value.strip()
        if any(ord(c) < 32 and c not in "\t" for c in value):
            findings.append(_finding("control_character", line=number))
        if key == "user-agent":
            if seen_rule:
                flush()
            if not value:
                findings.append(_finding("empty_user_agent", line=number))
                continue
            if value != "*" and not all(c in TOKEN_CHARS for c in value):
                findings.append(_finding("invalid_product_token", line=number,
                                         detail=value))
            if value.startswith("*") and value != "*":
                findings.append(_finding("wildcard_plus_text", line=number,
                                         detail=value))
            agents.append(value)
        elif key in ("allow", "disallow"):
            if not agents:
                findings.append(_finding("rule_outside_group", line=number,
                                         detail=key))
                continue
            seen_rule = True
            if not value:
                findings.append(_finding(
                    "empty_allow" if key == "allow" else "empty_disallow",
                    line=number))
                continue
            if not value.startswith("/"):
                findings.append(_finding("pattern_missing_leading_slash",
                                         line=number, detail=value))
            rules.append(Rule(key, canonicalize(value, is_pattern=True),
                              value, number))
        elif key == "sitemap":
            if value:
                sitemaps.append(value)
        else:
            findings.append(_finding("unknown_field", line=number, detail=key))
    flush()

    for group_agents, group_rules in groups:
        seen = {}
        for rule in group_rules:
            tag = (rule.kind, rule.pattern)
            if tag in seen:
                findings.append(_finding(
                    "duplicate_rule", line=rule.line,
                    detail="%s: %s" % (rule.kind, rule.raw)))
            seen[tag] = rule.line
        allows = {r.pattern for r in group_rules if r.kind == "allow"}
        disallows = {r.pattern for r in group_rules if r.kind == "disallow"}
        for pattern in sorted(allows & disallows):
            findings.append(_finding("allow_disallow_same_pattern",
                                     detail=pattern))
    return RobotsFile(groups, sitemaps, findings, size_bytes)


def url_to_path(url):
    """Extract path+query from a URL; fragments are dropped."""
    text = url.split("#", 1)[0]
    if "://" in text:
        text = text.split("://", 1)[1]
        slash = text.find("/")
        text = text[slash:] if slash >= 0 else "/"
    if not text.startswith("/"):
        text = "/" + text
    return text


def check_robots(text, agent, path):
    robots = parse_robots(text)
    return robots, robots.check(agent, url_to_path(path))


def _print_text(verdict, robots, agent, path):
    print("ALLOWED" if verdict["allowed"] else "DISALLOWED")
    print("agent: %s" % agent)
    print("path: %s" % url_to_path(path))
    print("reason: %s" % verdict["reason"])
    matched = verdict["matched_rule"]
    if matched:
        print("matched: %s: %s (line %d, length %d)" % (
            matched["kind"], matched["pattern"], matched["line"],
            matched["length"]))


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("file", help="path to a robots.txt file ('-' for stdin)")
    parser.add_argument("--agent", help="crawler product token, e.g. googlebot")
    parser.add_argument("--path", help="URL or path to test")
    parser.add_argument("--audit", action="store_true",
                        help="list static-analysis findings instead of checking")
    parser.add_argument("--format", choices=("text", "json"), default="text")
    parser.add_argument("--version", action="version", version=__version__)
    args = parser.parse_args(argv)
    if not args.audit and not (args.agent and args.path):
        parser.error("--agent and --path are required unless --audit is used")
    if args.agent and args.agent != "*" and not all(
            c in TOKEN_CHARS for c in args.agent):
        print("INPUT ERROR: invalid_agent_token", file=sys.stderr)
        return 2
    try:
        if args.file == "-":
            text = sys.stdin.read()
        else:
            with open(args.file, "r", encoding="utf-8", errors="replace") as fh:
                text = fh.read()
    except OSError:
        print("INPUT ERROR: file_unreadable", file=sys.stderr)
        return 2
    robots = parse_robots(text)
    if args.audit:
        report = {
            "format_version": FORMAT_VERSION,
            "groups": len(robots.groups),
            "rules": sum(len(r) for _, r in robots.groups),
            "sitemaps": robots.sitemaps,
            "size_bytes": robots.size_bytes,
            "findings": robots.findings,
        }
        if args.format == "json":
            print(json.dumps(report, indent=2, sort_keys=True))
        else:
            print("%d group(s), %d rule(s), %d sitemap(s), %d byte(s)" % (
                report["groups"], report["rules"],
                len(report["sitemaps"]), report["size_bytes"]))
            for item in report["findings"]:
                location = " (line %d)" % item["line"] if "line" in item else ""
                detail = ": %s" % item["detail"] if "detail" in item else ""
                print("FINDING: %s%s%s" % (item["code"], location, detail))
        return 0
    verdict = robots.check(args.agent, args.path)
    if args.format == "json":
        print(json.dumps({"format_version": FORMAT_VERSION,
                          "agent": args.agent,
                          "path": url_to_path(args.path),
                          **verdict}, indent=2, sort_keys=True))
    else:
        _print_text(verdict, robots, args.agent, args.path)
    return 0 if verdict["allowed"] else 1


if __name__ == "__main__":
    sys.exit(main())
