#!/usr/bin/env python3

import re
import sys
import urllib.request
from pathlib import Path
from collections import Counter

SOURCE_URL = (
    "https://adguardteam.github.io/"
    "HostlistsRegistry/assets/filter_1.txt"
)

OUTPUT_FILE = Path("rules/adguard-domain.txt")


# AdGuard:
#
#   ||example.com^
#   ||sub.example.com^
#
# The "||" means beginning of a domain name.
# "^" is AdGuard's separator/end-of-domain marker.
#
# Mihomo domain rule-set:
#
#   +.example.com
#
# matches:
#   example.com
#   www.example.com
#   a.b.example.com
#
# See:
# https://wiki.metacubex.one/en/config/rule-providers/content/


ADGUARD_DOMAIN_RE = re.compile(
    r"""
    ^
    \|\|                              # AdGuard domain-anchor
    (?P<domain>
        (?:[A-Za-z0-9_*-]+\.)*
        [A-Za-z0-9_*+-]+
    )
    (?:\^|$)                           # AdGuard separator
    """,
    re.VERBOSE,
)


# Some AdGuard lists contain plain domain names.
PLAIN_DOMAIN_RE = re.compile(
    r"""
    ^
    (?P<domain>
        (?:[A-Za-z0-9_-]+\.)+
        [A-Za-z]{2,63}
    )
    $
    """,
    re.VERBOSE | re.IGNORECASE,
)


# We deliberately don't try to translate arbitrary AdGuard regexes,
# cosmetic rules, HTML rules, etc. into Mihomo domain rules.
#
# A domain rule-set should contain domains only.


def download_filter() -> str:
    request = urllib.request.Request(
        SOURCE_URL,
        headers={
            "User-Agent": "mihomo-adguard-rule-generator/1.0"
        },
    )

    with urllib.request.urlopen(request, timeout=60) as response:
        data = response.read()

    return data.decode("utf-8", errors="replace")


def normalize_domain(domain: str) -> str:
    domain = domain.strip().lower()

    # Remove a trailing dot.
    domain = domain.rstrip(".")

    return domain


def convert_adguard_domain(domain: str) -> str | None:
    """
    Convert an AdGuard domain expression to Mihomo domain-set syntax.
    """

    domain = normalize_domain(domain)

    if not domain:
        return None

    # AdGuard domain expressions may contain wildcard syntax.
    #
    # We don't want to blindly copy '*' because Mihomo's '*' has
    # different semantics.
    #
    # For normal ||domain.com^ rules we use +.domain.com.
    if "*" in domain:
        # AdGuard wildcard domains cannot always be represented
        # exactly by a Mihomo domain-set entry.
        #
        # Do not generate an incorrect rule.
        return None

    # A leading dot is not useful here.
    domain = domain.lstrip(".")

    # Basic sanity checking.
    if "." not in domain:
        return None

    if not re.fullmatch(
        r"[a-z0-9](?:[a-z0-9_-]{0,61}[a-z0-9])?"
        r"(?:\.[a-z0-9](?:[a-z0-9_-]{0,61}[a-z0-9])?)+",
        domain,
    ):
        return None

    # Mihomo's "+." wildcard is the closest equivalent to
    # AdGuard's ||domain.com^:
    #
    # +.example.com
    #
    # matches example.com and all its subdomains.
    return "+." + domain


def process_filter(text: str):
    rules = set()

    stats = Counter()

    for raw_line in text.splitlines():
        line = raw_line.strip()

        if not line:
            stats["empty"] += 1
            continue

        # AdGuard comments.
        if line.startswith("!") or line.startswith("#"):
            stats["comments"] += 1
            continue

        # AdGuard exception rules.
        if line.startswith("@@"):
            stats["exceptions"] += 1
            continue

        # Cosmetic / HTML / scriptlet / regex rules.
        if (
            line.startswith("/")
            or "##" in line
            or "#@#" in line
            or "#?#" in line
            or "#@?#" in line
        ):
            stats["unsupported"] += 1
            continue

        # ---------------------------------------------------------
        # 1. Standard AdGuard domain rule
        #
        #    ||example.com^
        #    ||example.com^$third-party
        #    ||example.com^$important
        #
        # We only care about the part before the first '^'.
        # ---------------------------------------------------------

        if line.startswith("||"):
            rule_part = line.split("^", 1)[0]

            match = ADGUARD_DOMAIN_RE.match(rule_part + "^")

            if match:
                domain = match.group("domain")
                result = convert_adguard_domain(domain)

                if result:
                    rules.add(result)
                    stats["domain_rules"] += 1
                else:
                    stats["unsupported"] += 1

                continue

        # ---------------------------------------------------------
        # 2. Plain domain
        #
        # Some DNS lists contain:
        #
        #    example.com
        #
        # These are already valid Mihomo domain-set entries.
        # ---------------------------------------------------------

        if PLAIN_DOMAIN_RE.fullmatch(line):
            domain = normalize_domain(line)

            # Avoid accidentally treating localhost/private names
            # as public domains.
            if "." in domain:
                rules.add(domain)
                stats["plain_domains"] += 1
                continue

        # Everything else is intentionally ignored.
        stats["unsupported"] += 1

    return rules, stats


def write_output(rules: set[str]):
    OUTPUT_FILE.parent.mkdir(parents=True, exist_ok=True)

    sorted_rules = sorted(
        rules,
        key=lambda x: (
            x.lstrip("+."),  # domain
            x,               # deterministic tie breaker
        ),
    )

    with OUTPUT_FILE.open("w", encoding="utf-8", newline="\n") as f:
        for rule in sorted_rules:
            f.write(rule + "\n")


def main():
    print(f"Downloading: {SOURCE_URL}")

    text = download_filter()

    print(f"Downloaded: {len(text):,} bytes")

    rules, stats = process_filter(text)

    write_output(rules)

    print()
    print("Conversion statistics:")
    print(f"  Mihomo rules:      {len(rules):,}")
    print(f"  AdGuard domains:   {stats['domain_rules']:,}")
    print(f"  Plain domains:     {stats['plain_domains']:,}")
    print(f"  Exceptions:        {stats['exceptions']:,}")
    print(f"  Comments:          {stats['comments']:,}")
    print(f"  Unsupported:       {stats['unsupported']:,}")
    print(f"  Empty lines:       {stats['empty']:,}")
    print()
    print(f"Output: {OUTPUT_FILE}")

    if not rules:
        print("ERROR: no rules were generated", file=sys.stderr)
        sys.exit(1)


if __name__ == "__main__":
    main()
