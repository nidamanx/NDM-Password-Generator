#!/usr/bin/env python3
# SPDX-License-Identifier: AGPL-3.0-or-later
# pylint: disable=invalid-name
"""
ndm_password-generator.py

Generate high-entropy passwords that are safe for mobile keyboards,
URLs, shell/config files and copy-paste: letters and digits only (no
ambiguous glyphs) by default. Optionally add a few conservative symbols
(--symbols), never placed first or last.

Randomness comes from the OS CSPRNG via the `secrets` module.
Entropy is exact for uniform generation and is the sum of:
  - (length - symbols) * log2(alphanumeric alphabet size)
  - symbols * log2(symbol set size)
  - log2(C(length - 2, symbols))   (where the symbols are placed)
A fixed --prefix is never counted. The "at least one char per class"
policy uses rejection sampling, whose entropy loss is negligible for
normal lengths.

Copyright (C) 2026 Nicola Davide Mannarelli - @nidamanx

This program is free software: you can redistribute it and/or modify
it under the terms of the GNU Affero General Public License as published
by the Free Software Foundation, either version 3 of the License, or
(at your option) any later version.

This program is distributed in the hope that it will be useful,
but WITHOUT ANY WARRANTY; without even the implied warranty of
MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
GNU Affero General Public License for more details.

You should have received a copy of the GNU Affero General Public License
along with this program.  If not, see <https://www.gnu.org/licenses/>.

Exit codes: 0 success, 2 usage error, 3 missing requirements.

See DISCLAIMER below (also printed by --help) for security notes.
"""

from __future__ import annotations

import importlib.util
import os
import sys
from collections.abc import Callable
from typing import NamedTuple

try:
    import argparse
    import math
    import re
    import secrets
except ImportError as import_error:
    absent = [name for name in ("argparse", "math", "re", "secrets")
              if importlib.util.find_spec(name) is None]
    print(f"error: missing requirements for "
          f"{os.path.basename(sys.argv[0])}:", file=sys.stderr)
    if sys.version_info < (3, 8):  # noqa: UP036 (runtime guard, old Python)
        py_found = ".".join(str(part) for part in sys.version_info[:3])
        print(f"  - Python >= 3.8 (found {py_found})", file=sys.stderr)
    for module_name in absent or [str(import_error.name)]:
        print(f"  - Python module '{module_name}' (standard library)",
              file=sys.stderr)
    print("Install or upgrade them and run again.", file=sys.stderr)
    sys.exit(3)

__title__ = "NDM Password Generator"
__version__ = "1.1.0"
__release_date__ = "2026-10-06"
__author__ = "Nicola Davide Mannarelli - @nidamanx"
__license__ = "AGPL-3.0-or-later"

MIN_PYTHON = (3, 8)  # math.comb() needs Python 3.8

DISCLAIMER = """\
Security disclaimer:
  - Passwords are generated locally with the OS CSPRNG (secrets module).
    This script does not store, log or transmit them.
  - The entropy figure and strength label describe the generation process
    (alphabet sizes plus symbol placement). They are indicative, not a
    guarantee, and do not apply to passwords you choose or edit yourself.
  - A --prefix is fixed, guessable text: it is never counted as entropy.
  - Output may persist in terminal scrollback, logs or clipboard managers.
    Clear it, and keep the password in a password manager.
  - Never reuse a generated password across services.
  - A compromised host, a broken entropy source or screen/keyboard capture
    defeats any password.
  - Provided "as is", WITHOUT WARRANTY OF ANY KIND (see the AGPL-3.0
    license)."""

DISCLAIMER_SUMMARY = """\
Security summary (full text: --help):
  - Entropy and strength describe the generation process: indicative,
    not a guarantee.
  - Output may linger in scrollback or clipboard: keep the password in
    a password manager.
  - Never reuse a generated password. No warranty (AGPL-3.0)."""

VERSION_TEXT = (
    f"%(prog)s {__version__} (released {__release_date__})\n"
    f"Copyright (C) 2026 {__author__}\n"
    f"License: {__license__} <https://www.gnu.org/licenses/agpl-3.0.html>\n"
    "This program comes with ABSOLUTELY NO WARRANTY; "
    "see --help for the security disclaimer."
)

DESCRIPTION = "Mobile/URL/config-safe high-entropy password generator."

# Unambiguous alphabets: no I, O, l, 0, 1 (easy to misread on a phone).
UPPER = "ABCDEFGHJKLMNPQRSTUVWXYZ"
LOWER = "abcdefghijkmnopqrstuvwxyz"
DIGITS = "23456789"

# Symbol set used when --symbols N is requested (none by default): URL
# "unreserved" characters (RFC 3986) minus the tilde, which is hard to
# type on many keyboard layouts. Unlike @ # % ! $ & * ; : they do not
# break URLs with credentials, comments in config files, shell quoting
# or INI interpolation. Override with --symbol-set.
SYMBOLS = "-_."

CHARSETS: dict[str, tuple[str, ...]] = {
    "mixed": (UPPER, LOWER, DIGITS),  # default: upper + lower + digits
    "lower-digits": (LOWER, DIGITS),
    "lower": (LOWER,),                # lowercase letters only
    "digits": (DIGITS,),              # digits only (low entropy per char)
}

# Optional fixed prefix: a letter/digit, then letters, digits, . _ -
PREFIX_RE = re.compile(r"[A-Za-z0-9][A-Za-z0-9._-]{0,31}")

# Characters that can cause trouble in scripts, config files or URLs,
# with the reason. Used to warn about generated passwords (relevant
# with a custom --symbol-set).
RISKY_CHARS: dict[str, str] = {
    "!": "bash history expansion (interactive shells)",
    '"': "breaks double quoting (shell, JSON, INI, YAML)",
    "'": "breaks single quoting (shell, YAML, SQL)",
    "`": "command substitution (shell)",
    "#": "comment marker (shell, INI, env, YAML); URL fragment",
    "$": "variable expansion (shell, env files, compose files)",
    "%": "percent-encoding (URLs); INI interpolation; format strings",
    "&": "control operator (shell); query separator (URLs)",
    "(": "grouping / subshell (shell)",
    ")": "grouping / subshell (shell)",
    "*": "glob (shell)",
    "?": "glob (shell); query marker (URLs)",
    "[": "glob (shell); section marker (INI, TOML)",
    "]": "glob (shell); section marker (INI, TOML)",
    "{": "brace expansion (shell); template / flow syntax (YAML, JSON)",
    "}": "brace expansion (shell); template / flow syntax (YAML, JSON)",
    ";": "command separator (shell); parameter separator (URLs)",
    "<": "redirection (shell); markup (HTML, XML)",
    ">": "redirection (shell); markup (HTML, XML)",
    "|": "pipe (shell)",
    "\\": "escape character (shell, JSON, INI, Windows paths)",
    "^": "escape character (Windows cmd); regex anchor",
    "@": "credentials / host separator (URLs)",
    ":": "user:password and port separator (URLs); key: value (YAML)",
    "/": "path separator (URLs, filesystems)",
    "=": "key=value delimiter (env and INI files, shell assignments)",
    "+": "means a space in URL query strings",
    ",": "list separator (CSV, many config formats)",
    "~": "hard to type on many keyboard layouts",
}

# (upper bound in bits, label). Thresholds are a practical convention,
# not a standard.
RATINGS = (
    (28, "VERY WEAK"),
    (36, "WEAK"),
    (60, "FAIR"),
    (80, "STRONG"),
    (100, "VERY STRONG"),
)
TOP_RATING = "EXCELLENT"

DEFAULT_GROUPS = 4
DEFAULT_WIDTH = 4
MAX_GROUPS = 64
MAX_WIDTH = 64
MAX_SYMBOLS = 64
MAX_LENGTH = 4096

_RNG = secrets.SystemRandom()


class Plan(NamedTuple):
    """Resolved generation parameters."""

    classes: tuple[str, ...]
    alnum_size: int
    symbols: int
    symbol_set: str
    groups: int
    length: int
    bits: float


class HeaderParser(argparse.ArgumentParser):
    """ArgumentParser whose --help starts with title, version, author."""

    def format_help(self) -> str:
        header = (f"\n{__title__} v. {__version__} - {__release_date__}\n"
                  f"{DESCRIPTION}\n"
                  f"{__author__}\n\n")
        return header + super().format_help()


def check_requirements() -> None:
    """Exit with code 3 if Python or the OS random source is unusable."""
    missing: list[str] = []
    if sys.version_info < MIN_PYTHON:
        found = ".".join(str(part) for part in sys.version_info[:3])
        wanted = ".".join(str(part) for part in MIN_PYTHON)
        missing.append(f"Python >= {wanted} (found {found})")
    try:
        os.urandom(1)
    except (NotImplementedError, OSError):
        missing.append("operating system random source (os.urandom)")
    if missing:
        print(f"error: missing requirements for "
              f"{os.path.basename(sys.argv[0])}:", file=sys.stderr)
        for item in missing:
            print(f"  - {item}", file=sys.stderr)
        print("Install or upgrade them and run again.", file=sys.stderr)
        sys.exit(3)


def rate(bits: float) -> str:
    """Map an entropy value in bits to a human-readable strength label."""
    for limit, label in RATINGS:
        if bits < limit:
            return label
    return TOP_RATING


def rating_table(bits: float) -> list[str]:
    """Build the full classification scale, flagging the current band."""
    bands = []
    lower = None
    for limit, label in RATINGS:
        span = f"< {limit}" if lower is None else f"{lower} - <{limit}"
        bands.append((label, span))
        lower = limit
    bands.append((TOP_RATING, f">= {lower}"))

    current = rate(bits)
    lines = []
    for label, span in bands:
        mark = "  <-- this password" if label == current else ""
        lines.append(f"  {label:<12} {span:<10}{mark}".rstrip())
    return lines


def band_floors() -> dict[str, int]:
    """Minimum entropy (bits) to enter each strength band, by label."""
    floors = {}
    lower = 0
    for limit, label in RATINGS:
        floors[label] = lower
        lower = limit
    floors[TOP_RATING] = lower
    return floors


# CLI level names ("very-strong") mapped to their labels ("VERY STRONG").
LEVELS = {label.lower().replace(" ", "-"): label for label in band_floors()}


def resolve_symbols(length: int, symbols: int) -> int | None:
    """
    The requested number of symbols, or None if it does not fit in
    `length`. Symbols never take the first or last position.
    """
    return symbols if symbols <= max(0, length - 2) else None


def entropy_bits(length: int, alnum_size: int, symbols: int = 0,
                 symbol_set_size: int = 1) -> float:
    """Exact entropy, in bits, of a password built by generate()."""
    bits = (length - symbols) * math.log2(alnum_size)
    if symbols:
        bits += symbols * math.log2(symbol_set_size)
        bits += math.log2(math.comb(length - 2, symbols))
    return bits


def plan_groups(label: str, width: int, alnum_size: int,
                requested_symbols: int,
                symbol_set_size: int) -> int | None:
    """
    Smallest number of whole groups whose entropy reaches the requested
    band. Every group has exactly `width` characters. Returns None if
    the band cannot be reached.
    """
    floor = band_floors()[label]
    for groups in range(1, MAX_LENGTH // width + 1):
        length = groups * width
        symbols = resolve_symbols(length, requested_symbols)
        if symbols is not None and entropy_bits(
                length, alnum_size, symbols, symbol_set_size) >= floor:
            return groups
    return None


def generate(length: int, classes: tuple[str, ...], symbols: int,
             symbol_set: str) -> str:
    """
    Generate one password. Symbol positions are drawn uniformly among
    the inner positions (never first or last); every other position is
    drawn from the alphanumeric alphabet, requiring at least one char
    from each class.
    """
    alnum = "".join(classes)
    enforce = (length - symbols) >= len(classes)
    while True:
        slots = (set(_RNG.sample(range(1, length - 1), symbols))
                 if symbols else set())
        chars = [secrets.choice(symbol_set if i in slots else alnum)
                 for i in range(length)]
        body = "".join(c for i, c in enumerate(chars) if i not in slots)
        if not enforce or all(any(c in cls for c in body)
                              for cls in classes):
            return "".join(chars)


def risky_chars(text: str) -> dict[str, str]:
    """Return {char: reason} for each risky character in `text`."""
    return {c: RISKY_CHARS[c] for c in dict.fromkeys(text)
            if c in RISKY_CHARS}


def grouped(pwd: str, width: int, sep: str) -> str:
    """Split a password into fixed-width groups for readability."""
    return sep.join(pwd[i:i + width] for i in range(0, len(pwd), width))


def bounded_int(max_value: int, minimum: int = 1) -> Callable[[str], int]:
    """Build an argparse type: an integer within [minimum, max_value]."""
    def parse(value: str) -> int:
        number = int(value)
        if not minimum <= number <= max_value:
            raise argparse.ArgumentTypeError(
                f"must be between {minimum} and {max_value}")
        return number
    return parse


def prefix_text(value: str) -> str:
    """argparse type for --prefix."""
    if not PREFIX_RE.fullmatch(value):
        raise argparse.ArgumentTypeError(
            "1-32 chars: letters, digits, . _ - ; "
            "must start with a letter or digit")
    return value


def symbol_set_text(value: str) -> str:
    """argparse type for --symbol-set: printable ASCII symbols only."""
    chars = "".join(dict.fromkeys(value))  # drop duplicates, keep order
    bad = any(not (c.isascii() and c.isprintable()) or c.isalnum()
              or c == " " for c in chars)
    if not chars or bad:
        raise argparse.ArgumentTypeError(
            "must be printable ASCII symbols only "
            "(no letters, digits or spaces)")
    return chars


def build_parser() -> HeaderParser:
    """Create the command-line parser."""
    parser = HeaderParser(
        epilog=DISCLAIMER,
        formatter_class=argparse.RawDescriptionHelpFormatter,
    )
    parser.add_argument(
        "-g", "--groups", type=bounded_int(MAX_GROUPS), default=None,
        help=f"number of groups (default: {DEFAULT_GROUPS}; "
             "not combinable with --level)")
    parser.add_argument(
        "-l", "--level", choices=LEVELS,
        help="target strength: " + ", ".join(LEVELS) + "; uses the "
             "fewest whole groups that reach it (replaces --groups)")
    parser.add_argument(
        "-w", "--width", type=bounded_int(MAX_WIDTH),
        default=DEFAULT_WIDTH,
        help=f"characters per group (default: {DEFAULT_WIDTH})")
    parser.add_argument(
        "-c", "--charset", choices=CHARSETS, default="mixed",
        help="mixed = A-Z a-z 2-9 (default); lower-digits; lower; digits")
    parser.add_argument(
        "-y", "--symbols", type=bounded_int(MAX_SYMBOLS, minimum=0),
        default=0,
        help="number of symbols (default: 0 = alphanumeric only; "
             "never first or last)")
    parser.add_argument(
        "-Y", "--symbol-set", type=symbol_set_text, default=None,
        help="symbols to draw from when --symbols is used "
             f"(default: {SYMBOLS}); quote shell-special chars")
    parser.add_argument(
        "-p", "--prefix", type=prefix_text, default=None,
        help="fixed text prepended to the password (letters, digits, "
             ". _ -; max 32); adds no entropy")
    parser.add_argument(
        "-n", "--count", type=bounded_int(1000), default=1,
        help="how many passwords to generate (default: 1)")
    parser.add_argument(
        "-s", "--separator", default=" ",
        help="separator for the Readable line only (also after the "
             "prefix), never part of the password (default: space); "
             "quote shell-special chars, e.g. -s '*'")
    mode = parser.add_mutually_exclusive_group()
    mode.add_argument(
        "-q", "--quiet", action="store_true",
        help="print only the passwords, one per line (for piping)")
    mode.add_argument(
        "-v", "--verbose", action="store_true",
        help="also show generator details and the entropy scale")
    parser.add_argument("-V", "--version", action="version",
                        version=VERSION_TEXT)
    return parser


def make_plan(parser: argparse.ArgumentParser,
              args: argparse.Namespace) -> Plan:
    """Validate the options and resolve groups, length and entropy."""
    classes = CHARSETS[args.charset]
    alnum_size = sum(len(c) for c in classes)
    if args.symbol_set is not None and args.symbols == 0:
        parser.error(
            "--symbol-set has no effect without --symbols N (N > 0)")
    symbol_set = args.symbol_set or SYMBOLS

    if args.level:
        if args.groups is not None:
            parser.error("--level and --groups are mutually exclusive")
        found = plan_groups(LEVELS[args.level], args.width, alnum_size,
                            args.symbols, len(symbol_set))
        if found is None:
            parser.error(
                f"cannot reach level '{args.level}' with these options")
        groups = found
        if LEVELS[args.level] in ("VERY WEAK", "WEAK", "FAIR"):
            print(f"warning: level '{args.level}' is below STRONG",
                  file=sys.stderr)
    else:
        groups = args.groups or DEFAULT_GROUPS

    length = groups * args.width
    symbols = resolve_symbols(length, args.symbols)
    if symbols is None:
        parser.error(
            f"--symbols {args.symbols} does not fit in {length} chars "
            f"(max {max(0, length - 2)}: never first or last)")

    bits = entropy_bits(length, alnum_size, symbols, len(symbol_set))
    label = rate(bits)
    if args.level and label != LEVELS[args.level]:
        print(f"note: whole groups of {args.width} give {label} "
              f"(requested {LEVELS[args.level]})", file=sys.stderr)
    return Plan(classes, alnum_size, symbols, symbol_set, groups, length,
                bits)


def describe_entropy(plan: Plan) -> str:
    """Human-readable breakdown of the entropy figure."""
    alnum_bits = math.log2(plan.alnum_size)
    if not plan.symbols:
        return (f"{plan.length} chars x {alnum_bits:.2f} bits/char, "
                f"alphabet {plan.alnum_size}")
    plural = "s" if plan.symbols != 1 else ""
    placement = math.log2(math.comb(plan.length - 2, plan.symbols))
    return (f"{plan.length - plan.symbols} alnum x {alnum_bits:.2f} "
            f"+ {plan.symbols} symbol{plural} "
            f"x {math.log2(len(plan.symbol_set)):.2f} "
            f"+ {placement:.1f} placement")


def format_entry(body: str, prefix: str, args: argparse.Namespace,
                 plan: Plan) -> list[str]:
    """Lines describing one generated password."""
    readable = grouped(body, args.width, args.separator)
    if prefix:
        readable = prefix + args.separator + readable
    lines = [f"Password : {prefix}{body}", f"Readable : {readable}"]
    if prefix:
        lines.append(
            f"Prefix   : {prefix} (fixed text, not counted as entropy)")
    lines.append(f"Entropy  : {plan.bits:.1f} bits "
                 f"({describe_entropy(plan)})")
    lines.append(f"Strength : {rate(plan.bits)}")

    risky = risky_chars(prefix + body)
    if risky:
        lines.append("Caution  : contains characters that need care in "
                     "shell, config files or URLs:")
        lines.extend(f"             {char}  {reason}"
                     for char, reason in risky.items())
    else:
        lines.append("Safety   : no known risky characters for shell, "
                     "config files or URLs")
    return lines


def format_verbose(args: argparse.Namespace, plan: Plan) -> list[str]:
    """Generator details, strength scale and security summary."""
    lines = ["", "Generator:",
             (f"  Charset  : {args.charset}, "
              f"{plan.alnum_size} alphanumeric chars")]
    if plan.symbols:
        lines.append(f"  Symbols  : {plan.symbols} from "
                     f"\"{plan.symbol_set}\" (never first or last)")
    lines.append(f"  Layout   : {plan.groups} groups x {args.width} "
                 f"chars = {plan.length} chars")
    lines += ["", "Strength scale (bits of entropy):"]
    lines += rating_table(plan.bits)
    lines += ["", DISCLAIMER_SUMMARY]
    return lines


def main() -> int:
    """Entry point."""
    check_requirements()
    parser = build_parser()
    args = parser.parse_args()
    plan = make_plan(parser, args)
    prefix = args.prefix or ""

    flagged = 0
    flagged_chars: dict[str, str] = {}
    for i in range(args.count):
        body = generate(plan.length, plan.classes, plan.symbols,
                        plan.symbol_set)
        if args.quiet:
            print(prefix + body)
            risky = risky_chars(prefix + body)
            flagged += bool(risky)
            flagged_chars.update(risky)
            continue
        if i:
            print()
        print("\n".join(format_entry(body, prefix, args, plan)))

    if args.quiet and flagged:
        print(f"warning: {flagged} of {args.count} password(s) contain "
              f"characters that need care in shell, config files or URLs "
              f"({' '.join(flagged_chars)}); run without -q for details",
              file=sys.stderr)

    if args.verbose:
        print("\n".join(format_verbose(args, plan)))
    return 0


if __name__ == "__main__":
    sys.exit(main())
