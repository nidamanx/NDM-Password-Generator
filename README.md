# NDM Password Generator

[![Python](https://img.shields.io/badge/python-3.8%2B-blue.svg)](https://www.python.org/)
[![License: AGPL v3+](https://img.shields.io/badge/license-AGPL--3.0--or--later-blue.svg)](https://www.gnu.org/licenses/agpl-3.0.html)
[![Dependencies](https://img.shields.io/badge/dependencies-none-brightgreen.svg)](#requirements)

A single-file, dependency-free command-line generator of **high-entropy
passwords that are safe for mobile keyboards, URLs, shell and config files**.

Passwords are alphanumeric by default (no ambiguous glyphs), grouped for easy
reading, and **every result comes with a measured entropy and a strength
label** (`WEAK`, `STRONG`, `EXCELLENT`, ...). Optional symbols, a fixed prefix
and a target strength level are available.

> **License:** AGPL-3.0-or-later

---

## Table of contents

- [Features](#features)
- [Requirements](#requirements)
- [Quick start](#quick-start)
- [Usage](#usage)
- [Understanding the output](#understanding-the-output)
- [Entropy and strength levels](#entropy-and-strength-levels)
- [Symbols and risky characters](#symbols-and-risky-characters)
- [Security notes](#security-notes)
- [Things to watch out for](#things-to-watch-out-for)
- [Exit codes](#exit-codes)
- [Quality checks](#quality-checks)
- [Disclaimer](#disclaimer)
- [License](#license)
- [Author](#author)

---

## Features

- **Cryptographically secure**: randomness comes from the OS CSPRNG through
  Python's `secrets` module. No seed, no stored state, no network, no files.
- **Safe to type and paste**: letters and digits only by default, without the
  easily misread `I`, `O`, `l`, `0` and `1` (57-character alphabet).
- **Readable**: output is split into groups (default: 4 groups of 4) that you
  can dictate or type on a phone. The separator is for display only and is
  never part of the password.
- **Measured entropy**: exact for the way the password is generated, reported
  in bits, together with a strength classification.
- **Pick a strength, not a length**: `--level strong|very-strong|excellent|...`
  picks the fewest whole groups that reach it.
- **Optional symbols**: a conservative default set (`-_.`), never placed first
  or last, with exact entropy accounting for their placement.
- **Optional fixed prefix** (e.g. `ndm-`), reported as adding no entropy.
- **Risky-character warning**: tells you if a generated password contains
  characters that need care in shell, config files or URLs.
- **Requirements check**: exits with a clear message if something is missing.

## Requirements

- **Python 3.8 or newer** (uses `math.comb`).
- Python standard library only (`argparse`, `math`, `re`, `secrets`, ...).
  There is nothing to `pip install`.
- A working operating-system random source (`os.urandom`).

If something is missing, the script prints what and exits with code `3`.

> Python older than 3.7 cannot even parse the file, so the friendly message
> cannot be shown there.

## Quick start

```bash
# Download the script, then:
chmod +x ndm_password-generator.py

# Optional: record a checksum to detect later tampering
sha256sum ndm_password-generator.py

# Generate one password (4 groups of 4, 93.3 bits, VERY STRONG)
./ndm_password-generator.py
```

Example output:

```text
Password : 85bkDQbZwJCK9hkt
Readable : 85bk DQbZ wJCK 9hkt
Entropy  : 93.3 bits (16 chars x 5.83 bits/char, alphabet 57)
Strength : VERY STRONG
Safety   : no known risky characters for shell, config files or URLs
```

**Use the `Password` line.** `Readable` only exists to make the password
easier to read or dictate.

## Usage

```text
ndm_password-generator.py [-h] [-g GROUPS] [-l LEVEL] [-w WIDTH]
                          [-c {mixed,lower-digits,lower,digits}]
                          [-y SYMBOLS] [-Y SYMBOL_SET] [-p PREFIX]
                          [-n COUNT] [-s SEPARATOR] [-q | -v] [-V]
```

### Options

<!-- Column 1 is kept wide on purpose by the &nbsp; padding in the header cell,
     so option names never wrap. Do not remove it. -->
| Option&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp; | Default | Description |
|---|---|---|
| `-g, --groups N` | `4` | Number of groups (1-64). Cannot be combined with `--level`. |
| `-w, --width N` | `4` | Characters per group (1-64). |
| `-l, --level L` | - | Target strength: `very-weak`, `weak`, `fair`, `strong`, `very-strong`, `excellent`. Uses the fewest whole groups that reach it. |
| `-c, --charset C` | `mixed` | `mixed` (A-Z a-z 2-9), `lower-digits`, `lower`, `digits`. |
| `-y, --symbols N` | `0` | Number of symbols to include (0-64). Never first or last. `0` = alphanumeric only. |
| `-Y, --symbol-set S` | `-_.` | Symbols to draw from. Requires `-y N` with N > 0. Printable ASCII, no letters, digits or spaces. |
| `-p, --prefix TEXT` | - | Fixed text prepended to the password: letters, digits, `.` `_` `-`; 1-32 chars; must start with a letter or digit. Adds no entropy. |
| `-n, --count N` | `1` | How many passwords to generate (1-1000). |
| `-s, --separator S` | space | Separator for the `Readable` line only (also placed after the prefix). Never part of the password. |
| `-q, --quiet` | off | Print only the passwords, one per line (for pipes). Warnings go to stderr. |
| `-v, --verbose` | off | Also show generator details, the strength scale and a security summary. |
| `-V, --version` | - | Show version, release date, copyright and license. |
| `-h, --help` | - | Show help, including the full security disclaimer. |

`-q` and `-v` are mutually exclusive.

### Examples

```bash
# Default: 16 characters, ~93 bits
./ndm_password-generator.py

# Ask for a strength instead of a length
./ndm_password-generator.py -l excellent

# 5 groups of 5, shown with dashes (the dashes are NOT part of the password)
./ndm_password-generator.py -g 5 -w 5 -s -

# Add 2 symbols (never first or last)
./ndm_password-generator.py -y 2

# Custom symbol set (see the notes about risky characters)
./ndm_password-generator.py -y 3 -Y '+='

# Fixed prefix, shown as "ndm- xxxx xxxx xxxx"
./ndm_password-generator.py -p ndm- -g 3

# Digits only, at least STRONG
./ndm_password-generator.py -c digits -l strong

# Five passwords, passwords only (for scripts and pipes)
./ndm_password-generator.py -q -n 5

# Show the full strength scale and security summary
./ndm_password-generator.py -v
```

> **Quote shell-special characters** in `-s` and `-Y`, for example `-s '*'`.
> Unquoted `*` is expanded by the shell, and an unquoted `;` splits the
> command. Single quotes are the safest default.

## Understanding the output

| Line | Meaning |
|---|---|
| `Password` | The real password. This is what you set on the service. |
| `Readable` | The same password split into groups (and a prefix followed by the separator). For reading and dictation only. |
| `Prefix` | Shown only with `-p`: fixed text, not counted as entropy. |
| `Entropy` | Entropy in bits, with a breakdown. |
| `Strength` | Classification of the entropy (see below). |
| `Caution` / `Safety` | Whether the password contains characters that need care in shell, config files or URLs. |

When you set the password somewhere, **enter the `Password` line without
separators.** If you typed the separators, they would become part of the
password (spaces included).

## Entropy and strength levels

Entropy is computed from the generation process and is exact for uniform
random generation:

```text
entropy = (length - symbols) * log2(alphanumeric alphabet size)
        + symbols * log2(symbol set size)
        + log2( C(length - 2, symbols) )        # where the symbols are placed
```

Without symbols this reduces to `length * log2(alphabet size)`. A fixed prefix
is **never** counted.

### Classification

| Entropy (bits) | Strength |
|---|---|
| < 28 | `VERY WEAK` |
| 28 to < 36 | `WEAK` |
| 36 to < 60 | `FAIR` |
| 60 to < 80 | `STRONG` |
| 80 to < 100 | `VERY STRONG` |
| >= 100 | `EXCELLENT` |

These thresholds are a practical convention, **not** an official standard.
You can adjust them in the `RATINGS` tuple.

### Typical results (`mixed` charset, 57-character alphabet, width 4)

| Command | Length | Entropy | Strength |
|---|---|---|---|
| `-l strong` | 12 | 70.0 bits | `STRONG` |
| *(default)* / `-l very-strong` | 16 | 93.3 bits | `VERY STRONG` |
| `-l excellent` | 20 | 116.7 bits | `EXCELLENT` |
| `-y 2` | 16 | 91.3 bits | `VERY STRONG` |
| `-c digits` | 16 | 48.0 bits | `FAIR` |

### How `--level` works

- It picks the **fewest whole groups** that reach the requested band. Every
  group always has exactly `--width` characters, never a shorter last group.
- The level is therefore a **minimum**. With some widths the result lands in a
  higher band, and a note is printed on stderr, for example:
  `note: whole groups of 4 give FAIR (requested WEAK)`.
- `very-weak`, `weak` and `fair` print a warning on stderr
  (`level '...' is below STRONG`). Use them only when you know why.
- `--level` replaces `--groups`; using both is an error.

## Symbols and risky characters

Symbols are **off by default**. With `-y N` the script adds N symbols from the
symbol set, placed at random inner positions (never first or last). The default
set is `-_.`, chosen because these characters are URL-unreserved characters
(RFC 3986) and do not break credentials in URLs, comments in config files,
shell quoting or INI interpolation. The tilde is deliberately excluded because
it is hard to type on many keyboard layouts.

No symbol set is accepted everywhere. If a site rejects the default set, use
`-Y` with another one, and read the warnings.

For every generated password the script checks for characters known to cause
trouble and tells you why:

<details>
<summary>Characters flagged as risky (click to expand)</summary>

| Char | Why it needs care |
|---|---|
| `!` | bash history expansion (interactive shells) |
| `"` | breaks double quoting (shell, JSON, INI, YAML) |
| `'` | breaks single quoting (shell, YAML, SQL) |
| `` ` `` | command substitution (shell) |
| `#` | comment marker (shell, INI, env, YAML); URL fragment |
| `$` | variable expansion (shell, env files, compose files) |
| `%` | percent-encoding (URLs); INI interpolation; format strings |
| `&` | control operator (shell); query separator (URLs) |
| `(` `)` | grouping / subshell (shell) |
| `*` | glob (shell) |
| `?` | glob (shell); query marker (URLs) |
| `[` `]` | glob (shell); section marker (INI, TOML) |
| `{` `}` | brace expansion (shell); template / flow syntax (YAML, JSON) |
| `;` | command separator (shell); parameter separator (URLs) |
| `<` `>` | redirection (shell); markup (HTML, XML) |
| `\|` | pipe (shell) |
| `\` | escape character (shell, JSON, INI, Windows paths) |
| `^` | escape character (Windows cmd); regex anchor |
| `@` | credentials / host separator (URLs) |
| `:` | user:password and port separator (URLs); key: value (YAML) |
| `/` | path separator (URLs, filesystems) |
| `=` | key=value delimiter (env and INI files, shell assignments) |
| `+` | means a space in URL query strings |
| `,` | list separator (CSV, many config formats) |
| `~` | hard to type on many keyboard layouts |

</details>

With `-q`, a single warning listing the characters found is printed on stderr
at the end, so pipes stay clean. The list is **not exhaustive**: "no known
risky characters" means none of the characters above, not a guarantee for every
context.

## Security notes

### How it works

- Every character is drawn with `secrets.choice`, which uses the operating
  system CSPRNG (`getrandom(2)` on Linux). There is **no seed and no internal
  state**: `SystemRandom.seed()` has no effect and `getstate()` is not
  implemented. A password cannot be traced back to a seed.
- The script does not read the time, hostname, files or network, so a password
  carries no information about the machine, user or moment of creation.
- Characters are chosen with rejection sampling, so there is no modulo bias.
  The "at least one upper, lower and digit" policy also uses rejection
  sampling; its entropy loss is negligible for normal lengths.
- Symbol positions are drawn uniformly among the inner positions.
- Checked with `strace` on Linux (Python 3.13): no network syscalls, and
  random bytes come from `getrandom`. You can repeat the check:

  ```bash
  strace -f -qq -e trace=getrandom,socket,connect ./ndm_password-generator.py -q
  ```

- Statistical checks (uniform symbol positions, no symbol at the ends, all
  character classes present) were run during development. They are sanity
  checks, not a proof of randomness: the guarantee comes from the OS CSPRNG.

## Things to watch out for

1. **Use the `Password` line**, not `Readable`. Separators are display-only.
2. **Output can linger.** Terminal scrollback, clipboard managers and session
   logs (`tmux`, `script`) may keep it. Prefer `-q` piped straight to its
   destination, and keep passwords in a password manager:

   ```bash
   ./ndm_password-generator.py -q | wl-copy
   ./ndm_password-generator.py -q | pass insert -e site/name
   ```

   These are examples; adapt them to your platform and tools.
3. **`-p`, `-s` and `-Y` are visible** in the process list
   (`/proc/PID/cmdline` is world-readable by default) and in shell history.
   They are not secret by design: **never put secrets in the prefix.** The
   password itself is never in the command line or environment. To keep a
   command out of bash history, use `HISTCONTROL=ignorespace` and start the
   command with a space.
4. **A prefix adds no entropy.** It is fixed, guessable text. Strength is
   computed on the random part only.
5. **Entropy applies only to passwords generated by this script.** If you edit
   or choose a password yourself, the figure no longer applies.
6. **Never reuse a generated password.** One password per service.
7. **Check site rules.** Some sites limit length, refuse some symbols or require
   specific ones. No symbol set is universally accepted.
8. **Verify the script's integrity.** If someone replaced `secrets` with a
   seeded `random`, the output would look identical but be predictable. Keep
   a checksum or a signed git tag, and restrict write permissions on the file.
9. **VMs, snapshots and clones.** Behaviour depends on kernel and hypervisor
   versions. Verify that your environment reseeds the kernel RNG after a
   restore or clone.
10. **A compromised host defeats any password**: malware, keyloggers, screen
    capture or a broken entropy source.
11. **Levels are minimums.** A level can overshoot into a higher band because
    groups are always whole. Read the `Strength` line.

## Exit codes

| Code | Meaning |
|---|---|
| `0` | Success |
| `2` | Usage error (invalid or conflicting options) |
| `3` | Missing requirements (Python version, standard-library module, OS random source) |

## Quality checks

The script was checked with the following tools, all passing at the time of
release (run on Python 3.13):

| Tool | Setting | Result |
|---|---|---|
| `pycodestyle` | PEP 8, 79 columns | clean |
| `flake8` | default + complexity <= 10 | 0 findings |
| `pylint` | default | 10.00 / 10 |
| `mypy` | `--strict` | no issues |
| `ruff` | default | clean |
| `bandit` | security scan | 0 issues |
| `vermin` | minimum Python version | 3.8 |

The file also parses with the Python 3.8 grammar. It was not executed on a real
3.8 interpreter.

## Disclaimer

> **Security disclaimer**
>
> - Passwords are generated locally with the OS CSPRNG (`secrets` module).
>   This script does not store, log or transmit them.
> - The entropy figure and strength label describe the generation process
>   (alphabet sizes plus symbol placement). They are indicative, not a
>   guarantee, and do not apply to passwords you choose or edit yourself.
> - A `--prefix` is fixed, guessable text: it is never counted as entropy.
> - Output may persist in terminal scrollback, logs or clipboard managers.
>   Clear it, and keep the password in a password manager.
> - Never reuse a generated password across services.
> - A compromised host, a broken entropy source or screen/keyboard capture
>   defeats any password.
> - Provided "as is", **WITHOUT WARRANTY OF ANY KIND** (see the AGPL-3.0
>   license).

## License

Copyright (C) 2026 Nicola Davide Mannarelli - @nidamanx

This program is free software: you can redistribute it and/or modify it under
the terms of the **GNU Affero General Public License** as published by the Free
Software Foundation, either version 3 of the License, or (at your option) any
later version.

This program is distributed in the hope that it will be useful, but **WITHOUT
ANY WARRANTY**; without even the implied warranty of MERCHANTABILITY or FITNESS
FOR A PARTICULAR PURPOSE. See the GNU Affero General Public License for more
details.

You should have received a copy of the GNU Affero General Public License along
with this program. If not, see <https://www.gnu.org/licenses/>.

SPDX-License-Identifier: `AGPL-3.0-or-later`

> When distributing the script, include a copy of the full license text
> (`LICENSE`): <https://www.gnu.org/licenses/agpl-3.0.txt>

## Author

**Nicola Davide Mannarelli** - @nidamanx
