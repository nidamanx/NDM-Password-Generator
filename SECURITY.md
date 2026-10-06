# Security Policy

## Supported versions

Only the latest release receives fixes.

| Version | Supported |
| ------- | --------- |
| latest  | yes       |
| older   | no        |

## Reporting a vulnerability

Please **do not open a public issue** for security problems.

Use GitHub's private reporting instead: open the **Security** tab of this
repository and click **Report a vulnerability**. You will get a private
channel with the maintainer.

Useful details to include:

- script version (`./ndm_password-generator.py -V`) and Python version;
- operating system;
- steps to reproduce, or a minimal proof of concept;
- the impact you expect (for example "biased output" or "wrong entropy").

## What is in scope

- Flaws in randomness handling (bias, predictability, state or seed leaks).
- Wrong entropy calculation or wrong strength classification.
- Output that bypasses the documented character policy.
- Unsafe handling of arguments or environment that leaks secrets beyond what
  is documented in the README ("Security notes").

## What is out of scope

- Exposure of passwords through terminal scrollback, clipboard managers,
  shell history, or `ps` output when `-p`, `-s` or `-Y` are used: these
  behaviours are documented in the README.
- Weaknesses of the host OS random number generator.
- Strength ratings being a convention rather than a standard.

## Disclosure

This is a personal project maintained on a best-effort basis. Reports are
acknowledged as soon as reasonably possible and fixes are released before any
public disclosure.
