# aurscan

`aurscan` is a static risk scanner for AUR packages. It fetches AUR metadata,
clones the package repository, parses `PKGBUILD` and `.install` files, and
reports suspicious patterns without ever executing package code.

The scanner is deliberately conservative: it reads source text and builds an
AST, so the result is a **risk signal**, not a proof that a package is safe.

## Installation

On Arch Linux:

```bash
sudo pacman -S uv
uv tool install aurscan
```

From a checkout:

```bash
git clone https://github.com/example/aurscan.git
cd aurscan
uv sync
uv run aurscan <package>
```

Requirements: Python 3.12+, `git`, and network access to
`aur.archlinux.org` and AUR package repositories.

## Usage

```bash
aurscan <package>
aurscan <package> --json
aurscan <package> --timeout 30
aurscan <package> --no-history
aurscan --explain R01
```

Common options:

| Option | Meaning |
| --- | --- |
| `--json` | Print a machine-readable report instead of the human report. |
| `--timeout SECONDS` | Network timeout for AUR requests and the package clone. |
| `--max-deps N` | Maximum number of dependencies to scan. |
| `--no-cache` | Ignore the on-disk response cache. |
| `--no-history` | Skip the git history checks. |
| `--no-color` | Disable ANSI colours. |
| `--explain RULE_ID` | Print the full description of a rule and exit. |

Exit codes:

| Code | Meaning |
| --- | --- |
| `0` | `ok` |
| `1` | `review` |
| `2` | `risky` |
| `3` | error or invalid command line |

Example human output:

```text
aurscan: demo (version 1.0-1)
Risk: REVIEW (35/100) ███████░░░░░░░░░░░░░

Findings
  [MEDIUM]  R04  source host mirror.invalid differs from upstream host example.invalid  PKGBUILD:12
  [LOW]     R06  source/checksum count mismatch for sha256sums                          PKGBUILD:4

Dependencies
  none
```

## How it works

1. Fetch package metadata from the AUR RPC API.
2. Clone the AUR repository with a hardened `git` invocation.
3. Parse `PKGBUILD` and `.install` files with tree-sitter-bash.
4. Run the rule catalogue over the parsed commands.
5. Combine findings into a weighted `0`-`100` score and a verdict:
   `ok`, `review`, or `risky`.

The score is capped by severity so a single high-severity finding cannot be
hidden by many informational ones. Weights and thresholds live in
`config/scoring.yml`.

## Known limits

- Static analysis cannot see runtime behaviour, downloaded payloads, or
  commands generated dynamically by a build.
- Variables are not expanded for reporting; findings show the raw source slice.
- If the repository cannot be cloned, the report falls back to metadata-only
  analysis and says so. Content rules and history checks are then unavailable.
- Architecture-specific variables such as `source_x86_64` and
  `sha256sums_x86_64` are tracked explicitly, but arbitrary computed variable
  names are not resolved.
- AUR metadata can be stale, and maintainer history is limited to the commits
  available from the shallow clone.
- Rules are heuristics. Investigate every `risky` result and treat `ok` only as
  low-risk, not as a guarantee.

## Contributing rules

Rules are small Python functions in `src/aurscan/rules/`. Register one with
`@register("RXX", Severity.MEDIUM)` and give it a clear docstring: the same
docstring is printed by `aurscan --explain RXX`.

A rule should:

- read only parsed commands and metadata;
- never execute a `PKGBUILD` or `.install` file;
- return `Finding` objects with a stable `rule_id`, severity, file, and line;
- include tests in `tests/`, plus a suspicious fixture that triggers it and a
  benign fixture that must stay quiet.

Before opening a pull request:

```bash
uv run pytest
uv run ruff check .
uv run mypy src
```

Tests must not use the real network; use `respx` and local fixtures. Commit
messages follow `feat/fix/docs/test/refactor(scope): description (Mx)`.
