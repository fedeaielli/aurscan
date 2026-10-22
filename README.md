# aurscan

**Static risk scanner for AUR packages — inspect before you build.**

`aurscan` fetches AUR metadata, clones the package repository, parses
`PKGBUILD` and `.install` files, and highlights suspicious patterns without
ever executing package code.

It is built for the moment before `makepkg`: a fast, readable second opinion on
what a package is about to do.

[![Python 3.12+](https://img.shields.io/badge/python-3.12%2B-blue.svg)](https://www.python.org/)
[![Arch Linux](https://img.shields.io/badge/arch-linux-1793d1?logo=archlinux&logoColor=white)](https://archlinux.org/)
[![License: GPL-3.0-or-later](https://img.shields.io/badge/license-GPL--3.0--or--later-blue.svg)](LICENSE)

> **Status:** early development. The rule catalogue and scoring model may
> change between releases.

> [!WARNING]
> `aurscan` is a heuristic scanner. It does not execute package code and cannot
> prove that a package is safe. Treat its output as a risk signal, not a
> guarantee.

## Why aurscan?

AUR packages are built from user-maintained recipes. Before running
`makepkg -si`, it helps to know whether the recipe downloads something
unexpected, hides commands behind decoding, touches browser profiles or SSH
keys, writes outside `$pkgdir`, or changes hands recently.

`aurscan` answers those questions with a static AST pass, a weighted score, and
a plain-English finding for every rule that fires.

## Features

- **Static by design** — parses `PKGBUILD` and `.install` files with
  tree-sitter; never sources or executes them.
- **Architecture-aware** — tracks `source_x86_64`, `sha256sums_x86_64`, and
  other architecture-specific variables.
- **19 rules** covering downloads, obfuscation, persistence, permissions,
  sensitive paths, checksum coverage, and package metadata.
- **Weighted score** with `ok`, `review`, and `risky` verdicts.
- **Human and JSON output** — use it interactively or pipe it into CI.
- **Optional dependency scan** — follow AUR dependencies to a configurable
  depth.
- **Git history checks** — spot suspicious changes and maintainer handovers.
- **Hardened cloning** — shallow clones, no hooks, no submodules, size and
  time limits.

## Installation

### Option 1 — uv (recommended)

Install [`uv`](https://docs.astral.sh/uv/) first:

```bash
sudo pacman -S uv
```

Then clone and install the command from the checkout:

```bash
git clone https://github.com/faielli/aurscan.git
cd aurscan
uv tool install .
```

A PyPI release is planned. Once it lands, the shorter form works too:

```bash
uv tool install aurscan
```

If the command is not found afterwards, add uv's tool directory to your shell:

```bash
uv tool update-shell
```

### Option 2 — Arch package (`makepkg`)

Install the build tools, then install the AUR-only Python dependencies with
your AUR helper (for example `yay`):

```bash
sudo pacman -S --needed base-devel uv
yay -S --needed python-tree-sitter python-tree-sitter-bash
```

Clone the repository and build the package:

```bash
git clone https://github.com/faielli/aurscan.git
cd aurscan
makepkg -si
```

> [!TIP]
> This repository already contains a `src/` directory, which is also
> makepkg's default `$srcdir`. For a clean build that keeps makepkg's work
> outside the checkout, use:
>
> ```bash
> mkdir -p /tmp/aurscan-makepkg /tmp/aurscan-packages
> makepkg -si --cleanbuild \
>   BUILDDIR=/tmp/aurscan-makepkg \
>   PKGDEST=/tmp/aurscan-packages
> ```

## Usage

Scan a package:

```bash
aurscan yay
```

Scan a package and print JSON:

```bash
aurscan yay --json
```

Follow dependencies up to two levels:

```bash
aurscan yay --deps --depth 2
```

Ask what a rule does:

```bash
aurscan --explain R01
aurscan --explain M01
```

## Example output

```text
aurscan: demo  (version 1.0-1)
Risk: REVIEW (35/100) ███████░░░░░░░░░░░░░

Metadata
maintainer       someone
votes            42
...

Findings
          rule  location      finding
[MEDIUM]  R04   PKGBUILD:12   source host mirror.invalid differs from upstream host example.invalid
[LOW]     R06   PKGBUILD:4    source/checksum count mismatch for sha256sums
```

`[HIGH]` findings are red, `[MEDIUM]` yellow, `[LOW]` cyan, and `[INFO]` dim.

## Options

| Option | Meaning |
| --- | --- |
| `--json` | Print a machine-readable report instead of the human report. |
| `--timeout SECONDS` | Timeout for AUR requests and each clone attempt. |
| `--deps` | Also scan AUR dependencies. |
| `--depth N` | Dependency depth to scan, from `1` to `5`. |
| `--include-make` | Include `makedepends` when scanning dependencies. |
| `--max-deps N` | Maximum number of dependencies to scan. |
| `--no-cache` | Ignore the on-disk response cache. |
| `--no-history` | Skip git history checks. |
| `--explain RULE_ID` | Print the full description of a rule and exit. |

Exit codes:

| Code | Meaning |
| --- | --- |
| `0` | `ok` |
| `1` | `review` |
| `2` | `risky` |
| `3` | error or invalid command line |

## How it works

1. Fetch package metadata from the AUR RPC API.
2. Clone the AUR repository with a hardened `git` invocation.
3. Parse `PKGBUILD` and `.install` files with tree-sitter-bash.
4. Run the rule catalogue over the parsed commands.
5. Combine findings into a weighted `0`–`100` score and a verdict:
   `ok`, `review`, or `risky`.

The score is capped by severity, so a single high-severity finding cannot be
hidden by many low-severity ones. Weights and thresholds live in
[`config/scoring.yml`](config/scoring.yml).

## Rule catalogue

<details>
<summary><strong>Show all rules</strong></summary>

| ID | Severity | Checks |
| --- | --- | --- |
| `M01` | medium | Recent author change on a currently orphaned package. |
| `M02` | low | New package with no votes. |
| `M03` | low | Package marked out of date. |
| `M04` | low | Zero-vote, zero-popularity package that already has a high finding. |
| `R01` | high | `curl`/`wget` output piped into a shell. |
| `R02` | high | Encoded content decoded and then executed. |
| `R03` | medium | `eval`/`exec` with variable or substitution input. |
| `R04` | medium | Source host differs from the upstream project URL. |
| `R05` | medium | Source fetched over plain HTTP or from a literal IP address. |
| `R06` | low | `SKIP` checksum on a non-VCS source, or source/checksum count mismatch. |
| `R07` | medium | Network command in `prepare`, `build`, or `package`. |
| `R08` | high | Cron, shell-startup, loader, autostart, or service persistence. |
| `R09` | high | `chmod` that sets the setuid or setgid bit (removing them is not flagged). |
| `R10` | medium | Absolute write destination in `package()` outside `$pkgdir`. |
| `R11` | high | Risky command inside an `.install` hook. |
| `R12` | medium | High-entropy strings, escape runs, or escape-heavy `printf`. |
| `R13` | high | Reverse shells, netcat execution, or FIFO/netcat pairs. |
| `R14` | high | Access to SSH/GPG/AWS keys, browser profiles, or crypto wallets. |
| `R15` | medium | `install=` declared in the PKGBUILD but missing from the clone. |

</details>

Run `aurscan --explain RULE_ID` for the full description of any rule.

## Known limits

- Static analysis cannot see runtime behaviour, downloaded payloads, or
  commands generated dynamically by a build.
- Variables are not expanded for reporting; findings show the raw source slice.
- If the repository cannot be cloned, the report falls back to metadata-only
  analysis and says so. Content rules and history checks are then unavailable.
- With history enabled the clone includes the last 10 commits, so it can be
  larger than a content-only clone. If the repository exceeds 50 MiB or the
  clone times out, aurscan retries once at depth 1 without history: analysis
  continues on content only, and `history skipped: ...` appears in the report
  errors.
- Architecture-specific variables such as `source_x86_64` and
  `sha256sums_x86_64` are tracked explicitly, but arbitrary computed variable
  names are not resolved.
- AUR metadata can be stale, and maintainer history is limited to the commits
  available from the shallow clone.
- Rules are heuristics. Investigate every `risky` result and treat `ok` as
  low-risk, not as a guarantee.

## Development

```bash
git clone https://github.com/faielli/aurscan.git
cd aurscan
uv sync
uv run pytest
uv run ruff check .
uv run mypy src
```

Tests never use the real network: HTTP calls are mocked with `respx`, and clone
tests use local throwaway repositories.

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

Commit messages follow
`feat/fix/docs/test/refactor(scope): description (Mx)`.

## License

Copyright (C) 2026 faielli.

aurscan is free software: you can redistribute it and/or modify it under the
terms of the GNU General Public License as published by the Free Software
Foundation, either version 3 of the License, or (at your option) any later
version.

See [LICENSE](LICENSE) for the full text.
