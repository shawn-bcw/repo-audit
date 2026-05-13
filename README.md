# repo-audit

A CLI that scans sibling directories for npm, pnpm, and Cargo repositories and audits them for package vulnerabilities.

## Install

```bash
cargo build --release
cp target/release/repo-audit /usr/local/bin/
```

## Usage

Place the binary in (or run from) a root directory that contains multiple repositories:

```
/your-projects/
├── frontend-app/        # has pnpm-lock.yaml
├── backend-api/         # has package-lock.json
├── cli-tool/            # has Cargo.lock
└── repo-audit           # <- run from here
```

### Full audit

Scans every sibling repo and reports vulnerability counts by severity.

```bash
repo-audit
repo-audit --dir /path/to/projects
repo-audit --verbose
```

```
┌─────────────────────┬─────┬────────┬──────┬──────────┬───────┐
│ repo                ┆ low ┆ medium ┆ high ┆ critical ┆ total │
╞═════════════════════╪═════╪════════╪══════╪══════════╪═══════╡
│ backend-api         ┆ 0   ┆ 1      ┆ 2    ┆ 0        ┆ 3     │
├╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌┼╌╌╌╌╌┼╌╌╌╌╌╌╌╌┼╌╌╌╌╌╌┼╌╌╌╌╌╌╌╌╌╌┼╌╌╌╌╌╌╌┤
│ frontend-app        ┆ 3   ┆ 42     ┆ 25   ┆ 0        ┆ 70    │
├╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌┼╌╌╌╌╌┼╌╌╌╌╌╌╌╌┼╌╌╌╌╌╌┼╌╌╌╌╌╌╌╌╌╌┼╌╌╌╌╌╌╌┤
│ cli-tool            ┆ 0   ┆ 0      ┆ 1    ┆ 0        ┆ 1     │
└─────────────────────┴─────┴────────┴──────┴──────────┴───────┘
```

### Advisory check

Check repos against a specific GitHub Security Advisory or CVE.

```bash
# Global advisory URL
repo-audit --advisory https://github.com/advisories/GHSA-qwcr-r2fm-qrc7

# Repository-specific advisory URL
repo-audit --advisory https://github.com/TanStack/router/security/advisories/GHSA-g7cv-rxg3-hmpx

# NVD/CVE URL
repo-audit --advisory https://nvd.nist.gov/vuln/detail/CVE-2024-48949

# Multiple advisories
repo-audit --advisory <url1> --advisory <url2>
```

Shows which repos contain the affected package and whether the installed version is vulnerable. Also lists related packages from the same scope (e.g., other `@tanstack/*` packages) as `Clean`:

```
Advisory: GHSA-qwcr-r2fm-qrc7
Affected: body-parser < 1.20.3 (npm)

┌───────────────────┬───────────────────┬────────────────┐
│ repo              ┆ package           ┆ status         │
╞═══════════════════╪═══════════════════╪════════════════╡
│ backend-api       ┆ body-parser@1.19.0┆ Vulnerable     │
├╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌┼╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌┼╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌┤
│ frontend-app      ┆ body-parser@1.20.3┆ Not vulnerable │
├╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌┼╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌┼╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌┤
│ cli-tool          ┆ —                 ┆ Not found      │
└───────────────────┴───────────────────┴────────────────┘
```

## Supported ecosystems

| Ecosystem | Lockfile | Audit tool | Full audit | Advisory check |
|-----------|----------|------------|------------|----------------|
| npm | `package-lock.json` | `npm audit` | Yes | Yes |
| pnpm | `pnpm-lock.yaml` | `pnpm audit` | Yes | Yes |
| Cargo | `Cargo.lock` | `cargo audit` | Yes | Yes |

When both `pnpm-lock.yaml` and `package-lock.json` exist, pnpm takes priority.

## Missing tools

If a required tool isn't installed, the CLI warns and skips those repos instead of failing:

```
warning: cargo-audit is not installed — skipping Cargo repos
  Install with: cargo install cargo-audit
```

## Exit codes

| Code | Meaning |
|------|---------|
| 0 | No vulnerabilities found |
| 1 | Vulnerabilities found |
| 2 | Runtime error (no repos, bad URL, etc.) |

## Options

```
--dir <DIR>            Root directory to scan (defaults to cwd)
--advisory <URL>       Advisory URL to check (repeatable)
--verbose              Show scan details and raw audit commands
-h, --help             Print help
```
