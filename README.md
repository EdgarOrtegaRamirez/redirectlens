# RedirectLens

A CLI tool for analyzing HTTP redirect chains. Detects redirect loops, excessive hops, security issues (HTTPS downgrade, mixed content), and performance implications.

## Features

- **Chain Analysis** — Follow full redirect chains and report every hop
- **Loop Detection** — Identify infinite redirect loops automatically
- **Security Checks** — Detect HTTPS downgrade, mixed content, open redirects, cookie leakage
- **Performance Metrics** — Measure per-hop and total redirect latency
- **Batch Mode** — Scan multiple URLs from a file or stdin
- **CI-Friendly** — Exit codes for strict mode, JSON output for automation
- **Multiple Output Formats** — Text (colorized), JSON, CSV, SARIF
- **Configurable** — Max hops, timeout, follow redirects depth

## Quick Start

```bash
# Build
go build -o redirectlens ./cmd/redirectlens

# Analyze a single URL
./redirectlens check https://example.com

# Analyze with JSON output
./redirectlens check https://example.com --format json

# Scan multiple URLs from a file
./redirectlens scan urls.txt

# CI-friendly strict mode (fails on security issues)
./redirectlens check https://example.com --strict

# Save results to file
./redirectlens check https://example.com --output results.json
```

## Commands

### `check` — Analyze a single URL

```bash
./redirectlens check https://example.com
./redirectlens check https://example.com --max-hops 10 --timeout 30s
./redirectlens check https://example.com --format json --output results.json
```

### `scan` — Batch scan URLs from a file

```bash
./redirectlens scan urls.txt
./redirectlens scan urls.txt --format csv --output report.csv
./redirectlens scan urls.txt --workers 10
```

### `version` — Show version info

```bash
./redirectlens version
```

## Output Formats

- **text** (default) — Colorized terminal output with human-readable chain visualization
- **json** — Machine-readable JSON for CI/automation
- **csv** — Spreadsheet-compatible format for batch reports
- **sarif** — Static Analysis Results Interchange Format for IDE integration

## Security Checks

The tool detects:

1. **HTTPS Downgrade** — Redirect from HTTPS to HTTP
2. **Mixed Content** — Chain mixes HTTPS and HTTP endpoints
3. **Open Redirect** — URL contains redirect parameters that could be exploited
4. **Cookie Leakage** — Redirect to a different domain (potential cookie exposure)
5. **Excessive Hops** — Chain length exceeds configurable threshold (default: 10)
6. **Redirect Loop** — Circular redirect detected
7. **Long Chain** — Chain exceeds 5 hops (performance warning)

## Exit Codes

| Code | Meaning |
|------|---------|
| 0 | No issues found |
| 1 | Security issues found (in `--strict` mode) |
| 2 | Parse/input error |
| 3 | Network error |

## Configuration

Create a `redirectlens.yaml` for default settings:

```yaml
max_hops: 10
timeout: 30s
workers: 5
follow_redirects: true
```

## Architecture

```
cmd/redirectlens/       — CLI entry point (Cobra)
internal/models/        — Data structures (Hop, Chain, SecurityIssue)
internal/checker/       — HTTP redirect following engine
internal/analyzer/      — Chain analysis (loops, security, performance)
internal/reporter/      — Output formatters (text, JSON, CSV, SARIF)
```

## License

MIT — See [LICENSE](LICENSE)
