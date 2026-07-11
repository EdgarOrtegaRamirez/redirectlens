# RedirectLens — AI Agent Notes

## Project Overview

redirectlens is a Go CLI tool that analyzes HTTP redirect chains to detect loops, security issues, and performance problems.

## Architecture

```
cmd/redirectlens/main.go     — CLI entry point (Cobra)
internal/models/             — Data structures
internal/checker/            — HTTP redirect following
internal/analyzer/           — Security + performance analysis
internal/reporter/           — Output formatting (text/json/csv/sarif)
```

## Key Design Decisions

1. **No external network by default in tests** — Uses `httptest.NewServer` for all HTTP testing
2. **Chain length limited** — Max 10 hops by default to prevent DoS
3. **Strict mode as CI flag** — Security issues cause non-zero exit only in `--strict`
4. **Format selection via flags** — No interactive prompts, CLI-only

## Building

```bash
go build -o redirectlens ./cmd/redirectlens
```

## Running Tests

```bash
# All tests
go test ./... -v -race

# Specific package
go test ./internal/checker/ -v -race
go test ./internal/analyzer/ -v -race
```

## Common Tasks

### Adding a new redirect hop detail
1. Add field to `Hop` struct in `internal/models/models.go`
2. Capture data in `internal/checker/checker.go` `FollowChain()`
3. Add to JSON reporter in `internal/reporter/json_reporter.go`
4. Add tests

### Adding a new security check
1. Add issue type to `IssueType` enum in `internal/models/models.go`
2. Add check function in `internal/analyzer/analyzer.go`
3. Add to `AnalyzeChain()` method
4. Add tests in `internal/analyzer/analyzer_test.go`

## Error Handling

- Use `errors.New` for simple errors
- Use `fmt.Errorf` with `%w` for wrapped errors
- Never use bare `recover()` — handle panics explicitly
- Network errors return error code 3
