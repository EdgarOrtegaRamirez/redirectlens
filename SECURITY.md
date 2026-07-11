# Security

## Security Policy

### Reporting a Vulnerability

If you discover a security vulnerability, please **do not open a public issue**. Instead:

1. Email: Use GitHub's security advisory feature at [Security Advisory](https://github.com/EdgarOrtegaRamirez/redirectlens/security/advisories/new)
2. Include a description of the vulnerability and steps to reproduce
3. Allow 72 hours for an initial response

### What Constitutes a Vulnerability

- Uncontrolled resource consumption (DoS via malicious redirect chains)
- Path traversal in URL handling
- Insecure defaults (e.g., following HTTPS-downgrade redirects without warning)
- Information disclosure through error messages

### Mitigations

- **Max hops** is enforced to prevent DoS via infinite redirects (default: 10)
- **Timeout** limits resource consumption per request (default: 30s)
- **Strict mode** warns on HTTPS downgrade by default
- **URL validation** rejects malformed URLs
- **Error sanitization** prevents leaking internal server details

### Dependencies

All dependencies are pinned to specific versions. Run `go mod audit` to check for known vulnerabilities.
