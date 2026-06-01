# VulnerableApi — Security Scanner Practice Target

> **WARNING: This project is intentionally vulnerable.**
> Use it strictly as a target for SAST, DAST, IAST, and SCA tooling on an isolated machine.
> Do not deploy. Do not borrow code. Do not expose to a network.

An ASP.NET Core 8 Web API seeded with common CWEs so security scanners have something to find.

## Build and run

```bash
dotnet restore
dotnet build
dotnet run --project VulnerableApi
```

Swagger UI: `http://localhost:5080/swagger`

## What's in here

| Area | Endpoint(s) | CWEs you should expect to see flagged |
|---|---|---|
| SQL Injection | `GET /api/sqlinjection/user`, `GET /api/sqlinjection/search`, `POST /api/sqlinjection/login` | CWE-89, CWE-209 |
| Command Injection | `GET /api/commandinjection/ping`, `GET /api/commandinjection/nslookup` | CWE-78 |
| Path Traversal | `GET /api/pathtraversal/read`, `POST /api/pathtraversal/write`, `POST /api/pathtraversal/extract` | CWE-22, CWE-73 |
| XSS / Log Injection | `GET /api/xss/hello`, `GET /api/xss/log` | CWE-79, CWE-117 |
| XXE | `POST /api/xxe/parse` | CWE-611 |
| SSRF / Open Redirect | `GET /api/ssrf/fetch`, `GET /api/ssrf/redirect` | CWE-918, CWE-601 |
| Insecure Deserialization | `POST /api/deserialization/binary`, `POST /api/deserialization/json` | CWE-502 |
| Weak Crypto | `GET /api/crypto/md5`, `POST /api/crypto/hash-password`, `POST /api/crypto/encrypt`, `POST /api/crypto/aes-ecb`, `GET /api/crypto/token` | CWE-326, CWE-327, CWE-329, CWE-338 |
| Auth issues | `POST /api/auth/admin-login`, `GET /api/auth/profile/{userId}` | CWE-522, CWE-798, CWE-384, CWE-639 |
| App config | `Program.cs`, `appsettings.json` | CWE-209, CWE-319, CWE-942, hardcoded secrets |

The `.csproj` also pins outdated package versions so SCA tools (Snyk, Dependabot, OWASP Dependency-Check, Trivy) flag known CVEs.

## Suggested scanners to try

- SAST: Semgrep, SonarQube/SonarCloud, GitHub CodeQL, Microsoft Security Code Analysis, Snyk Code, Checkmarx
- SCA: `dotnet list package --vulnerable --include-transitive`, Snyk Open Source, OWASP Dependency-Check, Trivy
- DAST: OWASP ZAP, Burp Suite (point at `http://localhost:5080`)
- Secret scanning: gitleaks, trufflehog (the static keys in `appsettings.json` should trip these)

## Don't ship this

Seriously. Keep it on a dev VM or container. Add `VulnerableApi` to any allow-deny lists you have so it can't be deployed by accident.
