# Scanners

Each adapter implements `scan`, `getStatus`, `parseResults`, and `normalizeFinding`.

| Scanner | Target | Captured fields |
| --- | --- | --- |
| Semgrep | Path or cloned git repository | Rule id, file, line, severity, message, CWE |
| Trivy | Filesystem or container image | CVE, package, installed version, fixed version, severity, CVSS, references |
| OWASP ZAP | URL, through the ZAP API. Start the `zap` Compose profile; it is not part of the default stack. | URL, parameter, risk, confidence, CWE, evidence, remediation |
| Gitleaks | Path or cloned git repository | Secret type, file, line, commit, fingerprint. The secret value is discarded. Directories that are not git checkouts are scanned with `--no-git`. |

Bundled Semgrep rules live in `packages/scanner-adapters/rules`. Set `SEMGREP_CONFIG` to a registry ruleset such as `auto` only when the worker has network access. The default `bundled` uses the local rules.

`GET /api/scanners` reports whether each tool is actually available. A missing binary fails the scan job with an error. It does not invent findings.

Gitleaks evidence stored by the platform uses `[REDACTED]` in place of the matched value.

The product CI gate scans application code only. `lab/` and `tests/fixtures/` are intentional vulnerable targets and are excluded by `.semgrepignore`, `.gitleaks.toml`, and the workflow `--skip-dirs` flags. Point a platform scan at `lab/` when you want those findings.
