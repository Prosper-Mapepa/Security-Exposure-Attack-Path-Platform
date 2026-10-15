# DEVELOPMENT SECURITY LAB

This application is an isolated scanner target for local development of the Security Exposure & Attack Path Platform.

It is not part of the production attack surface. Docker Compose publishes it only on `127.0.0.1` and only when the `lab` profile is enabled.

The source intentionally contains patterns security scanners are meant to detect: SQL built by string concatenation, a synthetic AWS-shaped credential (not a real account key), an object lookup without an ownership check, and a dependency with published advisories. The public AWS documentation example key is not used, because current Gitleaks rules ignore values that end in `EXAMPLE`. The running service returns a lab banner header.

Do not deploy this service to a public network.

Set `LAB_VULNERABLE=false` to make the HTTP search handler stop reflecting quote-induced database errors. To clear source findings, run `node lab/scripts/apply-fix.js`, then run the platform validation scan against `lab/`. Restore the intentionally vulnerable source with `node lab/scripts/restore-lab.js`.
