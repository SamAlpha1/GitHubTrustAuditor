# Security Policy

GitHub Trust Auditor is a defensive static-analysis tool. It must never require or collect wallet seed phrases, private keys, passwords, authentication cookies, or unrelated credentials.

## Reporting a vulnerability

Please open a GitHub issue for non-sensitive security bugs. If a report would expose an active secret, do **not** paste the secret into an issue; revoke/rotate it first and describe the affected component without the value.

## Design rules

- Target repository code is never executed.
- Target dependencies are never installed.
- Potential secret values are redacted from reports.
- Private repositories are scanned only with pre-existing authorized read access and an explicit `--include-private` opt-in.
- A contribution graph, star count, fork count, follower count, or account age is never treated as proof that an account is safe.
- Static findings are indicators requiring context, not allegations about a person.
