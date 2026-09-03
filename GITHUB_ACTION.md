# GitHub Trust Auditor Action

Use GitHub Trust Auditor directly inside a GitHub Actions workflow.

Maintained by [SamAlpha1](https://github.com/SamAlpha1) · [@samalpha_ on X](https://x.com/samalpha_)

## Quick start

```yaml
name: GitHub Trust Audit

on:
  workflow_dispatch:
    inputs:
      username:
        description: GitHub username to audit
        required: true

permissions:
  contents: read

jobs:
  audit:
    runs-on: ubuntu-latest
    steps:
      - name: Run GitHub Trust Auditor
        uses: SamAlpha1/GitHubTrustAuditor@v1
        with:
          username: ${{ inputs.username }}
          github-token: ${{ github.token }}

      - name: Upload reports
        if: always()
        uses: actions/upload-artifact@v4
        with:
          name: github-trust-audit
          path: |
            github-trust-audit.json
            github-trust-audit.html
          if-no-files-found: warn
```

## Inputs

| Input | Required | Default | Description |
|---|---:|---:|---|
| `username` | yes | — | GitHub account to audit |
| `github-token` | no | empty | Optional read-only token for higher API limits |
| `max-files` | no | `350` | Maximum candidate text files per repository |
| `max-file-size` | no | `1000000` | Maximum text blob size in bytes |

## Outputs

| Output | Meaning |
|---|---|
| `report-json` | JSON report path |
| `report-html` | Standalone HTML report path |
| `exit-code` | Auditor exit code |

Exit codes: `0` = complete with no Critical alarm, `1` = partial coverage or an audit/API problem, `2` = Critical security alarm.

The Action treats a completed partial-coverage report as a workflow warning rather than a hard failure. Critical findings fail the Action. If no report can be generated, the Action also fails.

## Safety

The target repository code is not executed. The Action performs read-only static analysis of accessible GitHub source and metadata.

For private repositories, use only credentials that already have legitimate read access. Do not place wallet keys, seed phrases, or unrelated secrets in workflow inputs.
