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
| `username` | yes | — | GitHub account (`octocat`) or one repository (`owner/repository`) to audit |
| `github-token` | no | empty | Optional read-only token for higher API limits |
| `ref` | no | default branch | Branch, tag, or commit SHA; applies only to repository-only scans |
| `fail-on` | no | `critical` | Fail at `critical`, `high`, or `caution`; use `never` to disable risk-based failure |
| `max-files` | no | `350` | Maximum candidate text files per repository |
| `max-file-size` | no | `1000000` | Maximum text blob size in bytes |

The `owner/repository` target and `ref` input are available on the current `main` revision. The published `v1` tag remains the earlier account-scan interface until the next version is released.

## Scan one repository or a pull-request revision

The same `username` input accepts a repository target. The optional `ref` input lets the Action inspect a specific commit, which is useful for pull-request checks:

```yaml
- name: Audit the pull-request revision
  uses: SamAlpha1/GitHubTrustAuditor@main
  with:
    username: ${{ github.event.pull_request.head.repo.full_name }}
    ref: ${{ github.event.pull_request.head.sha }}
    github-token: ${{ github.token }}
```

Use a read-only token and do not check out or execute the pull-request code. The auditor retrieves source through GitHub's read-only API.

## Configurable failure threshold

Set `fail-on` to control when the Action returns a failing exit code:

| Value | Action fails when verdict is |
|---|---|
| `critical` | CRITICAL (default) |
| `high` | HIGH RISK or CRITICAL |
| `caution` | CAUTION, HIGH RISK, or CRITICAL |
| `never` | Never for a risk verdict |

Partial coverage still produces a warning when a report exists. API failures that prevent report generation still fail the Action.

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
