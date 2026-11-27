# GitHub Trust Auditor Roadmap

Public roadmap for high-value improvements. This roadmap reflects the current `main` branch.

## Completed

- Repository-only CLI scans for `owner/repository` and GitHub repository URLs, with explicit partial-coverage reporting.
- Reusable GitHub Action for account and repository-revision audits, including pull-request heads, main-branch pushes, and scheduled audits.
- Configurable CLI and Action failure thresholds: `critical`, `high`, `caution`, or `never`.
- Read-only pull-request auditing through the GitHub API; untrusted PR code is not checked out or executed.
- Bilingual, downloadable/shareable audit score cards with direct report and scan links.
- Regression coverage for benign scanner capabilities and genuinely suspicious external POST, sensitive environment access, wallet-address clipboard replacement, and sensitive-data source-to-network-sink correlation (including browser password fields, nested payloads, and unrelated nearby network calls).
- CI validation for Python tests, YAML workflows, CLI entry points, Pages score-card output, and reusable Action report generation.

## Near term

- Score history and side-by-side comparison across repeat audits.
- Expand false-positive and false-negative regression fixtures using reviewed, reproducible samples.
- Improve report coverage explanations and make partial scans easier to interpret.
- Publish a new tested Action release and keep the stable `v1` tag aligned with that release.

## Next

- Browser extension shortcut from GitHub profile and repository pages.
- Optional report export formats beyond JSON and HTML.
- Broader forge support where public APIs and permissions allow it.
- Community-contributed static-analysis rules with fixtures and documented evidence requirements.

## Principles

- Defensive static analysis only.
- Never execute target repository code.
- Security evidence outranks social/reputation signals.
- No real secrets in fixtures or reports.
- Risk labels describe observable technical signals, not a person's intent or identity.
- Prefer reproducible evidence and regression tests over activity or repository-count inflation.

Maintained by [SamAlpha1](https://github.com/SamAlpha1) · [@samalpha_](https://x.com/samalpha_)
