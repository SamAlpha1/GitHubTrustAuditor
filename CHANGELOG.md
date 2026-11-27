# Changelog

All notable changes to GitHub Trust Auditor are documented here.

## [Unreleased]

### Added
- Repository-only CLI scans using `owner/repository` or a GitHub repository URL.
- Repository-only scoring excludes account-age, stars, forks, and contribution activity.
- Exact candidate-file coverage counts and explicit partial status when candidate text files cannot be decoded.
- Reusable Action support for scanning a selected repository branch, tag, or commit SHA.
- A read-only pull-request and weekly scheduled audit workflow; pull-request source is fetched through the GitHub API and never checked out or executed.
- Safer composite-action argument handling through environment variables.


## [1.0.0] - 2026-09-03

### Added
- Bilingual English/Persian web interface.
- Public GitHub account scanning with defensive static analysis.
- 0–100 account score with Security, Repository Hygiene, History, and Contribution Activity components.
- Repository-by-repository scores and risk labels.
- Detection for suspicious seed/private-key/password handling, data exfiltration, clipboard/wallet replacement, wallet approvals, transaction behavior, install scripts, obfuscation/eval, and secret exposure.
- File/line evidence review with sensitive values redacted.
- Contribution graph context with bounded score weight.
- Shareable `?user=USERNAME` scan links.
- Share Result, Post on X, Copy Link, and Copy README Badge growth features.
- Star/Fork support links for SamAlpha1/GitHubTrustAuditor.
- Cache-first browser behavior and rate-limit fallback for repeated scans.
- GitHub Pages deployment and CI validation.
- CONTRIBUTING.md, CODE_OF_CONDUCT.md, SECURITY.md, issue templates, PR template, and public roadmap.

### Safety model
- Target repository code is never executed.
- No target dependencies are installed.
- The public web UI does not request wallet seeds, private keys, passwords, or GitHub tokens.
- Private third-party repositories are not inspected without legitimate authorized access.

### Maintainer
- GitHub: https://github.com/SamAlpha1
- X: https://x.com/samalpha_
