# GitHub Trust Auditor

**Defensive GitHub account & repository security auditing — in the browser, CLI, or GitHub Actions.**

[![Live Demo](https://img.shields.io/badge/LIVE_DEMO-Scan_GitHub-0b5cff?style=for-the-badge&logo=github)](https://samalpha1.github.io/GitHubTrustAuditor/)
[![MIT License](https://img.shields.io/badge/License-MIT-16a34a?style=for-the-badge)](LICENSE)
[![GitHub stars](https://img.shields.io/github/stars/SamAlpha1/GitHubTrustAuditor?style=for-the-badge&logo=github)](https://github.com/SamAlpha1/GitHubTrustAuditor/stargazers)
[![GitHub forks](https://img.shields.io/github/forks/SamAlpha1/GitHubTrustAuditor?style=for-the-badge&logo=github)](https://github.com/SamAlpha1/GitHubTrustAuditor/forks)
[![Latest release](https://img.shields.io/github/v/release/SamAlpha1/GitHubTrustAuditor?style=for-the-badge&logo=github)](https://github.com/SamAlpha1/GitHubTrustAuditor/releases/latest)

**Maintained by [SamAlpha1](https://github.com/SamAlpha1)** · **Follow [@samalpha_ on X](https://x.com/samalpha_)**

> Paste a GitHub username or profile URL. GitHub Trust Auditor scans accessible public repositories with static analysis and returns a **0–100 overall score**, repository-by-repository scores, risk signals, contribution context, and file/line evidence — without executing target code.

**فارسی:** یوزرنیم یا لینک GitHub را وارد کن؛ ابزار ریپوهای عمومی قابل‌دسترسی را بدون اجرای کد اسکن می‌کند و امتیاز کلی، ریسک‌ها و شواهد فایل/خط را نمایش می‌دهد.

## Live web app

**https://samalpha1.github.io/GitHubTrustAuditor/**

Accepted inputs:

```text
octocat
@octocat
github.com/octocat
https://github.com/octocat
https://github.com/octocat/Hello-World
```

Shareable scan links:

```text
https://samalpha1.github.io/GitHubTrustAuditor/?user=SamAlpha1
```

The web interface supports **English + فارسی**, result sharing, X posting, direct scan links, README badges, per-repository scores, evidence lines, and GitHub contribution context.

## Use it in GitHub Actions

GitHub Trust Auditor can also run directly inside another repository's workflow.

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
```

Full Action documentation: [`GITHUB_ACTION.md`](GITHUB_ACTION.md)  
Copy-ready example: [`examples/github-trust-audit.yml`](examples/github-trust-audit.yml)

The reusable Action was smoke-tested against the public `SamAlpha1` account and verifies that JSON and HTML reports are produced.

## Why use it?

- **Security-first:** security contributes 60% of the score and can override reputation signals.
- **Static analysis:** target code is read, not executed.
- **Wallet-aware checks:** private-key/seed handling, approvals, transaction behavior and clipboard replacement patterns.
- **Exfiltration checks:** correlates sensitive sources with explicit outbound/exfiltration behavior.
- **Install & obfuscation checks:** install hooks, encoded execution, `eval`/`exec`, suspicious download-and-run behavior.
- **Repository quality:** README, license, `SECURITY.md`, CI and scan completeness.
- **History context:** account age, original repositories, stars/forks and recent activity.
- **Contribution graph:** green-square activity is only a small 8% signal and never overrides security alarms.
- **Bilingual UI:** English + فارسی.
- **Automation-ready:** reusable GitHub Action plus CLI and JSON/HTML reports.

## Score model

| Area | Weight |
|---|---:|
| Security | 60 |
| Repository hygiene | 20 |
| History & reputation | 12 |
| Contribution activity | 8 |
| **Total** | **100** |

Verdict bands:

```text
85–100   TRUSTED
70–84    LOW RISK
40–69    CAUTION
16–39    HIGH RISK
0–15     CRITICAL
```

Generic wallet/network capability is treated as context, not proof of malicious behavior. Strong alarms require stronger correlated behavior, such as sensitive data combined with an explicit exfiltration destination or dangerous executable install behavior.

## What it checks

| Area | Examples |
|---|---|
| Seed / private-key / password handling | prompts, literals, `.env` access, sensitive variable flows |
| Data exfiltration | secrets correlated with HTTP/webhook/Telegram/Discord/socket sinks |
| Clipboard / wallet replacement | clipboard reads/writes and wallet-address replacement patterns |
| Wallet approvals | unlimited approvals, permit/allowance patterns |
| Transactions | signing/sending behavior and undocumented transaction capability |
| Install scripts | `preinstall`, `postinstall`, download-and-execute chains |
| Obfuscation | `eval`, `exec`, Base64 decode+execute, encoded PowerShell |
| Secret exposure | committed keys/tokens/mnemonic-shaped values and sensitive filenames |
| GitHub Actions | broad permissions, secrets used in network-capable shell steps |
| Repository hygiene | README, license, SECURITY, CI, completeness |
| Reputation context | account age, stars/forks, original repos, recent activity |
| Green squares | contributions, active days and streaks — capped at 8% |

## GitHub green squares

When public contribution data is available, the report includes contribution total, active days, longest streak, current streak and calendar cells.

Contribution activity is capped at **8%** of the account score and never cancels a security warning. Uniform-looking activity is not treated as proof of wrongdoing.

## CLI

```bash
git clone https://github.com/SamAlpha1/GitHubTrustAuditor.git
cd GitHubTrustAuditor
python -m venv .venv
source .venv/bin/activate
# Windows: .venv\Scripts\activate
pip install -r requirements.txt
python auditor.py octocat
```

Export reports:

```bash
python auditor.py octocat --json report.json --html report.html
```

## Safety model

GitHub Trust Auditor **does not execute target repository code**. It does not install target dependencies, run target scripts, connect a wallet, sign target transactions, or request seed phrases/private wallet keys from the scanned account.

A clean result is **not proof that a person is trustworthy**, and a red result is **not proof that a person is a scammer**. Results describe observable technical signals in scanned coverage. Static analysis can produce false positives and false negatives.

Private third-party repositories cannot be inspected without legitimate access.

## Community & contributing

- False-positive reports and useful detection improvements are welcome.
- See [`CONTRIBUTING.md`](CONTRIBUTING.md).
- Security reports: [`SECURITY.md`](SECURITY.md).
- Public discussions: [GitHub Discussions](https://github.com/SamAlpha1/GitHubTrustAuditor/discussions).

## Launch & updates

**Project launch post on X:**  
https://x.com/samalpha_/status/2095568206484164967

**Releases:**  
https://github.com/SamAlpha1/GitHubTrustAuditor/releases

## License

MIT — see [`LICENSE`](LICENSE).

## Maintainer

**GitHub:** [SamAlpha1](https://github.com/SamAlpha1)  
**X:** [@samalpha_](https://x.com/samalpha_)

If GitHub Trust Auditor is useful to you, **Star the repository, share your result, and follow SamAlpha1 on GitHub and X**.
