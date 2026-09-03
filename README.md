# GitHub Trust Auditor

**Defensive GitHub account & repository security auditing — in the browser.**

[![Live Demo](https://img.shields.io/badge/LIVE_DEMO-Scan_GitHub-0b5cff?style=for-the-badge&logo=github)](https://samalpha1.github.io/GitHubTrustAuditor/)
[![MIT License](https://img.shields.io/badge/License-MIT-16a34a?style=for-the-badge)](LICENSE)
[![GitHub stars](https://img.shields.io/github/stars/SamAlpha1/GitHubTrustAuditor?style=for-the-badge&logo=github)](https://github.com/SamAlpha1/GitHubTrustAuditor/stargazers)
[![GitHub forks](https://img.shields.io/github/forks/SamAlpha1/GitHubTrustAuditor?style=for-the-badge&logo=github)](https://github.com/SamAlpha1/GitHubTrustAuditor/forks)
[![Latest release](https://img.shields.io/github/v/release/SamAlpha1/GitHubTrustAuditor?style=for-the-badge&logo=github)](https://github.com/SamAlpha1/GitHubTrustAuditor/releases/latest)
[![Discussions](https://img.shields.io/badge/Community-Discussions-8250df?style=for-the-badge&logo=github)](https://github.com/SamAlpha1/GitHubTrustAuditor/discussions)

**Maintained by [SamAlpha1](https://github.com/SamAlpha1)** · **Follow [@samalpha_ on X](https://x.com/samalpha_)**

> Paste a GitHub username or profile URL. GitHub Trust Auditor scans accessible public repositories with static analysis and returns a **0–100 overall score**, repository-by-repository scores, risk signals, contribution context, and file/line evidence — without executing target code.

**فارسی:** یوزرنیم یا لینک GitHub را وارد کن؛ ابزار ریپوهای عمومی قابل‌دسترسی را بدون اجرای کد اسکن می‌کند و امتیاز کلی، ریسک‌ها و شواهد فایل/خط را نمایش می‌دهد.

## Try it now

**Live app:** https://samalpha1.github.io/GitHubTrustAuditor/

Shareable scan links are supported:

```text
https://samalpha1.github.io/GitHubTrustAuditor/?user=SamAlpha1
```

After a scan, the web app can:

- share the result,
- post the result on X,
- copy a direct scan link,
- copy a README badge that links back to the auditor.

## Why use it?

- **Security-first:** security contributes 60% of the score and can override reputation signals.
- **Static analysis:** target code is read, not executed.
- **Wallet-aware checks:** private-key/seed handling, approvals, transaction behavior and clipboard replacement patterns.
- **Exfiltration checks:** correlates sensitive sources with HTTP/webhook/socket/network sinks.
- **Install & obfuscation checks:** install hooks, encoded execution, `eval`/`exec`, suspicious download-and-run behavior.
- **Repository quality:** README, license, `SECURITY.md`, CI and scan completeness.
- **History context:** account age, original repositories, stars/forks and recent activity.
- **Contribution graph:** green-square activity is only a small 8% signal and never overrides security alarms.
- **Bilingual UI:** English + فارسی.
- **Shareable:** result links and README badges create an easy way to share an audit.

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

Critical exfiltration or dangerous executable behavior can cap the final score regardless of reputation.

## What it checks

| Area | Examples |
|---|---|
| Seed / private-key / password handling | prompts, literals, `.env` access, sensitive variable flows |
| Data exfiltration | secrets correlated with HTTP, webhook, Telegram/Discord, socket or other network sinks |
| Clipboard / wallet replacement | clipboard reads/writes and wallet-address replacement patterns |
| Wallet approvals | unlimited approvals, permit/allowance patterns |
| Transactions | signing/sending behavior and undocumented transaction capability |
| Install scripts | `preinstall`, `postinstall`, download-and-execute chains |
| Obfuscation | `eval`, `exec`, Base64 decode+execute, encoded PowerShell |
| Secret exposure | committed keys/tokens/mnemonic-shaped values and sensitive filenames |
| GitHub Actions | secrets used in network-capable shell steps and suspicious CI behavior |
| Repository hygiene | README, license, SECURITY, CI, completeness |
| Reputation context | account age, stars/forks, original repos, recent activity |
| Green squares | contributions, active days and streaks — capped at 8% |

## Safety model

GitHub Trust Auditor **does not execute target repository code**. It does not install target dependencies, run target scripts, connect a wallet, sign target transactions, or ask the scanned account for secrets.

A clean result is **not proof that a person is trustworthy**, and a red result is **not proof that a person is a scammer**. Results describe observable technical signals in the scanned coverage. Static analysis can produce false positives and false negatives.

Private third-party repositories cannot be inspected without legitimate access.

## Web usage

Open the live app and enter any of these:

```text
octocat
@octocat
github.com/octocat
https://github.com/octocat
https://github.com/octocat/Hello-World
```

A repository URL currently resolves to its owner/account for the account-level audit.

For repeated scans, the browser uses cache-first behavior to reduce GitHub API rate-limit pressure.

## Run locally

```bash
git clone https://github.com/SamAlpha1/GitHubTrustAuditor.git
cd GitHubTrustAuditor
python -m venv .venv
source .venv/bin/activate
# Windows: .venv\Scripts\activate
pip install -r requirements.txt
python web_server.py
```

Then open:

```text
http://127.0.0.1:8787
```

## CLI

```bash
python auditor.py octocat
```

Export reports:

```bash
python auditor.py octocat --json report.json --html report.html
```

For higher GitHub API limits, a server operator may configure an authorized **read-only** GitHub token in the environment. Do not expose tokens in browser JavaScript or commit them to the repository.

## Put the auditor in your README

After scanning your account, use **Copy README badge** in the web app. It generates a badge linked to your shareable audit URL.

Generic example:

```md
[![GitHub Trust Auditor](https://img.shields.io/badge/GitHub_Trust_Auditor-Scan_now-0b5cff?logo=github)](https://samalpha1.github.io/GitHubTrustAuditor/)
```

## Community

Join the public [GitHub Discussions](https://github.com/SamAlpha1/GitHubTrustAuditor/discussions) to share audit results, ask questions, report false positives, suggest detection rules, and discuss roadmap ideas.

Latest release: [GitHub Trust Auditor v1.0.0](https://github.com/SamAlpha1/GitHubTrustAuditor/releases/tag/v1.0.0).

## Contributing

Contributions, false-positive reports and useful rule improvements are welcome. See [`CONTRIBUTING.md`](CONTRIBUTING.md).

- Found a bug? Open a **Bug report**.
- Have a detection idea? Open a **Feature request**.
- Security issue? Follow [`SECURITY.md`](SECURITY.md).

## Roadmap

High-value next directions include:

- repository-only scan mode,
- GitHub Action integration,
- browser extension,
- exportable share cards/reports,
- opt-in score history,
- broader forge support where APIs permit it.

## License

MIT — see [`LICENSE`](LICENSE).

## Maintainer

**GitHub:** [SamAlpha1](https://github.com/SamAlpha1)  
**X:** [@samalpha_](https://x.com/samalpha_)

If GitHub Trust Auditor is useful to you, **Star the repository, share your result, and follow SamAlpha1** for updates.