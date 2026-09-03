# GitHub Trust Auditor

GitHub Trust Auditor is a defensive, read-only security and trust analyzer for GitHub accounts and repositories. It inventories repositories, scans source code for credential-theft and data-exfiltration indicators, reviews repository hygiene and activity signals, analyzes the GitHub contribution graph as a *minor* reputation signal, and produces terminal, JSON, and HTML reports.

> **Important:** A clean report is not proof that a person is trustworthy, and a green contribution graph is not proof of safety. The tool scores observable repository/code signals only. Private repositories are scanned **only when the supplied GitHub token is already authorized to read them**.

## What it checks

| Area | Examples | Weight / behavior |
|---|---|---|
| Seed / mnemonic handling | prompts, variables, files, suspicious 12/15/18/21/24-word handling | Critical when paired with exfiltration |
| Private keys | EVM/Solana-style private key handling, secret literals, `.env` access | Critical/High |
| Passwords / tokens | password, API key, session, cookie and token collection | High/Critical |
| Data exfiltration | `fetch`, `axios`, `requests`, webhook, Telegram/Discord, sockets | Critical when sensitive data flows to a sink |
| Clipboard abuse | reading clipboard, wallet-address replacement patterns | High |
| Wallet approvals | unlimited approvals, permit/allowance patterns | High warning; context required |
| Hidden transactions | transaction/sign/send behavior not reflected in obvious docs | High warning |
| Install hooks | `preinstall`, `postinstall`, `curl|bash`, PowerShell download/execute | High/Critical |
| Obfuscation | `eval`, `exec`, Base64 decoding + execution, packed scripts | Medium/High |
| Dependencies | git/tarball deps, unpinned deps, suspicious install scripts | Medium |
| GitHub Actions | secrets used in shell/network steps, broad workflow permissions | High |
| Secret exposure | hard-coded tokens/keys/mnemonic-shaped secrets | Critical; values never printed |
| Repository history | age, archive status, forks, stars, recent activity | Reputation-only |
| README / license / security | documentation, license, `SECURITY.md`, CI | Hygiene score |
| Contributions | active days, total contributions, streak/distribution | **Max 8 points; never overrides security findings** |

## Verdicts

- `TRUSTED` — 85–100 and no High/Critical findings
- `LOW RISK` — 70–84 and no Critical findings
- `CAUTION` — 40–69, or meaningful Medium/High findings
- `HIGH RISK` — 16–39, or serious security indicators
- `CRITICAL` — 0–15, or likely credential theft / secret exfiltration

A Critical finding triggers a visible terminal alarm, terminal bell where supported, and exit code `2`.

## Install

```bash
git clone https://github.com/SamAlpha1/GitHubTrustAuditor.git
cd GitHubTrustAuditor
python -m venv .venv
source .venv/bin/activate   # Windows: .venv\Scripts\activate
pip install -r requirements.txt
```

## Audit a public GitHub account

```bash
python auditor.py octocat
```

For higher API limits, use a token with the **minimum required read-only permissions**:

```bash
export GITHUB_TOKEN="your_read_only_token"
python auditor.py octocat
```

Never paste a seed phrase or wallet private key into this tool. It does not need them.

## Authorized private-repository scan

Private repositories are not public information. They are included only if the token already has read permission and you explicitly opt in:

```bash
export GITHUB_TOKEN="authorized_read_only_token"
python auditor.py YOUR_GITHUB_USERNAME --include-private
```

The report explicitly records whether private coverage was requested, authorized, complete, partial, or unavailable.

## Reports

```bash
python auditor.py USERNAME --json report.json --html report.html
```

The terminal report includes a score table per repository and an account summary. Findings contain the rule, severity, file and line number, but secret values are redacted.

Example summary:

```text
GitHub Trust Auditor — example
Coverage: 18 public repos, 0 private repos (not requested)

Security                 55/60
Repository hygiene       17/20
History & reputation     10/12
Contribution activity     6/8
TOTAL                    88/100
VERDICT                  TRUSTED

No significant malicious indicators detected in the scanned coverage.
Recommendation: review the project for your own use case; if it is useful, consider starring or forking it.
```

Critical example:

```text
🚨🚨🚨 CRITICAL SECURITY ALARM 🚨🚨🚨
Possible credential collection + outbound exfiltration detected.
Repository: owner/repo
File: src/example.js:42
Rule: SECRET_TO_NETWORK
Action: DO NOT RUN, DO NOT CONNECT A WALLET, DO NOT ENTER A SEED/PRIVATE KEY.
```

## Contribution graph / “green squares”

The auditor reads GitHub's public contribution-calendar endpoint when available and summarizes:

- total contributions reported by the graph
- active days
- longest and current streak
- activity distribution and concentration
- suspiciously uniform patterns (informational only)

Contribution activity is deliberately capped at **8% of the score**. A malicious repository can belong to an active account, and an excellent developer can have a sparse public graph because private contributions may be hidden.

## Scanning model

The scanner is static and read-only. It does **not** execute target code, install target dependencies, open target binaries, connect wallets, sign transactions, or submit secrets. It scans textual files using deterministic rules plus cross-signal correlation. A suspicious source (`seed`, `private key`, `password`, token, clipboard) combined with an outbound sink (`HTTP POST`, webhook, socket, Telegram/Discord API) receives much higher severity than either signal alone.

## Limitations

- Static analysis can have false positives and false negatives.
- Minified, encrypted, generated or binary payloads may require separate reverse engineering.
- Deleted history, releases, external downloads and runtime-only behavior can hide risk.
- GitHub API rate limits may cause partial coverage; the report flags this instead of claiming a complete scan.
- Private repositories belonging to third parties are not discoverable without legitimate access.
- The verdict describes observed technical risk, **not a factual claim that a person is a scammer or a good person**.

## Safe recommendation policy

The tool recommends `Star/Fork` only when no Critical/High indicators are present and the score passes the configured trust threshold. The wording is intentionally: **“If the project is useful to you, consider starring or forking it.”** It never treats social metrics as proof of safety.

## Exit codes

| Code | Meaning |
|---:|---|
| 0 | scan completed; no Critical alarm |
| 1 | incomplete scan / API or input error |
| 2 | Critical security alarm |

## Maintainer

SamAlpha1
