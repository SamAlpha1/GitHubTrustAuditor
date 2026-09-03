# GitHub Trust Auditor

A defensive, read-only GitHub account and repository security auditor with a **bilingual English/Persian web interface** and a CLI.

**Maintained by [SamAlpha1](https://github.com/SamAlpha1)**  
**X / Twitter: [@samalpha_](https://x.com/samalpha_)**

If this repository is useful to you, follow **SamAlpha1** on GitHub and **@samalpha_** on X for updates and related tools.

اگر این ریپو برات کاربردی بود، **SamAlpha1** رو در GitHub و **@samalpha_** رو در X دنبال کن.

Paste a GitHub username, profile URL, or repository URL. The auditor inventories the account's visible repositories, statically scans source code for credential-theft and data-exfiltration indicators, reviews wallet and install behavior, evaluates repository quality/history, includes GitHub contribution activity as a small reputation signal, and returns a 0–100 score with a clear risk verdict.

> A clean report is not proof that a person is trustworthy, and a red report is not proof that a person is a scammer. The verdict describes **observable technical risk in the scanned coverage**. Private third-party repositories cannot be inspected without legitimate access.

## Web UI — easiest way

The web interface is designed for normal users: enter a username or GitHub link and press **SCAN GITHUB**.

```bash
git clone https://github.com/SamAlpha1/GitHubTrustAuditor.git
cd GitHubTrustAuditor

python -m venv .venv
source .venv/bin/activate
# Windows: .venv\Scripts\activate

pip install -r requirements.txt
python web_server.py
```

Open:

```text
http://127.0.0.1:8787
```

Accepted input examples:

```text
octocat
@octocat
github.com/octocat
https://github.com/octocat
https://github.com/octocat/Hello-World
```

A repository URL is treated as an instruction to audit the **repository owner/account**, not just that one repository.

### Web verdict colors and alarms

| Verdict | Color | Browser alert | Meaning |
|---|---|---|---|
| `TRUSTED` | Green | None | No significant malicious indicators in complete scanned coverage |
| `LOW RISK` | Light green | One short tone | No critical signal, but minor issues exist |
| `CAUTION` | Amber | Two warning tones | Meaningful findings require manual review |
| `HIGH RISK` | Orange/red | Repeated warning tones | Serious behavior; possible scam-like technical patterns |
| `CRITICAL` | Red | Siren-style alternating tones | Critical credential theft, exfiltration, or dangerous execution indicators |

For severe results the UI uses wording such as **“SEVERE RISK • POSSIBLE SCAM BEHAVIOR”** or **“CRITICAL SCAM RISK”**. This is intentionally a *risk label*, not a factual accusation about a person's identity or intent.

The interface can switch instantly between **English** and **فارسی**.

## What it checks

| Area | Examples | Typical severity |
|---|---|---|
| Seed / mnemonic handling | prompts, variables, suspicious recovery-phrase handling | High/Critical |
| Private keys | wallet secret prompts, secret literals, `.env` access | High/Critical |
| Passwords / tokens | passwords, API keys, cookies, session/auth tokens | High/Critical |
| Secret exfiltration | sensitive source + HTTP/Webhook/Telegram/Discord/socket sink | Critical when correlated |
| Clipboard abuse | clipboard reads/writes, wallet-address replacement patterns | Medium/High |
| Wallet approvals | unlimited approvals, permit/allowance patterns | High |
| Wallet transactions | signing/sending behavior and undocumented transaction capability | Medium/High |
| Install hooks | `preinstall`, `postinstall`, download-and-execute chains | High/Critical |
| Obfuscation | `eval`, `exec`, Base64 decode + execute, encoded PowerShell | Medium/High |
| Dependencies | remote/VCS dependencies, unpinned Python packages | Low/Medium |
| GitHub Actions | secrets in network-capable shell commands, suspicious CI behavior | High |
| Secret exposure | committed keys/tokens/mnemonic-shaped values and sensitive filenames | High/Critical |
| Repository hygiene | README, license, `SECURITY.md`, CI, scan completeness | Up to 20 points |
| History & reputation | account age, original repos, stars/forks, recent activity | Up to 12 points |
| Contribution graph | total contributions, active days, streaks, unusual uniformity | **Up to 8 points only** |

Serious security findings always override social/reputation signals. A large number of green contribution squares can never cancel a Critical security finding.

## GitHub “green squares”

When GitHub's public contribution calendar is available, the web report shows contribution total, active days, longest streak, current streak, contribution calendar cells, and unusually uniform activity as an **informational** signal only.

Contribution activity is capped at **8%** of the account score. A sparse public graph is not automatically suspicious: legitimate developers may keep work private, contribute in organizations, or hide private contribution activity.

## Risk table

The web report groups findings into easy-to-read rows covering credential collection, exfiltration, clipboard/wallet replacement, wallet approvals, transactions, install scripts, obfuscation, secret exposure, repository hygiene, and contribution activity.

Every scanned repository receives its own score and risk badge, followed by the highest-value file/line evidence. Potential secret values are redacted from reports.

## Safe Star / Fork recommendation

A **Star/Fork** recommendation is shown only when the account verdict is `TRUSTED`, scan coverage is complete, there are no High/Critical findings, the recommended repository itself scores at least 85, and it is public, complete, and not archived.

> If the project is useful to you, consider starring or forking it.

A high score never automatically means a user should run unknown code with a valuable wallet.

## Public account scan

The web server can scan public repositories without asking the visitor for credentials.

For higher GitHub API limits, the server operator can set a **read-only** GitHub token in the environment:

```bash
export GITHUB_TOKEN="READ_ONLY_TOKEN"
python web_server.py
```

Do not expose that token in browser JavaScript or commit it to the repository.

## Authorized private-repository scan

Private repositories are not public information. They may be scanned only when the server operator already has legitimate read permission.

```bash
export GITHUB_TOKEN="AUTHORIZED_READ_ONLY_TOKEN"
python web_server.py --allow-private
```

The default web UI does not request a visitor's GitHub token, seed phrase, wallet key, or password. Private repositories belonging to an unrelated third party cannot be discovered or audited without authorized access.

## CLI

Public account:

```bash
python auditor.py octocat
```

Save JSON and HTML reports:

```bash
python auditor.py octocat --json report.json --html report.html
```

Authorized private coverage:

```bash
export GITHUB_TOKEN="AUTHORIZED_READ_ONLY_TOKEN"
python auditor.py YOUR_GITHUB_USERNAME --include-private
```

## Score model

```text
Security                 60
Repository hygiene       20
History & reputation     12
Contribution activity     8
---------------------------
TOTAL                    100
```

Verdict bands:

```text
85–100   TRUSTED
70–84    LOW RISK
40–69    CAUTION
16–39    HIGH RISK
0–15     CRITICAL
```

Critical exfiltration or dangerous install behavior can cap the final score regardless of reputation.

## Static, defensive design

The target repository code is **never executed** by the auditor. It does not install target dependencies, run target shell scripts, open a target wallet, sign transactions, connect to target RPC services, ask for a seed phrase, ask for a private wallet key, or submit credentials to a target project.

It reads accessible GitHub metadata and text blobs and performs deterministic static analysis plus cross-signal correlation.

## Limitations

- Static analysis can produce false positives and false negatives.
- Minified, encrypted, generated, or binary payloads may need independent reverse engineering.
- Runtime behavior can differ from source.
- Deleted history, external downloads, releases, or remote dependencies can hide risk.
- API rate limits can make coverage partial; the report marks that explicitly.
- Reputation metrics are context, not proof of honesty.
- The term `SCAM RISK` in the UI describes technical risk indicators, not a legal/factual determination about a person.

## Exit codes — CLI

| Code | Meaning |
|---:|---|
| `0` | Scan completed; no Critical alarm |
| `1` | Input/API problem or incomplete coverage |
| `2` | Critical security alarm |

## Security policy

See [`SECURITY.md`](SECURITY.md).

## License

MIT.

## Maintainer

**[SamAlpha1](https://github.com/SamAlpha1)**  
**X / Twitter: [@samalpha_](https://x.com/samalpha_)**
