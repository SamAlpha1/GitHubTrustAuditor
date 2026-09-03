from __future__ import annotations

import html
import json
from pathlib import Path
from typing import Any

from rich.console import Console
from rich.table import Table
from rich.text import Text

from .scanner import Finding


COLORS = {
    "CRITICAL": "bold red",
    "HIGH": "red",
    "MEDIUM": "yellow",
    "LOW": "cyan",
    "INFO": "dim",
    "TRUSTED": "bold green",
    "LOW RISK": "green",
    "CAUTION": "bold yellow",
    "HIGH RISK": "bold red",
}


def finding_dict(finding: Finding) -> dict[str, Any]:
    return finding.to_dict()


def serializable_report(report: dict[str, Any]) -> dict[str, Any]:
    copy = dict(report)
    repos = []
    for repo in report.get("repositories", []):
        item = dict(repo)
        item["findings"] = [finding_dict(f) if isinstance(f, Finding) else f for f in item.get("findings", [])]
        repos.append(item)
    copy["repositories"] = repos
    return copy


def write_json(report: dict[str, Any], path: str) -> None:
    Path(path).write_text(json.dumps(serializable_report(report), indent=2, ensure_ascii=False), encoding="utf-8")


def _repo_risk(findings: list[Finding]) -> str:
    severities = {f.severity for f in findings}
    if "CRITICAL" in severities:
        return "CRITICAL"
    if "HIGH" in severities:
        return "HIGH"
    if "MEDIUM" in severities:
        return "MEDIUM"
    if "LOW" in severities:
        return "LOW"
    return "CLEAN"


def print_terminal(report: dict[str, Any]) -> None:
    console = Console()
    score = report["score"]
    verdict = score["verdict"]
    console.print(f"\n[bold]GitHub Trust Auditor — {report['username']}[/bold]")
    coverage = report["coverage"]
    console.print(
        f"Coverage: {coverage['public_repos']} public, {coverage['private_repos']} private; "
        f"{coverage['files_scanned']}/{coverage['files_seen']} candidate files scanned"
        + (" [yellow](PARTIAL)[/yellow]" if coverage.get("partial") else "")
    )

    score_table = Table(title="Trust score", show_header=True, header_style="bold")
    score_table.add_column("Category")
    score_table.add_column("Score", justify="right")
    score_table.add_row("Security", f"{score['security']}/60")
    score_table.add_row("Repository hygiene", f"{score['hygiene']}/20")
    score_table.add_row("History & reputation", f"{score['history']}/12")
    score_table.add_row("Contribution activity", f"{score['contributions']}/8")
    score_table.add_row("TOTAL", f"[bold]{score['total']}/100[/bold]")
    console.print(score_table)
    console.print("Verdict: ", Text(verdict, style=COLORS.get(verdict, "bold")))

    repo_table = Table(title="Repository audit", show_lines=False)
    repo_table.add_column("Repository")
    repo_table.add_column("Visibility")
    repo_table.add_column("Files", justify="right")
    repo_table.add_column("Findings", justify="right")
    repo_table.add_column("Risk")
    repo_table.add_column("README/License/CI")
    for repo in report.get("repositories", []):
        findings = repo.get("findings", [])
        risk = _repo_risk(findings)
        repo_table.add_row(
            repo["full_name"],
            "private" if repo.get("private") else "public",
            str(repo.get("files_scanned", 0)),
            str(len(findings)),
            Text(risk, style=COLORS.get(risk, "green")),
            "/".join("✓" if repo.get(k) else "–" for k in ("has_readme", "has_license", "has_ci")),
        )
    console.print(repo_table)

    critical = [f for r in report.get("repositories", []) for f in r.get("findings", []) if f.severity == "CRITICAL"]
    if critical:
        console.print("\a")
        console.print("[bold red]🚨🚨🚨 CRITICAL SECURITY ALARM 🚨🚨🚨[/bold red]")
        console.print("[bold red]DO NOT RUN flagged code, connect a wallet, or enter a seed/private key until independently reviewed.[/bold red]")

    findings = [f for r in report.get("repositories", []) for f in r.get("findings", [])]
    if findings:
        table = Table(title="Findings", show_lines=True)
        table.add_column("Severity")
        table.add_column("Rule")
        table.add_column("Repository")
        table.add_column("Location")
        table.add_column("Summary")
        for f in findings[:100]:
            table.add_row(Text(f.severity, style=COLORS.get(f.severity, "")), f.rule_id, f.repository, f"{f.path}:{f.line}", f.summary)
        console.print(table)
        if len(findings) > 100:
            console.print(f"[dim]{len(findings)-100} additional findings are available in JSON/HTML output.[/dim]")
    else:
        console.print("[green]No significant malicious indicators detected by the static rules in scanned coverage.[/green]")

    contrib = report.get("contributions", {})
    if contrib.get("available"):
        console.print(
            f"Contribution graph: {contrib.get('total', 0)} contributions, "
            f"{contrib.get('active_days', 0)} active days, longest streak {contrib.get('longest_streak', 0)} days."
        )
        if contrib.get("suspicious_uniformity"):
            console.print("[yellow]Contribution activity is unusually uniform. This is informational only and is not evidence of abuse.[/yellow]")
    elif contrib.get("note"):
        console.print(f"[dim]Contribution graph: {contrib['note']}[/dim]")

    console.print(f"\n[bold]{score['recommendation']}[/bold]\n")


def write_html(report: dict[str, Any], path: str) -> None:
    data = serializable_report(report)
    score = data["score"]
    rows = []
    for repo in data.get("repositories", []):
        risk = _repo_risk([Finding(**f) for f in repo.get("findings", [])]) if repo.get("findings") else "CLEAN"
        rows.append(
            "<tr>"
            f"<td>{html.escape(repo['full_name'])}</td>"
            f"<td>{'Private' if repo.get('private') else 'Public'}</td>"
            f"<td>{repo.get('files_scanned', 0)}</td>"
            f"<td>{len(repo.get('findings', []))}</td>"
            f"<td class='{risk.lower().replace(' ', '-')}'>{html.escape(risk)}</td>"
            "</tr>"
        )
    finding_rows = []
    for repo in data.get("repositories", []):
        for f in repo.get("findings", []):
            finding_rows.append(
                "<tr>"
                f"<td class='{f['severity'].lower()}'>{html.escape(f['severity'])}</td>"
                f"<td>{html.escape(f['rule_id'])}</td>"
                f"<td>{html.escape(f['repository'])}</td>"
                f"<td>{html.escape(f['path'])}:{f['line']}</td>"
                f"<td>{html.escape(f['summary'])}</td>"
                f"<td><code>{html.escape(f['evidence'])}</code></td>"
                "</tr>"
            )
    critical_banner = "<div class='alarm'>🚨 CRITICAL SECURITY ALARM — DO NOT RUN FLAGGED CODE OR ENTER WALLET/AUTH SECRETS.</div>" if score["verdict"] == "CRITICAL" else ""
    page = f"""<!doctype html>
<html lang='en'><head><meta charset='utf-8'><meta name='viewport' content='width=device-width,initial-scale=1'>
<title>GitHub Trust Auditor — {html.escape(data['username'])}</title>
<style>
body{{font-family:system-ui,-apple-system,sans-serif;max-width:1200px;margin:40px auto;padding:0 18px;background:#0d1117;color:#e6edf3}}
h1,h2{{color:#f0f6fc}} .card{{background:#161b22;border:1px solid #30363d;border-radius:12px;padding:18px;margin:16px 0}}
table{{width:100%;border-collapse:collapse}}th,td{{padding:9px;border-bottom:1px solid #30363d;text-align:left;vertical-align:top}}
.critical,.high,.high-risk{{color:#ff7b72;font-weight:700}}.medium,.caution{{color:#d29922;font-weight:700}}.low{{color:#58a6ff}}.clean,.trusted,.low-risk{{color:#3fb950;font-weight:700}}
.alarm{{background:#8b0000;color:white;font-weight:900;padding:18px;border-radius:12px;font-size:1.1rem}}code{{white-space:pre-wrap;word-break:break-word}}
small{{color:#8b949e}}
</style></head><body>
<h1>GitHub Trust Auditor — {html.escape(data['username'])}</h1>{critical_banner}
<div class='card'><h2>{html.escape(score['verdict'])} — {score['total']}/100</h2>
<p>Security {score['security']}/60 · Hygiene {score['hygiene']}/20 · History {score['history']}/12 · Contributions {score['contributions']}/8</p>
<p>{html.escape(score['recommendation'])}</p></div>
<div class='card'><h2>Coverage</h2><pre>{html.escape(json.dumps(data['coverage'], indent=2))}</pre></div>
<div class='card'><h2>Repositories</h2><table><thead><tr><th>Repository</th><th>Visibility</th><th>Files</th><th>Findings</th><th>Risk</th></tr></thead><tbody>{''.join(rows)}</tbody></table></div>
<div class='card'><h2>Findings</h2><table><thead><tr><th>Severity</th><th>Rule</th><th>Repository</th><th>Location</th><th>Summary</th><th>Evidence</th></tr></thead><tbody>{''.join(finding_rows) or '<tr><td colspan=6>No findings.</td></tr>'}</tbody></table></div>
<div class='card'><h2>Contribution graph</h2><pre>{html.escape(json.dumps(data.get('contributions', {}), indent=2))}</pre><small>Contribution activity is a minor reputation signal only and never overrides security findings.</small></div>
</body></html>"""
    Path(path).write_text(page, encoding="utf-8")
