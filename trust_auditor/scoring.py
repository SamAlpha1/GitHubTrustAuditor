from __future__ import annotations

from dataclasses import asdict, dataclass
from datetime import datetime, timezone
from typing import Any

from .scanner import Finding


@dataclass
class ScoreBreakdown:
    security: int
    hygiene: int
    history: int
    contributions: int
    total: int
    verdict: str
    recommendation: str

    def to_dict(self) -> dict:
        return asdict(self)


SECURITY_PENALTY = {
    "CRITICAL": 18,
    "HIGH": 8,
    "MEDIUM": 3,
    "LOW": 1,
    "INFO": 0,
}


def _age_years(created_at: str | None) -> float:
    if not created_at:
        return 0.0
    try:
        created = datetime.fromisoformat(created_at.replace("Z", "+00:00"))
        return max(0.0, (datetime.now(timezone.utc) - created).days / 365.25)
    except ValueError:
        return 0.0


def score_account(
    user: dict[str, Any],
    repositories: list[dict[str, Any]],
    repo_results: list[dict[str, Any]],
    contribution_stats: dict[str, Any],
    coverage_partial: bool,
) -> ScoreBreakdown:
    findings: list[Finding] = []
    for result in repo_results:
        findings.extend(result.get("findings", []))

    security = 60
    per_rule_hits: dict[str, int] = {}
    for finding in findings:
        hits = per_rule_hits.get(finding.rule_id, 0)
        # Repeated hits matter, but cap each rule to avoid one noisy pattern consuming the full score.
        multiplier = 1.0 if hits == 0 else 0.45 if hits < 3 else 0.2
        security -= round(SECURITY_PENALTY.get(finding.severity, 0) * multiplier)
        per_rule_hits[finding.rule_id] = hits + 1
    security = max(0, min(60, security))

    hygiene = 0
    if repositories:
        has_readme = sum(1 for r in repo_results if r.get("has_readme")) / len(repo_results)
        has_license = sum(1 for r in repo_results if r.get("has_license")) / len(repo_results)
        has_security = sum(1 for r in repo_results if r.get("has_security")) / len(repo_results)
        has_ci = sum(1 for r in repo_results if r.get("has_ci")) / len(repo_results)
        hygiene += round(has_readme * 7)
        hygiene += round(has_license * 5)
        hygiene += round(has_security * 3)
        hygiene += round(has_ci * 5)
    hygiene = min(20, hygiene)

    history = 0
    account_age = _age_years(user.get("created_at"))
    history += min(4, int(account_age))
    original_repos = [r for r in repositories if not r.get("fork")]
    history += min(3, len(original_repos) // 3)
    stars = sum(int(r.get("stargazers_count") or 0) for r in repositories)
    forks = sum(int(r.get("forks_count") or 0) for r in repositories)
    history += 1 if stars >= 5 else 0
    history += 1 if stars >= 25 else 0
    history += 1 if forks >= 5 else 0
    recent = sum(1 for r in repositories if r.get("pushed_at") and _age_years(r.get("pushed_at")) < 1.0)
    history += min(2, recent // 3)
    history = min(12, history)

    contributions = 0
    if contribution_stats.get("available"):
        active_days = int(contribution_stats.get("active_days") or 0)
        total = int(contribution_stats.get("total") or 0)
        longest = int(contribution_stats.get("longest_streak") or 0)
        contributions += 1 if active_days >= 10 else 0
        contributions += 1 if active_days >= 30 else 0
        contributions += 1 if active_days >= 90 else 0
        contributions += 1 if active_days >= 180 else 0
        contributions += 1 if total >= 100 else 0
        contributions += 1 if total >= 500 else 0
        contributions += 1 if longest >= 14 else 0
        contributions += 1 if longest >= 60 else 0
        # Uniformity is not guilt evidence; only prevent it from being used as a strong positive signal.
        if contribution_stats.get("suspicious_uniformity"):
            contributions = min(contributions, 4)
    contributions = min(8, contributions)

    total = security + hygiene + history + contributions
    critical = any(f.severity == "CRITICAL" for f in findings)
    high = any(f.severity == "HIGH" for f in findings)
    exfil = any(f.rule_id in {"SECRET_TO_NETWORK", "DANGEROUS_INSTALL_HOOK"} and f.severity == "CRITICAL" for f in findings)

    if exfil:
        total = min(total, 15)
    elif critical:
        total = min(total, 39)
    elif high:
        total = min(total, 69)
    if coverage_partial:
        total = min(total, 84)

    if exfil or total <= 15:
        verdict = "CRITICAL"
    elif total <= 39:
        verdict = "HIGH RISK"
    elif total <= 69:
        verdict = "CAUTION"
    elif total <= 84:
        verdict = "LOW RISK"
    else:
        verdict = "TRUSTED"

    if verdict == "TRUSTED" and not high and not critical and not coverage_partial:
        recommendation = "No significant malicious indicators detected in scanned coverage. If the project is useful to you, consider starring or forking it."
    elif verdict == "LOW RISK" and not critical:
        recommendation = "No critical indicators detected, but review important code paths and permissions before use."
    elif verdict == "CAUTION":
        recommendation = "Review flagged files carefully before running code, connecting a wallet, or granting permissions."
    else:
        recommendation = "Do not run flagged code or provide wallet/authentication secrets until the findings are independently reviewed."

    return ScoreBreakdown(security, hygiene, history, contributions, total, verdict, recommendation)
