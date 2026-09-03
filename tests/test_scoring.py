from trust_auditor.scanner import Finding
from trust_auditor.scoring import score_account


def base_inputs():
    user = {"created_at": "2020-01-01T00:00:00Z"}
    repos = [
        {"fork": False, "stargazers_count": 10, "forks_count": 5, "pushed_at": "2026-08-01T00:00:00Z"}
        for _ in range(6)
    ]
    results = [
        {"has_readme": True, "has_license": True, "has_security": True, "has_ci": True, "findings": []}
        for _ in repos
    ]
    contrib = {"available": True, "active_days": 200, "total": 800, "longest_streak": 70, "suspicious_uniformity": False}
    return user, repos, results, contrib


def test_clean_account_can_reach_trusted():
    user, repos, results, contrib = base_inputs()
    score = score_account(user, repos, results, contrib, False)
    assert score.total >= 85
    assert score.verdict == "TRUSTED"


def test_exfiltration_caps_at_critical():
    user, repos, results, contrib = base_inputs()
    results[0]["findings"] = [
        Finding(
            "SECRET_TO_NETWORK",
            "CRITICAL",
            "possible-exfiltration",
            "owner/repo",
            "x.py",
            1,
            "Sensitive data sent out",
            "[REDACTED]",
            "high",
        )
    ]
    score = score_account(user, repos, results, contrib, False)
    assert score.total <= 15
    assert score.verdict == "CRITICAL"


def test_partial_coverage_never_gets_trusted():
    user, repos, results, contrib = base_inputs()
    score = score_account(user, repos, results, contrib, True)
    assert score.total <= 84
    assert score.verdict != "TRUSTED"
