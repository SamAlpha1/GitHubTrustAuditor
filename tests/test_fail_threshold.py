import pytest

from trust_auditor import cli


@pytest.mark.parametrize(
    ("verdict", "threshold", "expected"),
    [
        ("TRUSTED", "critical", 0),
        ("LOW RISK", "caution", 0),
        ("CAUTION", "caution", 2),
        ("HIGH RISK", "high", 2),
        ("HIGH RISK", "critical", 0),
        ("CRITICAL", "critical", 2),
        ("CRITICAL", "never", 0),
    ],
)
def test_cli_fail_on_threshold(monkeypatch, verdict, threshold, expected):
    report = {
        "score": {"verdict": verdict},
        "coverage": {"partial": False},
    }
    monkeypatch.setattr(cli, "audit_account", lambda *args, **kwargs: report)

    assert cli.main(["octocat", "--fail-on", threshold, "--quiet"]) == expected


def test_partial_coverage_remains_exit_one_even_when_threshold_is_never(monkeypatch):
    report = {
        "score": {"verdict": "CRITICAL"},
        "coverage": {"partial": True},
    }
    monkeypatch.setattr(cli, "audit_account", lambda *args, **kwargs: report)

    assert cli.main(["octocat", "--fail-on", "never", "--quiet"]) == 1
