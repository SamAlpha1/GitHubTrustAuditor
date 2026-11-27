import pytest

from trust_auditor.web import normalize_github_target, to_jsonable


@pytest.mark.parametrize(
    ("value", "expected"),
    [
        ("octocat", "octocat"),
        ("@octocat", "octocat"),
        ("octocat/Hello-World", "octocat"),
        ("github.com/octocat", "octocat"),
        ("https://github.com/octocat", "octocat"),
        ("https://github.com/octocat/Hello-World", "octocat"),
        ("https://www.github.com/octocat?tab=repositories", "octocat"),
    ],
)
def test_normalize_github_target(value, expected):
    assert normalize_github_target(value) == expected


@pytest.mark.parametrize(
    "value",
    ["", "https://example.com/octocat", "bad user", "-bad", "bad-", "bad--name"],
)
def test_normalize_rejects_invalid(value):
    with pytest.raises(ValueError):
        normalize_github_target(value)


def test_to_jsonable_nested_dataclass():
    from dataclasses import dataclass

    @dataclass
    class Example:
        value: int

    assert to_jsonable({"x": [Example(3)]}) == {"x": [{"value": 3}]}



def test_coverage_breakdown_separates_skipped_and_limit_excluded():
    from trust_auditor.report import coverage_breakdown

    assert coverage_breakdown({
        "files_seen": 20,
        "files_scanned": 12,
        "files_skipped": 3,
    }) == {
        "candidate_files": 20,
        "scanned_files": 12,
        "unreadable_or_unavailable": 3,
        "excluded_by_file_limit": 5,
    }


def test_coverage_breakdown_never_returns_negative_counts():
    from trust_auditor.report import coverage_breakdown

    assert coverage_breakdown({
        "files_seen": 2,
        "files_scanned": 4,
        "files_skipped": 1,
    }) == {
        "candidate_files": 2,
        "scanned_files": 4,
        "unreadable_or_unavailable": 1,
        "excluded_by_file_limit": 0,
    }

def test_bilingual_web_coverage_breakdown_shows_completion_rate():
    from pathlib import Path

    app = (Path(__file__).parents[1] / "web" / "app.js").read_text(encoding="utf-8")
    assert 'coverageRate: "Scan completion"' in app
    assert 'coverageRate: "درصد تکمیل اسکن"' in app
    assert "Math.round((scanned / seen) * 100)" in app
    assert '[tr("coverageRate"), `${formatNumber(completionRate)}%`]' in app


def test_pages_score_history_is_local_bounded_and_clearable():
    from pathlib import Path

    patch = (Path(__file__).parents[1] / "growth_boost.py").read_text(encoding="utf-8")
    assert "gta-score-history:" in patch
    assert "localStorage.setItem(gtaHistoryKey(),JSON.stringify(rows.slice(0,10)))" in patch
    assert "localStorage.removeItem(gtaHistoryKey())" in patch
    assert "date.textContent=new Date(v.at).toLocaleString()" in patch
    assert "score.textContent=(Number(v.score)||0)+'/100'" in patch
    assert "body.textContent=''" in patch
    assert "v.evidence" not in patch[patch.index("function gtaSaveScoreHistory"):patch.index("async function gtaCopy")]
