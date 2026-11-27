import pytest

from trust_auditor.cli import audit_repository, parse_repository_target
from trust_auditor.github_client import Coverage


@pytest.mark.parametrize(
    ("value", "expected"),
    [
        ("octocat/Hello-World", "octocat/Hello-World"),
        ("https://github.com/octocat/Hello-World", "octocat/Hello-World"),
        ("github.com/octocat/Hello-World/tree/main", "octocat/Hello-World"),
        ("https://www.github.com/octocat/Hello-World/issues", "octocat/Hello-World"),
        ("octocat", None),
    ],
)
def test_parse_repository_target(value, expected):
    assert parse_repository_target(value) == expected


@pytest.mark.parametrize(
    "value",
    [
        "https://example.com/octocat/Hello-World",
        "owner/repo/extra",
        "bad owner/repo",
        "owner/",
    ],
)
def test_parse_repository_target_rejects_invalid_input(value):
    with pytest.raises(ValueError):
        parse_repository_target(value)


class FakeClient:
    def tree(self, full_name, ref):
        return [
            {"type": "blob", "path": "README.md", "size": 20, "sha": "readme"},
            {"type": "blob", "path": "src/app.py", "size": 30, "sha": "source"},
            {"type": "blob", "path": "image.png", "size": 50, "sha": "image"},
        ]

    def blob_text(self, full_name, sha):
        if sha == "readme":
            return "# Example repository"
        if sha == "source":
            return None
        raise AssertionError(f"Unexpected blob: {sha}")

    @staticmethod
    def sleep_briefly():
        return None


def test_repository_coverage_counts_only_text_candidates_and_marks_skips_partial():
    coverage = Coverage()
    result = audit_repository(
        FakeClient(),
        {
            "full_name": "octocat/Hello-World",
            "default_branch": "main",
            "private": False,
            "fork": False,
            "license": {"key": "mit"},
        },
        coverage,
        max_files=10,
        max_file_size=1_000_000,
    )

    assert result["files_seen"] == 2
    assert result["files_scanned"] == 1
    assert coverage.files_seen == 2
    assert coverage.files_scanned == 1
    assert coverage.files_skipped == 1
    assert coverage.partial is True
    assert result["complete"] is False
