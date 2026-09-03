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
