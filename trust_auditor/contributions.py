from __future__ import annotations

import re
from dataclasses import asdict, dataclass
from datetime import date, datetime, timedelta, timezone

import requests


@dataclass
class ContributionStats:
    available: bool = False
    total: int = 0
    active_days: int = 0
    longest_streak: int = 0
    current_streak: int = 0
    max_day: int = 0
    uniformity_ratio: float = 0.0
    suspicious_uniformity: bool = False
    note: str = ""

    def to_dict(self) -> dict:
        return asdict(self)


def _parse_cells(text: str) -> dict[date, int]:
    days: dict[date, int] = {}

    # Current GitHub contribution markup has varied over time. Support several forms.
    patterns = [
        re.compile(r'data-date="(\d{4}-\d{2}-\d{2})"[^>]*data-count="(\d+)"', re.I),
        re.compile(r'data-count="(\d+)"[^>]*data-date="(\d{4}-\d{2}-\d{2})"', re.I),
        re.compile(r'data-date="(\d{4}-\d{2}-\d{2})"[^>]*data-level="([0-4])"', re.I),
    ]
    for index, pattern in enumerate(patterns):
        matches = pattern.findall(text)
        if not matches:
            continue
        for a, b in matches:
            if index == 1:
                count, raw_date = int(a), b
            else:
                raw_date, raw_value = a, b
                count = int(raw_value)
            try:
                d = date.fromisoformat(raw_date)
            except ValueError:
                continue
            days[d] = max(days.get(d, 0), count)
        if days:
            break
    return days


def _streaks(days: dict[date, int]) -> tuple[int, int]:
    if not days:
        return 0, 0
    active = sorted(d for d, count in days.items() if count > 0)
    if not active:
        return 0, 0

    longest = 1
    run = 1
    for prev, cur in zip(active, active[1:]):
        if cur == prev + timedelta(days=1):
            run += 1
            longest = max(longest, run)
        else:
            run = 1

    today = datetime.now(timezone.utc).date()
    cursor = today
    current = 0
    # GitHub's graph may not have today's update yet, so allow yesterday as the start.
    if days.get(cursor, 0) <= 0:
        cursor -= timedelta(days=1)
    while days.get(cursor, 0) > 0:
        current += 1
        cursor -= timedelta(days=1)
    return longest, current


def fetch_contributions(username: str, timeout: int = 20) -> ContributionStats:
    url = f"https://github.com/users/{username}/contributions"
    try:
        response = requests.get(
            url,
            timeout=timeout,
            headers={"User-Agent": "GitHubTrustAuditor/1.0", "Accept": "text/html"},
        )
        if response.status_code >= 400:
            return ContributionStats(note=f"Contribution endpoint returned HTTP {response.status_code}")
        days = _parse_cells(response.text)
        if not days:
            return ContributionStats(note="Contribution cells could not be parsed; GitHub markup may have changed")

        counts = [count for count in days.values() if count > 0]
        total = sum(counts)
        active_days = len(counts)
        max_day = max(counts, default=0)
        longest, current = _streaks(days)
        if counts:
            most_common_count = max(counts.count(value) for value in set(counts))
            uniformity = most_common_count / len(counts)
        else:
            uniformity = 0.0

        # Uniformity is informational only; many legitimate workflows are repetitive.
        suspicious = active_days >= 90 and uniformity >= 0.90
        return ContributionStats(
            available=True,
            total=total,
            active_days=active_days,
            longest_streak=longest,
            current_streak=current,
            max_day=max_day,
            uniformity_ratio=round(uniformity, 3),
            suspicious_uniformity=suspicious,
            note=(
                "Highly uniform contribution counts; treat as an informational pattern, not evidence of wrongdoing."
                if suspicious
                else ""
            ),
        )
    except requests.RequestException as exc:
        return ContributionStats(note=f"Contribution graph unavailable: {exc.__class__.__name__}")
