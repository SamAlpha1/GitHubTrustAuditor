from __future__ import annotations

import dataclasses
import re
from typing import Any
from urllib.parse import urlparse

_GITHUB_HOSTS = {"github.com", "www.github.com"}
_USERNAME = re.compile(r"^[A-Za-z0-9](?:[A-Za-z0-9-]{0,37}[A-Za-z0-9])?$")


def normalize_github_target(value: str) -> str:
    if not isinstance(value, str):
        raise ValueError("GitHub target must be text")
    raw = value.strip()
    if not raw:
        raise ValueError("Enter a GitHub username or URL")
    if raw.startswith("@"):
        raw = raw[1:].strip()
    if raw.lower().startswith(("github.com/", "www.github.com/")):
        raw = "https://" + raw
    if "://" in raw:
        parsed = urlparse(raw)
        if parsed.scheme not in {"http", "https"} or parsed.netloc.lower() not in _GITHUB_HOSTS:
            raise ValueError("Only github.com profile or repository URLs are accepted")
        parts = [part for part in parsed.path.split("/") if part]
        if not parts:
            raise ValueError("GitHub URL does not contain a username")
        raw = parts[0]
    elif "/" in raw:
        raw = raw.split("/", 1)[0]
    raw = raw.strip()
    if not _USERNAME.fullmatch(raw) or "--" in raw:
        raise ValueError("Invalid GitHub username")
    return raw


def to_jsonable(value: Any) -> Any:
    if dataclasses.is_dataclass(value):
        return {key: to_jsonable(item) for key, item in dataclasses.asdict(value).items()}
    if isinstance(value, dict):
        return {str(key): to_jsonable(item) for key, item in value.items()}
    if isinstance(value, (list, tuple, set)):
        return [to_jsonable(item) for item in value]
    return value
