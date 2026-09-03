from __future__ import annotations

import base64
import os
import time
from dataclasses import dataclass
from typing import Any, Iterable

import requests


class GitHubAPIError(RuntimeError):
    pass


@dataclass
class Coverage:
    public_repos: int = 0
    private_repos: int = 0
    files_seen: int = 0
    files_scanned: int = 0
    files_skipped: int = 0
    partial: bool = False
    notes: list[str] | None = None

    def __post_init__(self) -> None:
        if self.notes is None:
            self.notes = []


class GitHubClient:
    API = "https://api.github.com"

    def __init__(self, token: str | None = None, timeout: int = 20) -> None:
        self.token = token or os.getenv("GITHUB_TOKEN")
        self.timeout = timeout
        self.session = requests.Session()
        self.session.headers.update(
            {
                "Accept": "application/vnd.github+json",
                "X-GitHub-Api-Version": "2022-11-28",
                "User-Agent": "GitHubTrustAuditor/1.0",
            }
        )
        if self.token:
            self.session.headers["Authorization"] = f"Bearer {self.token}"

    def _request(self, method: str, url: str, **kwargs: Any) -> requests.Response:
        response = self.session.request(method, url, timeout=self.timeout, **kwargs)
        if response.status_code == 403 and response.headers.get("X-RateLimit-Remaining") == "0":
            reset = response.headers.get("X-RateLimit-Reset")
            suffix = f"; resets at unix {reset}" if reset else ""
            raise GitHubAPIError(f"GitHub API rate limit reached{suffix}")
        if response.status_code >= 400:
            detail = ""
            try:
                detail = response.json().get("message", "")
            except Exception:
                detail = response.text[:200]
            raise GitHubAPIError(f"GitHub API {response.status_code}: {detail}")
        return response

    def get_json(self, path_or_url: str, params: dict[str, Any] | None = None) -> Any:
        url = path_or_url if path_or_url.startswith("http") else self.API + path_or_url
        return self._request("GET", url, params=params).json()

    def get_text(self, url: str) -> str:
        return self._request("GET", url).text

    def paginate(self, path: str, params: dict[str, Any] | None = None) -> Iterable[Any]:
        params = dict(params or {})
        params.setdefault("per_page", 100)
        page = 1
        while True:
            params["page"] = page
            batch = self.get_json(path, params=params)
            if not isinstance(batch, list):
                raise GitHubAPIError(f"Expected list from {path}")
            if not batch:
                return
            yield from batch
            if len(batch) < int(params["per_page"]):
                return
            page += 1

    def user(self, username: str) -> dict[str, Any]:
        return self.get_json(f"/users/{username}")

    def authenticated_user(self) -> dict[str, Any] | None:
        if not self.token:
            return None
        try:
            return self.get_json("/user")
        except GitHubAPIError:
            return None

    def repositories(self, username: str, include_private: bool = False) -> tuple[list[dict[str, Any]], Coverage]:
        coverage = Coverage()
        public = list(
            self.paginate(
                f"/users/{username}/repos",
                {"type": "owner", "sort": "updated", "direction": "desc"},
            )
        )
        by_id = {repo["id"]: repo for repo in public}
        coverage.public_repos = sum(1 for r in public if not r.get("private"))

        if include_private:
            if not self.token:
                coverage.partial = True
                coverage.notes.append("Private scan requested but GITHUB_TOKEN is not set.")
            else:
                try:
                    accessible = self.paginate(
                        "/user/repos",
                        {
                            "visibility": "all",
                            "affiliation": "owner,collaborator,organization_member",
                            "sort": "updated",
                        },
                    )
                    for repo in accessible:
                        owner = (repo.get("owner") or {}).get("login", "")
                        if owner.lower() != username.lower():
                            continue
                        by_id[repo["id"]] = repo
                    coverage.private_repos = sum(1 for r in by_id.values() if r.get("private"))
                    if coverage.private_repos == 0:
                        coverage.notes.append(
                            "No private repositories for this owner were visible to the supplied token."
                        )
                except GitHubAPIError as exc:
                    coverage.partial = True
                    coverage.notes.append(f"Private repository enumeration failed: {exc}")

        repos = sorted(by_id.values(), key=lambda r: r.get("updated_at") or "", reverse=True)
        return repos, coverage

    def tree(self, full_name: str, ref: str) -> list[dict[str, Any]]:
        data = self.get_json(f"/repos/{full_name}/git/trees/{ref}", {"recursive": "1"})
        if data.get("truncated"):
            raise GitHubAPIError(f"Recursive tree for {full_name} was truncated by GitHub")
        return data.get("tree", [])

    def blob_text(self, full_name: str, sha: str) -> str | None:
        data = self.get_json(f"/repos/{full_name}/git/blobs/{sha}")
        if data.get("encoding") != "base64":
            return None
        try:
            raw = base64.b64decode(data.get("content", ""), validate=False)
            if b"\x00" in raw[:4096]:
                return None
            return raw.decode("utf-8")
        except (ValueError, UnicodeDecodeError):
            return None

    def commits(self, full_name: str, limit: int = 30) -> list[dict[str, Any]]:
        try:
            return self.get_json(f"/repos/{full_name}/commits", {"per_page": min(limit, 100)})[:limit]
        except GitHubAPIError:
            return []

    def workflows(self, full_name: str) -> list[dict[str, Any]]:
        try:
            return self.get_json(f"/repos/{full_name}/actions/workflows", {"per_page": 100}).get(
                "workflows", []
            )
        except GitHubAPIError:
            return []

    def rate_limit(self) -> dict[str, Any] | None:
        try:
            return self.get_json("/rate_limit")
        except GitHubAPIError:
            return None

    @staticmethod
    def sleep_briefly() -> None:
        time.sleep(0.02)
