from __future__ import annotations

import argparse
import json
import sys
from dataclasses import asdict
from typing import Any

from .contributions import fetch_contributions
from .github_client import Coverage, GitHubAPIError, GitHubClient
from .report import print_terminal, write_html, write_json
from .scanner import Finding, SEVERITY_RANK, deduplicate, is_text_candidate, scan_text
from .scoring import score_account


SPECIAL_PATHS = {
    "readme": {"readme.md", "readme.rst", "readme.txt", "readme"},
    "license": {"license", "license.md", "license.txt", "copying", "copying.md"},
    "security": {"security.md", ".github/security.md"},
}


def _path_flag(paths: set[str], kind: str) -> bool:
    if kind == "ci":
        return any(p.startswith(".github/workflows/") and p.endswith((".yml", ".yaml")) for p in paths)
    wanted = SPECIAL_PATHS[kind]
    return any(p.lower() in wanted for p in paths)


def _repo_score(findings: list[Finding], has_readme: bool, has_license: bool, has_ci: bool, complete: bool) -> int:
    score = 100
    penalty = {"CRITICAL": 30, "HIGH": 14, "MEDIUM": 5, "LOW": 2, "INFO": 0}
    hits: dict[str, int] = {}
    for finding in findings:
        count = hits.get(finding.rule_id, 0)
        factor = 1.0 if count == 0 else 0.4
        score -= round(penalty[finding.severity] * factor)
        hits[finding.rule_id] = count + 1
    score += 0 if has_readme else -4
    score += 0 if has_license else -3
    score += 0 if has_ci else -2
    if not complete:
        score = min(score, 79)
    if any(f.rule_id == "SECRET_TO_NETWORK" and f.severity == "CRITICAL" for f in findings):
        score = min(score, 10)
    elif any(f.severity == "CRITICAL" for f in findings):
        score = min(score, 30)
    elif any(f.severity == "HIGH" for f in findings):
        score = min(score, 69)
    return max(0, min(100, score))


def _readme_mentions_transactions(readme_text: str) -> bool:
    lowered = readme_text.lower()
    terms = ("transaction", "transfer", "approve", "permit", "sign", "wallet", "send token", "send eth", "mint", "swap")
    return any(term in lowered for term in terms)


def audit_repository(
    client: GitHubClient,
    repo: dict[str, Any],
    coverage: Coverage,
    max_files: int,
    max_file_size: int,
) -> dict[str, Any]:
    full_name = repo["full_name"]
    default_branch = repo.get("default_branch") or "main"
    findings: list[Finding] = []
    complete = True
    readme_text = ""

    try:
        tree = client.tree(full_name, default_branch)
    except GitHubAPIError as exc:
        coverage.partial = True
        coverage.notes.append(f"{full_name}: tree unavailable ({exc})")
        return {
            "full_name": full_name,
            "private": bool(repo.get("private")),
            "fork": bool(repo.get("fork")),
            "stars": int(repo.get("stargazers_count") or 0),
            "forks": int(repo.get("forks_count") or 0),
            "files_scanned": 0,
            "files_seen": 0,
            "has_readme": False,
            "has_license": bool(repo.get("license")),
            "has_security": False,
            "has_ci": False,
            "complete": False,
            "repo_score": 0,
            "findings": [],
            "note": str(exc),
        }

    blobs = [item for item in tree if item.get("type") == "blob"]
    paths = {str(item.get("path", "")) for item in blobs}
    has_readme = _path_flag(paths, "readme")
    has_license = bool(repo.get("license")) or _path_flag(paths, "license")
    has_security = _path_flag(paths, "security")
    has_ci = _path_flag(paths, "ci")

    candidates = [
        item for item in blobs
        if is_text_candidate(str(item.get("path", "")), int(item.get("size") or 0), max_file_size)
    ]
    coverage.files_seen += len(candidates)
    if len(candidates) > max_files:
        candidates = candidates[:max_files]
        complete = False
        coverage.partial = True
        coverage.notes.append(f"{full_name}: candidate file cap reached ({max_files})")

    for item in candidates:
        path = str(item["path"])
        try:
            text = client.blob_text(full_name, str(item["sha"]))
        except GitHubAPIError as exc:
            coverage.files_skipped += 1
            complete = False
            coverage.partial = True
            coverage.notes.append(f"{full_name}/{path}: blob unavailable ({exc})")
            continue
        if text is None:
            coverage.files_skipped += 1
            continue
        coverage.files_scanned += 1
        findings.extend(scan_text(full_name, path, text))
        if path.lower() in SPECIAL_PATHS["readme"]:
            readme_text = text[:250_000]
        client.sleep_briefly()

    # Cross-file/repository correlation: transaction capability without obvious documentation.
    tx_findings = [f for f in findings if f.rule_id in {"SIGN_TX", "UNLIMITED_APPROVAL"}]
    if tx_findings and (not has_readme or not _readme_mentions_transactions(readme_text)):
        first = tx_findings[0]
        findings.append(
            Finding(
                "UNDOCUMENTED_TRANSACTION_CAPABILITY",
                "HIGH",
                "documentation-mismatch",
                full_name,
                first.path,
                first.line,
                "Repository can sign/send transactions or request broad token permission, but this behavior is not obvious in the README",
                "[TRANSACTION CAPABILITY — REVIEW README AND CODE]",
                "medium",
            )
        )

    # Repository-level signals: broad workflow permissions and suspicious filenames.
    for path in paths:
        lowered = path.lower()
        if lowered in {".env", "id_rsa", "id_ed25519", "wallet.dat", "keystore.json", "seed.txt", "private_key.txt"}:
            findings.append(
                Finding(
                    "SENSITIVE_FILENAME_COMMITTED",
                    "HIGH",
                    "secret-exposure",
                    full_name,
                    path,
                    1,
                    "Sensitive-looking file is committed to the repository",
                    "[SENSITIVE FILE NAME]",
                    "medium",
                )
            )

    findings = deduplicate(findings)
    score = _repo_score(findings, has_readme, has_license, has_ci, complete)
    return {
        "full_name": full_name,
        "private": bool(repo.get("private")),
        "fork": bool(repo.get("fork")),
        "archived": bool(repo.get("archived")),
        "created_at": repo.get("created_at"),
        "updated_at": repo.get("updated_at"),
        "pushed_at": repo.get("pushed_at"),
        "stars": int(repo.get("stargazers_count") or 0),
        "forks": int(repo.get("forks_count") or 0),
        "open_issues": int(repo.get("open_issues_count") or 0),
        "language": repo.get("language"),
        "files_scanned": sum(1 for item in candidates if is_text_candidate(str(item.get("path", "")), int(item.get("size") or 0), max_file_size)),
        "files_seen": len(blobs),
        "has_readme": has_readme,
        "has_license": has_license,
        "has_security": has_security,
        "has_ci": has_ci,
        "complete": complete,
        "repo_score": score,
        "findings": findings,
    }


def audit_account(
    username: str,
    include_private: bool = False,
    token: str | None = None,
    max_files: int = 350,
    max_file_size: int = 1_000_000,
) -> dict[str, Any]:
    client = GitHubClient(token=token)
    user = client.user(username)
    repos, coverage = client.repositories(username, include_private=include_private)
    results: list[dict[str, Any]] = []

    for repo in repos:
        results.append(audit_repository(client, repo, coverage, max_files=max_files, max_file_size=max_file_size))

    contribution_stats = fetch_contributions(username).to_dict()
    score = score_account(user, repos, results, contribution_stats, coverage.partial).to_dict()

    return {
        "schema_version": 1,
        "username": username,
        "profile": {
            "login": user.get("login"),
            "created_at": user.get("created_at"),
            "public_repos": user.get("public_repos"),
            "followers": user.get("followers"),
            "following": user.get("following"),
            "type": user.get("type"),
        },
        "coverage": asdict(coverage),
        "contributions": contribution_stats,
        "score": score,
        "repositories": results,
    }


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="github-trust-auditor",
        description="Read-only GitHub account/repository security and trust auditor.",
    )
    parser.add_argument("username", help="GitHub username to audit")
    parser.add_argument("--include-private", action="store_true", help="Include private repos visible to your authorized GITHUB_TOKEN")
    parser.add_argument("--token", help="GitHub token; prefer the GITHUB_TOKEN environment variable to avoid shell history exposure")
    parser.add_argument("--max-files", type=int, default=350, help="Maximum candidate text files per repository (default: 350)")
    parser.add_argument("--max-file-size", type=int, default=1_000_000, help="Maximum text blob size in bytes (default: 1 MB)")
    parser.add_argument("--json", dest="json_path", help="Write machine-readable JSON report")
    parser.add_argument("--html", dest="html_path", help="Write standalone HTML report")
    parser.add_argument("--quiet", action="store_true", help="Do not print the terminal tables")
    return parser


def main(argv: list[str] | None = None) -> int:
    args = build_parser().parse_args(argv)
    if args.max_files < 1 or args.max_file_size < 1024:
        print("Invalid scan limits", file=sys.stderr)
        return 1
    try:
        report = audit_account(
            args.username,
            include_private=args.include_private,
            token=args.token,
            max_files=args.max_files,
            max_file_size=args.max_file_size,
        )
    except (GitHubAPIError, ValueError) as exc:
        print(f"Audit failed: {exc}", file=sys.stderr)
        return 1

    if args.json_path:
        write_json(report, args.json_path)
    if args.html_path:
        write_html(report, args.html_path)
    if not args.quiet:
        print_terminal(report)

    if report["score"]["verdict"] == "CRITICAL":
        return 2
    if report["coverage"].get("partial"):
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
