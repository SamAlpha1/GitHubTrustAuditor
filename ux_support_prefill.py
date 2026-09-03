from __future__ import annotations

import re
import subprocess
import sys
from pathlib import Path


OWNER = "SamAlpha1"
REPO = "GitHubTrustAuditor"
REPO_URL = f"https://github.com/{OWNER}/{REPO}"
FORK_URL = f"{REPO_URL}/fork"


def fail(msg: str) -> None:
    raise SystemExit(f"Support UX patch failed: {msg}")


def patch_tag_attr(html: str, tag: str, element_id: str, attr: str, value: str) -> str:
    pattern = rf'<{tag}\b(?=[^>]*\bid="{re.escape(element_id)}")[^>]*>'

    def repl(match: re.Match[str]) -> str:
        text = match.group(0)
        attr_pattern = rf'\b{re.escape(attr)}="[^"]*"'
        replacement = f'{attr}="{value}"'
        if re.search(attr_pattern, text):
            text = re.sub(attr_pattern, replacement, text, count=1)
        else:
            text = text[:-1] + f' {replacement}>'
        return text

    updated, count = re.subn(pattern, repl, html, count=1)
    if count != 1:
        fail(f"missing {tag}#{element_id}")
    return updated


def main() -> None:
    if len(sys.argv) != 2:
        fail("usage: ux_support_prefill.py <index.html>")

    path = Path(sys.argv[1])
    html = path.read_text()

    # Show SamAlpha1 by default in the optional support-verification field,
    # while keeping the field fully editable by the visitor.
    html = patch_tag_attr(html, "input", "visitor", "value", OWNER)
    html = re.sub(
        r'(<input\b(?=[^>]*\bid="visitor")[^>]*)\sdisabled(?=[\s>])',
        r'\1',
        html,
        count=1,
    )

    # Star/Fork destinations are always pinned to this project, regardless of
    # what username is entered in the editable verification field.
    html = patch_tag_attr(html, "a", "starMineBtn", "href", REPO_URL)
    html = patch_tag_attr(html, "a", "forkMineBtn", "href", FORK_URL)

    required = [
        'id="visitor"',
        'value="SamAlpha1"',
        'id="starMineBtn"',
        f'href="{REPO_URL}"',
        'id="forkMineBtn"',
        f'href="{FORK_URL}"',
    ]
    for marker in required:
        if marker not in html:
            fail(f"missing marker: {marker}")

    visitor_tag = re.search(r'<input\b(?=[^>]*\bid="visitor")[^>]*>', html)
    if not visitor_tag:
        fail("visitor input missing after patch")
    if re.search(r'\sdisabled(?=[\s>])', visitor_tag.group(0)):
        fail("visitor input is unexpectedly disabled")

    path.write_text(html)

    scripts = re.findall(r'<script[^>]*>(.*?)</script>', html, re.S)
    if not scripts:
        fail("inline script missing")
    runtime = path.parent / "support-runtime-check.js"
    runtime.write_text("\n".join(scripts))
    subprocess.run(["node", "--check", str(runtime)], check=True)
    runtime.unlink()


if __name__ == "__main__":
    main()
