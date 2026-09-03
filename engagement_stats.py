from __future__ import annotations

import re
import subprocess
import sys
from pathlib import Path

BASE = "https://vbr.nathanchung.dev/badge"
PAGE_ID = "SamAlpha1-GitHubTrustAuditor-page-visits"
STAR_ID = "SamAlpha1-GitHubTrustAuditor-star-clicks"
FORK_ID = "SamAlpha1-GitHubTrustAuditor-fork-clicks"


def fail(msg: str) -> None:
    raise SystemExit(f"Engagement stats patch failed: {msg}")


def badge(page_id: str, label: str, *, hit: bool) -> str:
    hit_q = "true" if hit else "off"
    return (
        f"{BASE}?page_id={page_id}&text={label}&color=2ea043&lcolor=111827"
        f"&style=flat-square&hit={hit_q}"
    )


def main() -> None:
    if len(sys.argv) != 2:
        fail("usage: engagement_stats.py <index.html>")

    p = Path(sys.argv[1])
    s = p.read_text()

    if 'id="engagementStats"' not in s:
        stats = f'''
<div id="engagementStats" class="engagementStats" aria-label="Public engagement counters">
  <img id="visitCountBadge" src="{badge(PAGE_ID, 'Page_Visits', hit=True)}" alt="Page visits">
  <img id="starClickBadge" src="{badge(STAR_ID, 'Star_Clicks', hit=False)}" alt="Star button clicks">
  <img id="forkClickBadge" src="{badge(FORK_ID, 'Fork_Clicks', hit=False)}" alt="Fork button clicks">
</div>'''
        pattern = r'(<a\b(?=[^>]*\bid="forkMineBtn")[^>]*>.*?</a>)'
        s, n = re.subn(pattern, r"\1" + stats, s, count=1, flags=re.S)
        if n != 1:
            fail("fork button anchor missing")

    css = r'''<style id="engagement-stats-style">
.engagementStats{display:flex;flex-wrap:wrap;align-items:center;justify-content:center;gap:7px;margin:10px 0 2px}
.engagementStats img{height:22px;max-width:100%;border-radius:4px}
@media(max-width:520px){.engagementStats{gap:5px}.engagementStats img{height:20px}}
</style>'''
    if 'id="engagement-stats-style"' not in s:
        if '</head>' not in s:
            fail("head anchor missing")
        s = s.replace('</head>', css + '\n</head>', 1)

    js = f'''<script id="engagement-stats-script">
const ENGAGEMENT_COUNTER_BASE={BASE!r};
const ENGAGEMENT_IDS={{star:{STAR_ID!r},fork:{FORK_ID!r}}};
function engagementBadgeUrl(id,label,hit){{return `${{ENGAGEMENT_COUNTER_BASE}}?page_id=${{encodeURIComponent(id)}}&text=${{label}}&color=2ea043&lcolor=111827&style=flat-square&hit=${{hit?'true':'off'}}`}}
function refreshEngagementBadge(kind){{
  const id=kind==='star'?'starClickBadge':'forkClickBadge';
  const label=kind==='star'?'Star_Clicks':'Fork_Clicks';
  const el=document.getElementById(id); if(!el)return;
  el.src=engagementBadgeUrl(ENGAGEMENT_IDS[kind],label,false)+`&_=${{Date.now()}}`;
}}
function recordEngagementClick(kind){{
  const img=new Image();
  img.onload=()=>setTimeout(()=>refreshEngagementBadge(kind),450);
  img.onerror=()=>setTimeout(()=>refreshEngagementBadge(kind),700);
  img.src=engagementBadgeUrl(ENGAGEMENT_IDS[kind],'_',true)+`&_=${{Date.now()}}`;
}}
const starBtn=document.getElementById('starMineBtn');
const forkBtn=document.getElementById('forkMineBtn');
if(starBtn)starBtn.addEventListener('click',()=>recordEngagementClick('star'),{{capture:true}});
if(forkBtn)forkBtn.addEventListener('click',()=>recordEngagementClick('fork'),{{capture:true}});
</script>'''
    if 'id="engagement-stats-script"' not in s:
        if '</body>' not in s:
            fail("body anchor missing")
        s = s.replace('</body>', js + '\n</body>', 1)

    required = [
        'id="engagementStats"',
        'id="visitCountBadge"',
        'id="starClickBadge"',
        'id="forkClickBadge"',
        'id="engagement-stats-style"',
        'id="engagement-stats-script"',
        PAGE_ID,
        STAR_ID,
        FORK_ID,
        "recordEngagementClick('star')",
        "recordEngagementClick('fork')",
    ]
    for marker in required:
        if marker not in s:
            fail(f"missing marker: {marker}")

    p.write_text(s)

    scripts = re.findall(r'<script[^>]*>(.*?)</script>', s, re.S)
    if not scripts:
        fail("inline scripts missing")
    runtime = p.parent / "engagement-runtime-check.js"
    runtime.write_text("\n".join(scripts))
    subprocess.run(["node", "--check", str(runtime)], check=True)
    runtime.unlink()


if __name__ == "__main__":
    main()
