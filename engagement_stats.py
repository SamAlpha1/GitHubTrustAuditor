from __future__ import annotations

import re
import subprocess
import sys
from pathlib import Path

BASE = "https://counterapi.com/api"
NAMESPACE = "samalpha1.github.io"
KEY = "GitHubTrustAuditor"


def fail(msg: str) -> None:
    raise SystemExit(f"Engagement stats patch failed: {msg}")


def main() -> None:
    if len(sys.argv) != 2:
        fail("usage: engagement_stats.py <index.html>")

    p = Path(sys.argv[1])
    s = p.read_text()

    if 'id="engagementStats"' not in s:
        stats = '''
<div id="engagementStats" class="engagementStats" aria-label="Public engagement counters">
  <span class="engagementStat"><small><span class="counter-en">Visits</span><span class="counter-fa">بازدید</span></small><b id="visitCount">—</b></span>
  <span class="engagementStat"><small><span class="counter-en">Star clicks</span><span class="counter-fa">کلیک استار</span></small><b id="starClickCount">—</b></span>
  <span class="engagementStat"><small><span class="counter-en">Fork clicks</span><span class="counter-fa">کلیک فورک</span></small><b id="forkClickCount">—</b></span>
</div>'''
        pattern = r'(<a\b(?=[^>]*\bid="forkMineBtn")[^>]*>.*?</a>)'
        s, n = re.subn(pattern, r"\1" + stats, s, count=1, flags=re.S)
        if n != 1:
            fail("fork button anchor missing")

    css = r'''<style id="engagement-stats-style">
.engagementStats{display:flex;flex-wrap:wrap;align-items:center;justify-content:center;gap:7px;margin:10px 0 2px}
.engagementStat{display:flex;align-items:center;gap:7px;padding:6px 10px;border-radius:10px;background:#111827;color:#fff;font-weight:850;font-size:12px;line-height:1}
.engagementStat small{font-size:11px;font-weight:800;opacity:.92}.engagementStat b{display:inline-grid;place-items:center;min-width:25px;padding:4px 6px;border-radius:7px;background:#16a34a;color:#fff;font-size:12px}
.counter-fa{display:none}.fa-mode .counter-en{display:none!important}.fa-mode .counter-fa{display:inline!important;direction:rtl}
@media(max-width:520px){.engagementStats{gap:5px}.engagementStat{padding:6px 8px;font-size:11px}.engagementStat small{font-size:10px}}
</style>'''
    if 'id="engagement-stats-style"' not in s:
        if '</head>' not in s:
            fail("head anchor missing")
        s = s.replace('</head>', css + '\n</head>', 1)

    js = f'''<script id="engagement-stats-script">
const GTA_COUNTER_BASE={BASE!r};
const GTA_COUNTER_NS={NAMESPACE!r};
const GTA_COUNTER_KEY={KEY!r};
function gtaCounterUrl(action,readOnly){{return `${{GTA_COUNTER_BASE}}/${{encodeURIComponent(GTA_COUNTER_NS)}}/${{encodeURIComponent(action)}}/${{encodeURIComponent(GTA_COUNTER_KEY)}}?readOnly=${{readOnly?'true':'false'}}&_=${{Date.now()}}`}}
async function gtaCounter(action,readOnly){{let r=await fetch(gtaCounterUrl(action,readOnly),{{cache:'no-store'}});if(!r.ok)throw Error(`counter HTTP ${{r.status}}`);let d=await r.json();let v=Number(d.value??d.count);if(!Number.isFinite(v))throw Error('counter value unavailable');return v}}
function gtaSetCounter(id,v){{let e=document.getElementById(id);if(e)e.textContent=Number.isFinite(v)?v.toLocaleString():'—'}}
async function gtaReadCounters(){{for(let [action,id] of [['view','visitCount'],['star','starClickCount'],['fork','forkClickCount']]){{try{{gtaSetCounter(id,await gtaCounter(action,true))}}catch{{gtaSetCounter(id,NaN)}}}}}}
async function gtaTrackVisit(){{try{{let already=sessionStorage.getItem('gta_visit_counted_v2');let v=already?await gtaCounter('view',true):await gtaCounter('view',false);sessionStorage.setItem('gta_visit_counted_v2','1');gtaSetCounter('visitCount',v)}}catch{{gtaSetCounter('visitCount',NaN)}}}}
async function gtaTrackClick(kind){{let id=kind==='star'?'starClickCount':'forkClickCount';try{{let v=await gtaCounter(kind,false);gtaSetCounter(id,v)}}catch{{try{{gtaSetCounter(id,await gtaCounter(kind,true))}}catch{{gtaSetCounter(id,NaN)}}}}}}
const gtaStarBtn=document.getElementById('starMineBtn');
const gtaForkBtn=document.getElementById('forkMineBtn');
if(gtaStarBtn)gtaStarBtn.addEventListener('click',()=>gtaTrackClick('star'),{{capture:true}});
if(gtaForkBtn)gtaForkBtn.addEventListener('click',()=>gtaTrackClick('fork'),{{capture:true}});
gtaReadCounters();gtaTrackVisit();
</script>'''
    if 'id="engagement-stats-script"' not in s:
        if '</body>' not in s:
            fail("body anchor missing")
        s = s.replace('</body>', js + '\n</body>', 1)

    required = [
        'id="engagementStats"',
        'id="visitCount"',
        'id="starClickCount"',
        'id="forkClickCount"',
        'id="engagement-stats-style"',
        'id="engagement-stats-script"',
        'counterapi.com/api',
        "gtaTrackClick('star')",
        "gtaTrackClick('fork')",
        "gtaTrackVisit()",
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
