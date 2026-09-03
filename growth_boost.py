from __future__ import annotations

import re
import subprocess
import sys
from pathlib import Path

DEMO = "https://samalpha1.github.io/GitHubTrustAuditor/"
REPO = "https://github.com/SamAlpha1/GitHubTrustAuditor"
X_PROFILE = "https://x.com/samalpha_"
OG_IMAGE = "https://opengraph.githubassets.com/1/SamAlpha1/GitHubTrustAuditor"


def fail(msg: str) -> None:
    raise SystemExit(f"Growth boost patch failed: {msg}")


def main() -> None:
    if len(sys.argv) != 2:
        fail("usage: growth_boost.py <index.html>")

    p = Path(sys.argv[1])
    s = p.read_text()

    meta = f'''<meta id="growth-meta-description" name="description" content="Defensive GitHub trust and repository security auditor. Scan public repositories for suspicious secret handling, wallet behavior, exfiltration and code-risk signals.">
<meta property="og:type" content="website">
<meta property="og:title" content="GitHub Trust Auditor by SamAlpha1">
<meta property="og:description" content="Scan a GitHub account for repository security, wallet, credential, exfiltration and trust signals — without executing target code.">
<meta property="og:url" content="{DEMO}">
<meta property="og:image" content="{OG_IMAGE}">
<meta name="twitter:card" content="summary_large_image">
<meta name="twitter:title" content="GitHub Trust Auditor by SamAlpha1">
<meta name="twitter:description" content="Defensive GitHub account and repository security scanner.">
<meta name="twitter:image" content="{OG_IMAGE}">
<meta name="keywords" content="github security, repository scanner, static analysis, web3 security, wallet security, crypto security, github auditor, malware analysis">'''
    if 'id="growth-meta-description"' not in s:
        if '</head>' not in s:
            fail("head anchor missing")
        s = s.replace('</head>', meta + '\n</head>', 1)

    share_markup = '''<div id="growthShareBar" class="growthShareBar" hidden>
  <b class="growthShareTitle"><span class="growth-en">Share this audit</span><span class="growth-fa">اشتراک‌گذاری این اسکن</span></b>
  <button id="growthShareBtn" type="button">↗ <span class="growth-en">Share</span><span class="growth-fa">اشتراک</span></button>
  <button id="growthXBtn" type="button">𝕏 <span class="growth-en">Post result</span><span class="growth-fa">ارسال در X</span></button>
  <button id="growthLinkBtn" type="button">🔗 <span class="growth-en">Copy link</span><span class="growth-fa">کپی لینک</span></button>
  <button id="growthBadgeBtn" type="button">🏷 <span class="growth-en">Copy README badge</span><span class="growth-fa">کپی بج README</span></button>
</div>'''
    anchor = '<div id="score" class="orb overallScoreOrb">—</div>\n</div>'
    if 'id="growthShareBar"' not in s:
        if anchor not in s:
            fail("overall score markup anchor missing")
        s = s.replace(anchor, anchor + '\n' + share_markup, 1)

    css = r'''<style id="growth-boost-style">
.growthShareBar{grid-column:1/-1;display:flex;flex-wrap:wrap;align-items:center;justify-content:flex-end;gap:7px;margin-top:10px;padding:10px 12px;border:1px solid #cfe0f5;border-radius:14px;background:#fff}
.growthShareBar[hidden]{display:none!important}.growthShareTitle{margin-right:auto;font-size:12px;color:#253956}.growthShareBar button{border:1px solid #c9d8ec;background:#f7faff;color:#10213d;border-radius:10px;padding:7px 10px;font-weight:850;cursor:pointer}.growthShareBar button:hover{background:#edf5ff}.growth-fa{display:none}.fa-mode .growth-en{display:none!important}.fa-mode .growth-fa{display:inline!important}.fa-mode .growthShareTitle{margin-right:0;margin-left:auto;direction:rtl}
@media(max-width:720px){.growthShareBar{justify-content:center}.growthShareTitle{width:100%;margin:0;text-align:center}.growthShareBar button{font-size:11px;padding:7px 8px}}
</style>'''
    if 'id="growth-boost-style"' not in s:
        s = s.replace('</head>', css + '\n</head>', 1)

    helper = r'''const GTA_DEMO_URL='https://samalpha1.github.io/GitHubTrustAuditor/';
function gtaShareUser(){let v=(document.getElementById('target')?.value||'').trim();v=v.replace(/^https?:\/\/github\.com\//i,'').replace(/^github\.com\//i,'').replace(/^@/,'').split(/[\/?#]/)[0];return v||'GitHub-user'}
function gtaShareUrl(){return `${GTA_DEMO_URL}?user=${encodeURIComponent(gtaShareUser())}`}
function gtaShareText(r){let u=gtaShareUser(),score=Number(r?.score?.total)||0,v=r?.score?.verdict||'AUDITED';return `GitHub Trust Auditor: @${u} scored ${score}/100 — ${v}. Scan your GitHub account:`}
function gtaBadgeMarkdown(r){let u=gtaShareUser(),score=Number(r?.score?.total)||0;let label=encodeURIComponent(`GitHub Trust Score ${score}/100`);let color=score>=90?'16a34a':score>=70?'84cc16':score>=50?'eab308':score>=30?'f97316':'dc2626';return `[![GitHub Trust Auditor](https://img.shields.io/badge/${label}-${color}?logo=github)](${gtaShareUrl()})`}
async function gtaCopy(text){try{await navigator.clipboard.writeText(text);return true}catch(_){return false}}
function updateGrowthShare(r){
 const bar=document.getElementById('growthShareBar'); if(!bar)return; bar.hidden=false;
 const shareUrl=gtaShareUrl(), text=gtaShareText(r);
 document.getElementById('growthShareBtn').onclick=async()=>{if(navigator.share){try{await navigator.share({title:'GitHub Trust Auditor',text,url:shareUrl});return}catch(_){}}await gtaCopy(`${text} ${shareUrl}`)};
 document.getElementById('growthXBtn').onclick=()=>window.open(`https://x.com/intent/post?text=${encodeURIComponent(text)}&url=${encodeURIComponent(shareUrl)}`,'_blank','noopener');
 document.getElementById('growthLinkBtn').onclick=()=>gtaCopy(shareUrl);
 document.getElementById('growthBadgeBtn').onclick=()=>gtaCopy(gtaBadgeMarkdown(r));
 try{history.replaceState(null,'',`${location.pathname}?user=${encodeURIComponent(gtaShareUser())}`)}catch(_){ }
}
function gtaPrefillFromQuery(){let u=new URLSearchParams(location.search).get('user');if(!u)return;let el=document.getElementById('target');if(el&&!el.value)el.value=u}
'''
    if 'function updateGrowthShare(r)' not in s:
        render_anchor = 'function render(r){'
        if render_anchor not in s:
            fail("render anchor missing")
        s = s.replace(render_anchor, helper + render_anchor, 1)

    score_anchor = "$('#score').textContent=r.score.total;overallScoreVisual(r.score.total);"
    if 'updateGrowthShare(r);' not in s:
        if score_anchor not in s:
            fail("score render anchor missing")
        s = s.replace(score_anchor, score_anchor + 'updateGrowthShare(r);', 1)

    init = "<script id=\"growth-prefill-init\">gtaPrefillFromQuery();</script>"
    if 'id="growth-prefill-init"' not in s:
        if '</body>' not in s:
            fail("body anchor missing")
        s = s.replace('</body>', init + '\n</body>', 1)

    required = [
        'id="growthShareBar"', 'id="growthShareBtn"', 'id="growthXBtn"',
        'id="growthLinkBtn"', 'id="growthBadgeBtn"', 'id="growth-boost-style"',
        'id="growth-meta-description"', 'function updateGrowthShare(r)',
        'function gtaPrefillFromQuery()', 'updateGrowthShare(r);',
        'img.shields.io', 'https://x.com/intent/post', 'gtaPrefillFromQuery();'
    ]
    for marker in required:
        if marker not in s:
            fail(f"missing marker: {marker}")

    p.write_text(s)
    (p.parent / 'robots.txt').write_text('User-agent: *\nAllow: /\nSitemap: https://samalpha1.github.io/GitHubTrustAuditor/sitemap.xml\n')
    (p.parent / 'sitemap.xml').write_text('<?xml version="1.0" encoding="UTF-8"?>\n<urlset xmlns="http://www.sitemaps.org/schemas/sitemap/0.9"><url><loc>https://samalpha1.github.io/GitHubTrustAuditor/</loc><changefreq>weekly</changefreq><priority>1.0</priority></url></urlset>\n')

    scripts = re.findall(r'<script[^>]*>(.*?)</script>', s, re.S)
    runtime = p.parent / 'growth-runtime-check.js'
    runtime.write_text('\n'.join(scripts))
    subprocess.run(['node', '--check', str(runtime)], check=True)
    runtime.unlink()


if __name__ == '__main__':
    main()
