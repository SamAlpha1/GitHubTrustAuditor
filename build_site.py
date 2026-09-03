from __future__ import annotations

import base64
import gzip
import re
import subprocess
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent
OUT = ROOT / "_site"
HTML = OUT / "index.html"


def fail(msg: str) -> None:
    raise SystemExit(f"Build failed: {msg}")


def build_base() -> str:
    parts = [ROOT / f"site.part0{i}" for i in range(1, 6)]
    raw = b"".join(p.read_bytes() for p in parts)
    return gzip.decompress(base64.b64decode(raw)).decode()


def patch_helpers(s: str) -> str:
    helpers = (
        "const SKIP=/(^|\\/)(node_modules|vendor|dist|build|coverage|\\.next|\\.cache|\\.git|target|\\.venv|venv|__pycache__)(\\/|$)/i;\n"
        "const EXT=/\\.(py|js|mjs|cjs|ts|tsx|jsx|json|yml|yaml|sh|bash|zsh|ps1|bat|cmd|rs|go|java|kt|sol|toml|ini|cfg|conf|env|txt|md|html|htm|xml|rb|php|pl|lua|swift|dart)$/i;\n"
        "function textCandidate(x){let p=x.path||'',z=+x.size||0;return x.type==='blob'&&z>0&&z<=CFG.maxFileSize&&!SKIP.test(p)&&(EXT.test(p)||/(Dockerfile|Makefile|requirements\\.txt|package-lock\\.json|yarn\\.lock|pnpm-lock\\.yaml)$/i.test(p))}\n"
    )
    if all(x in s for x in ("const SKIP=", "const EXT=", "function textCandidate(")):
        return s
    needle = "function lineNo(t,i)"
    if needle not in s:
        fail("scanner helper anchor missing")
    s = re.sub(r"function textCandidate\(x\)\{[^\n]*\}\n?", "", s, count=1)
    s = re.sub(r"const SKIP=[^\n]*\n?", "", s, count=1)
    s = re.sub(r"const EXT=[^\n]*\n?", "", s, count=1)
    return s.replace(needle, helpers + needle, 1)


def patch_partial_semantics(s: str) -> str:
    # Mark repository tree/API failures as unavailable instead of assigning a fake score of zero.
    old = "return{full_name:full,repo_score:0,findings:[],stars:r.stargazers_count||0,forks:r.forks_count||0,files_scanned:0,complete:false,archived:r.archived}"
    new = "return{full_name:full,repo_score:null,findings:[],stars:r.stargazers_count||0,forks:r.forks_count||0,files_scanned:0,complete:false,scan_status:'unavailable',archived:r.archived}"
    if old in s:
        s = s.replace(old, new, 1)

    old_ok = "return{full_name:full,repo_score:repoScore(f,flags,complete),findings:f,stars:r.stargazers_count||0,forks:r.forks_count||0,files_scanned:done,complete,archived:r.archived, ...{has_readme:flags.readme,has_license:flags.license,has_security:flags.security,has_ci:flags.ci}}"
    new_ok = "return{full_name:full,repo_score:repoScore(f,flags,complete),findings:f,stars:r.stargazers_count||0,forks:r.forks_count||0,files_scanned:done,complete,scan_status:'scanned',archived:r.archived, ...{has_readme:flags.readme,has_license:flags.license,has_security:flags.security,has_ci:flags.ci}}"
    if old_ok in s:
        s = s.replace(old_ok, new_ok, 1)

    new_score = r'''function score(user,repos,res,g,partial){
let rated=res.filter(x=>x.scan_status!=='unavailable'),f=rated.flatMap(x=>x.findings||[]),s=60,p={CRITICAL:18,HIGH:8,MEDIUM:2,LOW:0.5},hits={},info=new Set(['SECRET_PROMPT','WEBHOOK','OUTBOUND_POST','SIGN_TX','INLINE_INSTALL_CODE','UNDOCUMENTED_TRANSACTION_CAPABILITY']);
for(let x of f){if(info.has(x.rule_id))continue;let n=hits[x.rule_id]||0;s-=Math.round((p[x.severity]||0)*(n===0?1:n<3?.45:.2));hits[x.rule_id]=n+1}s=Math.max(0,s);
let h=0;if(rated.length){h+=Math.round(rated.filter(x=>x.has_readme).length/rated.length*7)+Math.round(rated.filter(x=>x.has_license).length/rated.length*5)+Math.round(rated.filter(x=>x.has_security).length/rated.length*3)+Math.round(rated.filter(x=>x.has_ci).length/rated.length*5)}h=Math.min(20,h);
let hist=Math.min(4,Math.floor(yrs(user.created_at)))+Math.min(3,(repos.filter(x=>!x.fork).length/3|0)),stars=repos.reduce((a,x)=>a+(+x.stargazers_count||0),0),forks=repos.reduce((a,x)=>a+(+x.forks_count||0),0);if(stars>=5)hist++;if(stars>=25)hist++;if(forks>=5)hist++;hist+=Math.min(2,(repos.filter(x=>x.pushed_at&&yrs(x.pushed_at)<1).length/3|0));hist=Math.min(12,hist);
let cg=0;if(g.available){let a=g.active_days,t=g.total,l=g.longest_streak;if(a>=10)cg++;if(a>=30)cg++;if(a>=90)cg++;if(a>=180)cg++;if(t>=100)cg++;if(t>=500)cg++;if(l>=14)cg++;if(l>=60)cg++;if(g.suspicious_uniformity)cg=Math.min(cg,4)}
let total=s+h+hist+cg,scamCritical=f.some(x=>['SECRET_TO_EXFIL_ENDPOINT','DIRECT_SECRET_TO_EXFIL_ENDPOINT'].includes(x.rule_id)),strongHigh=f.some(x=>['WALLET_CLIPBOARD_HIJACK','HARDCODED_PRIVATE_KEY','GITHUB_TOKEN','MNEMONIC','RAW_SECRET_TO_NETWORK','DIRECT_RAW_SECRET_TO_NETWORK','BASE64_EXEC','POWERSHELL_ENCODED','DANGEROUS_INSTALL_HOOK'].includes(x.rule_id));
if(scamCritical)total=Math.min(total,15);else if(strongHigh)total=Math.min(total,49);
let base=scamCritical||total<=15?'CRITICAL':total<=49?'HIGH RISK':total<=69?'CAUTION':total<=84?'LOW RISK':'TRUSTED';
let verdict=partial&&!['CRITICAL','HIGH RISK','CAUTION'].includes(base)?'INCOMPLETE':base;
return{security:s,hygiene:h,history:hist,contributions:cg,total,verdict,provisional:!!partial,scanned_repos:rated.length,unavailable_repos:res.length-rated.length}}
'''
    s, n = re.subn(r"function score\(user,repos,res,g,partial\)\{.*?\}\nasync function audit", new_score + "async function audit", s, count=1, flags=re.S)
    if n != 1:
        fail("score function anchor missing")

    s = s.replace(
        "function vc(v){return v==='TRUSTED'?'ok':v==='LOW RISK'?'low':v==='CAUTION'?'warn':v==='HIGH RISK'?'high':'crit'}",
        "function vc(v){return v==='TRUSTED'?'ok':v==='INCOMPLETE'?'low':v==='LOW RISK'?'low':v==='CAUTION'?'warn':v==='HIGH RISK'?'high':'crit'}",
        1,
    )

    # Add an explicit incomplete-scan copy block without weakening real security alarms.
    marker = "function copy(v){let f=lang==='fa',m={TRUSTED:"
    if marker not in s:
        fail("copy function anchor missing")
    s = s.replace(
        "TRUSTED:[f?'مطمئن • سیگنال‌های سالم':'TRUSTED • CLEAN SIGNALS',f?'در محدوده اسکن‌شده نشانه مهمی از رفتار مخرب پیدا نشد.':'No significant malicious indicator was detected in scanned coverage.'],",
        "TRUSTED:[f?'مطمئن • سیگنال‌های سالم':'TRUSTED • CLEAN SIGNALS',f?'در محدوده اسکن‌شده نشانه مهمی از رفتار مخرب پیدا نشد.':'No significant malicious indicator was detected in scanned coverage.'],INCOMPLETE:[f?'اسکن ناقص • نتیجه موقت':'INCOMPLETE SCAN • PROVISIONAL RESULT',f?'بخشی از داده‌ها به‌دلیل محدودیت API/مرورگر بررسی نشد. امتیاز فقط بر اساس بخش‌های واقعاً اسکن‌شده است و نباید نتیجه نهایی تلقی شود.':'Some data could not be scanned because of browser/GitHub API limits. The score reflects only successfully scanned coverage and is not a final trust verdict.'],",
        1,
    )

    old_table = "$('#tbody').innerHTML=r.repositories.map(x=>`<tr><td><a class=\"repo\" href=\"https://github.com/${x.full_name}\" target=\"_blank\">${x.full_name.split('/').pop()}</a></td><td><b>${x.repo_score}</b></td><td>${pill(x.repo_score>=85?'OK':x.repo_score>=70?'LOW':x.repo_score>=40?'MEDIUM':x.repo_score>=16?'HIGH':'CRITICAL')}</td><td>${x.stars}</td><td>${x.forks}</td><td>${x.files_scanned}${x.complete?'':'*'}</td></tr>`).join('');"
    new_table = "$('#tbody').innerHTML=r.repositories.map(x=>{let na=x.scan_status==='unavailable',partialRepo=!na&&!x.complete,scoreCell=na?'N/A':`${x.repo_score}${partialRepo?'*':''}`,riskCell=na?'<span class=\"pill low\">N/A</span>':partialRepo?'<span class=\"pill low\">PARTIAL</span>':pill(x.repo_score>=85?'OK':x.repo_score>=70?'LOW':x.repo_score>=40?'MEDIUM':x.repo_score>=16?'HIGH':'CRITICAL'),files=na?'—':`${x.files_scanned}${partialRepo?'*':''}`;return `<tr><td><a class=\"repo\" href=\"https://github.com/${x.full_name}\" target=\"_blank\">${x.full_name.split('/').pop()}</a></td><td><b>${scoreCell}</b></td><td>${riskCell}</td><td>${x.stars}</td><td>${x.forks}</td><td>${files}</td></tr>`}).join('');"
    if old_table not in s:
        fail("repository table render anchor missing")
    s = s.replace(old_table, new_table, 1)

    return s


def patch_score_explanation(s: str) -> str:
    metrics = '<div class="metrics"><span><i data-t="security">Security</i><b id="sec">—</b>/60</span><span><i data-t="hygiene">Repo hygiene</i><b id="hyg">—</b>/20</span><span><i data-t="history">History</i><b id="hist">—</b>/12</span><span><i data-t="greens">Green squares</i><b id="green">—</b>/8</span></div>'
    explain = metrics + '<div id="scoreExplain" style="margin-top:16px;padding:16px 18px;border:1px solid #d8e2f0;border-radius:18px;background:#f8fbff;line-height:1.55"></div>'
    if 'id="scoreExplain"' not in s:
        if metrics not in s:
            fail("score metrics anchor missing")
        s = s.replace(metrics, explain, 1)

    if "scoreParts=[" not in s:
        anchor = "$('#green').textContent=r.score.contributions;"
        if anchor not in s:
            fail("score render anchor missing")
        js = r'''$('#green').textContent=r.score.contributions;
let scoreParts=[
 {en:'Security',fa:'امنیت',got:r.score.security,max:60,whyEn:'security findings in scanned code',whyFa:'یافته‌های امنیتی در کدهای اسکن‌شده'},
 {en:'Repo hygiene',fa:'کیفیت ریپوها',got:r.score.hygiene,max:20,whyEn:'README / License / SECURITY / CI coverage among successfully scanned repositories',whyFa:'پوشش README / License / SECURITY / CI در ریپوهای واقعاً اسکن‌شده'},
 {en:'History',fa:'سابقه',got:r.score.history,max:12,whyEn:'account age, original repos, stars, forks and recent activity',whyFa:'سن اکانت، ریپوهای اصلی، استار، فورک و فعالیت اخیر'},
 {en:'Green squares',fa:'چمن‌های سبز',got:r.score.contributions,max:8,whyEn:'active days, contribution count and streak thresholds',whyFa:'روزهای فعال، تعداد کانتریبیوشن و استریک‌ها'}
];
let earnedRaw=scoreParts.reduce((a,x)=>a+(+x.got||0),0),shown=+r.score.total||0,capLoss=Math.max(0,earnedRaw-shown),missing=Math.max(0,100-shown);
let scoreRows=scoreParts.map(x=>{let lost=Math.max(0,x.max-(+x.got||0));return `<div style="display:flex;justify-content:space-between;gap:12px;padding:7px 0;border-bottom:1px solid #e8eef6"><span><b>${lang==='fa'?x.fa:x.en}</b><small style="display:block;color:#68758a">${lost?((lang==='fa'?`${lost} امتیاز نگرفته — `:`${lost} point${lost===1?'':'s'} not earned — `)+(lang==='fa'?x.whyFa:x.whyEn)):(lang==='fa'?'امتیاز کامل':'Full points')}</small></span><b style="white-space:nowrap">${x.got}/${x.max}</b></div>`}).join('');
let provisional=r.score.provisional?`<div style="margin:10px 0;padding:10px 12px;border-radius:12px;background:#fff4d8;color:#755300"><b>${lang==='fa'?'⚠️ امتیاز موقت؛ پوشش اسکن ناقص است':'⚠️ Provisional score; scan coverage is incomplete'}</b><small style="display:block;margin-top:4px">${lang==='fa'?`${r.score.scanned_repos} ریپو امتیازدهی شد؛ ${r.score.unavailable_repos} ریپو قابل بررسی نبود.`:`${r.score.scanned_repos} repositories scored; ${r.score.unavailable_repos} repositories unavailable for inspection.`}</small></div>`:'';
let capRow=capLoss?`<div style="padding-top:8px;color:#9b2c2c"><b>${lang==='fa'?`محدودیت ریسک: ${capLoss}- امتیاز`:`Risk cap: -${capLoss} points`}</b></div>`:'';
$('#scoreExplain').innerHTML=`<div style="display:flex;justify-content:space-between;align-items:center;gap:10px;margin-bottom:8px"><b>${lang==='fa'?'ریز امتیاز و علت کسر':'Score breakdown & why points were deducted'}</b><strong>${lang==='fa'?`${missing} امتیاز تا ۱۰۰`:`${missing} points to 100`}</strong></div>${provisional}${scoreRows}${capRow}`;'''
        s = s.replace(anchor, js, 1)
    else:
        # Existing explanation from a previous deployment: clarify provisional coverage by injecting a banner.
        anchor = "$('#scoreExplain').innerHTML=`<div style=\"display:flex;justify-content:space-between;align-items:center;gap:10px;margin-bottom:8px\">"
        if anchor in s and "Provisional score; scan coverage is incomplete" not in s:
            s = s.replace(
                "let capRow=capLoss?",
                "let provisional=r.score.provisional?`<div style=\"margin:10px 0;padding:10px 12px;border-radius:12px;background:#fff4d8;color:#755300\"><b>${lang==='fa'?'⚠️ امتیاز موقت؛ پوشش اسکن ناقص است':'⚠️ Provisional score; scan coverage is incomplete'}</b><small style=\"display:block;margin-top:4px\">${lang==='fa'?`${r.score.scanned_repos} ریپو امتیازدهی شد؛ ${r.score.unavailable_repos} ریپو قابل بررسی نبود.`:`${r.score.scanned_repos} repositories scored; ${r.score.unavailable_repos} repositories unavailable for inspection.`}</small></div>`:'';\nlet capRow=capLoss?",
                1,
            )
            s = s.replace("${scoreRows}${capRow}`;", "${provisional}${scoreRows}${capRow}`;", 1)
    return s


def patch_mobile(s: str) -> str:
    if 'id="mobile-layout-fix"' in s:
        return s
    css = '''<style id="mobile-layout-fix">
#results>.card{display:block!important;min-width:0}
#results .banner,#results .profile,#results .metrics,#results .activity,#results .riskRows,#scoreExplain{min-width:0;max-width:100%}
#scoreExplain{width:100%;overflow-wrap:anywhere;word-break:normal}
#results .banner{align-items:flex-start}
@media(max-width:720px){
 .wrap{padding:14px}
 #results>.card{padding:16px;margin:12px 0}
 #results .banner{display:grid;grid-template-columns:minmax(0,1fr) auto;gap:12px;padding:18px;width:100%}
 #results .banner h2{font-size:25px;line-height:1.08;overflow-wrap:anywhere}
 #results .banner p{line-height:1.5}
 #results .orb{width:74px;height:74px;min-width:74px;border-width:6px;font-size:23px}
 #results .profile{display:grid;grid-template-columns:62px minmax(0,1fr);gap:12px;width:100%}
 #results .ava{width:62px;height:62px}
 #results .profile h3{font-size:21px;overflow-wrap:anywhere}
 #results .stats{gap:10px 14px}
 #results .metrics,#results .activity{grid-template-columns:repeat(2,minmax(0,1fr));width:100%}
 #results .metrics span,#results .activity span{min-width:0}
 #results .risk{grid-template-columns:minmax(0,1fr) auto;width:100%}
 #scoreExplain{padding:14px!important;font-size:13px}
 #scoreExplain>div:first-child{align-items:flex-start!important;flex-direction:column;gap:4px!important}
 #results .head{width:100%}
 #results .table{max-width:100%;overflow-x:auto;-webkit-overflow-scrolling:touch}
}
</style>'''
    if "</head>" not in s:
        fail("head anchor missing")
    return s.replace("</head>", css + "\n</head>", 1)


def validate(s: str) -> None:
    required = [
        "const SKIP=",
        "const EXT=",
        "function textCandidate(x)",
        "cand=tree.filter(textCandidate)",
        "WALLET_CLIPBOARD_HIJACK",
        "SECRET_TO_EXFIL_ENDPOINT",
        "SEVERE SECURITY RISK",
        "scan_status:'unavailable'",
        "INCOMPLETE SCAN • PROVISIONAL RESULT",
        "repositories unavailable for inspection",
        'id="mobile-layout-fix"',
    ]
    for marker in required:
        if marker not in s:
            fail(f"missing runtime marker: {marker}")


def main() -> None:
    OUT.mkdir(exist_ok=True)
    HTML.write_text(build_base())
    subprocess.run([sys.executable, str(ROOT / "site_patch.py"), str(HTML)], check=True)
    s = HTML.read_text()
    s = patch_helpers(s)
    s = patch_partial_semantics(s)
    s = patch_score_explanation(s)
    s = patch_mobile(s)
    validate(s)
    HTML.write_text(s)
    (OUT / ".nojekyll").touch()

    scripts = re.findall(r"<script>(.*?)</script>", s, re.S)
    if not scripts:
        fail("inline script missing")
    runtime = OUT / "runtime-check.js"
    runtime.write_text("\n".join(scripts))
    subprocess.run(["node", "--check", str(runtime)], check=True)
    runtime.unlink()


if __name__ == "__main__":
    main()
