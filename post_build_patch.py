from __future__ import annotations

import re
import subprocess
import sys
from pathlib import Path


def fail(msg: str) -> None:
    raise SystemExit(f"Post-build failed: {msg}")


def main() -> None:
    if len(sys.argv) != 2:
        fail("usage: post_build_patch.py <index.html>")
    p = Path(sys.argv[1])
    s = p.read_text()

    # Informational observations stay visible, but are not presented as scored risk.
    old_risk = r"let cats=\[\['credential-collection'.*?\];\$\('#riskRows'\)\.innerHTML=cats\.map\(\(\[cat,en,fa\]\)=>\{.*?\}\)\.join\(''\);"
    new_risk = r'''const infoRules=new Set(['SECRET_PROMPT','WEBHOOK','OUTBOUND_POST','SIGN_TX','INLINE_INSTALL_CODE','UNDOCUMENTED_TRANSACTION_CAPABILITY']);
let cats=[['credential-collection','Seed / Private key / Password','سید / کلید خصوصی / پسورد'],['possible-exfiltration','Data exfiltration','خروج مخفیانه اطلاعات'],['clipboard','Clipboard / wallet replacement','کلیپ‌بورد / جایگزینی آدرس'],['wallet-permission','Wallet approvals','مجوزهای کیف پول'],['wallet-transaction','Transactions','تراکنش‌ها'],['install-execution','Install scripts','اسکریپت نصب'],['obfuscation','Obfuscation / eval','کد مبهم / eval'],['secret-exposure','Secret exposure','افشای اطلاعات حساس']];
$('#riskRows').innerHTML=cats.map(([cat,en,fa])=>{let raw=all.filter(z=>z.category===cat),x=raw.filter(z=>!infoRules.has(z.rule_id)),infoCount=raw.length-x.length,s=x.reduce((m,z)=>rank[z.severity]>rank[m]?z.severity:m,'LOW');let detail=x.length?(lang==='fa'?`${x.length} مورد ریسک علامت‌گذاری شد`:`${x.length} scored risk finding(s)`):infoCount?(lang==='fa'?`${infoCount} مورد اطلاعاتی؛ بدون کسر امتیاز امنیت`:`${infoCount} informational finding(s); no security-score penalty`):(lang==='fa'?'مورد مشکوکی پیدا نشد':'No suspicious finding detected');let badge=x.length?pill(s):infoCount?'<span class="pill low">INFO</span>':pill('OK');return `<div class="risk"><div><b>${lang==='fa'?fa:en}</b><div class="hint">${detail}</div></div>${badge}</div>`}).join('');'''
    s2, n = re.subn(old_risk, new_risk, s, count=1, flags=re.S)
    if n != 1:
        fail("risk-table render anchor missing")
    s = s2

    # Collapse detailed evidence by default so a long finding list does not dominate mobile UX.
    old_findings_markup = '<section id="findings" class="card hide"><div class="head"><small data-t="findLabel">FLAGGED EVIDENCE</small><h2 data-t="findTitle">Files and lines to review</h2></div><div id="findingList"></div></section>'
    new_findings_markup = '<section id="findings" class="card hide"><div class="head evidenceHead"><div><small data-t="findLabel">FLAGGED EVIDENCE</small><h2 data-t="findTitle">Files and lines to review</h2></div><button id="evidenceToggle" class="ghost evidenceToggle" type="button" aria-expanded="false"><span class="evidence-en">Show evidence</span><span class="evidence-fa">نمایش جزئیات</span></button></div><div id="findingList"></div></section>'
    if old_findings_markup not in s:
        fail("findings markup anchor missing")
    s = s.replace(old_findings_markup, new_findings_markup, 1)

    old_findings_render = "if(all.length){$('#findings').classList.remove('hide');$('#findingList').innerHTML=[...all].sort((a,b)=>(rank[b.severity]||0)-(rank[a.severity]||0)).slice(0,80).map(x=>`<div class=\"finding ${x.severity.toLowerCase()}\"><b>${pill(x.severity)} ${x.rule_id}</b><div class=\"hint\">${x.repository} • ${x.path}:${x.line}</div><div>${x.summary}</div>${x.evidence?`<code>${x.evidence.replace(/[&<>]/g,c=>({'&':'&amp;','<':'&lt;','>':'&gt;'}[c]))}</code>`:''}</div>`).join('')}else $('#findings').classList.add('hide');"
    new_findings_render = "if(all.length){$('#findings').classList.remove('hide','evidence-open');$('#findingList').innerHTML=[...all].sort((a,b)=>(rank[b.severity]||0)-(rank[a.severity]||0)).slice(0,80).map(x=>`<div class=\"finding ${x.severity.toLowerCase()}\"><b>${pill(x.severity)} ${x.rule_id}</b><div class=\"hint\">${x.repository} • ${x.path}:${x.line}</div><div>${x.summary}</div>${x.evidence?`<code>${x.evidence.replace(/[&<>]/g,c=>({'&':'&amp;','<':'&lt;','>':'&gt;'}[c]))}</code>`:''}</div>`).join('');syncEvidenceToggle()}else $('#findings').classList.add('hide');"
    if old_findings_render not in s:
        fail("findings render anchor missing")
    s = s.replace(old_findings_render, new_findings_render, 1)

    # Keep support recommendations compact: one repository per row, two small actions.
    old_support = "let clean=v==='TRUSTED'&&!r.coverage.partial&&!all.some(x=>['HIGH','CRITICAL'].includes(x.severity));if(clean){$('#support').classList.remove('hide');let best=r.repositories.filter(x=>x.repo_score>=85&&x.complete&&!x.archived).sort((a,b)=>b.stars-a.stars).slice(0,3);$('#supportLinks').innerHTML=best.map(x=>`<a class=\"btn dark\" href=\"https://github.com/${x.full_name}\" target=\"_blank\">⭐ Star ${x.full_name.split('/').pop()}</a><a class=\"btn dark\" href=\"https://github.com/${x.full_name}/fork\" target=\"_blank\">⑂ Fork</a>`).join('')||`<a class=\"btn dark\" href=\"https://github.com/${r.username}\" target=\"_blank\">GitHub @${r.username} ↗</a>`}else $('#support').classList.add('hide');"
    new_support = "let clean=v==='TRUSTED'&&!r.coverage.partial&&!all.some(x=>['HIGH','CRITICAL'].includes(x.severity));if(clean){$('#support').classList.remove('hide');let best=r.repositories.filter(x=>x.repo_score>=85&&x.complete&&!x.archived).sort((a,b)=>b.stars-a.stars).slice(0,2);$('#supportLinks').innerHTML=best.map(x=>`<div class=\"supportRepo\"><a class=\"supportRepoName\" href=\"https://github.com/${x.full_name}\" target=\"_blank\" rel=\"noopener noreferrer\">${x.full_name.split('/').pop()}</a><span class=\"supportActions\"><a href=\"https://github.com/${x.full_name}\" target=\"_blank\" rel=\"noopener noreferrer\">${lang==='fa'?'⭐ استار':'⭐ Star'}</a><a href=\"https://github.com/${x.full_name}/fork\" target=\"_blank\" rel=\"noopener noreferrer\">${lang==='fa'?'⑂ فورک':'⑂ Fork'}</a></span></div>`).join('')||`<a class=\"btn dark\" href=\"https://github.com/${r.username}\" target=\"_blank\">GitHub @${r.username} ↗</a>`}else $('#support').classList.add('hide');"
    if old_support not in s:
        fail("support render anchor missing")
    s = s.replace(old_support, new_support, 1)

    # Compact bilingual owner follow bar: always visible without making the page longer.
    cta = '''
<aside id="followCta" class="followCta" aria-label="SamAlpha1 social links">
  <span class="followText cta-en"><b>Useful?</b> Follow SamAlpha1</span>
  <span class="followText cta-fa"><b>برات کاربردی بود؟</b> SamAlpha1 رو دنبال کن</span>
  <a class="followBtn gh" href="https://github.com/SamAlpha1" target="_blank" rel="noopener noreferrer" aria-label="Follow SamAlpha1 on GitHub">GitHub</a>
  <a class="followBtn tw" href="https://x.com/samalpha_" target="_blank" rel="noopener noreferrer" aria-label="Follow @samalpha_ on X">X @samalpha_</a>
</aside>
'''
    if 'id="followCta"' not in s:
        if '</body>' not in s:
            fail("body anchor missing")
        s = s.replace('</body>', cta + '\n</body>', 1)

    # Lightweight owner/maintainer metadata.
    if '<meta name="author" content="SamAlpha1">' not in s:
        if '</head>' not in s:
            fail("head anchor missing")
        meta = '<meta name="author" content="SamAlpha1">\n<meta name="creator" content="SamAlpha1">\n<meta name="twitter:creator" content="@samalpha_">\n'
        s = s.replace('</head>', meta + '</head>', 1)

    css = '''<style id="mobile-repo-table-fix">
@media(max-width:720px){
  #results .table{overflow:visible!important;width:100%}
  #results table{min-width:0!important;width:100%!important;table-layout:fixed}
  #results th:nth-child(n+3),#results td:nth-child(n+3){display:none!important}
  #results th:first-child,#results td:first-child{width:auto}
  #results th:nth-child(2),#results td:nth-child(2){width:76px;text-align:right!important}
  [dir=rtl] #results th:nth-child(2),[dir=rtl] #results td:nth-child(2){text-align:left!important}
  #results th,#results td{padding:11px 10px!important}
  #results .repo{display:block;max-width:100%;overflow-wrap:anywhere;word-break:break-word}
}
</style>
<style id="compact-result-style">
body{padding-bottom:70px}
#supportLinks{display:grid;gap:8px!important;width:100%;margin:12px 0}
.supportRepo{display:grid;grid-template-columns:minmax(0,1fr) auto;align-items:center;gap:10px;padding:9px 10px;border:1px solid var(--line);border-radius:13px;background:#fff}
.supportRepoName{min-width:0;color:var(--b);font-weight:900;text-decoration:none;overflow:hidden;text-overflow:ellipsis;white-space:nowrap}
.supportActions{display:flex;gap:6px}.supportActions a{display:inline-flex;align-items:center;justify-content:center;padding:7px 9px;border-radius:10px;background:#111827;color:#fff!important;text-decoration:none;font-size:11px;font-weight:900;white-space:nowrap}
.evidenceHead{display:flex;align-items:center;justify-content:space-between;gap:12px}.evidenceHead>div{min-width:0}.evidenceToggle{flex:0 0 auto;padding:8px 10px;font-size:12px}.evidence-fa{display:none}[dir=rtl] .evidence-en{display:none}[dir=rtl] .evidence-fa{display:inline}
#findings #findingList{display:none}#findings.evidence-open #findingList{display:block}
.followCta{position:fixed;left:50%;bottom:max(10px,env(safe-area-inset-bottom));transform:translateX(-50%);z-index:9999;display:flex;align-items:center;gap:7px;width:min(720px,calc(100% - 20px));min-height:46px;padding:6px 8px;background:rgba(12,24,48,.93);color:#fff;border:1px solid rgba(255,255,255,.14);border-radius:14px;box-shadow:0 10px 28px rgba(11,32,70,.22);backdrop-filter:blur(14px);-webkit-backdrop-filter:blur(14px)}
.followText{font-size:12px;line-height:1.15;min-width:0;margin-right:auto}.cta-fa{display:none}.followBtn{flex:0 0 auto;text-decoration:none!important;color:#fff!important;font-weight:850;font-size:12px;padding:7px 9px;border-radius:10px;white-space:nowrap}.followBtn.gh{background:#24292f}.followBtn.tw{background:#0969da}
[dir=rtl] .cta-en{display:none}[dir=rtl] .cta-fa{display:inline}[dir=rtl] .followText{margin-right:0;margin-left:auto}
@media(max-width:520px){body{padding-bottom:66px}.followCta{width:calc(100% - 16px);min-height:43px;padding:5px 6px;gap:5px}.followText{font-size:10.5px;max-width:122px}.followBtn{font-size:10.5px;padding:7px 8px}.followBtn.tw{max-width:108px;overflow:hidden;text-overflow:ellipsis}.supportRepo{grid-template-columns:minmax(0,1fr);gap:7px}.supportActions{width:100%}.supportActions a{flex:1}.evidenceHead{align-items:flex-start}.evidenceHead h2{font-size:25px}.evidenceToggle{font-size:11px;padding:7px 8px}}
</style>'''
    if '</head>' not in s:
        fail("head anchor missing")
    s = s.replace('</head>', css + '\n</head>', 1)

    evidence_js = '''<script id="evidence-toggle-script">
function syncEvidenceToggle(){
  const sec=document.getElementById('findings'),btn=document.getElementById('evidenceToggle');
  if(!sec||!btn)return;
  const open=sec.classList.contains('evidence-open');
  btn.setAttribute('aria-expanded',open?'true':'false');
  const en=btn.querySelector('.evidence-en'),fa=btn.querySelector('.evidence-fa');
  if(en)en.textContent=open?'Hide evidence':'Show evidence';
  if(fa)fa.textContent=open?'بستن جزئیات':'نمایش جزئیات';
}
const evidenceToggle=document.getElementById('evidenceToggle');
if(evidenceToggle)evidenceToggle.addEventListener('click',()=>{document.getElementById('findings').classList.toggle('evidence-open');syncEvidenceToggle()});
syncEvidenceToggle();
</script>'''
    if 'id="evidence-toggle-script"' not in s:
        s = s.replace('</body>', evidence_js + '\n</body>', 1)

    required = [
        "const infoRules=new Set",
        "informational finding(s); no security-score penalty",
        'id="mobile-repo-table-fix"',
        'id="compact-result-style"',
        "th:nth-child(n+3)",
        'id="followCta"',
        'id="evidenceToggle"',
        'id="evidence-toggle-script"',
        "supportRepo",
        "slice(0,2)",
        "https://github.com/SamAlpha1",
        "https://x.com/samalpha_",
        '<meta name="author" content="SamAlpha1">',
        "body{padding-bottom:70px}",
        "Security",
    ]
    for marker in required:
        if marker not in s:
            fail(f"missing marker: {marker}")

    p.write_text(s)

    scripts = re.findall(r'<script[^>]*>(.*?)</script>', s, re.S)
    if not scripts:
        fail("inline script missing")
    runtime = p.parent / "post-runtime-check.js"
    runtime.write_text("\n".join(scripts))
    subprocess.run(["node", "--check", str(runtime)], check=True)
    runtime.unlink()


if __name__ == "__main__":
    main()
