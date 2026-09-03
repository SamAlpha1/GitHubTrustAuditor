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

    # Keep informational observations visible without presenting them as scored risk.
    old = r"let cats=\[\['credential-collection'.*?\];\$\('#riskRows'\)\.innerHTML=cats\.map\(\(\[cat,en,fa\]\)=>\{.*?\}\)\.join\(''\);"
    new = r'''const infoRules=new Set(['SECRET_PROMPT','WEBHOOK','OUTBOUND_POST','SIGN_TX','INLINE_INSTALL_CODE','UNDOCUMENTED_TRANSACTION_CAPABILITY']);
let cats=[['credential-collection','Seed / Private key / Password','سید / کلید خصوصی / پسورد'],['possible-exfiltration','Data exfiltration','خروج مخفیانه اطلاعات'],['clipboard','Clipboard / wallet replacement','کلیپ‌بورد / جایگزینی آدرس'],['wallet-permission','Wallet approvals','مجوزهای کیف پول'],['wallet-transaction','Transactions','تراکنش‌ها'],['install-execution','Install scripts','اسکریپت نصب'],['obfuscation','Obfuscation / eval','کد مبهم / eval'],['secret-exposure','Secret exposure','افشای اطلاعات حساس']];
$('#riskRows').innerHTML=cats.map(([cat,en,fa])=>{let raw=all.filter(z=>z.category===cat),x=raw.filter(z=>!infoRules.has(z.rule_id)),infoCount=raw.length-x.length,s=x.reduce((m,z)=>rank[z.severity]>rank[m]?z.severity:m,'LOW');let detail=x.length?(lang==='fa'?`${x.length} مورد ریسک علامت‌گذاری شد`:`${x.length} scored risk finding(s)`):infoCount?(lang==='fa'?`${infoCount} مورد اطلاعاتی؛ بدون کسر امتیاز امنیت`:`${infoCount} informational finding(s); no security-score penalty`):(lang==='fa'?'مورد مشکوکی پیدا نشد':'No suspicious finding detected');let badge=x.length?pill(s):infoCount?'<span class="pill low">INFO</span>':pill('OK');return `<div class="risk"><div><b>${lang==='fa'?fa:en}</b><div class="hint">${detail}</div></div>${badge}</div>`}).join('');'''
    s2, n = re.subn(old, new, s, count=1, flags=re.S)
    if n != 1:
        fail("risk-table render anchor missing")
    s = s2

    # Compact always-visible bilingual follow bar; no extra page length.
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
<style id="follow-cta-style">
.followCta{position:fixed;left:50%;bottom:max(14px,env(safe-area-inset-bottom));transform:translateX(-50%);z-index:9999;display:flex;align-items:center;gap:8px;width:min(760px,calc(100% - 24px));padding:9px 10px;background:rgba(12,24,48,.94);color:#fff;border:1px solid rgba(255,255,255,.15);border-radius:18px;box-shadow:0 12px 34px rgba(11,32,70,.24);backdrop-filter:blur(16px);-webkit-backdrop-filter:blur(16px)}
.followText{font-size:13px;line-height:1.2;min-width:0;margin-right:auto}.cta-fa{display:none}.followBtn{flex:0 0 auto;text-decoration:none!important;color:#fff!important;font-weight:800;font-size:13px;padding:9px 11px;border-radius:12px;white-space:nowrap}.followBtn.gh{background:#24292f}.followBtn.tw{background:#0969da}
[dir=rtl] .cta-en{display:none}[dir=rtl] .cta-fa{display:inline}[dir=rtl] .followText{margin-right:0;margin-left:auto}
@media(max-width:520px){.followCta{gap:6px;padding:7px 8px;border-radius:16px}.followText{font-size:11px;max-width:125px}.followBtn{font-size:11px;padding:8px 9px}.followBtn.tw{max-width:112px;overflow:hidden;text-overflow:ellipsis}}
</style>'''
    if 'id="mobile-repo-table-fix"' not in s:
        if '</head>' not in s:
            fail("head anchor missing")
        s = s.replace('</head>', css + '\n</head>', 1)
    elif 'id="follow-cta-style"' not in s:
        if '</head>' not in s:
            fail("head anchor missing")
        follow_css = css.split('</style>\n<style id="follow-cta-style">',1)[1]
        s = s.replace('</head>', '<style id="follow-cta-style">' + follow_css + '\n</head>', 1)

    required = [
        "const infoRules=new Set",
        "informational finding(s); no security-score penalty",
        'id="mobile-repo-table-fix"',
        "th:nth-child(n+3)",
        'id="followCta"',
        'id="follow-cta-style"',
        "https://github.com/SamAlpha1",
        "https://x.com/samalpha_",
        '<meta name="author" content="SamAlpha1">',
        "Security",
    ]
    for marker in required:
        if marker not in s:
            fail(f"missing marker: {marker}")

    p.write_text(s)

    scripts = re.findall(r'<script>(.*?)</script>', s, re.S)
    if not scripts:
        fail("inline script missing")
    runtime = p.parent / "post-runtime-check.js"
    runtime.write_text("\n".join(scripts))
    subprocess.run(["node", "--check", str(runtime)], check=True)
    runtime.unlink()


if __name__ == "__main__":
    main()
