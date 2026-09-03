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

    old = r"let cats=\[\['credential-collection'.*?\];\$\('#riskRows'\)\.innerHTML=cats\.map\(\(\[cat,en,fa\]\)=>\{.*?\}\)\.join\(''\);"
    new = r'''const infoRules=new Set(['SECRET_PROMPT','WEBHOOK','OUTBOUND_POST','SIGN_TX','INLINE_INSTALL_CODE','UNDOCUMENTED_TRANSACTION_CAPABILITY']);
let cats=[['credential-collection','Seed / Private key / Password','سید / کلید خصوصی / پسورد'],['possible-exfiltration','Data exfiltration','خروج مخفیانه اطلاعات'],['clipboard','Clipboard / wallet replacement','کلیپ‌بورد / جایگزینی آدرس'],['wallet-permission','Wallet approvals','مجوزهای کیف پول'],['wallet-transaction','Transactions','تراکنش‌ها'],['install-execution','Install scripts','اسکریپت نصب'],['obfuscation','Obfuscation / eval','کد مبهم / eval'],['secret-exposure','Secret exposure','افشای اطلاعات حساس']];
$('#riskRows').innerHTML=cats.map(([cat,en,fa])=>{let raw=all.filter(z=>z.category===cat),x=raw.filter(z=>!infoRules.has(z.rule_id)),infoCount=raw.length-x.length,s=x.reduce((m,z)=>rank[z.severity]>rank[m]?z.severity:m,'LOW');let detail=x.length?(lang==='fa'?`${x.length} مورد ریسک علامت‌گذاری شد`:`${x.length} scored risk finding(s)`):infoCount?(lang==='fa'?`${infoCount} مورد اطلاعاتی؛ بدون کسر امتیاز امنیت`:`${infoCount} informational finding(s); no security-score penalty`):(lang==='fa'?'مورد مشکوکی پیدا نشد':'No suspicious finding detected');let badge=x.length?pill(s):infoCount?'<span class="pill low">INFO</span>':pill('OK');return `<div class="risk"><div><b>${lang==='fa'?fa:en}</b><div class="hint">${detail}</div></div>${badge}</div>`}).join('');'''
    s2, n = re.subn(old, new, s, count=1, flags=re.S)
    if n != 1:
        fail("risk-table render anchor missing")
    s = s2

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
</style>'''
    if 'id="mobile-repo-table-fix"' not in s:
        if '</head>' not in s:
            fail("head anchor missing")
        s = s.replace('</head>', css + '\n</head>', 1)

    required = [
        "const infoRules=new Set",
        "informational finding(s); no security-score penalty",
        'id="mobile-repo-table-fix"',
        "th:nth-child(n+3)",
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
