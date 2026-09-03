from __future__ import annotations

import re
import subprocess
import sys
from pathlib import Path


def fail(msg: str) -> None:
    raise SystemExit(f"UX language fix failed: {msg}")


def main() -> None:
    if len(sys.argv) != 2:
        fail("usage: ux_language_fix.py <index.html>")

    p = Path(sys.argv[1])
    s = p.read_text()

    # Replace the ambiguous single toggle with explicit language choices.
    old_header = '<header class="top"><div class="brand"><b>◈</b> GitHub Trust Auditor</div><button id="lang" class="ghost">FA</button></header>'
    new_header = '<header class="top"><div class="brand"><b>◈</b> GitHub Trust Auditor</div><div class="langSwitch" role="group" aria-label="Language"><button id="langEn" type="button" class="langChoice">English</button><button id="langFa" type="button" class="langChoice">فارسی</button></div></header>'
    if old_header not in s:
        fail("language header anchor missing")
    s = s.replace(old_header, new_header, 1)

    # Keep the visual layout LTR in both languages. Persian text itself is RTL.
    old_lang = "function setLang(v){lang=v;localStorage.setItem('gta_lang',v);document.documentElement.lang=v;document.documentElement.dir=v==='fa'?'rtl':'ltr';$$('[data-t]').forEach(e=>{const k=e.dataset.t;if(T[v][k])e.textContent=T[v][k]});$('#lang').textContent=v==='fa'?'EN':'FA'}\nsetLang(lang);$('#lang').onclick=()=>setLang(lang==='en'?'fa':'en');"
    new_lang = "function setLang(v){lang=v==='fa'?'fa':'en';localStorage.setItem('gta_lang',lang);document.documentElement.lang=lang;document.documentElement.dir='ltr';document.body.classList.toggle('fa-mode',lang==='fa');$$('[data-t]').forEach(e=>{const k=e.dataset.t;if(T[lang][k])e.textContent=T[lang][k]});$('#langEn').classList.toggle('active',lang==='en');$('#langFa').classList.toggle('active',lang==='fa');$('#visitor').placeholder=lang==='fa'?'یوزرنیم GitHub خودت برای تأیید':'Your GitHub username for verification';$('#target').placeholder=lang==='fa'?'یوزرنیم یا لینک GitHub برای اسکن':'GitHub username or profile URL to scan';syncEvidenceToggle?.()}\nsetLang(lang);$('#langEn').onclick=()=>setLang('en');$('#langFa').onclick=()=>setLang('fa');"
    if old_lang not in s:
        fail("setLang anchor missing")
    s = s.replace(old_lang, new_lang, 1)

    # Let users type the target account at any time. Only the Scan button remains gated.
    old_target = '<form id="form" class="row"><input id="target" disabled placeholder="octocat or https://github.com/octocat" required><button id="go" class="btn blue" disabled data-t="scan">SCAN GITHUB</button></form>'
    new_target = '<form id="form" class="row"><input id="target" autocomplete="off" placeholder="GitHub username or profile URL to scan" required><button id="go" class="btn blue" disabled data-t="scan">SCAN GITHUB</button></form>'
    if old_target not in s:
        fail("target input anchor missing")
    s = s.replace(old_target, new_target, 1)

    # Do not visually disable the whole scanner card; the Scan button itself communicates the gate.
    s = s.replace('<section id="scanner" class="card locked">', '<section id="scanner" class="card">', 1)

    css = r'''<style id="language-layout-fix">
.langSwitch{display:flex;gap:6px;padding:4px;border:1px solid var(--line);background:#fff;border-radius:13px}
.langChoice{border:0;background:transparent;color:#5f6f86;font-weight:900;padding:7px 10px;border-radius:9px;cursor:pointer}
.langChoice.active{background:#0b5cff;color:#fff}
.fa-mode [data-t],.fa-mode .hero .sub,.fa-mode #gateMsg,.fa-mode .note,.fa-mode .good,.fa-mode #scoreExplain,.fa-mode .risk,.fa-mode .head,.fa-mode .finding{direction:rtl;text-align:right}
.fa-mode .card .grow>h2,.fa-mode .card .grow>p{direction:rtl;text-align:right}
.fa-mode #visitor,.fa-mode #target{direction:ltr;text-align:left}
.fa-mode .cta-en,.fa-mode .evidence-en{display:none!important}
.fa-mode .cta-fa,.fa-mode .evidence-fa{display:inline!important;direction:rtl}
.fa-mode .followText{margin-right:0;margin-left:auto;direction:rtl;text-align:right}
.fa-mode th,.fa-mode td{text-align:left}
.fa-mode #results th:first-child,.fa-mode #results td:first-child{text-align:left}
.fa-mode #results th:nth-child(2),.fa-mode #results td:nth-child(2){text-align:right!important}
@media(max-width:520px){.langChoice{padding:6px 8px;font-size:12px}.langSwitch{gap:3px}.top{gap:8px}.brand{font-size:17px}}
</style>'''
    if '</head>' not in s:
        fail("head anchor missing")
    s = s.replace('</head>', css + '\n</head>', 1)

    # Runtime assertions: language selection must be explicit and target input must not be disabled.
    required = [
        'id="langEn"',
        'id="langFa"',
        "$('#langEn').onclick=()=>setLang('en')",
        "$('#langFa').onclick=()=>setLang('fa')",
        "document.documentElement.dir='ltr'",
        'id="language-layout-fix"',
        'id="target" autocomplete="off"',
        'id="go" class="btn blue" disabled',
        "یوزرنیم GitHub خودت برای تأیید",
        "GitHub username for verification",
    ]
    for marker in required:
        if marker not in s:
            fail(f"missing marker: {marker}")

    if '<input id="target" disabled' in s:
        fail("target input is still disabled")
    if "$('#lang').onclick" in s or 'id="lang" class="ghost"' in s:
        fail("legacy ambiguous language toggle still present")

    p.write_text(s)

    scripts = re.findall(r'<script[^>]*>(.*?)</script>', s, re.S)
    if not scripts:
        fail("inline script missing")
    runtime = p.parent / "ux-runtime-check.js"
    runtime.write_text("\n".join(scripts))
    subprocess.run(["node", "--check", str(runtime)], check=True)
    runtime.unlink()


if __name__ == "__main__":
    main()
