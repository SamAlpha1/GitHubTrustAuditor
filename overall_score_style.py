from __future__ import annotations

import re
import subprocess
import sys
from pathlib import Path


def fail(msg: str) -> None:
    raise SystemExit(f"Overall score style failed: {msg}")


def main() -> None:
    if len(sys.argv) != 2:
        fail("usage: overall_score_style.py <index.html>")

    p = Path(sys.argv[1])
    s = p.read_text()

    old = '<div id="score" class="orb">—</div>'
    new = '''<div class="overallScoreBox" aria-label="This account overall score">
  <div class="overallScoreLabel"><span class="score-en">This Account’s Overall Score</span><span class="score-fa">جمع امتیاز این اکانت</span></div>
  <div id="score" class="orb overallScoreOrb">—</div>
</div>'''
    if old not in s:
        fail("score orb markup anchor missing")
    s = s.replace(old, new, 1)

    css = r'''<style id="overall-score-style">
.overallScoreBox{display:grid;justify-items:center;align-content:center;gap:7px;min-width:150px}
.overallScoreLabel{max-width:170px;text-align:center;font-size:10px;font-weight:950;letter-spacing:.08em;text-transform:uppercase;color:var(--score-color,#07945e);transition:color .25s ease}
.score-fa{display:none;text-transform:none;letter-spacing:0;font-size:12px}
.fa-mode .score-en{display:none!important}.fa-mode .score-fa{display:inline!important;direction:rtl}
.overallScoreOrb{color:var(--score-color,#07945e)!important;border-color:var(--score-color,#07945e)!important;background:var(--score-bg,#effbf6)!important;box-shadow:0 0 0 5px var(--score-ring,#d8f6e8);transition:color .3s ease,border-color .3s ease,background .3s ease,box-shadow .3s ease}
@media(max-width:720px){.overallScoreBox{min-width:108px}.overallScoreLabel{max-width:120px;font-size:8px}.score-fa{font-size:10px}}
</style>'''
    if '</head>' not in s:
        fail("head anchor missing")
    s = s.replace('</head>', css + '\n</head>', 1)

    helper = r'''function overallScoreVisual(raw){
  let n=Math.max(0,Math.min(100,Number(raw)||0)),h;
  if(n>=90)h=128;
  else if(n>=70)h=82+(n-70)*2.3;
  else if(n>=50)h=45+(n-50)*1.85;
  else if(n>=30)h=20+(n-30)*1.25;
  else h=n*(20/30);
  let sat=n>=90?62:72;
  let light=n>=90?36:40;
  let color=`hsl(${h.toFixed(1)} ${sat}% ${light}%)`;
  let bg=`hsl(${h.toFixed(1)} 78% 95%)`;
  let ring=`hsl(${h.toFixed(1)} 68% 88%)`;
  let box=document.querySelector('.overallScoreBox'),orb=document.getElementById('score');
  if(box){box.style.setProperty('--score-color',color);box.style.setProperty('--score-bg',bg);box.style.setProperty('--score-ring',ring)}
  if(orb){orb.setAttribute('title',`${Math.round(n)}/100 This Account’s Overall Score`);orb.setAttribute('aria-label',`${Math.round(n)} out of 100 overall account score`)}
}
'''
    anchor = 'function render(r){'
    if anchor not in s:
        fail("render anchor missing")
    s = s.replace(anchor, helper + anchor, 1)

    old_render = "$('#score').textContent=r.score.total;"
    new_render = "$('#score').textContent=r.score.total;overallScoreVisual(r.score.total);"
    if old_render not in s:
        fail("score render assignment missing")
    s = s.replace(old_render, new_render, 1)

    required = [
        'id="overall-score-style"',
        'class="overallScoreBox"',
        'This Account’s Overall Score',
        'جمع امتیاز این اکانت',
        'function overallScoreVisual(raw)',
        'overallScoreVisual(r.score.total)',
        'if(n>=90)h=128',
    ]
    for marker in required:
        if marker not in s:
            fail(f"missing marker: {marker}")

    p.write_text(s)

    scripts = re.findall(r'<script[^>]*>(.*?)</script>', s, re.S)
    if not scripts:
        fail("inline script missing")
    runtime = p.parent / 'overall-score-runtime-check.js'
    runtime.write_text('\n'.join(scripts))
    subprocess.run(['node', '--check', str(runtime)], check=True)
    runtime.unlink()


if __name__ == '__main__':
    main()
