from __future__ import annotations

import re
import subprocess
import sys
from pathlib import Path


def fail(msg: str) -> None:
    raise SystemExit(f"Cache/rate-limit patch failed: {msg}")


def main() -> None:
    if len(sys.argv) != 2:
        fail("usage: cache_rate_limit.py <index.html>")

    p = Path(sys.argv[1])
    s = p.read_text()

    old_gj = re.search(r"async function gj\(path\)\{.*?return r\.json\(\)\}", s, re.S)
    if not old_gj:
        fail("gj function anchor missing")

    new_gj = r'''const GTA_API_CACHE_TTL=20*60*1000;
const GTA_API_STALE_TTL=6*60*60*1000;
const GTA_AUDIT_CACHE_TTL=30*60*1000;
const GTA_AUDIT_STALE_TTL=24*60*60*1000;
function gtaCacheRead(key,maxAge){try{let x=JSON.parse(localStorage.getItem(key)||'null');if(!x||!x.ts||Date.now()-x.ts>maxAge)return null;return{data:x.data,age:Date.now()-x.ts,ts:x.ts}}catch{return null}}
function gtaCacheWrite(key,data){try{localStorage.setItem(key,JSON.stringify({ts:Date.now(),data}))}catch{}}
function gtaApiKey(path){return'gta_api_v3:'+path}
function gtaAuditKey(u){return'gta_audit_v3:'+String(u).toLowerCase()}
function gtaRememberAuditKey(key){try{let a=JSON.parse(localStorage.getItem('gta_audit_keys_v3')||'[]').filter(x=>x!==key);a.unshift(key);for(let old of a.slice(3))localStorage.removeItem(old);localStorage.setItem('gta_audit_keys_v3',JSON.stringify(a.slice(0,3)))}catch{}}
function gtaRateResetText(r){let raw=Number(r.headers.get('x-ratelimit-reset')||0),d=raw?new Date(raw*1000):null;if(!d||!Number.isFinite(d.getTime()))return'';let when=d.toLocaleTimeString(lang==='fa'?'fa-IR':'en-US',{hour:'2-digit',minute:'2-digit'});return lang==='fa'?` سهمیه حدود ${when} دوباره باز می‌شود.`:` Limit resets around ${when}.`}
function gtaIsRateLimitError(e){return /rate limit|محدودیت GitHub API|HTTP 403/i.test((e&&e.message)||String(e||''))}
async function gj(path,opts={}){
  let key=gtaApiKey(path),fresh=!opts.fresh&&gtaCacheRead(key,GTA_API_CACHE_TTL),stale=gtaCacheRead(key,GTA_API_STALE_TTL);
  if(fresh)return fresh.data;
  let r;
  try{r=await fetch('https://api.github.com'+path,{headers:{Accept:'application/vnd.github+json'},cache:'no-store'})}
  catch(e){if(stale)return stale.data;throw e}
  if(r.status===401)throw Error('GitHub API HTTP 401');
  if(r.status===403){let rem=r.headers.get('x-ratelimit-remaining');if(stale&&rem==='0')return stale.data;let base=rem==='0'?(lang==='fa'?'محدودیت GitHub API فعال است.':'GitHub API rate limit reached.'):`GitHub API HTTP 403`;throw Error(base+(rem==='0'?gtaRateResetText(r):''))}
  if(!r.ok)throw Error(r.status===404?(lang==='fa'?'اکانت یا منبع GitHub پیدا نشد.':'GitHub account/resource not found.'):`GitHub API HTTP ${r.status}`);
  let data=await r.json();gtaCacheWrite(key,data);return data
}'''
    s = s[:old_gj.start()] + new_gj + s[old_gj.end():]

    audit_match = re.search(r"async function audit\(v\)\{.*?\}\nconst rank=", s, re.S)
    if not audit_match:
        fail("audit function anchor missing")
    old_audit_block = audit_match.group(0)
    old_audit = old_audit_block[:-len("\nconst rank=")]
    network_audit = old_audit.replace("async function audit(v)", "async function auditNetwork(v)", 1)
    wrapper = r'''async function audit(v){
  let u=norm(v),key=gtaAuditKey(u),fresh=gtaCacheRead(key,GTA_AUDIT_CACHE_TTL),stale=gtaCacheRead(key,GTA_AUDIT_STALE_TTL);
  if(fresh){stage.textContent=lang==='fa'?'نتیجه از کش امن مرورگر بارگذاری شد…':'Loading cached scan…';let out=fresh.data;out._cache={mode:'fresh',age:fresh.age};return out}
  try{let out=await auditNetwork(u);gtaCacheWrite(key,out);gtaRememberAuditKey(key);out._cache={mode:'network',age:0};return out}
  catch(e){if(stale&&gtaIsRateLimitError(e)){stage.textContent=lang==='fa'?'محدودیت API فعال است؛ آخرین اسکن ذخیره‌شده نمایش داده می‌شود…':'API limit active; showing the last saved scan…';let out=stale.data;out._cache={mode:'stale-rate-limit',age:stale.age};return out}throw e}
}
'''
    replacement = network_audit + "\n" + wrapper + "const rank="
    s = s[:audit_match.start()] + replacement + s[audit_match.end():]

    old_note = "(r.coverage.partial?(lang==='fa'?'پوشش اسکن به‌دلیل سقف ایمن مرورگر/GitHub API ناقص بود.':'Scan coverage was partial due to safe browser/GitHub API limits.'):'')"
    new_note = "(r.coverage.partial?(lang==='fa'?'پوشش اسکن به‌دلیل سقف ایمن مرورگر/GitHub API ناقص بود.':'Scan coverage was partial due to safe browser/GitHub API limits.'):'')+(r._cache&&r._cache.mode==='fresh'?(lang==='fa'?' نتیجه از کش اسکن اخیر نمایش داده شد.':' Result loaded from a recent scan cache.'):'')+(r._cache&&r._cache.mode==='stale-rate-limit'?(lang==='fa'?' به‌دلیل محدودیت GitHub API، آخرین نتیجه ذخیره‌شده نمایش داده شد.':' GitHub API is rate-limited; the last saved scan is shown.'):'')"
    if old_note not in s:
        fail("limit-note render anchor missing")
    s = s.replace(old_note, new_note, 1)

    required = [
        'GTA_API_CACHE_TTL',
        'GTA_AUDIT_CACHE_TTL',
        'function gtaCacheRead(',
        'function gtaRateResetText(',
        'async function auditNetwork(v)',
        'async function audit(v)',
        "mode:'stale-rate-limit'",
        'last saved scan is shown',
    ]
    for marker in required:
        if marker not in s:
            fail(f"missing marker: {marker}")

    p.write_text(s)

    scripts = re.findall(r'<script[^>]*>(.*?)</script>', s, re.S)
    if not scripts:
        fail("inline scripts missing")
    runtime = p.parent / "cache-runtime-check.js"
    runtime.write_text("\n".join(scripts))
    subprocess.run(["node", "--check", str(runtime)], check=True)
    runtime.unlink()


if __name__ == "__main__":
    main()
