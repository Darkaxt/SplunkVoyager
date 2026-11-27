"""Credentials in request URLs: found in the merged requests (path and query string), written to
credentials.jsonl (full values) and shown in the HTML report masked and encoded, decoded one value at a time on
click (the page never holds them as plain text).

What counts, after URL-decoding (repeatedly, for double encoding):
  url-credentials  scheme://user:password@host inside a parameter value or the path
  basic-auth       a value "Basic <base64 of user:password>"
  password         a parameter whose name says password (password, passwd, pwd, passphrase, pass, pw, ...)
  token / key      a parameter whose name says secret, token, api key, access/refresh/id/auth token, ...
                   (not anti-CSRF, captcha, nonce, paging or state parameters)
Placeholders and empty values are left out. The user is taken from the URL, the Basic value or a user-like
parameter of the same request.
"""
import base64
import binascii
import hashlib
import html
import json
import re
import sys
from pathlib import Path
from urllib.parse import parse_qsl, quote, quote_plus, unquote, unquote_plus

# a line is only parsed when it holds one of these (lowercased; plain substring tests are fast on huge files)
HINTS = ("@", "%40", "pass", "pwd", "secret", "token", "key", "auth", "basic", "bearer")
# the password runs to the last @ before the host (a decoded password may contain @)
USERINFO = re.compile(r"\b([a-z][a-z0-9+.\-]{1,15})://([^\s/@:?#\\]{1,128}):([^\s/?#\\]{1,256})@([^\s/?#:@\\]{1,255})", re.I)
BASIC = re.compile(r"\bbasic\s+([A-Za-z0-9+/_\-]{6,}={0,2})", re.I)
PASS_NAME = re.compile(r"passw(or)?d|passphrase|pwd|^pass\d?$|^pw\d?$|^pword$|^userpass$", re.I)
TOKEN_NAME = re.compile(r"secret|api[_\-.]?key|apikey|access[_\-.]?token|refresh[_\-.]?token|id[_\-.]?token|"
                        r"auth[_\-.]?token|bearer|private[_\-.]?key|^token$|^auth$|^authorization$|_token$|^jwt$", re.I)
NOT_SECRET = re.compile(r"csrf|xsrf|authenticity|captcha|nonce|^state$|page|next|cursor|continuation|sync|verify_?token", re.I)
USER_NAME = re.compile(r"^(user(name|_?id)?|login|email|e-mail|mail|uid|usr|account|acct|u)$", re.I)
PLACEHOLDER = re.compile(r"^(|null|none|nil|undefined|true|false|0|-|[*•x.]+|\{\{?.*\}\}?|\$\{.*\}|\$\w+|%s|<.*>|\[.*\])$", re.I)
KIND_ORDER = {"url-credentials": 0, "basic-auth": 1, "password": 2, "token": 3}
MAX_IN_REPORT = 5000


def decode(s, plus=True):
    """URL-decode until stable (at most 4 times)."""
    s = str(s or "")
    for _ in range(4):
        d = unquote_plus(s) if plus else unquote(s)
        if d == s:
            break
        s = d
    return s


def _b64(s):
    return base64.b64encode(s.encode("utf-8", "surrogatepass")).decode("ascii")


def _basic(blob):
    try:
        raw = base64.b64decode(blob + "=" * (-len(blob) % 4), altchars=b"-_" if ("-" in blob or "_" in blob) else None,
                               validate=True)
        t = raw.decode("utf-8")
    except (binascii.Error, ValueError, UnicodeDecodeError):
        return None
    if ":" not in t or not t.isprintable():
        return None
    u, p = t.split(":", 1)
    return (u, p) if p else None


def _levels(s, plus=True):
    """s, then s decoded once, twice... until stable (at most 4)."""
    out = [str(s or "")]
    for _ in range(4):
        d = unquote_plus(out[-1]) if plus else unquote(out[-1])
        if d == out[-1]:
            break
        out.append(d)
    return out


def scan_row(r):
    """Credentials in one request group: list of (kind, param, user, secret), and the evidence (decoded URL as
    parts: plain strings and {"h": base64} for every hidden value)."""
    site, path, query = str(r.get("site") or ""), str(r.get("uri_path") or ""), str(r.get("uri_query") or "")
    raw = parse_qsl(query.lstrip("?"), keep_blank_values=True)            # values decoded once
    shown = [[decode(k), decode(v)] for k, v in raw]                       # what the evidence shows
    path_shown = decode(path, plus=False)
    user = next((v for k, v in shown if USER_NAME.match(k) and v and not PLACEHOLDER.match(v)), "")
    hits, spans = [], {}                        # spans: index (-1 = path) -> [(start, end, hidden value)]

    def userinfo(levels, idx, pname):
        # match at the first decoding level where it appears, so an encoded # / ? @ inside the password
        # doesn't cut it; the user and password are then decoded on their own
        for text in levels:
            ms = [m for m in USERINFO.finditer(text) if not PLACEHOLDER.match(decode(m.group(3), plus=False))]
            if ms:
                for m in ms:
                    hits.append(("url-credentials", pname, decode(m.group(2), plus=False), decode(m.group(3), plus=False)))
                    spans.setdefault(idx, []).append((m.start(3), m.end(3), m.group(3)))
                return text
        return None

    t = userinfo(_levels(path, plus=False), -1, "(path)")
    if t is not None:
        path_shown = t
    for i, (k, v) in enumerate(raw):
        kd = decode(k)
        t = userinfo(_levels(v)[:5], i, kd)
        if t is not None:
            shown[i][1] = t
            continue
        for text in _levels(v):
            ms = [(m, _basic(m.group(1))) for m in BASIC.finditer(text)]
            ms = [(m, up) for m, up in ms if up]
            if ms:
                for m, up in ms:
                    hits.append(("basic-auth", kd, up[0], up[1]))
                    spans.setdefault(i, []).append((m.start(1), m.end(1), m.group(1)))
                shown[i][1] = text
                break
        if i in spans:
            continue
        vd = shown[i][1]
        if not vd or PLACEHOLDER.match(vd.strip()):
            continue
        kind = "password" if PASS_NAME.search(kd) else "token" if TOKEN_NAME.search(kd) and not NOT_SECRET.search(kd) else None
        if kind:
            hits.append((kind, kd, user, vd))
            spans.setdefault(i, []).append((0, len(vd), vd))
    params = shown
    dpath = path_shown
    if not hits:
        return [], None

    def parts(text, sp):
        out, pos = [], 0
        for a, b, val in sorted(sp or []):
            if a < pos:
                continue
            out += [text[pos:a], {"h": _b64(val)}]
            pos = b
        out.append(text[pos:])
        return out

    ev = [site] + parts(dpath, spans.get(-1))
    for i, (k, v) in enumerate(params):
        ev.append(("?" if i == 0 else "&") + k + "=")
        ev += parts(v, spans.get(i))
    merged = []                                  # join neighbouring strings
    for p in ev:
        if isinstance(p, str) and merged and isinstance(merged[-1], str):
            merged[-1] += p
        elif p != "":
            merged.append(p)
    return hits, merged


def scan_requests(requests_path, log=None):
    """Aggregated credentials over the merged requests (streamed; lines without a hint are skipped unparsed)."""
    log = log or (lambda m: print(m, file=sys.stderr, flush=True))
    agg, rows, looked = {}, 0, 0
    with open(requests_path, encoding="utf-8") as fh:
        for line in fh:
            rows += 1
            low = line.lower()
            if not any(h in low for h in HINTS):
                continue
            looked += 1
            try:
                r = json.loads(line)
            except ValueError:
                continue
            hits, ev = scan_row(r)
            for kind, param, user, secret in hits:
                key = (kind, r.get("site", ""), r.get("uri_path", ""), param, user, secret)
                a = agg.get(key)
                if a is None:
                    a = agg[key] = {"kind": kind, "site": r.get("site", ""), "path": r.get("uri_path", ""),
                                    "param": param, "user": user, "secret": secret, "requests": 0, "groups": 0,
                                    "status": set(), "src": set(), "first": None, "last": None, "evidence": ev}
                a["requests"] += int(r.get("count") or 0)
                a["groups"] += 1
                a["status"].update(r.get("status") or [])
                a["src"].update(r.get("src") or [])
                for k, f, v in (("first", min, r.get("et")), ("last", max, r.get("lt"))):
                    if v:
                        a[k] = v if a[k] is None else f(a[k], v)
    out = []
    for a in agg.values():
        a["status"], a["src"] = sorted(a["status"]), sorted(a["src"])
        out.append(a)
    # the same secret elsewhere (other sites, users or parameters)
    by_secret = {}
    for a in out:
        by_secret.setdefault(a["secret"], []).append(a)
    for a in out:
        a["same_secret"] = len(by_secret[a["secret"]]) - 1
    out.sort(key=lambda a: (KIND_ORDER[a["kind"]], -a["requests"], a["site"], a["path"]))
    log(f"Credentials: {len(out):,} found in {rows:,} request groups ({looked:,} looked at)")
    return out


def mask(s):
    n = len(s)
    if n <= 3:
        return "•" * max(n, 3)
    return s[0] + "•" * min(n - 2, 10) + s[-1]


def summary(creds, attack_sources=()):
    """For findings.json and the web page: no secret, only its mask, length and a short fingerprint."""
    att = set(attack_sources)
    return [{"kind": a["kind"], "site": a["site"], "path": a["path"], "param": a["param"], "user": a["user"],
             "masked": mask(a["secret"]), "length": len(a["secret"]),
             "fingerprint": hashlib.sha256(a["secret"].encode("utf-8", "surrogatepass")).hexdigest()[:12],
             "requests": a["requests"], "status": a["status"], "sources": len(a["src"]),
             "attack_sources": sorted(att & set(a["src"]))[:20], "first": a["first"], "last": a["last"],
             "same_secret": a["same_secret"]} for a in creds]


def write_jsonl(creds, path):
    tmp = Path(str(path) + ".tmp")
    with open(tmp, "w", encoding="utf-8", newline="\n") as fh:
        for a in creds:
            fh.write(json.dumps({k: v for k, v in a.items() if k != "evidence"}, ensure_ascii=False) + "\n")
    tmp.replace(path)


START, END = "<!--voyager-credentials-->", "<!--/voyager-credentials-->"
_NAV = '<a href="#s-cred">Credentials</a>'
_CSS = """
#s-cred .cr-note{color:var(--muted);margin:0 0 10px}
#s-cred table{border-collapse:collapse;width:100%;font-size:13px}
#s-cred th,#s-cred td{border-bottom:1px solid var(--line);padding:5px 7px;text-align:left;vertical-align:top}
#s-cred th{background:var(--th);font-weight:600;position:sticky;top:0}
#s-cred td.n{text-align:right;white-space:nowrap}
#s-cred .mono{font-family:Consolas,Menlo,monospace;font-size:12.5px;word-break:break-all}
.sec{cursor:pointer;border-bottom:1px dashed var(--muted);padding:0 2px;border-radius:3px}
.sec.open{background:var(--sel);border-bottom-style:solid}
#s-cred .sec{cursor:pointer;border-bottom:1px dashed var(--muted);padding:0 2px;border-radius:3px;white-space:pre-wrap}
#s-cred .sec:hover{background:var(--hover)}
#s-cred .sec.open{background:var(--sel);border-bottom-style:solid}
#s-cred .kind{display:inline-block;padding:0 6px;border-radius:8px;border:1px solid var(--line);font-size:12px;white-space:nowrap}
#s-cred .att{color:#c0392b;font-weight:600;font-size:12px}
#s-cred .ev{color:var(--muted)}
#s-cred .cr-more{margin-top:8px}
#s-cred button{font:inherit;font-size:12px;padding:2px 8px;border:1px solid var(--line);background:var(--panel);color:var(--fg);border-radius:4px;cursor:pointer}
"""
_JS = r"""
(function(){
const D=JSON.parse(atob(document.getElementById('cred-data').textContent.trim()));
const dec=b=>new TextDecoder().decode(Uint8Array.from(atob(b),c=>c.charCodeAt(0)));
const esc=s=>String(s??'').replace(/[&<>"]/g,c=>({'&':'&amp;','<':'&lt;','>':'&gt;','"':'&quot;'}[c]));
const mask=s=>s.length<=3?'•'.repeat(Math.max(s.length,3)):s[0]+'•'.repeat(Math.min(s.length-2,10))+s[s.length-1];
const sec=b=>{const v=dec(b);return `<span class="sec mono" data-b="${b}" title="Click to decode (${v.length} characters); click again to mask">${esc(mask(v))}</span>`;};
const KIND={'url-credentials':'URL credentials','basic-auth':'Basic auth','password':'password parameter','token':'token / key parameter'};
const host=document.getElementById('cred'), A=new Set(D.attack_sources);
let all=false;
function draw(){
  const rows=all?D.items:D.items.slice(0,200);
  host.innerHTML=`<table><tr><th>Kind</th><th>Site and path</th><th>Parameter</th><th>User</th><th>Secret</th><th>Requests</th><th>Status</th><th>Sources</th><th>First seen</th><th>Last seen</th></tr>
  ${rows.map(a=>`<tr><td><span class="kind">${esc(KIND[a.kind]||a.kind)}</span>${a.same_secret?`<br><span class="ev">same secret in ${a.same_secret} other row(s)</span>`:''}</td>
   <td class="mono">${esc(a.site)}${esc(a.path)}</td><td class="mono">${esc(a.param)}</td><td class="mono">${esc(a.user)}</td><td>${sec(a.s)}</td>
   <td class="n">${a.requests.toLocaleString()}</td><td class="mono">${esc(a.status.join(', '))}</td>
   <td class="mono">${a.src.slice(0,5).map(s=>esc(s)+(A.has(s)?' <span class="att" title="also an attack source in this report">attack source</span>':'')).join('<br>')}${a.src.length>5?`<br><span class="ev">+${a.src.length-5} more</span>`:''}</td>
   <td class="mono">${esc(a.first||'')}</td><td class="mono">${esc(a.last||'')}</td></tr>
   <tr><td></td><td colspan="9" class="mono ev">Evidence: ${a.ev.map(p=>typeof p==='string'?esc(p):sec(p.h)).join('')}</td></tr>`).join('')}</table>
  ${D.items.length>200?`<div class="cr-more"><button id="cred-all">${all?'Show the first 200':'Show all '+D.items.length.toLocaleString()}</button></div>`:''}`;
}
document.addEventListener('click',e=>{
  if(e.target.id==='cred-all'){all=!all;draw();return;}
  const s=e.target.closest('.sec'); if(!s) return;
  e.preventDefault(); e.stopPropagation();
  const v=dec(s.dataset.b); s.classList.toggle('open'); s.textContent=s.classList.contains('open')?v:mask(v);
},true);
draw();
// the same secrets anywhere else in the report (payload tables, graph, focus results): masked, click to decode
const F=D.forms.map(b=>[dec(b),b]);
if(F.length){
  const reEsc=s=>s.replace(/[.*+?^${}()|[\]\\]/g,'\\$&');
  const RX=new RegExp(F.map(f=>reEsc(f[0])).join('|'),'g'), B=new Map(F);
  const skip=n=>n.parentElement&&n.parentElement.closest('script,style,textarea,.sec,#s-cred');
  function scan(root){
    if(root.nodeType===1&&root.closest&&root.closest('#s-cred,.sec')) return;
    if(root.nodeType===1){ for(const el of [root,...root.querySelectorAll('[title]')]){ const t=el.getAttribute&&el.getAttribute('title');
      if(t&&RX.test(t)){ RX.lastIndex=0; el.setAttribute('title',t.replace(RX,m=>mask(m))); } RX.lastIndex=0; } }
    const w=document.createTreeWalker(root,NodeFilter.SHOW_TEXT), hits=[];
    for(let n=w.currentNode.nodeType===3?w.currentNode:w.nextNode();n;n=w.nextNode()){ RX.lastIndex=0; if(RX.test(n.data)&&!skip(n)) hits.push(n); }
    for(const n of hits){
      const f=document.createDocumentFragment(); let pos=0; RX.lastIndex=0; let m;
      while((m=RX.exec(n.data))){ f.append(n.data.slice(pos,m.index));
        const sp=document.createElement('span'); sp.className='sec mono'; sp.dataset.b=B.get(m[0]); sp.title='Click to decode; click again to mask';
        sp.textContent=mask(m[0]); f.append(sp); pos=m.index+m[0].length; }
      f.append(n.data.slice(pos)); n.replaceWith(f);
    }
  }
  scan(document.body);
  let queued=new Set();
  new MutationObserver(ms=>{ for(const m of ms) for(const n of m.addedNodes) queued.add(n);
    requestAnimationFrame(()=>{ const q=[...queued]; queued=new Set(); q.forEach(n=>n.isConnected&&scan(n)); });
  }).observe(document.body,{childList:true,subtree:true});
}
})();
"""


def report_section(creds, attack_sources=(), total_rows=None):
    """HTML pieces for the report: nav link, section (with the data, base64-encoded JSON), style and script."""
    items = [{"kind": a["kind"], "site": a["site"], "path": a["path"], "param": a["param"], "user": a["user"],
              "s": _b64(a["secret"]), "requests": a["requests"], "status": a["status"], "src": a["src"][:50],
              "first": a["first"], "last": a["last"], "same_secret": a["same_secret"], "ev": a["evidence"]}
             for a in creds[:MAX_IN_REPORT]]
    # every form a secret can take in the rest of the report (Payload Analyzer's sections show the payloads as
    # sent or decoded): the page masks them wherever they are displayed; shorter than 4 characters are left
    forms = set()
    for a in creds:
        sec = a["secret"]
        forms.update({sec, quote(sec, safe=""), quote(sec), quote_plus(sec)})
        for p in a["evidence"]:
            if isinstance(p, dict):
                forms.add(base64.b64decode(p["h"]).decode("utf-8", "surrogatepass"))
    forms = sorted((f for f in forms if len(f) >= 4), key=len, reverse=True)
    data = {"items": items, "attack_sources": sorted(set(attack_sources)), "forms": [_b64(f) for f in forms]}
    blob = base64.b64encode(json.dumps(data, ensure_ascii=False).encode("utf-8")).decode("ascii")
    kinds = {}
    for a in creds:
        kinds[a["kind"]] = kinds.get(a["kind"], 0) + 1
    by = ", ".join(f"{n:,} {k}" for k, n in sorted(kinds.items(), key=lambda x: KIND_ORDER[x[0]]))
    note = (f"{len(creds):,} credential(s) seen in request URLs (path or query string){': ' + by if by else ''}. "
            "Values are masked and stored encoded in this page: click a value to decode it, click again to mask it. "
            "Requests, status codes and sources are those of the request groups the value appears in.")
    if len(creds) > MAX_IN_REPORT:
        note += f" The {MAX_IN_REPORT:,} first are listed here; all are in credentials.jsonl."
    if not creds:
        note = "No credentials seen in the request URLs (path or query string)."
    section = (f'<section id="s-cred"><h2>Credentials in URLs</h2><p class="cr-note">{html.escape(note)}</p>'
               f'<div id="cred"></div><script type="application/octet-stream" id="cred-data">{blob}</script></section>')
    return section, f"<style>{_CSS}</style>", f"<script>{_JS}</script>"


def inject_report(report_path, creds, attack_sources=()):
    """Add (or replace) the credentials section in Payload Analyzer's HTML report."""
    p = Path(report_path)
    h = p.read_text(encoding="utf-8")
    h = re.sub(re.escape(START) + r".*?" + re.escape(END), "", h, flags=re.S)
    section, style, script = report_section(creds, attack_sources)
    wrap = lambda s: START + s + END
    if '<input id="focus"' in h:
        h = h.replace('<input id="focus"', wrap(_NAV) + '<input id="focus"', 1)
    elif "</nav>" in h:
        h = h.replace("</nav>", wrap(_NAV) + "</nav>", 1)
    h = h.replace("</head>", wrap(style) + "</head>", 1)
    if "</main>" in h:
        h = h.replace("</main>", wrap(section) + "</main>", 1)
    else:
        h = h.replace("</body>", wrap(section) + "</body>", 1)
    h = h.replace("</body>", wrap(script) + "</body>", 1)
    tmp = p.with_name(p.name + ".tmp")
    tmp.write_text(h, encoding="utf-8")
    tmp.replace(p)
