"""Zero-dependency local desktop UI.

Serves a small single-page app from Python's standard-library HTTP server,
bound to localhost only. The operator pastes an engagement scope, picks modules,
and runs an audit; results render in the browser. No external packages, so it
runs on any machine with Python — Linux or Windows alike.

Security note: this binds to 127.0.0.1 by default and is intended for the
operator's own machine. It performs the same scope-gated audits as the CLI.
"""
from __future__ import annotations

import json
import threading
import webbrowser
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

from sentinel import __version__
from sentinel.core.engine import Engine
from sentinel.core.scope import Scope, ScopeError
from sentinel.modules import all_modules
from sentinel.modules.base import ModuleContext


def _parse_scope_text(text: str) -> dict:
    text = text.strip()
    if not text:
        raise ScopeError("scope is empty")
    try:
        return json.loads(text)
    except json.JSONDecodeError:
        pass
    try:
        import yaml  # type: ignore
    except ModuleNotFoundError:
        raise ScopeError("scope is not valid JSON and PyYAML is not installed for YAML parsing")
    data = yaml.safe_load(text)
    if not isinstance(data, dict):
        raise ScopeError("scope did not parse to an object")
    return data


INDEX_HTML = """<!DOCTYPE html>
<html lang="en"><head><meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>Sentinel Audit</title>
<style>
  :root { color-scheme: dark; }
  * { box-sizing: border-box; }
  body { margin:0; font-family: system-ui,-apple-system,Segoe UI,Roboto,sans-serif;
         background:#0f1115; color:#e6e6e6; }
  header { padding:16px 24px; background:#161a22; border-bottom:1px solid #272c38;
           display:flex; align-items:center; gap:12px; }
  header h1 { font-size:16px; margin:0; } header .v{color:#6b7280;font-size:12px;}
  .wrap { display:grid; grid-template-columns: 380px 1fr; gap:0; height: calc(100vh - 53px); }
  .panel { padding:18px 20px; overflow:auto; }
  .left { border-right:1px solid #272c38; background:#12151c; }
  label { display:block; font-size:12px; color:#9aa4b2; margin:14px 0 4px; text-transform:uppercase; letter-spacing:.04em;}
  textarea, input { width:100%; background:#0b0d12; color:#e6e6e6; border:1px solid #272c38;
                    border-radius:8px; padding:10px; font-family:ui-monospace,Menlo,Consolas,monospace; font-size:13px;}
  textarea { min-height:190px; resize:vertical; }
  .mods { display:flex; flex-wrap:wrap; gap:8px; }
  .mods label { display:flex; align-items:center; gap:6px; margin:0; text-transform:none;
                background:#0b0d12; border:1px solid #272c38; padding:6px 10px; border-radius:999px; color:#e6e6e6; cursor:pointer;}
  .mods input { width:auto; }
  button { margin-top:16px; background:#2d6cdf; color:#fff; border:0; padding:11px 16px;
           border-radius:8px; font-size:14px; cursor:pointer; width:100%; }
  button:disabled { opacity:.5; cursor:default; }
  .note { font-size:12px; color:#6b7280; margin-top:10px; line-height:1.5; }
  .chips { display:flex; gap:8px; flex-wrap:wrap; margin:4px 0 16px; }
  .chip { color:#fff; padding:4px 10px; border-radius:999px; font-size:12px; }
  table { width:100%; border-collapse:collapse; }
  th,td { text-align:left; padding:9px 10px; border-bottom:1px solid #222733; font-size:13px; vertical-align:top;}
  th { color:#9aa4b2; font-size:11px; text-transform:uppercase; }
  .pill{color:#fff;padding:2px 8px;border-radius:6px;font-size:11px;white-space:nowrap;}
  .rec{color:#7fd1a0;font-size:12px;margin-top:3px;} .detail{color:#c7cdd6;margin-top:3px;}
  .err{color:#ff6b6b;white-space:pre-wrap;}
  .muted{color:#6b7280;}
  #status{font-size:13px;color:#9aa4b2;margin-top:10px;}
</style></head>
<body>
<header><h1>🛡️ Sentinel Audit</h1><span class="v">v__VERSION__ · local UI · authorized testing only</span></header>
<div class="wrap">
  <div class="panel left">
    <label>Engagement scope (JSON or YAML)</label>
    <textarea id="scope">{
  "engagement": "Local self-test",
  "authorized_by": "you@example.com (you own these hosts)",
  "authorized_until": "2030-12-31",
  "targets": ["127.0.0.1"],
  "exclude": []
}</textarea>
    <label>Targets (comma-separated, optional — defaults to scope)</label>
    <input id="targets" placeholder="127.0.0.1">
    <label>Modules</label>
    <div class="mods" id="mods"></div>
    <label>Ports</label>
    <input id="ports" value="common">
    <button id="runBtn">Run audit</button>
    <div id="status"></div>
    <div class="note">The server refuses any target not authorized by the scope.
       It binds to localhost and runs the same checks as the CLI.</div>
  </div>
  <div class="panel right" id="results">
    <p class="muted">Configure a scope on the left and run an audit. Results appear here.</p>
  </div>
</div>
<script>
const SEV_COLOR={CRITICAL:"#7b1fa2",HIGH:"#c62828",MEDIUM:"#ef6c00",LOW:"#f9a825",INFO:"#1565c0"};
let MODULES=[];
async function loadModules(){
  const r=await fetch("/api/modules"); MODULES=await r.json();
  const box=document.getElementById("mods");
  box.innerHTML=MODULES.map(m=>`<label title="${m.description}"><input type="checkbox" value="${m.name}" checked>${m.name}</label>`).join("");
}
function selectedModules(){return [...document.querySelectorAll("#mods input:checked")].map(e=>e.value);}
function esc(s){return (s==null?"":String(s)).replace(/[&<>]/g,c=>({'&':'&amp;','<':'&lt;','>':'&gt;'}[c]));}
async function run(){
  const btn=document.getElementById("runBtn"), status=document.getElementById("status");
  btn.disabled=true; status.textContent="Running audit…";
  const payload={scope_text:document.getElementById("scope").value,
     targets:document.getElementById("targets").value.split(",").map(s=>s.trim()).filter(Boolean),
     modules:selectedModules(), ports:document.getElementById("ports").value.trim()||"common"};
  try{
    const r=await fetch("/api/run",{method:"POST",headers:{"Content-Type":"application/json"},body:JSON.stringify(payload)});
    const data=await r.json();
    if(!r.ok){document.getElementById("results").innerHTML=`<div class="err">${esc(data.error||"error")}</div>`;}
    else{render(data);}
  }catch(e){document.getElementById("results").innerHTML=`<div class="err">${esc(e)}</div>`;}
  finally{btn.disabled=false; status.textContent="";}
}
function render(rep){
  const c=rep.severity_counts;
  const chips=["CRITICAL","HIGH","MEDIUM","LOW","INFO"].map(s=>`<span class="chip" style="background:${SEV_COLOR[s]}">${s}: ${c[s]}</span>`).join("");
  let findings=[];
  rep.results.forEach(res=>res.findings.forEach(f=>findings.push(f)));
  findings.sort((a,b)=>b.severity_level-a.severity_level);
  const denied=(rep.scope_summary.denied_targets||[]);
  const rows=findings.map(f=>`<tr>
     <td><span class="pill" style="background:${SEV_COLOR[f.severity]}">${f.severity}</span></td>
     <td>${esc(f.target)}</td><td>${esc(f.module)}</td>
     <td><strong>${esc(f.title)}</strong>
       ${f.detail?`<div class="detail">${esc(f.detail)}</div>`:""}
       ${f.recommendation?`<div class="rec">↳ ${esc(f.recommendation)}</div>`:""}</td></tr>`).join("")
     || `<tr><td colspan="4" class="muted">No findings.</td></tr>`;
  document.getElementById("results").innerHTML=`
    <h2 style="margin:0 0 4px">${esc(rep.engagement)}</h2>
    <div class="muted" style="font-size:12px">Authorized by ${esc(rep.authorized_by)} · ${rep.duration_seconds}s · ${rep.targets.length} target(s)</div>
    <div class="chips" style="margin-top:12px">${chips}</div>
    ${denied.length?`<div class="note">Skipped (out of scope): ${denied.map(esc).join("; ")}</div>`:""}
    <table><thead><tr><th>Sev</th><th>Target</th><th>Module</th><th>Finding</th></tr></thead><tbody>${rows}</tbody></table>`;
}
document.getElementById("runBtn").addEventListener("click",run);
loadModules();
</script>
</body></html>"""


class Handler(BaseHTTPRequestHandler):
    server_version = f"Sentinel/{__version__}"

    def log_message(self, fmt, *args):  # quieter console
        return

    def _send(self, code: int, body: bytes, ctype: str = "application/json"):
        self.send_response(code)
        self.send_header("Content-Type", ctype)
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def _json(self, code: int, obj) -> None:
        self._send(code, json.dumps(obj).encode("utf-8"))

    def do_GET(self):
        if self.path in ("/", "/index.html"):
            html = INDEX_HTML.replace("__VERSION__", __version__).encode("utf-8")
            self._send(200, html, "text/html; charset=utf-8")
        elif self.path == "/api/modules":
            mods = [{"name": n, "description": m.description} for n, m in sorted(all_modules().items())]
            self._json(200, mods)
        else:
            self._json(404, {"error": "not found"})

    def do_POST(self):
        length = int(self.headers.get("Content-Length", 0))
        raw = self.rfile.read(length) if length else b"{}"
        try:
            payload = json.loads(raw.decode("utf-8"))
        except json.JSONDecodeError:
            self._json(400, {"error": "invalid JSON body"})
            return

        if self.path == "/api/run":
            self._handle_run(payload)
        else:
            self._json(404, {"error": "not found"})

    def _handle_run(self, payload: dict) -> None:
        try:
            raw_scope = _parse_scope_text(payload.get("scope_text", ""))
            scope = Scope.from_dict(raw_scope, source_path="<gui>")
        except ScopeError as exc:
            self._json(400, {"error": f"scope error: {exc}"})
            return

        module_names = payload.get("modules") or ["discovery", "portscan", "services", "tls", "http", "dns"]
        available = set(all_modules())
        unknown = [m for m in module_names if m not in available]
        if unknown:
            self._json(400, {"error": f"unknown module(s): {', '.join(unknown)}"})
            return

        specs = payload.get("targets") or list(scope.targets)
        ctx = ModuleContext(scope=scope, ports=payload.get("ports", "common"))
        engine = Engine(scope, ctx)
        report = engine.run(specs, module_names)
        self._json(200, report.to_dict())


def serve(host: str = "127.0.0.1", port: int = 8787, open_browser: bool = True) -> int:
    httpd = ThreadingHTTPServer((host, port), Handler)
    url = f"http://{host}:{port}/"
    print(f"Sentinel desktop UI running at {url}")
    print("Authorized testing only. Press Ctrl+C to stop.")
    if open_browser:
        threading.Timer(0.6, lambda: webbrowser.open(url)).start()
    try:
        httpd.serve_forever()
    except KeyboardInterrupt:
        print("\nShutting down.")
    finally:
        httpd.server_close()
    return 0
