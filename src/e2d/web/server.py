"""Local web server wrapping `e2d migrate`.

Design notes
------------
* **Stdlib only.** `http.server` + `zipfile` + `tempfile` — no third-party deps,
  no external assets. The whole UI (HTML/CSS/JS) is inlined below, so it works
  with no internet connection.
* **Localhost only.** `serve()` binds 127.0.0.1 by default. The data on a real
  migration reveals architecture and often contains secrets, so we never expose
  it on the network.
* **Raw-body uploads.** Browsers POST each file's raw bytes with the name in an
  `X-Filename` header, so we avoid a multipart parser (the stdlib `cgi` helper is
  gone in 3.13). The server reuses the same `run_migration` core as the CLI.
* **Untrusted input.** Session ids, filenames, and zip member paths are all
  validated against path traversal before they touch the filesystem.
"""

from __future__ import annotations

import json
import re
import secrets
import shutil
import tempfile
import threading
import zipfile
from dataclasses import asdict
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from typing import Dict, List, Optional

from e2d.config import MappingConfig
from e2d.migrate import run_migration

_ZIP_MAGIC = b"PK\x03\x04"
_SESSION_RE = re.compile(r"^[a-zA-Z0-9_-]{8,64}$")
_MAX_UPLOAD = 200 * 1024 * 1024  # 200 MB ceiling per file — a sane guard, not a real limit


def _safe_name(name: str) -> str:
    """Reduce an arbitrary upload name to a single safe path segment."""
    name = name.replace("\\", "/").split("/")[-1]
    name = re.sub(r"[^A-Za-z0-9._-]", "_", name).lstrip(".")
    return name or "upload.dat"


_MAX_INLINE = 256 * 1024  # cap per-artifact text shown inline in the page
_LANGS = {".dql": "dql", ".json": "json", ".md": "markdown", ".tf": "hcl",
          ".dpl": "dpl", ".txt": "text"}


def _read_artifacts(out_dir: Path, outputs: List[str]) -> List[dict]:
    """Read each output's text so the page can show it inline + copy it.

    Directory outputs (e.g. a Terraform module `pipelines_tf/<x>/`) are listed
    by their files; oversized or binary content is summarised, never inlined raw.
    """
    artifacts: List[dict] = []
    for rel in outputs:
        target = (out_dir / rel)
        paths = sorted(p for p in target.rglob("*") if p.is_file()) if target.is_dir() \
            else ([target] if target.is_file() else [])
        for p in paths:
            name = str(p.relative_to(out_dir)).replace("\\", "/")
            try:
                raw = p.read_bytes()
            except OSError:
                continue
            if len(raw) > _MAX_INLINE:
                artifacts.append({"path": name, "lang": "text", "truncated": True,
                                  "content": raw[:_MAX_INLINE].decode("utf-8", "replace")})
                continue
            try:
                content = raw.decode("utf-8")
            except UnicodeDecodeError:
                artifacts.append({"path": name, "lang": "binary",
                                  "content": f"(binary file, {len(raw)} bytes)"})
                continue
            artifacts.append({"path": name, "lang": _LANGS.get(p.suffix.lower(), "text"),
                              "content": content})
    return artifacts


class Sessions:
    """Owns per-upload temp directories and runs migrations against them.

    Kept deliberately separate from the HTTP handler so it can be unit-tested
    without opening a socket.
    """

    def __init__(self, config: Optional[MappingConfig] = None):
        self.config = config or MappingConfig()
        self._base = Path(tempfile.mkdtemp(prefix="e2d-web-"))
        self._sessions: Dict[str, Dict[str, Path]] = {}
        self._lock = threading.Lock()

    # -- lifecycle ---------------------------------------------------------- #

    def new(self) -> str:
        sid = secrets.token_urlsafe(12)
        sdir = self._base / sid
        (sdir / "in").mkdir(parents=True)
        (sdir / "out").mkdir(parents=True)
        with self._lock:
            self._sessions[sid] = {"in": sdir / "in", "out": sdir / "out"}
        return sid

    def _dirs(self, sid: str) -> Dict[str, Path]:
        if not _SESSION_RE.match(sid or ""):
            raise KeyError("bad session id")
        with self._lock:
            if sid not in self._sessions:
                raise KeyError("unknown session")
            return self._sessions[sid]

    def close(self) -> None:
        shutil.rmtree(self._base, ignore_errors=True)

    # -- uploads ------------------------------------------------------------ #

    def add_file(self, sid: str, filename: str, data: bytes) -> int:
        """Stash one uploaded file in the session input dir.

        If the bytes are a zip, its members are extracted (path-traversal safe);
        otherwise the file is written as-is. Returns the number of input files
        the session now contains.
        """
        indir = self._dirs(sid)["in"]
        if data[:4] == _ZIP_MAGIC:
            self._extract_zip(data, indir)
        else:
            (indir / _safe_name(filename)).write_bytes(data)
        return sum(1 for p in indir.rglob("*") if p.is_file())

    @staticmethod
    def _extract_zip(data: bytes, dest: Path) -> None:
        import io

        with zipfile.ZipFile(io.BytesIO(data)) as zf:
            for member in zf.namelist():
                if member.endswith("/"):
                    continue
                # zip-slip guard: resolve and confirm the target stays under dest
                target = (dest / member).resolve()
                if not str(target).startswith(str(dest.resolve())):
                    continue
                target.parent.mkdir(parents=True, exist_ok=True)
                with zf.open(member) as src, open(target, "wb") as out:
                    shutil.copyfileobj(src, out)

    # -- migration ---------------------------------------------------------- #

    def migrate(self, sid: str) -> dict:
        dirs = self._dirs(sid)
        summary = run_migration(str(dirs["in"]), str(dirs["out"]), self.config)
        # bundle the outputs for download
        archive = dirs["out"].parent / "converted.zip"
        with zipfile.ZipFile(archive, "w", zipfile.ZIP_DEFLATED) as zf:
            for p in sorted(dirs["out"].rglob("*")):
                if p.is_file():
                    zf.write(p, p.relative_to(dirs["out"]))
        with self._lock:
            self._sessions[sid]["zip"] = archive
        from e2d.remediation import remediations_for_notes
        items = []
        for it in summary.items:
            d = asdict(it)
            d["artifacts"] = _read_artifacts(dirs["out"], it.outputs)
            d["remediation"] = [{"title": r.title, "what": r.what, "fix": r.fix}
                                for r in remediations_for_notes(it.notes)]
            items.append(d)
        return {
            "counts": summary.counts(),
            "total": len(summary.items),
            "items": items,
            "secrets": list(dict.fromkeys(summary.secrets)),
            "skipped": summary.skipped,
            "download": f"/download/{sid}",
        }

    def download(self, sid: str) -> bytes:
        zip_path = self._dirs(sid).get("zip")
        if not zip_path or not zip_path.exists():
            raise KeyError("nothing to download")
        return zip_path.read_bytes()

    # -- deploy converted dashboards to Dynatrace (creds kept in memory) ----- #

    def deploy(self, sid: str, cfg: dict) -> dict:
        from e2d.sinks import deploy_dashboards
        from e2d.sinks.dynatrace import deploy_detectors
        dirs = self._dirs(sid)
        out, indir = dirs["out"], dirs["in"]
        env, token, apply = cfg.get("env_url", ""), cfg.get("token", ""), bool(cfg.get("apply"))

        # 1) dashboards via the Document API
        ddir = out / "dashboards"
        dashboards = []
        for p in sorted(ddir.glob("*.json")) if ddir.exists() else []:
            try:
                dashboards.append((p.name, json.loads(p.read_text(encoding="utf-8"))))
            except (ValueError, OSError):
                continue
        dash_results = deploy_dashboards(env, token, dashboards, apply=apply)

        # 2) anomaly detectors via the Settings API — re-translate the alert inputs
        from e2d.migrate import classify
        from e2d.alerts import translate_alert
        specs = []
        for p in sorted(indir.rglob("*")):
            if not p.is_file():
                continue
            try:
                t = p.read_text(encoding="utf-8")
            except (OSError, UnicodeDecodeError):
                continue
            if classify(p, t) in ("watcher", "alerting_rule"):
                try:
                    specs.append(translate_alert(t, self.config, name=p.stem).spec)
                except Exception:
                    continue
        det_results = deploy_detectors(env, token, specs, apply=apply)

        # 3) pipelines still deploy via Terraform (OpenPipeline API is more involved)
        pipe = sorted(d.name for d in (out / "pipelines_tf").glob("*")) if (out / "pipelines_tf").exists() else []
        return {
            "applied": apply,
            "dashboards": [{"name": r.name, "ok": r.ok, "detail": r.detail} for r in dash_results],
            "detectors": [{"name": r.name, "ok": r.ok, "detail": r.detail} for r in det_results],
            "terraform": {"pipelines": pipe},
        }

    # -- pull from a live Elastic estate (creds kept in memory only) --------- #

    def connect(self, sid: str, cfg: dict) -> None:
        from e2d.sources import Connection
        self._dirs(sid)  # validate session
        conn = Connection(kibana_url=cfg.get("kibana_url", ""), es_url=cfg.get("es_url", ""),
                          token=cfg.get("token", ""), auth_scheme=cfg.get("auth_scheme", "ApiKey"),
                          verify_tls=cfg.get("verify_tls", True))
        with self._lock:
            self._sessions[sid]["conn"] = conn   # never written to disk

    def discover(self, sid: str) -> dict:
        from e2d.sources import discover
        conn = self._dirs(sid).get("conn")
        if conn is None:
            raise KeyError("not connected")
        return discover(conn)

    def pull(self, sid: str, selection: list) -> int:
        from e2d.sources import pull
        dirs = self._dirs(sid)
        conn = dirs.get("conn")
        if conn is None:
            raise KeyError("not connected")
        for name, content in pull(conn, selection):
            (dirs["in"] / _safe_name(name)).write_text(content, encoding="utf-8")
        return sum(1 for p in dirs["in"].rglob("*") if p.is_file())


# --------------------------------------------------------------------------- #
# HTTP handler
# --------------------------------------------------------------------------- #

def make_handler(sessions: Sessions):
    class Handler(BaseHTTPRequestHandler):
        server_version = "e2d-web"

        def log_message(self, *args):  # keep the console quiet
            pass

        def _send(self, code: int, body: bytes, ctype: str) -> None:
            self.send_response(code)
            self.send_header("Content-Type", ctype)
            self.send_header("Content-Length", str(len(body)))
            self.end_headers()
            self.wfile.write(body)

        def _json(self, code: int, obj: dict) -> None:
            self._send(code, json.dumps(obj).encode("utf-8"), "application/json")

        def _read_body(self) -> bytes:
            length = int(self.headers.get("Content-Length", 0))
            if length > _MAX_UPLOAD:
                raise ValueError("upload too large")
            return self.rfile.read(length) if length else b""

        def do_GET(self):  # noqa: N802
            if self.path == "/" or self.path == "/index.html":
                self._send(200, PAGE.encode("utf-8"), "text/html; charset=utf-8")
            elif self.path.startswith("/download/"):
                sid = self.path[len("/download/"):]
                try:
                    data = sessions.download(sid)
                except KeyError:
                    self._json(404, {"error": "not found"})
                    return
                self.send_response(200)
                self.send_header("Content-Type", "application/zip")
                self.send_header("Content-Disposition", "attachment; filename=converted.zip")
                self.send_header("Content-Length", str(len(data)))
                self.end_headers()
                self.wfile.write(data)
            else:
                self._json(404, {"error": "not found"})

        def do_POST(self):  # noqa: N802
            try:
                if self.path == "/session":
                    self._json(200, {"session": sessions.new()})
                elif self.path == "/upload":
                    sid = self.headers.get("X-Session", "")
                    name = self.headers.get("X-Filename", "upload.dat")
                    count = sessions.add_file(sid, name, self._read_body())
                    self._json(200, {"files": count})
                elif self.path == "/migrate":
                    sid = self.headers.get("X-Session", "")
                    self._json(200, sessions.migrate(sid))
                elif self.path == "/connect":
                    sid = self.headers.get("X-Session", "")
                    sessions.connect(sid, json.loads(self._read_body() or b"{}"))
                    self._json(200, {"ok": True})
                elif self.path == "/discover":
                    sid = self.headers.get("X-Session", "")
                    self._json(200, sessions.discover(sid))
                elif self.path == "/pull":
                    sid = self.headers.get("X-Session", "")
                    sel = json.loads(self._read_body() or b"[]")
                    self._json(200, {"files": sessions.pull(sid, sel)})
                elif self.path == "/deploy":
                    sid = self.headers.get("X-Session", "")
                    self._json(200, sessions.deploy(sid, json.loads(self._read_body() or b"{}")))
                else:
                    self._json(404, {"error": "not found"})
            except KeyError as e:
                self._json(404, {"error": str(e)})
            except Exception as e:  # surface failures to the page rather than 500-ing silently
                self._json(400, {"error": str(e)})

    return Handler


def serve(host: str = "127.0.0.1", port: int = 8765, open_browser: bool = True,
          config: Optional[MappingConfig] = None) -> None:
    """Run the local GUI until interrupted. Blocks the calling thread."""
    sessions = Sessions(config)
    httpd = ThreadingHTTPServer((host, port), make_handler(sessions))
    url = f"http://{host}:{port}/"
    print(f"e2d web GUI running at {url}  (offline — data stays on this machine)")
    print("Press Ctrl-C to stop.")
    if open_browser:
        import webbrowser

        threading.Thread(target=lambda: webbrowser.open(url), daemon=True).start()
    try:
        httpd.serve_forever()
    except KeyboardInterrupt:
        print("\nShutting down…")
    finally:
        httpd.server_close()
        sessions.close()


# --------------------------------------------------------------------------- #
# the page (inlined so it works with zero external assets / no network)
# --------------------------------------------------------------------------- #

PAGE = r"""<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>Elastic → Dynatrace migration</title>
<style>
  :root { --bg:#111315; --card:#16191d; --raise:#1b2026; --line:#272c33; --line2:#39414b;
          --ink:#d7dce2; --mut:#8b949f; --faint:#626b76;
          --ok:#57b769; --rev:#d4a63e; --man:#dd8047; --err:#e25b55;
          --act:#d4a63e; --act-ink:#1c1305; }
  * { box-sizing:border-box; }
  html { color-scheme:dark; }
  body { margin:0; background:var(--bg); color:var(--ink);
         font:14px/1.55 "Segoe UI",system-ui,sans-serif; }
  .wrap { max-width:880px; margin:0 auto; padding:0 22px 72px; }
  header { display:flex; align-items:baseline; justify-content:space-between; gap:14px;
           flex-wrap:wrap; padding:22px 0 14px; border-bottom:1px solid var(--line); }
  .brand { font-family:ui-monospace,"Cascadia Mono",Consolas,monospace; font-size:14px;
           color:var(--mut); }
  .brand b { color:var(--act); font-weight:700; border:1px solid var(--act);
             border-radius:3px; padding:1px 7px; margin-right:9px; }
  .runs { font-family:ui-monospace,Consolas,monospace; font-size:11.5px; color:var(--faint);
          letter-spacing:.04em; }
  .sub { color:var(--mut); margin:16px 0 4px; max-width:64ch; }
  .sub strong { color:var(--ink); }
  .lab { display:flex; align-items:center; gap:12px; margin:30px 0 10px;
         font-family:ui-monospace,Consolas,monospace; font-size:11px; letter-spacing:.18em;
         text-transform:uppercase; color:var(--faint); }
  .lab::after { content:""; flex:1; height:1px; background:var(--line); }
  .card { background:var(--card); border:1px solid var(--line); border-radius:4px; padding:18px; }
  summary.h { cursor:pointer; font-weight:600; }
  #drop { border:1px dashed var(--line2); border-radius:4px; padding:40px 20px; text-align:center;
          color:var(--mut); cursor:pointer; transition:border-color .15s, background .15s; }
  #drop:hover, #drop.hot { border-color:var(--act); background:var(--raise); color:var(--ink); }
  #drop strong { color:var(--ink); }
  .files { list-style:none; padding:0; margin:14px 0 0; font-size:13px; color:var(--mut); }
  .files li { padding:2px 0; }
  button { font-family:ui-monospace,Consolas,monospace; font-size:12px; font-weight:600;
           letter-spacing:.08em; text-transform:uppercase; color:var(--act-ink);
           background:var(--act); border:1px solid var(--act); border-radius:3px;
           padding:9px 18px; cursor:pointer; margin-top:16px; }
  button:disabled { opacity:.35; cursor:default; }
  .counts { display:flex; gap:8px; flex-wrap:wrap; margin:0 0 18px; }
  .pill { border:1px solid var(--line2); border-radius:3px; padding:5px 11px; font-size:12px;
          font-family:ui-monospace,Consolas,monospace; color:var(--mut); }
  .pill b { font-size:13px; }
  .ok b{color:var(--ok)} .rev b{color:var(--rev)} .man b{color:var(--man)} .err b{color:var(--err)}
  table { width:100%; border-collapse:collapse; margin-top:8px; font-size:13.5px; }
  th,td { text-align:left; padding:8px 6px; border-bottom:1px solid var(--line); vertical-align:top; }
  th { color:var(--faint); font-weight:600; font-size:12px; }
  code { background:#1b1f25; border:1px solid var(--line); padding:0 5px; border-radius:3px;
         font-size:12px; font-family:ui-monospace,Consolas,monospace; }
  .note { color:var(--mut); font-size:13px; }
  h2 { font-size:15px; margin:26px 0 6px; }
  .hide { display:none; }
  a.dl { display:inline-block; margin-top:18px; background:var(--ok); border:1px solid var(--ok);
         color:#0b1f10; padding:9px 18px; border-radius:3px; text-decoration:none; font-weight:600;
         font-family:ui-monospace,Consolas,monospace; font-size:12px; letter-spacing:.08em;
         text-transform:uppercase; }
  .err-box { color:var(--err); margin-top:12px; }
  /* per-item result cards */
  .item { border:1px solid var(--line); border-radius:4px; margin-top:10px; overflow:hidden; }
  .item-head { display:flex; align-items:center; gap:10px; padding:10px 14px; cursor:pointer;
               background:var(--raise); user-select:none; }
  .item-head:hover { background:#20252c; }
  .item-head .src { font-weight:600; }
  .item-head .cat { color:var(--faint); font-size:12px; }
  .item-head .chev { margin-left:auto; color:var(--faint); transition:transform .15s; }
  .item.open .chev { transform:rotate(90deg); }
  .badge { font-size:11px; font-weight:600; letter-spacing:.08em; padding:2px 8px;
           border-radius:3px; border:1px solid var(--line2); color:var(--mut);
           font-family:ui-monospace,Consolas,monospace; }
  .badge.ok{color:var(--ok); border-color:rgba(87,183,105,.5)}
  .badge.rev{color:var(--rev); border-color:rgba(212,166,62,.5)}
  .badge.man{color:var(--man); border-color:rgba(221,128,71,.5)}
  .badge.err{color:var(--err); border-color:rgba(226,91,85,.5)}
  .badge.dql{color:var(--rev); border-color:rgba(212,166,62,.5)}
  .item-body { display:none; padding:0 14px 14px; }
  .item.open .item-body { display:block; }
  .item-body .notes { margin:10px 0 4px; padding-left:18px; }
  .art { margin-top:12px; }
  .art-head { display:flex; align-items:center; gap:10px; margin-bottom:4px; }
  .art-head .path { font-family:ui-monospace,Consolas,monospace; font-size:12px; color:var(--mut); }
  .copy { margin:0 0 0 auto; padding:4px 12px; font-size:11px;
          background:transparent; border-color:var(--line2); color:var(--mut); }
  .copy.done { background:var(--ok); border-color:var(--ok); color:#0b1f10; }
  pre { background:#0d0f12; border:1px solid var(--line); border-radius:3px; padding:12px;
        margin:0; overflow:auto; max-height:340px; font-family:ui-monospace,Consolas,monospace;
        font-size:12.5px; line-height:1.45; color:#c8cfd9; white-space:pre; }
  .toolbar { display:flex; gap:8px; flex-wrap:wrap; align-items:center; margin:6px 0 2px; }
  .toolbar button { margin-top:0; padding:5px 12px; font-size:11px;
                    background:transparent; border-color:var(--line2); color:var(--mut); }
  details.remedy { background:var(--raise); border:1px solid var(--line);
                   border-left:2px solid var(--ok); border-radius:3px; padding:8px 12px; margin:8px 0; }
  details.remedy summary { cursor:pointer; color:var(--ok); font-weight:600; font-size:13px; }
  details.remedy p { margin:8px 0 0; }
  .conn { display:flex; flex-wrap:wrap; gap:8px; margin-top:10px; }
  .conn input, .conn select { background:#0d0f12; border:1px solid var(--line2); color:var(--ink);
    border-radius:3px; padding:9px 11px; font:13px ui-monospace,Consolas,monospace; flex:1 1 200px; }
  .conn button { margin-top:0; }
  .disc-item { display:flex; align-items:center; gap:8px; padding:3px 0; font-size:13px; }
  .disc-group { color:var(--faint); font-weight:600; margin:10px 0 2px; font-size:11px;
                letter-spacing:.14em; text-transform:uppercase;
                font-family:ui-monospace,Consolas,monospace; }
  /* coverage & caveats */
  .cov { width:100%; border-collapse:collapse; font-size:13px; margin-top:0; }
  .cov td { padding:8px 0; border-bottom:0; border-top:1px solid var(--line); }
  .cov tr:first-child td { border-top:0; padding-top:0; }
  .cov td.from { width:47%; padding-right:14px; }
  .cov td.to-arrow { width:26px; color:var(--faint); font-family:ui-monospace,Consolas,monospace; }
  .cov td.to { color:var(--mut); padding-left:2px; }
  .cov .det { color:var(--mut); }
  .also { color:var(--mut); font-size:13px; border-top:1px solid var(--line);
          margin:10px 0 0; padding-top:10px; }
  ul.cavs { list-style:none; margin:0; padding:0; font-size:13px; }
  ul.cavs li { padding:6px 0 6px 18px; position:relative; color:var(--mut); }
  ul.cavs li::before { content:"—"; position:absolute; left:0; color:var(--faint); }
  ul.cavs strong { color:var(--ink); font-weight:600; }
</style>
</head>
<body>
<div class="wrap">
  <header>
    <div class="brand"><b>e2d</b>elastic &#8594; dynatrace</div>
    <div class="runs">localhost only &middot; nothing leaves this machine</div>
  </header>

  <p class="sub">Drop your Elastic exports (a <code>.zip</code>, or individual
     <code>.ndjson&nbsp;.esql&nbsp;.conf&nbsp;.json&nbsp;.txt</code> files) and get Dynatrace
     dashboards, DQL, alerts and OpenPipeline configs. Everything runs
     <strong>on this machine, offline</strong> — nothing is uploaded anywhere.</p>

  <div class="lab">Input</div>
  <details class="card" id="pull-card" style="margin-bottom:16px">
    <summary class="h">Pull from a live Elastic estate — optional</summary>
    <p class="note">Connect to Kibana/Elasticsearch and pull dashboards, rules, ingest pipelines and
       watchers via their APIs. Credentials stay in memory on this machine — never written anywhere.</p>
    <div class="conn">
      <input id="kibana_url" placeholder="Kibana URL (https://kibana:5601)">
      <input id="es_url" placeholder="Elasticsearch URL (https://es:9200)">
      <input id="token" type="password" placeholder="API key or token">
      <select id="auth_scheme"><option>ApiKey</option><option>Bearer</option></select>
      <button id="discover">Connect & discover</button>
    </div>
    <div id="discovery"></div>
  </details>

  <div class="card" id="stage-input">
    <div id="drop">
      <p><strong>Drop files here</strong> or click to choose</p>
      <p class="note">Kibana dashboards · ES|QL · Query DSL · KQL/Lucene · Logstash · ingest pipelines</p>
      <input type="file" id="picker" multiple class="hide">
    </div>
    <ul class="files" id="filelist"></ul>
    <button id="go" disabled>Convert</button>
    <div class="err-box hide" id="err"></div>
  </div>

  <div class="card hide" id="stage-result" style="margin-top:18px"></div>

  <div class="lab">What this converts</div>
  <div class="card">
    <table class="cov">
      <tr><td class="from">Kibana dashboards <span class="det">(.ndjson) — Lens incl.
            formulas, TSVB, legacy visualizations, saved searches, controls, Vega with an
            embedded ES query</span></td>
          <td class="to-arrow">&#8594;</td>
          <td class="to">Dynatrace dashboard JSON — DQL tiles, variables, series colours;
            importable in the Dashboards app or pushed from here</td></tr>
      <tr><td class="from">ES|QL &middot; Query DSL &middot; KQL &middot; Lucene</td>
          <td class="to-arrow">&#8594;</td>
          <td class="to">DQL, linted offline before it reaches you</td></tr>
      <tr><td class="from">Logstash <span class="det">(.conf)</span> &middot; Elasticsearch
            ingest pipelines</td>
          <td class="to-arrow">&#8594;</td>
          <td class="to">OpenPipeline stages — readable <code>.dpl</code> plus a deployable
            Terraform module</td></tr>
      <tr><td class="from">Watchers &middot; Kibana alerting rules
            <span class="det">(incl. index-threshold and ES-query rules)</span></td>
          <td class="to-arrow">&#8594;</td>
          <td class="to">Davis anomaly detectors + Workflows, as Terraform; detectors can
            also be pushed from here</td></tr>
      <tr><td class="from">Continuous transforms</td>
          <td class="to-arrow">&#8594;</td>
          <td class="to">Rollup DQL with a migration note per transform</td></tr>
      <tr><td class="from">ILM policies &middot; index templates &middot; enrich policies</td>
          <td class="to-arrow">&#8594;</td>
          <td class="to">Written guides — bucket retention, OpenPipeline routing,
            Grail lookups</td></tr>
    </table>
    <p class="also">Every run also writes <code>MIGRATION_REPORT.md</code>, a field manifest
       per dashboard (<code>*.fields.md</code>), <code>METRICS-GUIDE.md</code> for
       log&#8594;metric extraction, and a suggested <code>mapping.config.json</code> when your
       index patterns need rules.</p>
  </div>

  <div class="lab">Caveats</div>
  <ul class="cavs">
    <li><strong>Maps and truly-custom Vega panels</strong> become placeholder tiles flagged
        MANUAL — rebuild those by hand in Dynatrace.</li>
    <li><strong>Lens formulas with no DQL equivalent</strong> fall back to a flagged
        <code>count()</code> placeholder; nothing is ever converted silently wrong.</li>
    <li><strong>A converted tile renders empty — with no error —</strong> when a custom field
        it queries isn't ingested in Dynatrace. Check each dashboard's
        <code>.fields.md</code> manifest before trusting a blank chart.</li>
    <li><strong>Index patterns without a mapping rule default to <code>logs</code></strong>;
        review the suggested <code>mapping.config.json</code> and re-run to make routing
        explicit.</li>
    <li><strong>Alert thresholds and evaluation windows are best-effort</strong> — review each
        anomaly detector before enabling it in production.</li>
    <li><strong>Canvas workpads, ML jobs and SLOs have no converter.</strong> Unrecognised
        files are listed as skipped, with a reason — never silently dropped.</li>
  </ul>
</div>

<script>
const $ = s => document.querySelector(s);
const drop = $("#drop"), picker = $("#picker"), filelist = $("#filelist"),
      go = $("#go"), err = $("#err"), result = $("#stage-result");
let chosen = [];

function showFiles() {
  filelist.innerHTML = chosen.map(f => `<li>• ${f.name} <span class="note">(${(f.size/1024|0)} KB)</span></li>`).join("");
  go.disabled = chosen.length === 0;
}
function addFiles(list) { chosen = chosen.concat([...list]); showFiles(); }

drop.addEventListener("click", () => picker.click());
picker.addEventListener("change", e => addFiles(e.target.files));
["dragover","dragenter"].forEach(ev => drop.addEventListener(ev, e => { e.preventDefault(); drop.classList.add("hot"); }));
["dragleave","drop"].forEach(ev => drop.addEventListener(ev, e => { e.preventDefault(); drop.classList.remove("hot"); }));
drop.addEventListener("drop", e => addFiles(e.dataTransfer.files));

async function post(path, body, headers) {
  const r = await fetch(path, { method:"POST", body, headers });
  const j = await r.json().catch(() => ({}));
  if (!r.ok) throw new Error(j.error || ("HTTP " + r.status));
  return j;
}

let currentSession = null;   // the session that produced the shown results (for deploy)
// Creds persist across re-renders AND page reloads (localStorage). This is a
// localhost, single-user tool, so the convenience is worth keeping the token here.
const LS = window.localStorage;
let deployEnv = LS.getItem("e2d_dt_env") || "";
let deployToken = LS.getItem("e2d_dt_token") || "";
function saveDeployCreds() { LS.setItem("e2d_dt_env", deployEnv); LS.setItem("e2d_dt_token", deployToken); }
// restore the Elastic-pull connection fields + persist them on edit
window.addEventListener("DOMContentLoaded", () => {
  ["kibana_url", "es_url", "token", "auth_scheme"].forEach(id => {
    const el = document.getElementById(id);
    if (!el) return;
    const v = LS.getItem("e2d_" + id);
    if (v != null) el.value = v;
    const save = () => LS.setItem("e2d_" + id, el.value);
    el.addEventListener("input", save); el.addEventListener("change", save);
  });
});

go.addEventListener("click", async () => {
  err.classList.add("hide"); go.disabled = true; go.textContent = "Converting…";
  try {
    const { session } = await post("/session");
    currentSession = session;
    for (const f of chosen) {
      await post("/upload", await f.arrayBuffer(),
                 { "X-Session": session, "X-Filename": f.name });
    }
    const data = await post("/migrate", "", { "X-Session": session });
    render(data);
  } catch (e) {
    err.textContent = "Something went wrong: " + e.message;
    err.classList.remove("hide");
  } finally {
    go.disabled = false; go.textContent = "Convert";
  }
});

// ---- pull from a live Elastic estate -----------------------------------
let pulledSession = null;   // set once we've pulled; Convert reuses it
$("#discover").addEventListener("click", async () => {
  const btn = $("#discover"); btn.disabled = true; btn.textContent = "Connecting…";
  const disc = $("#discovery");
  try {
    const { session } = await post("/session");
    pulledSession = session;
    await post("/connect", JSON.stringify({
      kibana_url: $("#kibana_url").value.trim(), es_url: $("#es_url").value.trim(),
      token: $("#token").value, auth_scheme: $("#auth_scheme").value,
    }), { "X-Session": session, "Content-Type": "application/json" });
    const data = await post("/discover", "", { "X-Session": session });
    disc.innerHTML = renderDiscovery(data);
  } catch (e) {
    disc.innerHTML = `<p class="err-box">Discovery failed: ${esc(e.message)}</p>`;
  } finally { btn.disabled = false; btn.textContent = "Connect & discover"; }
});

function renderDiscovery(data) {
  const items = data.items || [];
  let h = "";
  for (const [src, msg] of Object.entries(data.errors || {}))
    h += `<p class="note">could not read ${esc(src)}: ${esc(msg)}</p>`;
  if (!items.length) return h + `<p class="note">No convertible objects found.</p>`;
  const byKind = {};
  items.forEach((it, i) => { (byKind[it.kind] = byKind[it.kind] || []).push({ ...it, i }); });
  for (const kind of Object.keys(byKind)) {
    h += `<div class="disc-group">${kind}s (${byKind[kind].length})</div>`;
    for (const it of byKind[kind])
      h += `<label class="disc-item"><input type="checkbox" class="pick" checked
              data-kind="${esc(it.kind)}" data-id="${esc(it.id)}"> ${esc(it.name)}</label>`;
  }
  h += `<button id="pullbtn" style="margin-top:14px">Pull selected & convert</button>`;
  setTimeout(() => $("#pullbtn").addEventListener("click", pullAndConvert), 0);
  return h;
}

async function pullAndConvert() {
  const btn = $("#pullbtn"); btn.disabled = true; btn.textContent = "Pulling…";
  try {
    const sel = [...document.querySelectorAll(".pick:checked")].map(c =>
      ({ kind: c.dataset.kind, id: c.dataset.id }));
    await post("/pull", JSON.stringify(sel), { "X-Session": pulledSession, "Content-Type": "application/json" });
    btn.textContent = "Converting…";
    currentSession = pulledSession;
    const data = await post("/migrate", "", { "X-Session": pulledSession });
    render(data);
  } catch (e) {
    $("#discovery").innerHTML += `<p class="err-box">Pull failed: ${esc(e.message)}</p>`;
  } finally { btn.disabled = false; btn.textContent = "Pull selected & convert"; }
}

const SCLASS = { OK:"ok", REVIEW:"rev", MANUAL:"man", ERROR:"err" };
function esc(s){ return (s||"").replace(/[&<>]/g, c => ({'&':'&amp;','<':'&lt;','>':'&gt;'}[c])); }

let LAST = null;  // last render payload, for expand/collapse-all

function itemCard(it, idx) {
  const dqlNotes = (it.notes||[]).filter(n => n.includes("[DQL:"));
  const open = it.status !== "OK" ? " open" : "";   // auto-expand things needing a look
  let h = `<div class="item${open}" data-i="${idx}">`;
  h += `<div class="item-head" data-toggle>
          <span class="badge ${SCLASS[it.status]||""}">${it.status}</span>
          <span class="src">${esc(it.source)}</span>
          <span class="cat">${esc(it.category)}</span>
          ${dqlNotes.length ? `<span class="badge dql">DQL ${dqlNotes.length}</span>` : ""}
          <span class="chev">&#9656;</span>
        </div>`;
  h += `<div class="item-body">`;
  const notes = [...new Set(it.notes||[])];
  if (notes.length)
    h += `<ul class="notes">` + notes.map(n=>`<li class="note">${esc(n)}</li>`).join("") + `</ul>`;
  for (const r of (it.remediation||[])) {
    h += `<details class="remedy">
            <summary>How to fix — ${esc(r.title)}</summary>
            <p class="note"><b>What it is.</b> ${esc(r.what)}</p>
            <p class="note"><b>In Dynatrace.</b> ${esc(r.fix)}</p>
          </details>`;
  }
  for (const a of (it.artifacts||[])) {
    h += `<div class="art">
            <div class="art-head">
              <span class="path">${esc(a.path)}</span>
              ${a.truncated ? `<span class="note">(truncated)</span>` : ""}
              <button class="copy" data-copy>Copy</button>
            </div>
            <pre>${esc(a.content)}</pre>
          </div>`;
  }
  if (!(it.artifacts||[]).length)
    h += `<p class="note">No inline output (see the downloaded bundle).</p>`;
  h += `</div></div>`;
  return h;
}

function render(d) {
  LAST = d;
  const c = d.counts;
  let h = `<h2 style="margin-top:0">Done — ${d.total} item(s) converted</h2>`;
  h += `<div class="counts">
    <span class="pill ok"><b>${c.OK}</b> ready</span>
    <span class="pill rev"><b>${c.REVIEW}</b> review</span>
    <span class="pill man"><b>${c.MANUAL}</b> manual</span>
    ${c.ERROR ? `<span class="pill err"><b>${c.ERROR}</b> error</span>` : ""}
  </div>`;
  if (d.items.length) {
    h += `<div class="toolbar">
            <button data-expand>Expand all</button>
            <button data-collapse>Collapse all</button>
            <span class="note">Click a file to view & copy its converted output.</span>
          </div>`;
    h += d.items.map((it, i) => itemCard(it, i)).join("");
  }
  if (d.secrets.length) {
    h += `<h2>Possible secrets in your inputs</h2>
          <p class="note">Not copied into any output — swap in your Dynatrace-side secrets when deploying.</p><ul>`;
    h += d.secrets.map(s=>`<li class="note"><code>${esc(s)}</code></li>`).join("") + `</ul>`;
  }
  if (d.skipped.length) {
    h += `<h2>Not converted</h2><ul>` +
         d.skipped.map(s=>`<li class="note"><code>${esc(s)}</code></li>`).join("") + `</ul>`;
  }
  h += `<a class="dl" href="${d.download}">Download converted artifacts (.zip)</a>`;
  h += deployPanel(d);
  result.innerHTML = h;
  result.classList.remove("hide");
  result.scrollIntoView({ behavior:"smooth" });
}

function deployPanel(d) {
  const nDash = d.items.filter(it => it.category === "dashboard" && it.status !== "ERROR").length;
  const nAlert = d.items.filter(it => it.category === "alert").length;
  const nPipe = d.items.filter(it => it.category === "pipeline").length;
  return `<details class="card" style="margin-top:18px" id="deploy-card">
    <summary class="h">Deploy to Dynatrace</summary>
    <p class="note">Pushes <b>${nDash} dashboard(s)</b> (Document API) and the anomaly detectors from
      <b>${nAlert} alert(s)</b> (Settings API) straight to your tenant. Credentials persist on this
      machine only. ${nPipe ? `The <b>${nPipe}</b> pipeline(s) deploy via <code>terraform apply</code> —
      download the bundle.` : ""}</p>
    <p class="note">Token scopes: <code>document:documents:write</code>,
      <code>settings:objects:write</code>, <code>storage:*:read</code>,
      <code>davis:analyzers:execute</code>.</p>
    <div class="conn">
      <input id="dt_env" placeholder="Dynatrace env URL (https://abc12345.apps.dynatrace.com)"
             value="${esc(deployEnv)}">
      <input id="dt_token" type="password" placeholder="Platform token"
             value="${esc(deployToken)}">
      <button id="dryrun">Dry run</button>
      <button id="deploybtn" style="background:var(--ok);border-color:var(--ok);color:#0b1f10">Deploy</button>
    </div>
    <div id="deploy-out"></div>
  </details>`;
}

async function runDeploy(apply) {
  const out = $("#deploy-out");
  out.innerHTML = `<p class="note">${apply ? "Deploying…" : "Dry run…"}</p>`;
  try {
    deployEnv = $("#dt_env").value.trim(); deployToken = $("#dt_token").value;
    saveDeployCreds();
    const res = await post("/deploy", JSON.stringify({
      env_url: deployEnv, token: deployToken, apply,
    }), { "X-Session": currentSession, "Content-Type": "application/json" });
    const rows = (label, arr) => arr.length ? `<tr><th colspan="3">${label}</th></tr>` +
      arr.map(r => `<tr><td><span class="badge ${r.ok ? "ok" : "err"}">${r.ok ? "OK" : "FAIL"}</span></td>
            <td><code>${esc(r.name)}</code></td>
            <td class="note">${esc(r.detail)}</td></tr>`).join("") : "";
    let h = `<table>` + rows("Dashboards", res.dashboards || []) +
            rows("Anomaly detectors", res.detectors || []) + `</table>`;
    const tf = res.terraform.pipelines || [];
    if (tf.length) h += `<p class="note">Pipelines (run <code>terraform apply</code> on the bundle):
                         ${tf.map(t=>`<code>${esc(t)}</code>`).join(" ")}</p>`;
    out.innerHTML = h;
  } catch (e) { out.innerHTML = `<p class="err-box">${esc(e.message)}</p>`; }
}
// deploy buttons live inside the (re-rendered) results — delegate
result.addEventListener("click", e => {
  if (e.target.id === "dryrun") runDeploy(false);
  if (e.target.id === "deploybtn") runDeploy(true);
});
// remember deploy creds as they're typed, so they survive a new conversion
result.addEventListener("input", e => {
  if (e.target.id === "dt_env") { deployEnv = e.target.value; saveDeployCreds(); }
  if (e.target.id === "dt_token") { deployToken = e.target.value; saveDeployCreds(); }
});

async function copyText(text, btn) {
  try {
    if (navigator.clipboard && window.isSecureContext) {
      await navigator.clipboard.writeText(text);
    } else {                                   // http://localhost fallback
      const ta = document.createElement("textarea");
      ta.value = text; ta.style.position = "fixed"; ta.style.opacity = "0";
      document.body.appendChild(ta); ta.select();
      document.execCommand("copy"); ta.remove();
    }
    btn.textContent = "Copied"; btn.classList.add("done");
    setTimeout(() => { btn.textContent = "Copy"; btn.classList.remove("done"); }, 1400);
  } catch (e) { btn.textContent = "Copy failed"; }
}

// one delegated listener handles toggles, copy buttons, and expand/collapse-all
result.addEventListener("click", e => {
  const copyBtn = e.target.closest("[data-copy]");
  if (copyBtn) {
    e.stopPropagation();
    const pre = copyBtn.closest(".art").querySelector("pre");
    copyText(pre.textContent, copyBtn);
    return;
  }
  const head = e.target.closest("[data-toggle]");
  if (head) { head.parentElement.classList.toggle("open"); return; }
  if (e.target.closest("[data-expand]"))
    result.querySelectorAll(".item").forEach(it => it.classList.add("open"));
  if (e.target.closest("[data-collapse]"))
    result.querySelectorAll(".item").forEach(it => it.classList.remove("open"));
});
</script>
</body>
</html>
"""
