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
        from e2d.plan import build_plan
        return {
            "counts": summary.counts(),
            "total": len(summary.items),
            "items": items,
            "secrets": list(dict.fromkeys(summary.secrets)),
            "skipped": summary.skipped,
            "plan": build_plan(summary),
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
                elif self.path == "/query":
                    body = json.loads(self._read_body() or b"{}")
                    from e2d.quick import convert_query
                    self._json(200, convert_query(body.get("query", ""),
                                                  body.get("lang", "auto"),
                                                  sessions.config))
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
<title>e2d</title>
<style>
  :root {
    --bg:#0b0e14; --panel:#121722; --panel2:#161c29; --line:rgba(255,255,255,.08);
    --line2:rgba(255,255,255,.16); --ink:#e6eaf2; --mut:#94a0b3; --faint:#5f6b7f;
    --ok:#34c07c; --rev:#e0a63c; --man:#e07b4a; --err:#e5544e;
    --blue:#4d8dff; --teal:#2dd4bf;
  }
  * { box-sizing:border-box; }
  html { color-scheme:dark; }
  body { margin:0; color:var(--ink);
         background:radial-gradient(ellipse 90% 55% at 50% -12%, rgba(77,141,255,.16), transparent 70%),
                    radial-gradient(ellipse 45% 35% at 12% -5%, rgba(45,212,191,.10), transparent 70%),
                    var(--bg);
         font:15px/1.6 "Segoe UI Variable Text","Segoe UI",system-ui,-apple-system,sans-serif; }
  code { font-family:ui-monospace,"Cascadia Mono",Consolas,monospace; font-size:.86em;
         background:rgba(255,255,255,.06); border:1px solid var(--line);
         padding:1px 6px; border-radius:6px; }
  .wrap { max-width:920px; margin:0 auto; padding:0 24px 64px; }
  .top { position:sticky; top:0; z-index:10; background:rgba(11,14,20,.72);
         backdrop-filter:blur(12px); -webkit-backdrop-filter:blur(12px);
         border-bottom:1px solid var(--line); }
  .bar { max-width:920px; margin:0 auto; display:flex; align-items:center;
         justify-content:space-between; gap:12px; flex-wrap:wrap; padding:13px 24px; }
  .logo { display:inline-flex; align-items:center; gap:10px; font-weight:700; font-size:15px; }
  .logo .mark { width:28px; height:28px; border-radius:8px; display:grid; place-items:center;
                background:linear-gradient(135deg,var(--teal),var(--blue));
                color:#08101d; font-size:11px; font-weight:800;
                font-family:ui-monospace,Consolas,monospace; }
  .local { display:inline-flex; align-items:center; gap:8px; font-size:12.5px; color:var(--mut);
           border:1px solid var(--line); border-radius:999px; padding:5px 13px;
           background:rgba(255,255,255,.03); }
  .hero { text-align:center; padding:46px 0 30px; }
  h1 { margin:0 0 12px; padding-bottom:.08em; font-size:clamp(30px,5vw,44px); line-height:1.15; font-weight:700;
       letter-spacing:-.025em;
       font-family:"Segoe UI Variable Display","Segoe UI",system-ui,sans-serif;
       background:linear-gradient(92deg,var(--teal) 8%,#7cc4ff 55%,var(--blue) 92%);
       -webkit-background-clip:text; background-clip:text; color:transparent; }
  .tagline { margin:0 auto; max-width:58ch; color:var(--mut); font-size:15.5px; }
  .tagline strong { color:var(--ink); font-weight:600; }
  h2 { font-size:20px; font-weight:650; letter-spacing:-.01em; margin:44px 0 6px;
       font-family:"Segoe UI Variable Display","Segoe UI",system-ui,sans-serif; }
  .lede { color:var(--mut); margin:0 0 16px; font-size:14px; }
  .card { background:linear-gradient(180deg,var(--panel2),var(--panel));
          border:1px solid var(--line); border-radius:16px; padding:22px;
          box-shadow:0 10px 30px rgba(0,0,0,.35); }
  summary.h { cursor:pointer; font-weight:600; }
  #drop { border:1.5px dashed var(--line2); border-radius:12px; padding:38px 24px;
          text-align:center; color:var(--mut); cursor:pointer;
          transition:border-color .2s, background .2s; }
  #drop:hover, #drop.hot { border-color:var(--blue); background:rgba(77,141,255,.06);
                           color:var(--ink); }
  #drop svg { display:block; margin:0 auto 12px; color:var(--blue); opacity:.9; }
  #drop strong { color:var(--ink); font-size:16px; }
  .files { list-style:none; padding:0; margin:14px 0 0; font-size:13px; color:var(--mut); }
  .files li { padding:2px 0; }
  button { font:600 14px/1 "Segoe UI Variable Text","Segoe UI",system-ui,sans-serif;
           color:#fff; background:linear-gradient(180deg,#4d8dff,#2f6fe0);
           border:1px solid rgba(255,255,255,.16); border-radius:10px;
           padding:11px 22px; cursor:pointer; margin-top:16px;
           transition:filter .15s, transform .05s; box-shadow:0 1px 2px rgba(0,0,0,.4); }
  button:hover:not(:disabled) { filter:brightness(1.1); }
  button:active:not(:disabled) { transform:translateY(1px); }
  button:disabled { opacity:.35; cursor:default; }
  button:focus-visible { outline:2px solid var(--blue); outline-offset:2px; }
  .counts { display:flex; gap:8px; flex-wrap:wrap; margin:0 0 18px; }
  .pill { display:inline-flex; align-items:center; gap:7px; font-size:12.5px; font-weight:600;
          padding:5px 12px; border-radius:999px; border:1px solid var(--line);
          background:rgba(255,255,255,.03); color:var(--mut); }
  .ok b{color:var(--ok)} .rev b{color:var(--rev)} .man b{color:var(--man)} .err b{color:var(--err)}
  table { width:100%; border-collapse:collapse; margin-top:8px; font-size:13.5px; }
  th,td { text-align:left; padding:8px 6px; border-bottom:1px solid var(--line); vertical-align:top; }
  th { color:var(--faint); font-weight:600; font-size:12px; }
  .note { color:var(--mut); font-size:13px; }
  .hide { display:none; }
  a.dl { display:inline-block; margin-top:18px; background:linear-gradient(180deg,#3bc98a,#27a56d);
         border:1px solid rgba(255,255,255,.16); color:#06210f; padding:11px 22px;
         border-radius:10px; text-decoration:none; font-weight:650; font-size:14px;
         box-shadow:0 1px 2px rgba(0,0,0,.4); }
  a.dl:hover { filter:brightness(1.07); }
  .err-box { color:var(--err); margin-top:12px; }
  /* per-item result cards */
  .item { border:1px solid var(--line); border-radius:12px; margin-top:10px; overflow:hidden;
          background:rgba(255,255,255,.015); }
  .item-head { display:flex; align-items:center; gap:10px; padding:11px 14px; cursor:pointer;
               user-select:none; }
  .item-head:hover { background:rgba(255,255,255,.03); }
  .item-head .src { font-weight:600; }
  .item-head .cat { color:var(--faint); font-size:12px; }
  .item-head .chev { margin-left:auto; color:var(--faint); transition:transform .15s; }
  .item.open .chev { transform:rotate(90deg); }
  .badge { display:inline-flex; align-items:center; gap:6px; font-size:11.5px; font-weight:600;
           padding:3px 10px; border-radius:999px; border:1px solid var(--line);
           background:rgba(255,255,255,.03); color:var(--mut); }
  .badge.ok{color:var(--ok)} .badge.rev{color:var(--rev)} .badge.man{color:var(--man)}
  .badge.err{color:var(--err)} .badge.dql{color:var(--rev)}
  .item-body { display:none; padding:0 14px 14px; }
  .item.open .item-body { display:block; }
  .item-body .notes { margin:10px 0 4px; padding-left:18px; }
  .art { margin-top:12px; }
  .art-head { display:flex; align-items:center; gap:10px; margin-bottom:4px; }
  .art-head .path { font-family:ui-monospace,Consolas,monospace; font-size:12px; color:var(--mut); }
  .copy { margin:0 0 0 auto; padding:5px 14px; font-size:12px; background:transparent;
          border-color:var(--line2); color:var(--mut); box-shadow:none; }
  .copy.done { background:linear-gradient(180deg,#3bc98a,#27a56d); color:#06210f;
               border-color:rgba(255,255,255,.16); }
  pre { background:#0a0d13; border:1px solid var(--line); border-radius:10px; padding:12px;
        margin:0; overflow:auto; max-height:340px; font-family:ui-monospace,Consolas,monospace;
        font-size:12.5px; line-height:1.45; color:#c8cfd9; white-space:pre; }
  .toolbar { display:flex; gap:8px; flex-wrap:wrap; align-items:center; margin:6px 0 2px; }
  .toolbar button { margin-top:0; padding:6px 14px; font-size:12px; background:transparent;
                    border-color:var(--line2); color:var(--mut); box-shadow:none; }
  details.remedy { background:rgba(52,192,124,.06); border:1px solid rgba(52,192,124,.25);
                   border-radius:10px; padding:8px 12px; margin:8px 0; }
  details.remedy summary { cursor:pointer; color:#63d69a; font-weight:600; font-size:13px; }
  details.remedy p { margin:8px 0 0; }
  .qbox { width:100%; min-height:110px; resize:vertical; background:rgba(0,0,0,.35);
          border:1px solid var(--line2); border-radius:10px; color:var(--ink);
          padding:12px; font:13px/1.5 ui-monospace,Consolas,monospace; }
  .qbox:focus-visible { outline:2px solid var(--blue); outline-offset:1px; }
  .conn { display:flex; flex-wrap:wrap; gap:8px; margin-top:10px; }
  .conn input, .conn select { background:rgba(0,0,0,.35); border:1px solid var(--line2);
    color:var(--ink); border-radius:10px; padding:10px 12px;
    font:13px ui-monospace,Consolas,monospace; flex:1 1 200px; }
  .conn input:focus-visible, .conn select:focus-visible { outline:2px solid var(--blue);
    outline-offset:1px; }
  .conn button { margin-top:0; }
  .disc-item { display:flex; align-items:center; gap:8px; padding:3px 0; font-size:13px; }
  .disc-group { color:var(--faint); font-weight:600; margin:10px 0 2px; font-size:11px;
                letter-spacing:.14em; text-transform:uppercase;
                font-family:ui-monospace,Consolas,monospace; }
  /* coverage & caveats */
  .grid { display:grid; grid-template-columns:repeat(auto-fit,minmax(260px,1fr)); gap:12px; }
  .feat { background:linear-gradient(180deg,var(--panel2),var(--panel));
          border:1px solid var(--line); border-radius:14px; padding:18px;
          transition:border-color .2s, transform .2s; }
  .feat:hover { border-color:var(--line2); transform:translateY(-2px); }
  .try { margin-top:12px; padding:7px 14px; font-size:12.5px; font-weight:600;
         background:transparent; border:1px solid var(--line2); color:var(--mut);
         border-radius:8px; box-shadow:none; }
  .try:hover:not(:disabled) { border-color:var(--blue); color:var(--ink); filter:none; }
  .feat .ic { width:36px; height:36px; border-radius:10px; display:grid; place-items:center;
              background:rgba(77,141,255,.12); color:#7cc4ff; margin-bottom:12px; }
  .feat h3 { margin:0 0 4px; font-size:14.5px; font-weight:650; }
  .feat p { margin:0; font-size:13px; color:var(--mut); }
  .feat p b { color:#9fc3f5; font-weight:600; }
  .alsonote { color:var(--mut); font-size:13.5px; margin-top:14px; }
  .cavs { border:1px solid var(--line); border-left:3px solid var(--rev); border-radius:12px;
          background:linear-gradient(180deg,rgba(224,166,60,.05),transparent 60%), var(--panel);
          padding:8px 22px 14px; }
  .cavs ul { list-style:none; margin:0; padding:0; }
  .cavs li { padding:10px 0; color:var(--mut); font-size:13.5px;
             border-top:1px solid var(--line); }
  .cavs li:first-child { border-top:0; }
  .cavs strong { color:var(--ink); font-weight:600; }
  /* deployment order */
  .plan { margin:8px 0 0; padding-left:22px; }
  .plan li { margin:12px 0; }
  .plan li b { font-weight:650; }
  .plan .arts { margin:4px 0 2px; }
  .plan .arts code { margin-right:4px; }
  .gap { border:1px solid rgba(224,166,60,.35); background:rgba(224,166,60,.06);
         border-radius:10px; padding:12px 16px; margin-top:14px; }
  .gap ul { margin:6px 0 0; padding-left:18px; }
</style>
</head>
<body>
<header class="top">
  <div class="bar">
    <span class="logo"><span class="mark">e2d</span> elastic-to-dynatrace</span>
    <span class="local">localhost only, nothing leaves this machine</span>
  </div>
</header>
<main class="wrap">
  <div class="hero">
    <h1>Elastic &#8594; Dynatrace</h1>
    <p class="tagline">Drop your exports, a <code>.zip</code> or individual
       <code>.ndjson&nbsp;.esql&nbsp;.conf&nbsp;.json&nbsp;.txt</code> files, and get
       dashboards, DQL, alerts and OpenPipeline configs.
       <strong>Everything runs on this machine.</strong> Nothing is uploaded anywhere.</p>
  </div>

  <details class="card" id="pull-card" style="margin-bottom:16px">
    <summary class="h">Pull from a live Elastic estate (optional)</summary>
    <p class="note">Connect to Kibana/Elasticsearch and pull dashboards, rules, ingest pipelines
       and watchers via their APIs. Credentials are kept in memory and never written to disk.</p>
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
      <svg width="34" height="34" viewBox="0 0 24 24" fill="none" stroke="currentColor"
           stroke-width="1.6" stroke-linecap="round" stroke-linejoin="round">
        <path d="M21 15v4a2 2 0 0 1-2 2H5a2 2 0 0 1-2-2v-4"/>
        <polyline points="17 8 12 3 7 8"/><line x1="12" y1="3" x2="12" y2="15"/>
      </svg>
      <strong>Drop files here</strong> or click to choose
      <p class="note" style="margin:6px 0 0">Kibana dashboards &middot; ES|QL &middot; Query DSL
         &middot; KQL/Lucene &middot; Logstash &middot; ingest pipelines</p>
      <input type="file" id="picker" multiple class="hide">
    </div>
    <ul class="files" id="filelist"></ul>
    <button id="go" disabled>Convert</button>
    <div class="err-box hide" id="err"></div>
  </div>

  <div class="card" id="quick" style="margin-top:16px">
    <h2 style="margin:0 0 4px;font-size:17px">Paste a query</h2>
    <p class="note" style="margin:0 0 10px">Paste one ES|QL, Query DSL, KQL or Lucene query.
       The DQL appears below with any warnings, ready to copy.</p>
    <textarea id="qin" class="qbox" spellcheck="false"
      placeholder="FROM logs-* | WHERE status &gt;= 500 | STATS count = COUNT() BY host.name"></textarea>
    <div class="conn">
      <select id="qlang">
        <option value="auto">Detect language</option>
        <option value="esql">ES|QL</option>
        <option value="dsl">Query DSL (JSON)</option>
        <option value="kql">KQL</option>
        <option value="lucene">Lucene</option>
      </select>
      <button id="qgo">Convert query</button>
    </div>
    <div id="qout"></div>
  </div>

  <div class="card hide" id="stage-result" style="margin-top:24px"></div>

  <h2>What it converts</h2>
  <div class="grid">
    <div class="feat">
      <div class="ic"><svg width="18" height="18" viewBox="0 0 24 24" fill="none"
        stroke="currentColor" stroke-width="1.8" stroke-linecap="round" stroke-linejoin="round">
        <rect x="3" y="3" width="7" height="9" rx="1"/><rect x="14" y="3" width="7" height="5" rx="1"/>
        <rect x="14" y="12" width="7" height="9" rx="1"/><rect x="3" y="16" width="7" height="5" rx="1"/></svg></div>
      <h3>Kibana dashboards</h3>
      <p>Lens incl. formulas, TSVB, legacy visualizations, saved searches, controls, and Vega
         with an embedded ES query <b>&#8594; dashboard JSON</b> with DQL tiles, variables and
         series colours. Import in the Dashboards app or push from here.</p>
      <button class="try" data-eg="dashboard">Try an example</button>
    </div>
    <div class="feat">
      <div class="ic"><svg width="18" height="18" viewBox="0 0 24 24" fill="none"
        stroke="currentColor" stroke-width="1.8" stroke-linecap="round" stroke-linejoin="round">
        <polyline points="4 17 10 11 4 5"/><line x1="12" y1="19" x2="20" y2="19"/></svg></div>
      <h3>Queries</h3>
      <p>ES|QL, Query DSL, KQL and Lucene <b>&#8594; DQL</b>, linted offline before it
         reaches you.</p>
      <button class="try" data-eg="query">Try an example</button>
    </div>
    <div class="feat">
      <div class="ic"><svg width="18" height="18" viewBox="0 0 24 24" fill="none"
        stroke="currentColor" stroke-width="1.8" stroke-linecap="round" stroke-linejoin="round">
        <path d="M22 3H2l8 9.46V19l4 2v-8.54L22 3z"/></svg></div>
      <h3>Ingest pipelines</h3>
      <p>Logstash <code>.conf</code> and Elasticsearch ingest pipelines
         <b>&#8594; OpenPipeline stages</b>: a readable <code>.dpl</code> plus a deployable
         Terraform module.</p>
      <button class="try" data-eg="pipeline">Try an example</button>
    </div>
    <div class="feat">
      <div class="ic"><svg width="18" height="18" viewBox="0 0 24 24" fill="none"
        stroke="currentColor" stroke-width="1.8" stroke-linecap="round" stroke-linejoin="round">
        <path d="M18 8a6 6 0 0 0-12 0c0 7-3 9-3 9h18s-3-2-3-9"/>
        <path d="M13.7 21a2 2 0 0 1-3.4 0"/></svg></div>
      <h3>Alerts &amp; watchers</h3>
      <p>Watchers and Kibana alerting rules, incl. index-threshold and ES-query rules
         <b>&#8594; Davis anomaly detectors + Workflows</b> as Terraform. Detectors can also
         be pushed from here.</p>
      <button class="try" data-eg="alert">Try an example</button>
    </div>
    <div class="feat">
      <div class="ic"><svg width="18" height="18" viewBox="0 0 24 24" fill="none"
        stroke="currentColor" stroke-width="1.8" stroke-linecap="round" stroke-linejoin="round">
        <polygon points="12 2 2 7 12 12 22 7 12 2"/><polyline points="2 12 12 17 22 12"/></svg></div>
      <h3>Transforms</h3>
      <p>Continuous transforms <b>&#8594; rollup DQL</b> with a migration note per
         transform.</p>
      <button class="try" data-eg="transform">Try an example</button>
    </div>
    <div class="feat">
      <div class="ic"><svg width="18" height="18" viewBox="0 0 24 24" fill="none"
        stroke="currentColor" stroke-width="1.8" stroke-linecap="round" stroke-linejoin="round">
        <line x1="4" y1="21" x2="4" y2="14"/><line x1="4" y1="10" x2="4" y2="3"/>
        <line x1="12" y1="21" x2="12" y2="12"/><line x1="12" y1="8" x2="12" y2="3"/>
        <line x1="20" y1="21" x2="20" y2="16"/><line x1="20" y1="12" x2="20" y2="3"/>
        <line x1="1" y1="14" x2="7" y2="14"/><line x1="9" y1="8" x2="15" y2="8"/>
        <line x1="17" y1="16" x2="23" y2="16"/></svg></div>
      <h3>Cluster config</h3>
      <p>ILM policies, index templates and enrich policies <b>&#8594; written guides</b> for
         bucket retention, OpenPipeline routing and Grail lookups.</p>
      <button class="try" data-eg="config">Try an example</button>
    </div>
  </div>
  <p class="alsonote">Every run also writes <code>MIGRATION_REPORT.md</code> with a
     deployment-order plan, a field manifest per dashboard (<code>*.fields.md</code>),
     <code>METRICS-GUIDE.md</code> for log&#8594;metric extraction, and a suggested
     <code>mapping.config.json</code> when your index patterns need rules.</p>

  <h2>Limitations</h2>
  <div class="cavs">
    <ul>
      <li><strong>Maps and truly-custom Vega panels</strong> become placeholder tiles flagged
          MANUAL. Rebuild those by hand in Dynatrace.</li>
      <li><strong>Lens formulas with no DQL equivalent</strong> fall back to a flagged
          <code>count()</code> placeholder. Nothing is converted silently wrong.</li>
      <li><strong>A converted tile renders empty, with no error,</strong> when a custom field
          it queries isn't ingested in Dynatrace. Check each dashboard's
          <code>.fields.md</code> manifest before trusting a blank chart.</li>
      <li><strong>Index patterns without a mapping rule default to <code>logs</code>.</strong>
          Review the suggested <code>mapping.config.json</code> and re-run to make routing
          explicit.</li>
      <li><strong>Alert thresholds and evaluation windows are best-effort.</strong> Review
          each anomaly detector before enabling it in production.</li>
      <li><strong>Canvas workpads, ML jobs and SLOs have no converter.</strong> Unrecognised
          files are listed as skipped, with a reason.</li>
    </ul>
  </div>
</main>

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

function planBlock(p) {
  if (!p || !p.steps || !p.steps.length) return "";
  let h = `<h2>Deployment order</h2>
           <p class="note">Deploy in this order. Each step creates what the next depends on.</p>
           <ol class="plan">`;
  for (const s of p.steps) {
    h += `<li><b>${esc(s.title)}.</b> <span class="note">${esc(s.why)}</span>
            <div class="arts">${s.items.map(i => `<code>${esc(i)}</code>`).join(" ")}</div>
            <span class="note">${esc(s.how)}</span></li>`;
  }
  h += `</ol>`;
  if (p.field_gaps && p.field_gaps.length) {
    const lead = p.have_pipelines
      ? "These dashboards query custom fields that no converted pipeline produces. Their tiles stay empty until the fields are ingested some other way:"
      : "No pipelines were part of this run, so these dashboards' custom fields must already exist in your tenant. Verify before importing:";
    h += `<div class="gap"><b>Field gaps to close.</b> <span class="note">${lead}</span><ul>`;
    for (const g of p.field_gaps)
      h += `<li class="note"><code>${esc(g.dashboard)}</code>: ` +
           g.fields.map(f => `<code>${esc(f)}</code>`).join(", ") + `</li>`;
    h += `</ul></div>`;
  }
  return h;
}

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
            <summary>How to fix: ${esc(r.title)}</summary>
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
  let h = `<h2 style="margin-top:0">Converted ${d.total} item(s)</h2>`;
  h += `<div class="counts">
    <span class="pill ok"><b>${c.OK}</b> ready</span>
    <span class="pill rev"><b>${c.REVIEW}</b> review</span>
    <span class="pill man"><b>${c.MANUAL}</b> manual</span>
    ${c.ERROR ? `<span class="pill err"><b>${c.ERROR}</b> error</span>` : ""}
  </div>`;
  h += planBlock(d.plan);
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
          <p class="note">Not copied into any output. Swap in your Dynatrace-side secrets when deploying.</p><ul>`;
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
      machine only. ${nPipe ? `The <b>${nPipe}</b> pipeline(s) deploy via <code>terraform apply</code>;
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

// ---- paste-a-query converter -------------------------------------------
function qResult(r) {
  if (r.error) return `<p class="err-box">${esc(r.error)}</p>`;
  let h = `<div class="art"><div class="art-head">
      <span class="badge ${SCLASS[r.status] || ""}">${esc(r.status)}</span>
      <span class="path">${esc(r.lang)}</span>
      <button class="copy" data-copy>Copy</button></div>
      <pre>${esc(r.dql)}</pre></div>`;
  if (r.notes && r.notes.length)
    h += `<ul class="notes">` + r.notes.map(n => `<li class="note">${esc(n)}</li>`).join("") + `</ul>`;
  return h;
}

$("#qgo").addEventListener("click", async () => {
  const q = $("#qin").value.trim(), out = $("#qout"), btn = $("#qgo");
  if (!q) { out.innerHTML = `<p class="note">Paste a query first.</p>`; return; }
  btn.disabled = true; btn.textContent = "Converting…";
  try {
    const r = await post("/query", JSON.stringify({ query: q, lang: $("#qlang").value }),
                         { "Content-Type": "application/json" });
    out.innerHTML = qResult(r);
  } catch (e) {
    out.innerHTML = `<p class="err-box">${esc(e.message)}</p>`;
  } finally { btn.disabled = false; btn.textContent = "Convert query"; }
});
$("#qout").addEventListener("click", e => {
  const b = e.target.closest("[data-copy]");
  if (b) copyText(b.closest(".art").querySelector("pre").textContent, b);
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
// ---- try-an-example buttons ---------------------------------------------
const EX_QUERY = "FROM logs-* | WHERE status >= 500 | STATS errors = COUNT() BY service.name | SORT errors DESC | LIMIT 10";
const EXAMPLES = {
  dashboard: { file: "example_dashboard.ndjson",
    text: JSON.stringify({ id: "eg-vis", type: "visualization", references: [], attributes: {
      title: "Errors by service",
      visState: JSON.stringify({ type: "horizontal_bar", title: "Errors by service",
        aggs: [{ id: "1", type: "count", schema: "metric", params: {} },
               { id: "2", type: "terms", schema: "segment",
                 params: { field: "service.name", size: 5 } }] }),
      kibanaSavedObjectMeta: { searchSourceJSON: JSON.stringify(
        { query: { query: "", language: "kuery" }, filter: [] }) } } }) },
  pipeline: { file: "example_logstash.conf",
    text: 'input { beats { port => 5044 } }\n' +
      'filter {\n' +
      '  grok { match => { "message" => "%{IP:client_ip} %{WORD:method} %{URIPATH:request_uri} %{NUMBER:status}" } }\n' +
      '  mutate { convert => { "status" => "integer" } }\n' +
      '  if [request_uri] =~ /^\\/health/ { drop { } }\n' +
      '}\n' +
      'output { elasticsearch { hosts => ["es:9200"] } }\n' },
  alert: { file: "example_watcher.json",
    text: JSON.stringify({ trigger: { schedule: { interval: "5m" } },
      input: { search: { request: { indices: ["logs-*"], body: {
        query: { bool: { must: [{ match: { level: "ERROR" } }] } } } } } },
      condition: { compare: { "ctx.payload.hits.total": { gt: 100 } } },
      actions: { notify_team: { email: { to: "ops@example.com", subject: "Error spike" } } } }) },
  transform: { file: "example_transform.json",
    text: JSON.stringify({ source: { index: ["logs-*"] },
      pivot: { group_by: { service: { terms: { field: "service.name" } } },
               aggregations: { avg_duration: { avg: { field: "duration" } } } },
      dest: { index: "svc-rollup" }, frequency: "5m" }) },
  config: { file: "example_ilm.json",
    text: JSON.stringify({ policy: { phases: {
      hot: { min_age: "0ms", actions: { rollover: { max_size: "50gb", max_age: "7d" } } },
      delete: { min_age: "30d", actions: { delete: {} } } } } }) },
};

document.querySelectorAll("[data-eg]").forEach(b => b.addEventListener("click", () => {
  const kind = b.dataset.eg;
  if (kind === "query") {
    $("#qin").value = EX_QUERY;
    $("#qlang").value = "esql";
    document.getElementById("quick").scrollIntoView({ behavior: "smooth" });
    $("#qgo").click();
    return;
  }
  const eg = EXAMPLES[kind];
  chosen = [new File([eg.text], eg.file)];
  showFiles();
  document.getElementById("stage-input").scrollIntoView({ behavior: "smooth" });
  go.click();
}));
</script>
</body>
</html>
"""
