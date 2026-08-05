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

    Directory outputs (e.g. the Terraform module `terraform/`) are listed
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

    def migrate(self, sid: str, emit: str = "both") -> dict:
        dirs = self._dirs(sid)
        summary = run_migration(str(dirs["in"]), str(dirs["out"]), self.config, emit=emit)
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
            try:
                d["source_text"] = (dirs["in"] / it.source).read_text(
                    encoding="utf-8")[:20000]
            except OSError:
                d["source_text"] = ""
            d["artifacts"] = _read_artifacts(dirs["out"], it.outputs)
            d["remediation"] = [{"title": r.title, "what": r.what, "fix": r.fix}
                                for r in remediations_for_notes(it.notes)]
            items.append(d)
        from e2d.plan import build_plan
        from e2d.score import build_scorecard, scorecard_line
        sc = build_scorecard(summary)
        return {
            "counts": summary.counts(),
            "total": len(summary.items),
            "items": items,
            "secrets": list(dict.fromkeys(summary.secrets)),
            "skipped": summary.skipped,
            "plan": build_plan(summary),
            "scorecard": sc,
            "scorecard_line": scorecard_line(sc),
            "unmatched": summary.unmatched_indexes,
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

    # -- backfill historical logs (background job per session) --------------- #

    def backfill_discover(self, sid: str, cfg: dict) -> dict:
        self._dirs(sid)  # validate session
        from e2d.backfill import discover_indices
        return {"indices": discover_indices(
            cfg.get("es_url", ""), cfg.get("token", ""),
            cfg.get("auth_scheme", "ApiKey"), cfg.get("pattern") or "*",
            verify_tls=cfg.get("verify_tls", True))}

    def backfill_start(self, sid: str, cfg: dict) -> dict:
        self._dirs(sid)
        rows = [{"index": s.get("index", ""), "from": s.get("from", ""),
                 "to": s.get("to", ""), "state": "queued", "scanned": 0,
                 "prepared": 0, "sent": 0, "batches": 0, "skipped": 0,
                 "dlq": 0, "note": "", "errors": [], "sample": None,
                 "dql_count": None}
                for s in cfg.get("selection", []) if s.get("index")]
        sdir = self._base / sid
        for n, row in enumerate(rows):
            row["state_path"] = str(sdir / f"bf-{n}.state.json")
        if not rows:
            raise ValueError("no indices selected")
        job = {"state": "running", "apply": bool(cfg.get("apply")), "rows": rows}
        with self._lock:
            self._sessions[sid]["backfill"] = job

        def work():
            from e2d.backfill import run_backfill
            for row in rows:
                row["state"] = "running"
                try:
                    def prog(st, row=row):
                        row.update(scanned=st.scanned, prepared=st.prepared,
                                   sent=st.sent, batches=st.batches,
                                   skipped=st.skipped, dlq=st.dlq, note=st.note)
                        if st.sample is not None and row["sample"] is None:
                            row["sample"] = st.sample
                    stats = run_backfill(
                        es_url=cfg.get("es_url", ""), es_token=cfg.get("token", ""),
                        es_auth=cfg.get("auth_scheme", "ApiKey"),
                        index=row["index"], time_from=row["from"],
                        time_to=row["to"], query=cfg.get("query") or None,
                        env_url=cfg.get("env_url", ""),
                        dt_token=cfg.get("dt_token", ""),
                        stamp=cfg.get("stamp", "spread"), apply=job["apply"],
                        limit=int(cfg.get("limit") or 0),
                        verify_tls=cfg.get("verify_tls", True),
                        out=None, on_progress=prog,
                        state_path=row["state_path"],
                        dlq_path=row["state_path"].replace(".state.json",
                                                           ".dlq.ndjson"))
                    row["errors"] = stats.errors
                    row["dlq"] = stats.dlq
                    row["note"] = stats.note
                    if job["apply"] and cfg.get("env_url") and cfg.get("dt_token"):
                        # count what actually landed, by source index
                        from e2d.parity import _dql_count
                        n, _err = _dql_count(
                            cfg["env_url"], cfg["dt_token"],
                            'fetch logs, from: now() - 24h\n'
                            '| filter backfilled == "true" and source.index == '
                            f'"{row["index"]}"\n'
                            '| summarize parity_count = count()')
                        row["dql_count"] = n
                    row["state"] = "error" if stats.errors else "done"
                except Exception as e:  # one bad index never kills the job
                    row["errors"] = [str(e)]
                    row["state"] = "error"
            job["state"] = "done"

        threading.Thread(target=work, daemon=True).start()
        return {"started": len(rows), "apply": job["apply"]}

    def backfill_status(self, sid: str) -> dict:
        job = self._dirs(sid).get("backfill")
        if job is None:
            raise KeyError("no backfill job in this session")
        return job

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
                    body = json.loads(self._read_body() or b"{}")
                    self._json(200, sessions.migrate(sid, body.get("emit", "both")))
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
                elif self.path == "/backfill/discover":
                    sid = self.headers.get("X-Session", "")
                    self._json(200, sessions.backfill_discover(
                        sid, json.loads(self._read_body() or b"{}")))
                elif self.path == "/backfill/run":
                    sid = self.headers.get("X-Session", "")
                    self._json(200, sessions.backfill_start(
                        sid, json.loads(self._read_body() or b"{}")))
                elif self.path == "/backfill/status":
                    sid = self.headers.get("X-Session", "")
                    self._json(200, sessions.backfill_status(sid))
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
  /* ---- view switching -------------------------------------------------
     One attribute on #app decides which platform's sections are on screen.
     `!important` is deliberate: the view system must beat every component's
     own display rule, or a panel styled `display:flex` would ignore it. */
  .v { display:none !important; }
  [data-plat="home"] .v-home,
  [data-plat="elastic"] .v-elastic,
  [data-plat="appd"] .v-appd,
  [data-plat="elastic"] .v-conv,
  [data-plat="appd"] .v-conv { display:revert !important; }
  /* a hidden result panel must stay hidden even when its view is active */
  .card.hide.v-conv { display:none !important; }
  /* inline runs inside a paragraph must not become blocks */
  span.v { display:revert !important; }
  [data-plat="home"] span.v-home,
  [data-plat="elastic"] span.v-elastic,
  [data-plat="appd"] span.v-appd { display:inline !important; }
  [data-plat="home"] span.v:not(.v-home),
  [data-plat="elastic"] span.v:not(.v-elastic):not(.v-conv),
  [data-plat="appd"] span.v:not(.v-appd):not(.v-conv) { display:none !important; }

  .tabs { display:flex; gap:4px; padding:3px; border:1px solid var(--line2);
          border-radius:999px; background:rgba(0,0,0,.25); }
  .tab { margin:0; padding:6px 15px; font-size:13px; font-weight:600; border-radius:999px;
         background:transparent; border:0; color:var(--mut); box-shadow:none; cursor:pointer; }
  .tab:hover:not(:disabled) { color:var(--ink); filter:none; }
  .tab[aria-current="page"] { background:var(--panel2); color:var(--ink); }
  .tab:focus-visible { outline:2px solid var(--blue); outline-offset:2px; }

  .picker { display:grid; gap:16px; grid-template-columns:repeat(auto-fit,minmax(270px,1fr)); }
  .pcard { display:flex; flex-direction:column; align-items:flex-start; gap:10px;
           text-align:left; margin:0; padding:24px 22px; cursor:pointer;
           background:var(--panel); border:1px solid var(--line); border-radius:14px;
           box-shadow:none; transition:border-color .15s ease, transform .15s ease; }
  .pcard:hover:not(:disabled) { border-color:var(--blue); transform:translateY(-2px);
                                filter:none; }
  .pcard:focus-visible { outline:2px solid var(--blue); outline-offset:3px; }
  .pname { font-size:20px; font-weight:700; letter-spacing:-.015em; color:var(--ink);
           font-family:"Segoe UI Variable Display","Segoe UI",system-ui,sans-serif; }
  .pdesc { font-size:13.5px; line-height:1.6; color:var(--mut); font-weight:400; }
  .pgo { margin-top:auto; font-size:13px; font-weight:650; color:var(--teal); }
  .pickfoot { text-align:center; max-width:60ch; margin:18px auto 0; }
  .platintro { padding:34px 0 18px; }
  .platintro h1 { font-size:clamp(26px,4vw,36px); }

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
  #bf_list input { background:rgba(0,0,0,.35); border:1px solid var(--line2);
    color:var(--ink); border-radius:8px; padding:6px 8px; width:200px;
    font:12px ui-monospace,Consolas,monospace; }
  #bf_list table, #bf_out table { font-size:12.5px; }
  a.logo { color:inherit; text-decoration:none; }
  .cat-h { font:600 11px ui-monospace,Consolas,monospace; letter-spacing:.14em;
           text-transform:uppercase; color:var(--faint); margin:20px 0 2px; }
  .steps { list-style:none; margin:0; padding:0; }
  .steps li { position:relative; padding:0 0 22px 44px; }
  .steps li::before { content:""; position:absolute; left:13px; top:30px; bottom:0;
                      width:2px; background:var(--line); }
  .steps li:last-child::before { display:none; }
  .steps .dot { position:absolute; left:0; top:0; width:28px; height:28px;
                border-radius:50%; border:1px solid var(--line2); display:grid;
                place-items:center; background:var(--panel); color:var(--mut);
                font:600 12px ui-monospace,Consolas,monospace; }
  .steps li.done .dot { background:var(--ok); border-color:var(--ok); color:#06210f; }
  .steps h3 { margin:2px 0 3px; font-size:14.5px; }
  .steps h3 label { display:inline-flex; gap:10px; align-items:center; cursor:pointer; }
  .steps li.done h3 { color:var(--mut); text-decoration:line-through;
                      text-decoration-color:var(--faint); }
  .steps p { margin:0; font-size:13px; color:var(--mut); }
  .steps input[type="checkbox"] { width:15px; height:15px; accent-color:#27a56d; }
  .where { font:600 10.5px ui-monospace,Consolas,monospace; letter-spacing:.08em;
           text-transform:uppercase; color:var(--faint); border:1px solid var(--line2);
           border-radius:6px; padding:2px 7px; margin-left:8px; white-space:nowrap; }
  .steps h3 { display:flex; align-items:center; flex-wrap:wrap; gap:4px; }
  .map-h { margin:0 0 6px; font-size:14.5px; }
  .egrow { margin-top:12px; display:flex; gap:6px; flex-wrap:wrap; align-items:center; }
  .egsep { margin-left:8px; font-size:12px; font-weight:600; color:var(--faint); }
  .egchip { margin:0; padding:6px 14px; font-size:12px; font-weight:600; line-height:1.45;
            background:transparent; border:1px solid var(--line2); color:var(--mut);
            border-radius:999px; box-shadow:none; }
  .egchip:hover:not(:disabled) { border-color:var(--blue); color:var(--ink); filter:none; }
  .egchip:focus-visible { outline:2px solid var(--blue); outline-offset:2px; }
  .gap select { background:rgba(0,0,0,.35); border:1px solid var(--line2); color:var(--ink);
                border-radius:8px; padding:6px 9px; font:12.5px ui-monospace,Consolas,monospace; }
  .srcview { margin-top:10px; }
  .srcview summary { cursor:pointer; }
  #map_idx input, #map_fld input, #map_idx select {
    background:rgba(0,0,0,.35); border:1px solid var(--line2); color:var(--ink);
    border-radius:8px; padding:7px 9px; width:100%;
    font:12.5px ui-monospace,Consolas,monospace; }
  #map_idx td, #map_fld td { border-bottom:0; padding:4px 6px 4px 0; }
  #map_idx th, #map_fld th { padding-left:0; }
  .disc-item { display:flex; align-items:center; gap:8px; padding:3px 0; font-size:13px; }
  .disc-group { color:var(--faint); font-weight:600; margin:10px 0 2px; font-size:11px;
                letter-spacing:.14em; text-transform:uppercase;
                font-family:ui-monospace,Consolas,monospace; }
  /* coverage & caveats */
  .grid { display:grid; grid-template-columns:repeat(auto-fit,minmax(258px,1fr));
          gap:14px; align-items:start; }
  .grid + .grid { margin-top:14px; }
  .feat { background:linear-gradient(180deg,var(--panel2),var(--panel));
          border:1px solid var(--line); border-radius:14px; padding:20px;
          transition:border-color .2s, transform .2s; }
  .feat:hover { border-color:var(--line2); transform:translateY(-2px); }
  .try { margin-top:12px; padding:7px 14px; font-size:12.5px; font-weight:600;
         background:transparent; border:1px solid var(--line2); color:var(--mut);
         border-radius:8px; box-shadow:none; }
  .try:hover:not(:disabled) { border-color:var(--blue); color:var(--ink); filter:none; }
  .feat .ic { width:36px; height:36px; border-radius:10px; display:grid; place-items:center;
              background:rgba(77,141,255,.12); color:#7cc4ff; margin-bottom:12px; }
  .feat h3 { margin:0 0 6px; font-size:14.5px; font-weight:650; line-height:1.35; }
  .feat p { margin:0; font-size:13px; line-height:1.62; color:var(--mut); }
  .feat p b { color:#9fc3f5; font-weight:600; }
  .alsonote { color:var(--mut); font-size:13.5px; margin-top:14px; }

  /* how-it-works stages */
  .stages { counter-reset:stage; list-style:none; margin:14px 0 4px; padding:0; }
  .stages li { counter-increment:stage; position:relative; padding:0 0 16px 40px;
               color:var(--mut); font-size:13.5px; line-height:1.62; }
  .stages li:last-child { padding-bottom:4px; }
  .stages li::before { content:counter(stage); position:absolute; left:0; top:1px;
                       width:24px; height:24px; border-radius:8px; display:grid;
                       place-items:center; font:700 11.5px ui-monospace,Consolas,monospace;
                       background:rgba(77,141,255,.14); color:#7cc4ff; }
  .stages li::after { content:""; position:absolute; left:11.5px; top:29px; bottom:4px;
                      width:1px; background:var(--line); }
  .stages li:last-child::after { display:none; }
  .stages b { color:var(--ink); font-weight:620; }

  /* how-to-deploy panel */
  .howto { list-style:none; margin:8px 0 18px; padding:0; }
  .howto li { position:relative; padding:0 0 0 18px; margin-bottom:9px;
              color:var(--mut); font-size:13.5px; line-height:1.62; }
  .howto li:last-child { margin-bottom:0; }
  .howto li::before { content:""; position:absolute; left:2px; top:.66em;
                      width:7px; height:1.5px; background:var(--line2); }
  .howto li b { color:var(--ink); font-weight:620; }
  .cmdblock { margin:8px 0 14px; padding:12px 14px; overflow-x:auto;
              background:rgba(0,0,0,.35); border:1px solid var(--line);
              border-radius:10px; font:12.5px/1.7 ui-monospace,Consolas,monospace;
              color:var(--ink); white-space:pre; }
  #howto-card .map-h { margin:20px 0 4px; }
  #howto-card .map-h:first-of-type { margin-top:14px; }
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
    <span class="logo"><span class="mark">e2d</span> migration assist</span>

    <nav class="tabs" id="tabs" aria-label="Source platform">
      <button class="tab" data-view="home" aria-current="page">Home</button>
      <button class="tab" data-view="elastic">Elastic</button>
      <button class="tab" data-view="appd">AppDynamics</button>
    </nav>

    <span class="local">localhost only, nothing leaves this machine</span>
  </div>
</header>
<main class="wrap" id="app" data-plat="home">
  <div class="hero v v-home">
    <h1>Elastic &amp; AppDynamics &#8594; Dynatrace</h1>
    <p class="tagline">Convert your source platform's dashboards, alerts, queries and
       configuration into Dynatrace equivalents, pull straight from a live estate, and push
       the results to a tenant.
       <strong>Everything runs on this machine.</strong> Nothing is uploaded anywhere.</p>
  </div>

  <div class="picker v v-home">
    <button class="pcard" data-view="elastic">
      <span class="pname">Elastic</span>
      <span class="pdesc">Kibana dashboards, ES|QL / Query DSL / KQL / Lucene, Logstash and
        ingest pipelines, watchers and alerting rules, transforms, SLOs, Beats configs and
        ILM policies. Includes live pull from Kibana and log backfill.</span>
      <span class="pgo">Start converting &#8594;</span>
    </button>
    <button class="pcard" data-view="appd">
      <span class="pname">AppDynamics</span>
      <span class="pdesc">Health rules, custom dashboards, application/tier/node inventory,
        policies and actions &mdash; plus a OneAgent onboarding plan sized by host rather
        than by application.</span>
      <span class="pgo">Start converting &#8594;</span>
    </button>
  </div>
  <p class="note pickfoot v v-home">Not sure, or migrating both at once? Pick either &mdash;
     every file is identified by its own contents, so a mixed drop converts correctly
     whichever tab you are on.</p>

  <div class="v v-elastic">
    <div class="hero platintro">
      <h1>Elastic &#8594; Dynatrace</h1>
      <p class="tagline">Kibana dashboards, queries, ingest pipelines, watchers, transforms,
         SLOs and Beats configs.</p>
    </div>
    <div class="egrow note">Try an example:
      <button class="egchip" data-eg="dashboard">dashboard</button>
      <button class="egchip" data-eg="query">query</button>
      <button class="egchip" data-eg="pipeline">pipeline</button>
      <button class="egchip" data-eg="alert">alert</button>
      <button class="egchip" data-eg="slo">SLO</button>
      <button class="egchip" data-eg="transform">transform</button>
      <button class="egchip" data-eg="shipper">filebeat</button>
      <button class="egchip" data-eg="synthetic">heartbeat</button>
      <button class="egchip" data-eg="config">ILM</button>
    </div>
  </div>

  <div class="v v-appd">
    <div class="hero platintro">
      <h1>AppDynamics &#8594; Dynatrace</h1>
      <p class="tagline">Health rules, custom dashboards, policies and actions &mdash; and an
         onboarding plan that sizes the OneAgent rollout by host.</p>
    </div>
    <div class="egrow note">Try an example:
      <button class="egchip" data-eg="appdrule">health rules</button>
      <button class="egchip" data-eg="appddash">dashboard</button>
      <button class="egchip" data-eg="appdinv">node inventory</button>
      <button class="egchip" data-eg="appdcollector">data collectors</button>
      <button class="egchip" data-eg="appdsched">schedules</button>
    </div>
  </div>

  <div class="card v v-conv" id="stage-input">
    <div id="drop">
      <svg width="34" height="34" viewBox="0 0 24 24" fill="none" stroke="currentColor"
           stroke-width="1.6" stroke-linecap="round" stroke-linejoin="round">
        <path d="M21 15v4a2 2 0 0 1-2 2H5a2 2 0 0 1-2-2v-4"/>
        <polyline points="17 8 12 3 7 8"/><line x1="12" y1="3" x2="12" y2="15"/>
      </svg>
      <strong>Drop files here</strong> or click to choose
      <p class="note v v-elastic" style="margin:6px 0 0">Kibana dashboards &middot; ES|QL
         &middot; Query DSL &middot; KQL/Lucene &middot; Logstash &middot; watchers &middot;
         transforms &middot; SLOs &middot; Beats configs &middot; ILM policies</p>
      <p class="note v v-appd" style="margin:6px 0 0">Health rules &middot; custom dashboards
         &middot; application/tier/node inventory &middot; policies &amp; actions, exported
         as JSON from the Controller</p>
      <input type="file" id="picker" multiple class="hide">
    </div>
    <ul class="files" id="filelist"></ul>
    <div class="conn">
      <select id="emitsel" title="Deployable format written for alerts and pipelines">
        <option value="both">Export JSON + Terraform</option>
        <option value="json">JSON only &mdash; upload via API, no Terraform</option>
        <option value="tf">Terraform only</option>
      </select>
      <button id="go" disabled>Convert</button>
    </div>
    <div class="err-box hide" id="err"></div>
  </div>

  <div class="card v v-elastic" id="quick" style="margin-top:16px">
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

  <div class="card hide v v-conv" id="stage-result" style="margin-top:24px"></div>

  <details class="card v v-conv" id="how-card" style="margin-top:16px">
    <summary class="h">How it works, and what it will not do</summary>

    <ol class="stages">
      <li><b>Identify.</b> Every file is classified by its own contents, not its name or
        the tab you are on. A mixed drop of Elastic and AppDynamics exports sorts itself
        out; anything unrecognised is listed as skipped with a reason, never dropped
        silently.</li>
      <li><b>Translate.</b> Each artifact is lowered into a shared, product-neutral model
        &mdash; filters, aggregations, alert specs &mdash; and then emitted as DQL and
        Dynatrace configuration. That shared middle is why Elastic and AppDynamics produce
        consistent output rather than two dialects.</li>
      <li><b>Lint.</b> Generated DQL is checked offline against the mistakes that fail
        quietly: scalar maths on timeseries arrays, the deprecated entity namespace,
        percentiles missing a rollup. Findings land in the report next to the artifact.</li>
      <li><b>Report.</b> A scorecard, a deployment order, and per-artifact notes saying
        exactly what a human still has to decide.</li>
      <li><b>Deploy.</b> Upload-ready JSON, an importable Terraform module, or a direct
        push &mdash; your choice, per run.</li>
    </ol>

    <h3 class="map-h">Four honest categories</h3>
    <p class="note">Everything the tool touches falls into one of these, and the report
       says which. The fourth is usually the largest and the most valuable.</p>
    <ul class="howto">
      <li><b>Converted.</b> A deployable artifact you can apply as-is after review.</li>
      <li><b>Guided.</b> The plan is generated; you apply it. Onboarding waves, notification
        routing, management zone design.</li>
      <li><b>Rebuild by hand.</b> A copy would mislead, so the tool inventories what exists
        and names what to build instead &mdash; business events, method-level capture
        rules, dashboards whose entity model has genuinely changed.</li>
      <li><b>Nothing to migrate.</b> Dynatrace already does it. Business transactions,
        transaction snapshots, dynamic baselines, tier and node definitions, diagnostic
        capture actions. Carrying these across costs weeks and delivers nothing.</li>
    </ul>

    <h3 class="map-h">What it will not do</h3>
    <ul class="howto">
      <li><b>Guess a metric.</b> An AppD metric path with no documented Dynatrace
        equivalent is reported as manual with the reason, never mapped to a lookalike key.
        A wrong metric deploys cleanly and watches the wrong thing.</li>
      <li><b>Invent a threshold.</b> Baseline health rules carry no static number, so none
        is fabricated &mdash; they are reported as already covered by Davis.</li>
      <li><b>Scope an entity.</b> AppD tier and business-transaction names have no reliable
        offline mapping to Dynatrace entities. A guessed filter would match nothing while
        looking correct, so the original scope travels as a note for a human to apply.</li>
      <li><b>Turn your alerts on.</b> Detectors are created disabled. You enable them per
        wave, after validation.</li>
      <li><b>Move history.</b> Dynatrace rejects logs older than 24 hours and metrics older
        than an hour. Log history can be re-stamped and replayed; AppD metric history
        cannot move at all, which is why parity means running both stacks in parallel.</li>
    </ul>
  </details>

  <details class="card v v-conv" id="howto-card" style="margin-top:16px">
    <summary class="h">How to deploy what you downloaded</summary>
    <p class="note">The converted files fall into three groups, each with its own route into
       Dynatrace. Everything below is a one-time setup per environment.</p>

    <h3 class="map-h">1. Dashboards &mdash; <code>dashboards/*.json</code></h3>
    <p class="note">Each file is a bare dashboard document, so the Dashboards app imports it
       directly and names it after the file.</p>
    <ul class="howto">
      <li><b>In the UI:</b> Dashboards app &rarr; <b>Upload</b> &rarr; pick the
        <code>.json</code>. Nothing else to configure.</li>
      <li><b>Via API:</b> <code>POST {env}/platform/document/v1/documents</code> as
        <code>multipart/form-data</code> with <code>name</code>, <code>type=dashboard</code>
        and the file as <code>content</code>. Token scope:
        <code>document:documents:write</code>.</li>
    </ul>

    <h3 class="map-h">2. Settings objects &mdash; <code>*.detectors.json</code>,
        <code>*.pipeline.json</code>, <code>*.windows.json</code></h3>
    <p class="note">These files <em>are</em> the request body &mdash; a JSON array of
       <code>{schemaId, scope, value}</code> objects. Post one file, get one or more
       configuration objects.</p>
    <ul class="howto">
      <li><code>POST {env}/api/v2/settings/objects</code> with
        <code>Content-Type: application/json</code> and the file as the body.
        Token scope: <code>settings:objects:write</code>.</li>
      <li>Covers Davis anomaly detectors (from alerts and health rules), OpenPipeline
        pipelines, and maintenance windows (from AppD schedules).</li>
      <li>A <code>207</code> response is normal for a multi-object body &mdash; check each
        entry's <code>code</code>, because one object can fail while the rest succeed.</li>
      <li>Detectors converted from a dynamic threshold ship <b>disabled</b> on purpose, with
        a <code>0</code> placeholder. Set a real threshold before enabling.</li>
    </ul>

    <h3 class="map-h">3. Terraform &mdash; <code>terraform/</code></h3>
    <p class="note">One <b>child module</b> for the whole run, not a folder per artifact.
       It declares which provider it needs but configures none, so it drops into an
       existing repository and inherits your provider setup &mdash; no duplicate
       <code>terraform&nbsp;{}</code> block to collide with yours.</p>
    <pre class="cmdblock">module "migrated" {
  source = "./modules/migrated"

  name_prefix       = "[migrated] "
  detectors_enabled = false   # flip per wave, once validated
}</pre>
    <ul class="howto">
      <li><b>Already have a Terraform repo?</b> Copy <code>terraform/</code> in, add the
        block above, and <code>terraform init &amp;&amp; terraform plan</code>. Nothing in
        it configures a provider, alias or backend, so it will not fight your setup.</li>
      <li><b>Starting fresh?</b> <code>terraform/example-root/</code> is a working root
        configuration with the provider block. Run terraform from in there &mdash; a child
        module cannot be applied directly.</li>
      <li><b>Detectors are created disabled</b> by default. Enabling hundreds at once pages
        people about a system nobody has validated, and Davis needs 7&ndash;14 days before
        its baselines are trustworthy. Set <code>detectors_enabled = true</code> per wave.</li>
      <li><b>Anomaly detectors and request attributes</b> use an API token:
        <code>DYNATRACE_ENV_URL</code> and <code>DYNATRACE_API_TOKEN</code>.</li>
      <li><b>OpenPipeline</b> needs an OAuth client instead, not a token:
        <code>DT_CLIENT_ID</code>, <code>DT_CLIENT_SECRET</code>,
        <code>DT_ACCOUNT_ID</code>, with scopes
        <code>openpipeline:configurations:read</code> and
        <code>&hellip;:write</code>.</li>
      <li>No Terraform state story yet? Choose <b>JSON only</b> in the export selector and
        skip this section entirely.</li>
    </ul>

    <h3 class="map-h">Order matters</h3>
    <p class="note">Deploy pipelines before dashboards, and dashboards before alerts:
       pipelines create the fields the tiles query, and detectors evaluating data that is
       not flowing yet will just fire false alarms. Each run writes the exact order for
       your artifacts into <code>MIGRATION_REPORT.md</code>.</p>

    <h3 class="map-h">Or skip all of it</h3>
    <p class="note">You are running locally, so dashboards and detectors can be pushed
       straight from the deploy panel in the results below &mdash; enter your environment
       URL and a token and it calls the same APIs described above. Credentials stay on this
       machine. Terraform is still the route for OpenPipeline and Workflows.</p>
  </details>

  <details class="card v v-elastic" id="mapping-card" style="margin-top:16px">
    <summary class="h">Mapping rules (applied to every conversion)</summary>
    <p class="note">Route Elastic index patterns to Grail data objects and rename fields.
     Rules are saved in this browser and applied to every conversion automatically;
     a <code>mapping.config.json</code> dropped with your files takes precedence.
     Custom index rules are tried before the built-in defaults. Field references are lowercased automatically because Dynatrace
     normalizes attribute keys to lowercase at ingest; an explicit rename here
     overrides that.</p>

    <h3 class="map-h">Index patterns &#8594; data objects</h3>
    <table id="map_idx"></table>
    <button id="map_idx_add" class="copy" style="margin-top:8px">Add rule</button>
    <h3 class="map-h" style="margin-top:22px">Field renames</h3>
    <table id="map_fld"></table>
    <button id="map_fld_add" class="copy" style="margin-top:8px">Add rename</button>
    <div class="row">
      <button id="map_dl">Download mapping.config.json</button>
      <button id="map_copy" class="copy" style="padding:9px 16px;font-size:13px">Copy JSON</button>
      <span class="note" id="map_note"></span>
    </div>
  
  </details>

  <details class="card v v-elastic" id="pull-card" style="margin-top:16px">
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

  <details class="card v v-elastic" id="backfill-card" style="margin-top:16px">
    <summary class="h">Backfill historical logs (past the 24h wall)</summary>
    <p class="note">Streams old logs straight from Elasticsearch into Dynatrace: each record
       is re-stamped into the accepted window and keeps its true event time in
       <code>original_timestamp</code>. Fill in the Elastic connection in the panel above,
       then discover, pick indices and windows, dry run, and backfill.</p>
    <div class="conn">
      <input id="bf_pattern" placeholder="Index pattern (default: *)">
      <button id="bf_discover">Discover indices</button>
    </div>
    <div id="bf_list"></div>
    <div id="bf_ctl" class="hide">
      <div class="conn">
        <input id="bf_env" placeholder="Dynatrace env URL (https://abc12345.apps.dynatrace.com)">
        <input id="bf_token" type="password" placeholder="Dynatrace token (logs ingest)">
        <select id="bf_stamp">
          <option value="spread">Spread over last 23h (keeps order)</option>
          <option value="now">Stamp everything with now</option>
        </select>
        <input id="bf_query" placeholder="Optional Lucene filter (level:ERROR)">
        <button id="bf_dry">Dry run</button>
        <button id="bf_go" style="background:linear-gradient(180deg,#3bc98a,#27a56d)">Backfill</button>
      </div>
      <div id="bf_out"></div>
    </div>
  </details>


  <details class="card v v-conv" style="margin-top:16px">
    <summary class="h">What it converts, and limits</summary>
  <div class="grid v v-elastic">
    <div class="feat">
      <div class="ic"><svg width="18" height="18" viewBox="0 0 24 24" fill="none"
        stroke="currentColor" stroke-width="1.8" stroke-linecap="round" stroke-linejoin="round">
        <rect x="3" y="3" width="7" height="9" rx="1"/><rect x="14" y="3" width="7" height="5" rx="1"/>
        <rect x="14" y="12" width="7" height="9" rx="1"/><rect x="3" y="16" width="7" height="5" rx="1"/></svg></div>
      <h3>Kibana dashboards</h3>
      <p>Lens incl. formulas, TSVB, legacy visualizations, saved searches, controls, and Vega
         with an embedded ES query <b>&#8594; dashboard JSON</b> with DQL tiles, variables and
         series colours. Import in the Dashboards app or push from here.</p>
    </div>
    <div class="feat">
      <div class="ic"><svg width="18" height="18" viewBox="0 0 24 24" fill="none"
        stroke="currentColor" stroke-width="1.8" stroke-linecap="round" stroke-linejoin="round">
        <polyline points="4 17 10 11 4 5"/><line x1="12" y1="19" x2="20" y2="19"/></svg></div>
      <h3>Queries</h3>
      <p>ES|QL, Query DSL, KQL and Lucene <b>&#8594; DQL</b>, linted offline before it
         reaches you.</p>
    </div>
    <div class="feat">
      <div class="ic"><svg width="18" height="18" viewBox="0 0 24 24" fill="none"
        stroke="currentColor" stroke-width="1.8" stroke-linecap="round" stroke-linejoin="round">
        <path d="M22 3H2l8 9.46V19l4 2v-8.54L22 3z"/></svg></div>
      <h3>Ingest pipelines</h3>
      <p>Logstash <code>.conf</code> and Elasticsearch ingest pipelines
         <b>&#8594; OpenPipeline stages</b>: a readable <code>.dpl</code> plus your choice of
         upload-ready Settings JSON or a Terraform module.</p>
    </div>
    <div class="feat">
      <div class="ic"><svg width="18" height="18" viewBox="0 0 24 24" fill="none"
        stroke="currentColor" stroke-width="1.8" stroke-linecap="round" stroke-linejoin="round">
        <path d="M18 8a6 6 0 0 0-12 0c0 7-3 9-3 9h18s-3-2-3-9"/>
        <path d="M13.7 21a2 2 0 0 1-3.4 0"/></svg></div>
      <h3>Alerts &amp; watchers</h3>
      <p>Watchers and Kibana alerting rules, incl. index-threshold and ES-query rules
         <b>&#8594; Davis anomaly detectors + Workflows</b> as upload-ready Settings JSON
         or Terraform. Detectors can also be pushed from here.</p>
    </div>
    <div class="feat">
      <div class="ic"><svg width="18" height="18" viewBox="0 0 24 24" fill="none"
        stroke="currentColor" stroke-width="1.8" stroke-linecap="round" stroke-linejoin="round">
        <polygon points="12 2 2 7 12 12 22 7 12 2"/><polyline points="2 12 12 17 22 12"/></svg></div>
      <h3>Transforms</h3>
      <p>Continuous transforms <b>&#8594; rollup DQL</b> with a migration note per
         transform.</p>
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
    </div>
    <div class="feat">
      <div class="ic"><svg width="18" height="18" viewBox="0 0 24 24" fill="none"
        stroke="currentColor" stroke-width="1.8" stroke-linecap="round" stroke-linejoin="round">
        <circle cx="12" cy="12" r="10"/><line x1="22" y1="12" x2="18" y2="12"/>
        <line x1="6" y1="12" x2="2" y2="12"/><line x1="12" y1="6" x2="12" y2="2"/>
        <line x1="12" y1="22" x2="12" y2="18"/></svg></div>
      <h3>SLOs</h3>
      <p>Kibana SLO definitions <b>&#8594; DQL SLI queries</b> with the objective and
         window carried over, ready for the SLO app or API. APM indicators are flagged
         for the service-native path.</p>
    </div>
    <div class="feat">
      <div class="ic"><svg width="18" height="18" viewBox="0 0 24 24" fill="none"
        stroke="currentColor" stroke-width="1.8" stroke-linecap="round" stroke-linejoin="round">
        <line x1="22" y1="2" x2="11" y2="13"/><polygon points="22 2 15 22 11 13 2 9 22 2"/></svg></div>
      <h3>Shippers</h3>
      <p>Filebeat configs <b>&#8594; OpenTelemetry Collector configs</b> shipping straight
         to Dynatrace; Metricbeat modules are mapped to OneAgent and Extensions Hub
         advice.</p>
    </div>
    <div class="feat">
      <div class="ic"><svg width="18" height="18" viewBox="0 0 24 24" fill="none"
        stroke="currentColor" stroke-width="1.8" stroke-linecap="round" stroke-linejoin="round">
        <circle cx="12" cy="12" r="10"/><line x1="2" y1="12" x2="22" y2="12"/>
        <path d="M12 2a15.3 15.3 0 0 1 4 10 15.3 15.3 0 0 1-4 10 15.3 15.3 0 0 1-4-10 15.3 15.3 0 0 1 4-10z"/></svg></div>
      <h3>Synthetic monitors</h3>
      <p>Heartbeat HTTP monitors <b>&#8594; Dynatrace Synthetic monitor definitions</b>;
         TCP and ICMP checks are flagged for network availability monitors.</p>
    </div>
  </div>
  <div class="grid v v-appd">
    <div class="feat">
      <div class="ic"><svg width="18" height="18" viewBox="0 0 24 24" fill="none"
        stroke="currentColor" stroke-width="1.8" stroke-linecap="round" stroke-linejoin="round">
        <rect x="2" y="3" width="20" height="14" rx="2"/><line x1="8" y1="21" x2="16" y2="21"/>
        <line x1="12" y1="17" x2="12" y2="21"/></svg></div>
      <h3>AppD onboarding plan</h3>
      <p>Application/tier/node inventory <b>&#8594; a OneAgent rollout sized by host</b>.
         AppD needs an agent per process; OneAgent installs once per host and instruments
         everything on it — so the plan dedupes nodes to hosts, batches them into waves and
         carries the AppD identity across as host groups and tags.</p>
    </div>
    <div class="feat">
      <div class="ic"><svg width="18" height="18" viewBox="0 0 24 24" fill="none"
        stroke="currentColor" stroke-width="1.8" stroke-linecap="round" stroke-linejoin="round">
        <path d="M18 8a6 6 0 0 0-12 0c0 7-3 9-3 9h18s-3-2-3-9"/>
        <path d="M13.7 21a2 2 0 0 1-3.4 0"/></svg></div>
      <h3>AppD health rules</h3>
      <p>Static-threshold rules <b>&#8594; Davis anomaly detectors</b> with units rescaled
         (AppD reports milliseconds where Dynatrace uses microseconds). Baseline rules are
         reported as <b>already covered</b> by built-in Davis rather than converted &mdash;
         porting them would duplicate coverage and add noise.</p>
    </div>
    <div class="feat">
      <div class="ic"><svg width="18" height="18" viewBox="0 0 24 24" fill="none"
        stroke="currentColor" stroke-width="1.8" stroke-linecap="round" stroke-linejoin="round">
        <rect x="3" y="3" width="7" height="9" rx="1"/><rect x="14" y="3" width="7" height="5" rx="1"/>
        <rect x="14" y="12" width="7" height="9" rx="1"/><rect x="3" y="16" width="7" height="5" rx="1"/></svg></div>
      <h3>AppD dashboards &amp; actions</h3>
      <p>Custom dashboard widgets <b>&#8594; DQL tiles</b> with metric paths mapped to Grail
         keys; policies and actions <b>&#8594; a notification plan</b>. Diagnostic-capture
         actions are called out as needing no equivalent &mdash; Dynatrace captures
         continuously.</p>
    </div>
  </div>
  <p class="alsonote">Every run also writes <code>MIGRATION_REPORT.md</code> with a
     deployment-order plan and a scorecard, plus a field manifest per dashboard
     (<code>*.fields.md</code>) listing what must exist at ingest or a tile renders empty.
     <span class="v v-elastic">Elastic runs add <code>METRICS-GUIDE.md</code> for
     log&#8594;metric extraction, a <code>CUTOVER-PLAN.md</code> dual-ship schedule when ILM
     policies are present, and a suggested <code>mapping.config.json</code> when your index
     patterns need rules.</span>
     <span class="v v-appd">AppDynamics runs add <code>ONBOARDING-PLAN.md</code> with the
     OneAgent rollout waves (plus <code>waves.json</code> and <code>host_groups.json</code>
     for driving an Ansible inventory), <code>APPD-SEQUENCING.md</code> with the ten-phase
     running order and per-wave exit criteria, and <code>APPD-CATALOGUE.md</code> listing
     every kind of AppD configuration against its Dynatrace equivalent &mdash; including
     the items that need no migration at all.</span></p>

  <h2>Limitations</h2>
  <div class="cavs">
    <ul>
      <li class="v v-elastic"><strong>Maps and truly-custom Vega panels</strong> become
          placeholder tiles flagged MANUAL. Rebuild those by hand in Dynatrace.</li>
      <li class="v v-elastic"><strong>Lens formulas with no DQL equivalent</strong> fall back
          to a flagged <code>count()</code> placeholder. Nothing is converted silently wrong.</li>
      <li><strong>A converted tile renders empty, with no error,</strong> when a custom field
          it queries isn't ingested in Dynatrace. Check each dashboard's
          <code>.fields.md</code> manifest before trusting a blank chart.</li>
      <li class="v v-elastic"><strong>Index patterns without a mapping rule default to
          <code>logs</code>.</strong> Review the suggested <code>mapping.config.json</code> and
          re-run to make routing explicit.</li>
      <li><strong>Alert thresholds and evaluation windows are best-effort.</strong> Review
          each anomaly detector before enabling it in production.</li>
      <li class="v v-elastic"><strong>Canvas workpads and ML jobs have no converter.</strong>
          Unrecognised files are listed as skipped, with a reason.</li>
      <li class="v v-appd"><strong>Converted AppD alerts and tiles are not entity-scoped.</strong>
          AppD scopes by application/tier/business-transaction name, and there is no reliable
          offline mapping to Dynatrace entities &mdash; a guessed filter would silently match
          nothing. Each one carries its original AppD scope as a note; add the filter before
          enabling.</li>
      <li class="v v-appd"><strong>The AppD dashboard widget schema is not publicly
          documented,</strong> so widgets are read defensively. Anything unrecognised becomes a
          placeholder tile naming the original widget type rather than disappearing.</li>
      <li class="v v-appd"><strong>AppD history cannot be backfilled.</strong> Dynatrace rejects
          metric data older than an hour, so before/after comparison means running both stacks
          over the same window. Budget a dual-run period per wave.</li>
      <li class="v v-appd"><strong>No live AppD Controller pull yet.</strong> Export the health
          rules, dashboards and node inventory from the Controller and drop the files here.</li>
      <li class="v v-elastic"><strong>Dynatrace rejects log records older than 24 hours,</strong>
          so history cannot be replayed as-is. <code>e2d backfill</code> re-stamps it and keeps
          the true event time in <code>original_timestamp</code>; <code>CUTOVER-PLAN.md</code>
          schedules the dual-ship overlap instead.</li>
    </ul>
  </div>
  </details>
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

// ---- platform tabs ---------------------------------------------------
// The tab only decides which sections are on screen. Conversion always
// identifies each file by its own contents, so a mixed drop still converts
// correctly whichever tab is active — the tab never gates the engine.
const VIEWS = ["home", "elastic", "appd"];
function showView(name) {
  if (!VIEWS.includes(name)) name = "home";
  $("#app").dataset.plat = name;
  document.querySelectorAll("#tabs .tab").forEach(t => {
    if (t.dataset.view === name) t.setAttribute("aria-current", "page");
    else t.removeAttribute("aria-current");
  });
  window.localStorage.setItem("e2d_view", name);
  if (name !== "home") window.scrollTo({ top: 0, behavior: "smooth" });
}
document.querySelectorAll("[data-view]").forEach(el =>
  el.addEventListener("click", () => showView(el.dataset.view)));
showView(window.localStorage.getItem("e2d_view") || "home");

// alerts/pipelines export format (JSON vs Terraform) — remembered per browser
const emitSel = $("#emitsel");
const emitBody = () => JSON.stringify({ emit: emitSel.value });

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
  const em = LS.getItem("e2d_emit");
  if (em) emitSel.value = em;
  emitSel.addEventListener("change", () => LS.setItem("e2d_emit", emitSel.value));
});

go.addEventListener("click", async () => {
  err.classList.add("hide"); go.disabled = true; go.textContent = "Converting…";
  try {
    const { session } = await post("/session");
    currentSession = session;
    const toSend = chosen.slice();
    if (mapHasRules() && !toSend.some(f => f.name === "mapping.config.json"))
      toSend.push(new File([mappingJson()], "mapping.config.json"));
    for (const f of toSend) {
      await post("/upload", await f.arrayBuffer(),
                 { "X-Session": session, "X-Filename": f.name });
    }
    const data = await post("/migrate", emitBody(),
                            { "X-Session": session, "Content-Type": "application/json" });
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
    const data = await post("/migrate", emitBody(),
                            { "X-Session": pulledSession, "Content-Type": "application/json" });
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
  if (it.source_text)
    h += `<details class="srcview"><summary class="note">original source</summary>
          <pre>${esc(it.source_text)}</pre></details>`;
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
  if (d.scorecard_line)
    h += `<p class="note" style="margin:0 0 10px">${esc(d.scorecard_line)}</p>`;
  h += tuneBlock(d);
  h += planBlock(d.plan);
  if (d.items.length) {
    h += `<div class="toolbar">
            <button data-expand>Expand all</button>
            <button data-collapse>Collapse all</button>
            <span class="note">Click a file to view & copy its converted output.</span>
          </div>`;
    const CATS = [["onboarding", "OneAgent onboarding"], ["dashboard", "Dashboards"],
      ["query", "Queries"], ["pipeline", "Pipelines"], ["alert", "Alerts & health rules"],
      ["slo", "SLOs"], ["shipper", "Shippers"], ["synthetic", "Synthetic monitors"],
      ["transform", "Transforms"], ["notification", "Alert routing"],
      ["config", "Cluster config"]];
    const known = new Set(CATS.map(c => c[0]));
    for (const [cat, title] of CATS) {
      const group = d.items.map((it, i) => [it, i]).filter(([it]) => it.category === cat);
      if (!group.length) continue;
      h += `<h3 class="cat-h">${title} (${group.length})</h3>`;
      h += group.map(([it, i]) => itemCard(it, i)).join("");
    }
    h += d.items.map((it, i) => [it, i]).filter(([it]) => !known.has(it.category))
          .map(([it, i]) => itemCard(it, i)).join("");
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
  slo: { file: "example_slo.json",
    text: JSON.stringify({ name: "Checkout availability",
      indicator: { type: "sli.kql.custom", params: { index: "logs-checkout-*",
        filter: 'service.name: "checkout"', good: "status < 500",
        total: "status >= 100" } },
      objective: { target: 0.995 },
      timeWindow: { duration: "30d", type: "rolling" },
      budgetingMethod: "occurrences" }) },
  shipper: { file: "example_filebeat.yml",
    text: 'filebeat.inputs:\n  - type: filestream\n    id: app-logs\n    paths:\n      - /var/log/app/*.log\n    multiline.pattern: \'^\\d{4}-\'\n    multiline.negate: true\n    multiline.match: after\noutput.elasticsearch:\n  hosts: ["es:9200"]\n' },
  synthetic: { file: "example_heartbeat.yml",
    text: 'heartbeat.monitors:\n  - type: http\n    id: api-check\n    name: API health\n    schedule: \'@every 60s\'\n    urls: ["https://api.example.com/health"]\n    check.response.status: [200]\n' },
  appdrule: { file: "example_appd_health_rules.json",
    text: JSON.stringify([
      { id: 1, name: "Checkout response time too high", enabled: true,
        useDataFromLastNMinutes: 30, waitTimeAfterViolation: 30, scheduleName: "Always",
        affects: { affectedEntityType: "BUSINESS_TRANSACTION_PERFORMANCE" },
        evalCriterias: { criticalCriteria: { conditionAggregationType: "ANY", conditions: [
          { name: "ART", evalDetail: { evalDetailType: "SINGLE_METRIC",
            metricPath: "Business Transaction Performance|Business Transactions|checkout|/cart|Average Response Time (ms)",
            metricEvalDetail: { metricEvalDetailType: "SPECIFIC_TYPE",
              compareCondition: "GREATER_THAN", compareValue: 2000 } } }] } } },
      { id: 2, name: "Response time much higher than normal", enabled: true,
        affects: { affectedEntityType: "BUSINESS_TRANSACTION_PERFORMANCE" },
        evalCriterias: { criticalCriteria: { conditionAggregationType: "ANY", conditions: [
          { name: "baseline ART", evalDetail: { metricPath: "Average Response Time (ms)",
            metricEvalDetail: { metricEvalDetailType: "BASELINE_TYPE",
              baselineCondition: "GREATER_THAN_BASELINE", baselineName: "All Data",
              compareValue: 3, baselineUnit: "STANDARD_DEVIATIONS" } } }] } } }]) },
  appddash: { file: "example_appd_dashboard.json",
    text: JSON.stringify({ name: "Checkout health", width: 1200, widgetTemplates: [
      { widgetType: "GraphWidget", title: "Response time", x: 0, y: 0, width: 600, height: 240,
        dataSeriesTemplates: [{ name: "ART", metricMatchCriteriaTemplate: {
          metricExpressionTemplate: {
            metricPath: "Overall Application Performance|checkout|Average Response Time (ms)" } } }] },
      { widgetType: "GraphWidget", title: "Calls per minute", x: 600, y: 0, width: 600, height: 240,
        dataSeriesTemplates: [{ metricMatchCriteriaTemplate: { metricExpressionTemplate: {
          metricPath: "Overall Application Performance|Calls per Minute" } } }] }] }) },
  appdcollector: { file: "example_appd_data_collectors.json",
    text: JSON.stringify({ dataGathererConfigs: [
      { name: "userId", dataGathererType: "HTTP", parameters: ["userId"],
        headers: ["X-Tenant"], cookies: ["session_id"] },
      { name: "orderTotal", dataGathererType: "METHOD_INVOCATION",
        className: "com.shop.OrderService", methodName: "checkout",
        agentType: "APP_AGENT" }] }) },
  appdsched: { file: "example_appd_schedules.json",
    text: JSON.stringify([
      { name: "Business Hours", timezone: "Europe/London", scheduleType: "WEEKLY",
        startTime: "09:00", endTime: "17:30",
        days: ["MONDAY", "TUESDAY", "WEDNESDAY", "THURSDAY", "FRIDAY"] },
      { name: "Nightly Batch", timeZone: "UTC", recurrenceType: "DAILY",
        startTime: "23:00", endTime: "02:00" }]) },
  appdinv: { file: "example_appd_nodes.json",
    text: JSON.stringify([
      { id: 11, name: "node-a", tierName: "web", applicationName: "Checkout",
        machineName: "host01", appAgentVersion: "23.1", type: "Java" },
      { id: 12, name: "node-b", tierName: "web", applicationName: "Checkout",
        machineName: "host01", appAgentVersion: "23.1", type: "Java" },
      { id: 13, name: "node-c", tierName: "api", applicationName: "Checkout",
        machineName: "host02", appAgentVersion: "23.1", type: "Java" },
      { id: 14, name: "node-d", tierName: "core", applicationName: "Booking",
        machineName: "host03", appAgentVersion: "23.1", type: "Java" }]) },
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
// ---- backfill historical logs -------------------------------------------
let bfSession = null, bfTimer = null;
$("#bf_env").value = deployEnv;
$("#bf_token").value = deployToken;

$("#bf_discover").addEventListener("click", async () => {
  const btn = $("#bf_discover"); btn.disabled = true; btn.textContent = "Discovering…";
  const list = $("#bf_list");
  try {
    if (!bfSession) bfSession = (await post("/session")).session;
    const data = await post("/backfill/discover", JSON.stringify({
      es_url: $("#es_url").value.trim(), token: $("#token").value,
      auth_scheme: $("#auth_scheme").value,
      pattern: $("#bf_pattern").value.trim() || "*",
    }), { "X-Session": bfSession, "Content-Type": "application/json" });
    const idx = data.indices || [];
    if (!idx.length) { list.innerHTML = `<p class="note">No matching indices.</p>`; return; }
    list.innerHTML = `<table><tr><th></th><th>Index</th><th>Docs</th><th>Size</th>
        <th>From (ISO)</th><th>To (ISO)</th></tr>` +
      idx.map(r => `<tr>
        <td><input type="checkbox" class="bf-pick" checked data-index="${esc(r.index)}"></td>
        <td><code>${esc(r.index)}</code></td>
        <td class="note">${(r.docs || 0).toLocaleString()}</td>
        <td class="note">${esc(r.size || "")}</td>
        <td><input class="bf-from" value="${esc(r.oldest || "")}"></td>
        <td><input class="bf-to" value="${esc(r.newest || "")}"></td>
      </tr>`).join("") + `</table>`;
    $("#bf_ctl").classList.remove("hide");
  } catch (e) {
    list.innerHTML = `<p class="err-box">Discovery failed: ${esc(e.message)}</p>`;
  } finally { btn.disabled = false; btn.textContent = "Discover indices"; }
});

function bfSelection() {
  return [...document.querySelectorAll(".bf-pick:checked")].map(c => {
    const tr = c.closest("tr");
    return { index: c.dataset.index,
             from: tr.querySelector(".bf-from").value.trim(),
             to: tr.querySelector(".bf-to").value.trim() };
  }).filter(s => s.from && s.to);
}

async function bfRun(apply) {
  const out = $("#bf_out");
  const sel = bfSelection();
  if (!sel.length) {
    out.innerHTML = `<p class="note">Pick at least one index with a from/to window.</p>`;
    return;
  }
  deployEnv = $("#bf_env").value.trim(); deployToken = $("#bf_token").value;
  saveDeployCreds();
  if (apply && (!deployEnv || !deployToken)) {
    out.innerHTML = `<p class="err-box">Backfill needs the Dynatrace env URL and token.</p>`;
    return;
  }
  try {
    await post("/backfill/run", JSON.stringify({
      es_url: $("#es_url").value.trim(), token: $("#token").value,
      auth_scheme: $("#auth_scheme").value, selection: sel,
      query: $("#bf_query").value.trim(), stamp: $("#bf_stamp").value,
      env_url: deployEnv, dt_token: deployToken, apply,
    }), { "X-Session": bfSession, "Content-Type": "application/json" });
    out.innerHTML = `<p class="note">${apply ? "Backfilling…" : "Dry run…"}</p>`;
    clearInterval(bfTimer);
    bfTimer = setInterval(bfPoll, 1500);
  } catch (e) { out.innerHTML = `<p class="err-box">${esc(e.message)}</p>`; }
}

async function bfPoll() {
  let job;
  try {
    job = await post("/backfill/status", "", { "X-Session": bfSession });
  } catch (e) { return; /* transient poll error: keep trying */ }
  const rows = job.rows.map(r => {
    const cls = { done: "ok", error: "err", running: "rev" }[r.state] || "";
    let verify = "";
    if (r.dql_count != null)
      verify = r.dql_count >= r.sent
        ? ` · verified: ${r.dql_count.toLocaleString()} in Grail`
        : ` · in Grail so far: ${r.dql_count.toLocaleString()} of ${r.sent.toLocaleString()} (ingest lags a little)`;
    let h = `<tr><td><span class="badge ${cls}">${esc(r.state)}</span></td>
      <td><code>${esc(r.index)}</code></td>
      <td class="note">scanned ${r.scanned.toLocaleString()} ·
        ${job.apply ? "sent" : "would send"} ${r.sent.toLocaleString()}
        in ${r.batches} batch(es)${r.skipped ? ` · ${r.skipped} skipped` : ""}${verify}</td></tr>`;
    if (r.errors && r.errors.length)
      h += `<tr><td></td><td colspan="2" class="err-box">${r.errors.map(esc).join("; ")}</td></tr>`;
    if (r.sample && !job.apply)
      h += `<tr><td></td><td colspan="2"><details><summary class="note">sample record</summary>
            <pre>${esc(JSON.stringify(r.sample, null, 2).slice(0, 1500))}</pre></details></td></tr>`;
    return h;
  }).join("");
  $("#bf_out").innerHTML = `<table>${rows}</table>` +
    (job.state === "done" ? `<p class="note">${job.apply
      ? 'Done. Query history with: <code>fetch logs | filter backfilled == "true" and original_timestamp >= "..."</code>'
      : "Dry run complete. Nothing was sent; press Backfill to ship."}</p>` : "");
  if (job.state === "done") clearInterval(bfTimer);
}

$("#bf_dry").addEventListener("click", () => bfRun(false));
$("#bf_go").addEventListener("click", () => bfRun(true));

// ---- mapping rules builder ------------------------------------------------
const MAP_KEY = "e2d_mapping";
const DATA_OBJECTS = ["logs", "spans", "events", "user.events", "bizevents", "__metrics__"];
function mapState() {
  try {
    const m = JSON.parse(LS.getItem(MAP_KEY)) || {};
    return { index_map: m.index_map || [], field_map: m.field_map || [] };
  } catch (e) { return { index_map: [], field_map: [] }; }
}
function saveMapState(m) { LS.setItem(MAP_KEY, JSON.stringify(m)); paintMap(); }
function mappingJson() {
  const m = mapState();
  const fm = {};
  for (const [a, b] of m.field_map) if (a && b) fm[a] = b;
  return JSON.stringify({
    index_map: m.index_map.filter(r => r.pattern && r.data_object),
    field_map: fm,
  }, null, 2) + "\n";
}
function mapHasRules() {
  const m = mapState();
  return m.index_map.some(r => r.pattern) || m.field_map.some(([a, b]) => a && b);
}
function paintMap() {
  const m = mapState();
  $("#map_idx").innerHTML =
    `<tr><th>Pattern (regex)</th><th>Data object</th><th></th></tr>` +
    m.index_map.map((r, i) => `<tr>
      <td><input class="mi-pat" data-i="${i}" value="${esc(r.pattern || "")}" placeholder="^myapp-logs-"></td>
      <td><select class="mi-obj" data-i="${i}">${DATA_OBJECTS.map(o =>
        `<option value="${o}"${o === r.data_object ? " selected" : ""}>` +
        `${o === "__metrics__" ? "metrics (timeseries)" : o}</option>`).join("")}</select></td>
      <td><button class="copy mi-del" data-i="${i}">Remove</button></td></tr>`).join("");
  $("#map_fld").innerHTML =
    `<tr><th>Elastic field</th><th>DQL field</th><th></th></tr>` +
    m.field_map.map((r, i) => `<tr>
      <td><input class="mf-from" data-i="${i}" value="${esc(r[0] || "")}" placeholder="user.id"></td>
      <td><input class="mf-to" data-i="${i}" value="${esc(r[1] || "")}" placeholder="user.id"></td>
      <td><button class="copy mf-del" data-i="${i}">Remove</button></td></tr>`).join("");
  $("#map_note").textContent = mapHasRules()
    ? "Applied automatically to every conversion on this machine."
    : "No custom rules yet; the built-in defaults apply.";
}
$("#map_idx_add").addEventListener("click", () => {
  const m = mapState(); m.index_map.push({ pattern: "", data_object: "logs" }); saveMapState(m);
});
$("#map_fld_add").addEventListener("click", () => {
  const m = mapState(); m.field_map.push(["", ""]); saveMapState(m);
});
document.getElementById("mapping-card").addEventListener("input", e => {
  const i = +e.target.dataset.i; const m = mapState();
  if (e.target.classList.contains("mi-pat")) m.index_map[i].pattern = e.target.value;
  else if (e.target.classList.contains("mf-from")) m.field_map[i][0] = e.target.value;
  else if (e.target.classList.contains("mf-to")) m.field_map[i][1] = e.target.value;
  else return;
  LS.setItem(MAP_KEY, JSON.stringify(m));
  $("#map_note").textContent = "Applied automatically to every conversion on this machine.";
});
document.getElementById("mapping-card").addEventListener("change", e => {
  if (!e.target.classList.contains("mi-obj")) return;
  const m = mapState(); m.index_map[+e.target.dataset.i].data_object = e.target.value;
  LS.setItem(MAP_KEY, JSON.stringify(m));
});
document.getElementById("mapping-card").addEventListener("click", e => {
  const i = +e.target.dataset.i; const m = mapState();
  if (e.target.classList.contains("mi-del")) { m.index_map.splice(i, 1); saveMapState(m); }
  if (e.target.classList.contains("mf-del")) { m.field_map.splice(i, 1); saveMapState(m); }
});
$("#map_dl").addEventListener("click", () => {
  const url = URL.createObjectURL(new Blob([mappingJson()], { type: "application/json" }));
  const a = document.createElement("a");
  a.href = url; a.download = "mapping.config.json"; a.click();
  URL.revokeObjectURL(url);
});
$("#map_copy").addEventListener("click", e => copyText(mappingJson(), e.target));
paintMap();

// ---- tune the conversion from flagged results ----------------------------
function tuneRegex(pat) {
  const prefix = pat.split("*")[0].replace(/[.*+?^${}()|[\]\\]/g, "\\$&");
  return "^" + prefix;
}
function tuneBlock(d) {
  const un = d.unmatched || [];
  if (!un.length) return "";
  let h = `<div class="gap" id="tune"><b>Tune the conversion.</b>
    <span class="note">These index patterns had no mapping rule and fell back to
    logs. Pick the right target and re-convert; the rules are saved for future
    runs too.</span><table>`;
  h += un.map(p => `<tr><td><code>${esc(p)}</code></td>
    <td><select class="tune-obj" data-pat="${esc(p)}">${DATA_OBJECTS.map(o =>
      `<option value="${o}"${o === "logs" ? " selected" : ""}>` +
      `${o === "__metrics__" ? "metrics (timeseries)" : o}</option>`).join("")}</select></td></tr>`).join("");
  h += `</table><button id="tune-apply" style="margin-top:10px">Save rules & re-convert</button></div>`;
  return h;
}

result.addEventListener("click", e => {
  if (e.target.id !== "tune-apply") return;
  const m = mapState();
  document.querySelectorAll(".tune-obj").forEach(s =>
    m.index_map.push({ pattern: tuneRegex(s.dataset.pat), data_object: s.value }));
  saveMapState(m);
  go.click();
});
</script>
</body>
</html>
"""
