"""Local web GUI: the Sessions core plus a live-socket smoke test."""

import io
import json
import threading
import urllib.request
import zipfile
from http.server import ThreadingHTTPServer

import pytest

from e2d.web.server import Sessions, make_handler, _safe_name

ESQL = b'FROM logs-* | WHERE status == 500 | STATS n = COUNT(*) BY host\n'


def _zip(members: dict) -> bytes:
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w") as zf:
        for name, data in members.items():
            zf.writestr(name, data)
    return buf.getvalue()


# --------------------------------------------------------------------------- #
# Sessions core (no socket)
# --------------------------------------------------------------------------- #

def test_single_file_upload_and_migrate():
    s = Sessions()
    try:
        sid = s.new()
        assert s.add_file(sid, "q.esql", ESQL) == 1
        res = s.migrate(sid)
        assert res["total"] == 1
        assert res["counts"]["OK"] + res["counts"]["REVIEW"] >= 1
        assert res["download"] == f"/download/{sid}"
        # the download bundle is a valid zip containing the report
        with zipfile.ZipFile(io.BytesIO(s.download(sid))) as zf:
            assert "MIGRATION_REPORT.md" in zf.namelist()
    finally:
        s.close()


def test_migrate_returns_inline_artifact_content():
    s = Sessions()
    try:
        sid = s.new()
        s.add_file(sid, "q.esql", ESQL)
        res = s.migrate(sid)
        arts = res["items"][0]["artifacts"]
        # the converted DQL is inlined so the page can show & copy it
        dql = next(a for a in arts if a["path"].endswith(".dql"))
        assert dql["lang"] == "dql"
        assert "fetch logs" in dql["content"]
    finally:
        s.close()


def test_zip_upload_is_extracted():
    s = Sessions()
    try:
        sid = s.new()
        count = s.add_file(sid, "export.zip",
                           _zip({"a.esql": ESQL, "b.esql": b"FROM logs | LIMIT 5\n"}))
        assert count == 2
        res = s.migrate(sid)
        assert res["total"] == 2
    finally:
        s.close()


def test_zip_slip_is_blocked(tmp_path):
    s = Sessions()
    try:
        sid = s.new()
        s.add_file(sid, "evil.zip", _zip({"../../escape.esql": ESQL}))
        indir = s._dirs(sid)["in"]
        # nothing was written outside the session input dir
        assert not (indir.parent.parent / "escape.esql").exists()
        # the traversal member is dropped, so no input files landed
        assert list(indir.rglob("*.esql")) == []
    finally:
        s.close()


def test_bad_session_id_rejected():
    s = Sessions()
    try:
        with pytest.raises(KeyError):
            s.add_file("../etc", "x.esql", ESQL)
        with pytest.raises(KeyError):
            s.migrate("nope")
    finally:
        s.close()


def test_safe_name_strips_paths():
    assert _safe_name("../../etc/passwd") == "passwd"
    assert _safe_name("a/b/c.json") == "c.json"
    assert _safe_name("") == "upload.dat"


# --------------------------------------------------------------------------- #
# live-socket smoke test
# --------------------------------------------------------------------------- #

@pytest.fixture
def live_server():
    sessions = Sessions()
    httpd = ThreadingHTTPServer(("127.0.0.1", 0), make_handler(sessions))
    t = threading.Thread(target=httpd.serve_forever, daemon=True)
    t.start()
    host, port = httpd.server_address
    yield f"http://{host}:{port}"
    httpd.shutdown()
    httpd.server_close()
    sessions.close()


def _post(url, data=b"", headers=None):
    req = urllib.request.Request(url, data=data, method="POST", headers=headers or {})
    with urllib.request.urlopen(req) as r:
        return r.status, json.loads(r.read().decode())


def test_http_round_trip(live_server):
    # page serves
    with urllib.request.urlopen(live_server + "/") as r:
        assert r.status == 200 and b"Elastic" in r.read()

    _, sess = _post(live_server + "/session")
    sid = sess["session"]
    _post(live_server + "/upload", ESQL, {"X-Session": sid, "X-Filename": "q.esql"})
    status, res = _post(live_server + "/migrate", b"", {"X-Session": sid})
    assert status == 200 and res["total"] == 1

    with urllib.request.urlopen(live_server + res["download"]) as r:
        assert r.status == 200
        assert r.headers["Content-Type"] == "application/zip"
        with zipfile.ZipFile(io.BytesIO(r.read())) as zf:
            assert "MIGRATION_REPORT.md" in zf.namelist()
