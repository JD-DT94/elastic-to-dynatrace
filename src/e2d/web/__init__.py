"""Local web GUI for e2d — a friendly, fully-offline front door for `migrate`.

Runs on localhost only (binds 127.0.0.1 by default). Nothing leaves the machine:
the conversion engine is stdlib-only and makes no network calls, and uploaded
files are processed in a per-session temp directory that is cleaned up on exit.
"""

from e2d.web.server import Sessions, serve

__all__ = ["Sessions", "serve"]
