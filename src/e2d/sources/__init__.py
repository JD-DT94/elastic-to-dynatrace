"""Source connectors — pull artifacts straight from a live Elastic/Kibana estate.

Optional and best-effort: needs `requests` and credentials, and only runs from
the local GUI/CLI (creds stay in memory, never written to outputs). The pulled
artifacts feed the same offline conversion engine as a folder of files.
"""

from e2d.sources.elastic import Connection, discover, pull

__all__ = ["Connection", "discover", "pull"]
