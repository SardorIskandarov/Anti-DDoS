#!/usr/bin/env python3
"""
main.py — Anti-DDoS per-service collector entrypoint (P12).

The legacy main.py launched the CSV collector thread, the temporal
collector thread, and a blocking Flask web server. P7 retired the
legacy per-IP engine path, and P11/P12 replaced the collector with the
binary per-service collector.

This entrypoint now simply runs the new collector (collector.main()),
which manages its own reader / writer / stats threads and blocks until
SIGTERM / SIGINT. It returns 0 on a clean shutdown so systemd sees a
successful exit.

The Flask dashboard (web.py) is intentionally NOT launched here: it
reads the legacy shared_state buffers that the new collector no longer
populates, and it is slated for a full rewrite in P14. Re-add the web
launch in P14 once the dashboard consumes the new ClickHouse tables.

Run:
    python3 ddos_monitor/main.py
    # or, from inside ddos_monitor/:
    python3 main.py
"""

import os
import sys

# Make the flat ddos_monitor modules (config, wire_parser, collector)
# importable regardless of the current working directory — consistent
# with the legacy package's `import config` convention.
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from collector import main  # noqa: E402  (import after sys.path tweak)


if __name__ == "__main__":
    sys.exit(main())
