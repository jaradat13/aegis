from __future__ import annotations

import html
from http import HTTPStatus
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from urllib.parse import parse_qs

from .actions import ResponseOrchestrator
from .audit import AuditLog
from .config import Settings
from .llm import suggest_response


def serve(settings: Settings, host: str, port: int) -> None:
    handler = _handler_for(settings)
    httpd = ThreadingHTTPServer((host, port), handler)
    print(f"Aegis IR dashboard listening on http://{host}:{port}")
    try:
        httpd.serve_forever()
    except KeyboardInterrupt:
        print("\nAegis IR dashboard stopped")
    finally:
        httpd.server_close()


def _handler_for(settings: Settings):
    class DashboardHandler(BaseHTTPRequestHandler):
        def do_GET(self) -> None:
            if self.path != "/":
                self.send_error(HTTPStatus.NOT_FOUND)
                return
            self._send_html(_render(settings))

        def do_POST(self) -> None:
            length = int(self.headers.get("Content-Length", "0"))
            form = parse_qs(self.rfile.read(length).decode("utf-8"), keep_blank_values=True)
            orch = ResponseOrchestrator(settings)
            execute = form.get("execute", [""])[0] == "true"

            if self.path == "/kill-process":
                orch.kill_process(int(_first(form, "pid")), _first(form, "reason"), dry_run=not execute)
                self._redirect()
            elif self.path == "/isolate-interface":
                orch.isolate_interface(_first(form, "interface"), _first(form, "reason"), dry_run=not execute)
                self._redirect()
            elif self.path == "/collect-triage":
                paths = [Path(line.strip()) for line in _first(form, "paths").splitlines() if line.strip()]
                orch.collect_triage(_first(form, "incident_id"), paths or None, dry_run=not execute)
                self._redirect()
            elif self.path == "/save-cron-baseline":
                source = _first(form, "source")
                orch.save_cron_baseline(_first(form, "name"), Path(source) if source else None)
                self._redirect()
            elif self.path == "/rollback-cron":
                destination = _first(form, "destination_root")
                orch.rollback_cron(_first(form, "baseline"), Path(destination) if destination else None, dry_run=not execute)
                self._redirect()
            elif self.path == "/suggest":
                suggestions = suggest_response(_first(form, "indicator"), _first(form, "context"))
                self._send_html(_render(settings, suggestions))
            else:
                self.send_error(HTTPStatus.NOT_FOUND)

        def _redirect(self) -> None:
            self.send_response(HTTPStatus.SEE_OTHER)
            self.send_header("Location", "/")
            self.end_headers()

        def _send_html(self, body: str) -> None:
            encoded = body.encode("utf-8")
            self.send_response(HTTPStatus.OK)
            self.send_header("Content-Type", "text/html; charset=utf-8")
            self.send_header("Content-Length", str(len(encoded)))
            self.end_headers()
            self.wfile.write(encoded)

        def log_message(self, format: str, *args) -> None:
            return

    return DashboardHandler


def _first(form: dict[str, list[str]], key: str) -> str:
    return form.get(key, [""])[0]


def _render(settings: Settings, suggestions=None) -> str:
    entries = AuditLog(settings).entries(limit=50)
    suggestion_html = "\n".join(
        f"""<div class="suggestion"><strong>{html.escape(item.title)}</strong>{html.escape(item.rationale)}<br><code>{html.escape(item.command)}</code></div>"""
        for item in (suggestions or [])
    )
    rows = "\n".join(
        "<tr>"
        f"<td>{html.escape(entry.get('ts', ''))}</td>"
        f"<td>{html.escape(entry.get('action', ''))}</td>"
        f"<td>{html.escape(entry.get('target', ''))}</td>"
        f"<td>{html.escape(entry.get('status', ''))}</td>"
        f"<td><code>{html.escape(entry.get('signature', '')[:18])}...</code></td>"
        "</tr>"
        for entry in entries
    )
    return f"""
<!doctype html>
<html lang="en">
<head>
  <meta charset="utf-8">
  <meta name="viewport" content="width=device-width, initial-scale=1">
  <title>Aegis IR</title>
  <style>
    :root {{ color-scheme: light; --ink:#172026; --muted:#5e6b73; --line:#ccd6dd; --bg:#f7f9fa; --panel:#ffffff; --accent:#12635f; --warn:#9b3d12; }}
    * {{ box-sizing: border-box; }}
    body {{ margin:0; font:14px/1.45 system-ui, -apple-system, BlinkMacSystemFont, "Segoe UI", sans-serif; color:var(--ink); background:var(--bg); }}
    header {{ padding:18px 24px; border-bottom:1px solid var(--line); background:var(--panel); display:flex; justify-content:space-between; gap:16px; align-items:center; }}
    h1 {{ margin:0; font-size:22px; letter-spacing:0; }}
    main {{ padding:24px; max-width:1180px; margin:0 auto; }}
    .grid {{ display:grid; grid-template-columns: repeat(auto-fit, minmax(280px, 1fr)); gap:16px; align-items:start; }}
    section, table {{ background:var(--panel); border:1px solid var(--line); border-radius:8px; }}
    section {{ padding:16px; }}
    h2 {{ margin:0 0 12px; font-size:15px; }}
    label {{ display:block; margin:10px 0 4px; color:var(--muted); font-size:12px; }}
    input, textarea {{ width:100%; padding:9px 10px; border:1px solid var(--line); border-radius:6px; font:inherit; background:#fff; }}
    button {{ margin-top:12px; border:0; border-radius:6px; background:var(--accent); color:white; padding:9px 12px; font-weight:650; cursor:pointer; }}
    .danger button {{ background:var(--warn); }}
    .check {{ display:flex; align-items:center; gap:8px; margin-top:10px; color:var(--muted); }}
    .check input {{ width:auto; }}
    table {{ width:100%; border-collapse:collapse; margin-top:18px; overflow:hidden; }}
    th, td {{ border-bottom:1px solid var(--line); padding:10px; text-align:left; vertical-align:top; overflow-wrap:anywhere; }}
    th {{ color:var(--muted); font-size:12px; background:#eef3f1; }}
    code {{ font-family: ui-monospace, SFMono-Regular, Menlo, Consolas, monospace; }}
    .suggestions {{ display:grid; gap:8px; }}
    .suggestion {{ border:1px solid var(--line); border-radius:6px; padding:10px; }}
    .suggestion strong {{ display:block; }}
  </style>
</head>
<body>
  <header>
    <h1>Aegis IR</h1>
    <span>Offline response console</span>
  </header>
  <main>
    <div class="grid">
      <section class="danger">
        <h2>Kill Process</h2>
        <form method="post" action="/kill-process">
          <label>PID</label><input name="pid" type="number" required>
          <label>Reason</label><input name="reason" required>
          <label class="check"><input name="execute" type="checkbox" value="true"> Execute</label>
          <button>Submit</button>
        </form>
      </section>
      <section class="danger">
        <h2>Isolate Interface</h2>
        <form method="post" action="/isolate-interface">
          <label>Interface</label><input name="interface" placeholder="eth0" required>
          <label>Reason</label><input name="reason" required>
          <label class="check"><input name="execute" type="checkbox" value="true"> Execute</label>
          <button>Submit</button>
        </form>
      </section>
      <section>
        <h2>Collect Triage</h2>
        <form method="post" action="/collect-triage">
          <label>Incident ID</label><input name="incident_id" required>
          <label>Extra paths, one per line</label><textarea name="paths" rows="3"></textarea>
          <label class="check"><input name="execute" type="checkbox" value="true"> Execute</label>
          <button>Submit</button>
        </form>
      </section>
      <section>
        <h2>Cron Baseline</h2>
        <form method="post" action="/save-cron-baseline">
          <label>Name</label><input name="name" value="known-good" required>
          <label>Source root</label><input name="source" placeholder="/etc">
          <button>Save</button>
        </form>
        <form method="post" action="/rollback-cron">
          <label>Baseline</label><input name="baseline" value="known-good" required>
          <label>Destination root</label><input name="destination_root" placeholder="/etc">
          <label class="check"><input name="execute" type="checkbox" value="true"> Execute</label>
          <button>Roll Back</button>
        </form>
      </section>
      <section>
        <h2>LLM-Style Suggestions</h2>
        <form method="post" action="/suggest">
          <label>Indicator</label><input name="indicator" placeholder="C2 beacon from unknown process" required>
          <label>Context</label><textarea name="context" rows="3"></textarea>
          <button>Suggest</button>
        </form>
        <div class="suggestions">{suggestion_html}</div>
      </section>
    </div>
    <table>
      <thead><tr><th>Time</th><th>Action</th><th>Target</th><th>Status</th><th>Signature</th></tr></thead>
      <tbody>{rows}</tbody>
    </table>
  </main>
</body>
</html>
"""
