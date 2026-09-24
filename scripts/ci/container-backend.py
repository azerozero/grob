#!/usr/bin/env python3
"""Synthetic provider and volume fixture for container-recovery.py, never deployed."""

import datetime
import json
import os
import threading
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path

HOME = Path("/var/lib/grob")
CONFIG = '''[server]
host = "0.0.0.0"
port = 8080
[auth]
mode = "api_key"
api_key = "synthetic-container-admin"
adopt_from_system = false
[router]
default = "test"
[cache]
enabled = false
[security]
enabled = false
[pricing]
fetch_openrouter = false
[[providers]]
name = "mock"
provider_type = "openai"
models = ["gpt-4o"]
api_key = "synthetic-container-provider"
base_url = "http://127.0.0.1:9000/v1"
[[models]]
name = "test"
[[models.mappings]]
provider = "mock"
actual_model = "gpt-4o"
priority = 1
'''


class Backend(BaseHTTPRequestHandler):
    """Holds selected requests before reporting any usage to Grob."""

    lock = threading.Lock()
    release = threading.Event()
    held = 0

    def log_message(self, *_args):
        pass

    def reply(self, body, status=200):
        data = json.dumps(body).encode()
        self.send_response(status)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(data)))
        self.end_headers()
        try:
            self.wfile.write(data)
        except (BrokenPipeError, ConnectionResetError):
            pass  # The caller deliberately kills Grob while requests are held.

    def do_GET(self):
        if self.path != "/state":
            return self.reply({}, 404)
        with self.lock:
            self.reply({"held": type(self).held})

    def do_POST(self):
        body = json.loads(self.rfile.read(int(self.headers["Content-Length"])))
        if self.path == "/release":
            self.release.set()
            return self.reply({"released": True})
        if self.path == "/arm":
            with self.lock:
                if type(self).held:
                    return self.reply({"error": "requests still held"}, 409)
                self.release.clear()
            return self.reply({"armed": True})
        if self.path == "/corrupt":
            month = datetime.datetime.now(datetime.timezone.utc).strftime("%Y-%m")
            path = HOME / "spend" / f"{month}.jsonl"
            if not path.is_file() or not path.stat().st_size:
                return self.reply({"error": "no populated current journal"}, 409)
            with path.open("ab") as journal:
                journal.write(b'{"incomplete":')
                journal.flush()
                os.fsync(journal.fileno())
            return self.reply({"corrupted": True})
        if self.path != "/v1/chat/completions":
            return self.reply({}, 404)
        if self.headers.get("Authorization") != "Bearer synthetic-container-provider":
            return self.reply({"error": "unexpected provider credential"}, 401)
        if "hold-for-crash" in json.dumps(body.get("messages")):
            with self.lock:
                type(self).held += 1
            try:
                if not self.release.wait(timeout=60):
                    return self.reply({"error": "crash barrier timed out"}, 504)
            finally:
                with self.lock:
                    type(self).held -= 1
        self.reply({
            "id": "synthetic-completion", "object": "chat.completion",
            "created": 1, "model": "gpt-4o",
            "choices": [{"index": 0, "message": {"role": "assistant", "content": "container-ok"},
                         "finish_reason": "stop"}],
            "usage": {"prompt_tokens": 1000, "completion_tokens": 100, "total_tokens": 1100},
        })


if __name__ == "__main__":
    # Only the disposable volume needs ownership setup; the HTTP server drops root.
    HOME.mkdir(parents=True, exist_ok=True)
    os.chown(HOME, 65534, 65534)
    os.setgroups([])
    os.setgid(65534)
    os.setuid(65534)
    (HOME / "config.toml").write_text(CONFIG)
    ThreadingHTTPServer(("0.0.0.0", 9000), Backend).serve_forever()
