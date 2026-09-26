#!/usr/bin/env python3
"""Qualify credential routing against disposable OpenBao, including process crashes."""

import argparse
import concurrent.futures
import json
import os
import platform
import re
import socket
import subprocess
import tempfile
import threading
import time
import urllib.error
import urllib.request
import uuid
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path

HTTP = urllib.request.build_opener(urllib.request.ProxyHandler({}))
ROOT = "synthetic-openbao-root"
ADMIN = "synthetic-gateway-admin"


def require(condition, message):
    if not condition:
        raise RuntimeError(message)


def http(base, path, body=None, token=None, vault=False):
    headers = {"Content-Type": "application/json"}
    if token:
        headers["X-Vault-Token" if vault else "Authorization"] = token if vault else f"Bearer {token}"
    request = urllib.request.Request(base + path, headers=headers,
                                     data=None if body is None else json.dumps(body).encode())
    try:
        response = HTTP.open(request, timeout=12)
    except urllib.error.HTTPError as error:
        response = error
    with response:
        data = response.read()
        return response.status, json.loads(data) if data else {}


def eventually(check, timeout=30):
    until = time.monotonic() + timeout
    while time.monotonic() < until:
        try:
            if check():
                return
        except (OSError, urllib.error.URLError):
            pass
        time.sleep(0.1)
    raise TimeoutError("service did not reach expected state")


class Upstream(BaseHTTPRequestHandler):
    expected = {"/remote": "synthetic-remote-1", "/local": "synthetic-local-1"}
    protocol_version = "HTTP/1.1"
    calls = 0
    lock = threading.Lock()

    def log_message(self, *_args):
        pass

    def do_GET(self):
        with self.lock:
            type(self).calls += 1
            expected = self.expected.get(self.path)
        auth = self.headers.get("Authorization", "")
        ok = expected and auth == f"Bearer {expected}" and not self.headers.get("Cookie")
        body = json.dumps({"ok": bool(ok), "echo": auth}).encode()
        self.send_response(200 if ok else 401)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)


class Qualification:
    def __init__(self, args, home):
        self.args = args
        self.home = home
        self.name = f"grob-credential-test-{uuid.uuid4().hex[:12]}"
        self.created = False
        self.paused = False
        self.process = None
        self.logs = []
        self.env = dict(os.environ, GROB_HOME=str(home), RUST_LOG="warn", TOKIO_WORKER_THREADS="4")
        self.config = home / "config.toml"
        self.upstream = ThreadingHTTPServer(("127.0.0.1", 0), Upstream)
        threading.Thread(target=self.upstream.serve_forever, daemon=True).start()

    def engine(self, *args, check=True):
        return subprocess.run([self.args.engine, *args], capture_output=True, text=True,
                              timeout=120, check=check)

    def cli(self, *args, body=None):
        result = subprocess.run([str(self.args.binary), "--config", str(self.config), *args],
                                env=self.env, input=body, text=True, capture_output=True, timeout=30)
        require(result.returncode == 0, f"Grob {args[0]} failed")
        return result.stdout

    def start(self):
        log = open(self.args.output / f"grob-{len(self.logs)}.log", "wb")
        self.logs.append(log)
        self.process = subprocess.Popen([str(self.args.binary), "--config", str(self.config), "run"],
                                        env=self.env, stdout=log, stderr=subprocess.STDOUT)
        eventually(lambda: http(self.base, "/live")[0] == 200)

    def crash(self):
        self.process.kill()
        require(self.process.wait(timeout=15) == -9, "unexpected process crash status")
        self.process = None

    def gateway(self, service="remote"):
        return http(self.base, f"/v1/services/{service}/{service}", token=self.agent)

    def good(self, service="remote"):
        started = time.monotonic()
        status, body = self.gateway(service)
        require(status == 200 and body == {"ok": True, "echo": "[redacted]"}, "injection or echo protection failed")
        return (time.monotonic() - started) * 1000

    def rss_kib(self):
        result = subprocess.run(["ps", "-o", "rss=", "-p", str(self.process.pid)],
                                text=True, capture_output=True, check=True, timeout=5)
        return int(result.stdout.strip())

    def provision(self, service, token):
        self.cli("credentials", "local", service, body=json.dumps({"token": token}))

    def vault(self, path, body=None):
        status, result = http(self.vault_base, path, body, ROOT, vault=True)
        require(status in (200, 204), "OpenBao administrative fixture failed")
        return result

    def issue_reader(self):
        token = self.vault("/v1/auth/token/create", {"policies": ["grob-reader"], "ttl": "10m", "no_default_policy": True})["auth"]["client_token"]
        self.token_file.write_text(token)
        self.token_file.chmod(0o600)
        return token

    def setup(self):
        self.engine("run", "--detach", "--name", self.name, "--cap-drop=ALL",
                    "--security-opt=no-new-privileges", "--memory=256m", "--pids-limit=128",
                    "--entrypoint", "bao",
                    "-p", "127.0.0.1::8200", self.args.vault_image,
                    "server", "-dev", "-dev-no-store-token", f"-dev-root-token-id={ROOT}", "-dev-listen-address=0.0.0.0:8200")
        self.created = True
        port = self.engine("port", self.name, "8200/tcp").stdout.strip()
        require(port.startswith("127.0.0.1:"), "OpenBao must be bound to loopback")
        self.vault_base = "http://" + port
        eventually(lambda: http(self.vault_base, "/v1/sys/health")[0] == 200)
        self.vault("/v1/secret/data/service", {"data": {"token": "synthetic-remote-1"}})
        self.vault("/v1/sys/policies/acl/grob-reader", {"policy": 'path "secret/data/service" { capabilities = ["read"] }'})
        self.token_file = self.home / "vault-token"
        self.reader = self.issue_reader()
        with socket.socket() as listener:
            listener.bind(("127.0.0.1", 0))
            port = listener.getsockname()[1]
        self.base = f"http://127.0.0.1:{port}"
        text = f'''providers = []
models = []
[server]
host = "127.0.0.1"
port = {port}
[auth]
mode = "api_key"
api_key = "{ADMIN}"
adopt_from_system = false
[router]
default = "unused"
[pricing]
fetch_openrouter = false
'''
        self.config.write_text(text)
        created = self.cli("key", "create", "--name", "gateway-test", "--tenant", "gateway-test")
        self.agent = re.search(r"Key:\s+(grob_\S+)", created).group(1)
        identity = re.search(r"ID:\s+(\S+)", created).group(1)
        for service in ("local", "remote"):
            text += f'''
[[credential_services]]
id = "{service}"
tenant = "gateway-test"
agents = ["key:{identity}"]
origin = "http://127.0.0.1:{self.upstream.server_port}"
allowed_ips = ["127.0.0.1"]
paths = ["/{service}"]
methods = ["GET"]
[credential_services.injection]
type = "bearer"
'''
            if service == "remote":
                text += f'''[credential_services.vault]
endpoint = "{self.vault_base}/v1/secret/data/service"
allowed_ips = ["127.0.0.1"]
token_file = {json.dumps(str(self.token_file))}
refresh_secs = 1
max_offline_secs = 20
'''
        self.config.write_text(text)
        self.provision("local", "synthetic-local-1")
        self.start()

    def run(self, report):
        self.setup()
        self.good("local")
        self.provision("local", "synthetic-local-2")
        Upstream.expected["/local"] = "synthetic-local-2"
        self.good("local")
        self.crash()
        self.start()
        self.good("local")
        report["local_rotation_and_crash"] = "passed"
        self.cli("credentials", "vault", "remote")
        self.good()
        self.vault("/v1/secret/data/service", {"data": {"token": "synthetic-remote-2"}})
        Upstream.expected["/remote"] = "synthetic-remote-2"
        time.sleep(1.1)
        self.good()
        rss_before = self.rss_kib()
        started = time.monotonic()
        with concurrent.futures.ThreadPoolExecutor(max_workers=16) as pool:
            latencies = sorted(pool.map(lambda _: self.good(), range(128)))
        report["remote_rotation_and_load"] = {
            "requests": 128, "concurrency": 16, "failures": 0,
            "elapsed_seconds": time.monotonic() - started,
            "p50_ms": latencies[64], "p95_ms": latencies[121],
            "rss_kib_before": rss_before, "rss_kib_after": self.rss_kib(),
        }
        self.engine("pause", self.name)
        self.paused = True
        time.sleep(1.1)
        self.good()
        self.good("local")
        self.crash()
        self.start()
        self.good()
        status, summary = http(self.base, "/api/credentials/status", token=ADMIN)
        require(status == 200, "credential status unavailable")
        remote = next(s for s in summary["services"] if s["service"] == "remote")
        require(remote["state"] == "recovery", "outage not reported")
        time.sleep(max(0, remote["verified_at"] + 21 - time.time()))
        before = Upstream.calls
        require(self.gateway()[0] == 503, "expired recovery still authorized")
        require(Upstream.calls == before, "expired recovery reached upstream")
        self.good("local")
        report["outage_restart_expiry_isolation"] = "passed"
        self.engine("unpause", self.name)
        self.paused = False
        time.sleep(1.1)
        self.good()
        self.vault("/v1/auth/token/revoke", {"token": self.reader})
        time.sleep(1.1)
        require(self.gateway()[0] == 403, "revoked Vault token fell back")
        self.crash()
        self.start()
        require(self.gateway()[0] == 403, "revocation did not survive crash")
        self.issue_reader()
        require(self.gateway()[0] == 403, "token replacement silently cleared revocation")
        self.provision("remote", "synthetic-emergency")
        Upstream.expected["/remote"] = "synthetic-emergency"
        self.good()
        self.vault("/v1/secret/data/service", {"data": {"token": "synthetic-remote-3"}})
        self.good()
        self.cli("credentials", "vault", "remote")
        Upstream.expected["/remote"] = "synthetic-remote-3"
        self.good()
        self.vault("/v1/sys/seal", {})
        time.sleep(1.1)
        require(self.gateway()[0] == 403, "sealed Vault fell back")
        self.good("local")
        report["revocation_seal_and_explicit_authority_switch"] = "passed"
        for path in (self.home / "credentials").glob("*.enc"):
            require(b"synthetic-" not in path.read_bytes(), "plaintext credential persisted")
        report["encrypted_records"] = "passed"

    def cleanup(self):
        if self.process:
            self.process.terminate()
            try:
                self.process.wait(timeout=15)
            except subprocess.TimeoutExpired:
                self.process.kill()
                self.process.wait(timeout=5)
        self.upstream.shutdown()
        self.upstream.server_close()
        for log in self.logs:
            log.close()
        if self.created:
            if self.paused:
                self.engine("unpause", self.name, check=False)
            self.engine("rm", "--force", self.name)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--binary", type=Path, required=True)
    parser.add_argument("--engine", choices=("docker", "podman"), default="docker")
    parser.add_argument("--vault-image", default="ghcr.io/openbao/openbao:2.7.0")
    parser.add_argument("--output", type=Path, required=True)
    args = parser.parse_args()
    args.binary = args.binary.resolve()
    args.output.mkdir(parents=True, exist_ok=True)
    report = {"status": "failed", "vault_image": args.vault_image,
              "platform": platform.system(), "architecture": platform.machine(),
              "scope": "real KV v2, local authority, bounded outage recovery and Grob process SIGKILL"}
    with tempfile.TemporaryDirectory(prefix="grob-credential-test-") as temporary:
        qualification = Qualification(args, Path(temporary))
        try:
            qualification.run(report)
            report["status"] = "passed"
        finally:
            qualification.cleanup()
            (args.output / "credential-recovery.json").write_text(json.dumps(report, indent=2) + "\n")
    print("PASS local rotation, real OpenBao KV v2, 128 requests, outage, expiry, revocation and crash recovery")


if __name__ == "__main__":
    main()
