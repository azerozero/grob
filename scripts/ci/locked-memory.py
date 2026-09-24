#!/usr/bin/env python3
"""Exercise the real Grob binary under a finite memlock limit, without root rights."""

import argparse
import concurrent.futures
import http.client
import http.server
import json
import os
from pathlib import Path
import resource
import signal
import socket
import subprocess
import tempfile
import threading
import time


class Backend(http.server.BaseHTTPRequestHandler):
    def do_POST(self):
        self.rfile.read(int(self.headers["Content-Length"]))
        body = json.dumps({"id": "synthetic", "object": "chat.completion", "model": "alpha",
                           "choices": [{"index": 0, "message": {"role": "assistant", "content": "ok"},
                                        "finish_reason": "stop"}],
                           "usage": {"prompt_tokens": 1, "completion_tokens": 1}}).encode()
        self.send_response(200)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def log_message(self, *_args):
        pass


class BackendServer(http.server.ThreadingHTTPServer):
    request_queue_size = 128


def identity_and_limit(uid, gid, limit):
    # Called only before any Python threads start; limits survive exec/setuid.
    resource.setrlimit(resource.RLIMIT_MEMLOCK, (limit, limit))
    resource.setrlimit(resource.RLIMIT_AS, (2 * 1024**3, 2 * 1024**3))
    os.setgroups([])
    os.setgid(gid)
    os.setuid(uid)


def status(pid):
    values = {}
    for line in Path(f"/proc/{pid}/status").read_text().splitlines():
        name, value = line.split(":", 1)
        if name in ("VmLck", "VmRSS", "VmSize", "VmSwap", "Threads", "Uid", "CapEff"):
            values[name] = int(value.split()[0], 16 if name == "CapEff" else 10)
    return values


def request(port):
    connection = http.client.HTTPConnection("127.0.0.1", port, timeout=15)
    try:
        body = json.dumps({"model": "alpha", "max_tokens": 8,
                           "messages": [{"role": "user", "content": "x" * 65536}]})
        connection.request("POST", "/v1/chat/completions", body,
                           {"Authorization": "Bearer synthetic-admin", "Content-Type": "application/json"})
        response = connection.getresponse()
        payload = json.loads(response.read())
        if response.status != 200 or payload["choices"][0]["message"]["content"] != "ok":
            raise RuntimeError(f"unexpected response: {response.status}")
    finally:
        connection.close()


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--binary", type=Path, required=True)
    parser.add_argument("--output", type=Path, required=True)
    parser.add_argument("--uid", type=int, required=True)
    parser.add_argument("--gid", type=int, required=True)
    parser.add_argument("--memlock-mib", type=int, default=512)
    args = parser.parse_args()
    if os.uname().sysname != "Linux" or os.geteuid() != 0 or args.uid <= 0:
        parser.error("run on an ephemeral Linux runner with sudo and a non-root target uid")
    if not 64 <= args.memlock_mib <= 1024:
        parser.error("memlock must be between 64 and 1024 MiB")
    binary = str(args.binary.resolve())
    output = args.output.resolve()
    output.mkdir(parents=True, exist_ok=True)
    env = {"PATH": os.defpath, "LANG": "C.UTF-8", "GROB_MEMORY_HARDENING": "locked",
           "TOKIO_WORKER_THREADS": "4", "RUST_LOG": "warn"}
    failed = subprocess.run([binary, "--version"], env=env, capture_output=True, text=True,
                            timeout=15, preexec_fn=lambda: identity_and_limit(args.uid, args.gid, 0))
    (output / "insufficient-limit.log").write_text(failed.stdout + failed.stderr)
    if failed.returncode == 0 or "Cannot lock process memory" not in failed.stderr:
        raise RuntimeError("zero memlock did not fail closed")
    samples = []
    completed = 0
    with tempfile.TemporaryDirectory(prefix="grob-locked-memory-") as directory:
        home = Path(directory)
        os.chown(home, args.uid, args.gid)
        backend = BackendServer(("127.0.0.1", 0), Backend)
        # Reserve an unused port, then release it immediately before startup.
        with socket.socket() as reservation:
            reservation.bind(("127.0.0.1", 0))
            port = reservation.getsockname()[1]
        config = home / "config.toml"
        config.write_text(f'''[server]
host = "127.0.0.1"
port = {port}
[auth]
mode = "api_key"
api_key = "synthetic-admin"
adopt_from_system = false
[router]
default = "alpha"
[cache]
enabled = false
[security]
enabled = false
[[providers]]
name = "mock"
provider_type = "openai"
api_key = "synthetic-provider"
base_url = "http://127.0.0.1:{backend.server_port}/v1"
[[models]]
name = "alpha"
[[models.mappings]]
provider = "mock"
actual_model = "alpha"
priority = 1
''')
        os.chown(config, args.uid, args.gid)
        env["GROB_HOME"] = str(home)
        limit = args.memlock_mib * 1024**2
        with (output / "grob.log").open("w") as log, subprocess.Popen(
            [binary, "--config", str(config), "run"], env=env, stdout=log, stderr=log,
            preexec_fn=lambda: identity_and_limit(args.uid, args.gid, limit),
        ) as daemon:
            # Start threads only after the child has exec'd and shed root rights.
            thread = threading.Thread(target=backend.serve_forever, daemon=True)
            thread.start()
            try:
                deadline = time.monotonic() + 30
                while True:
                    if daemon.poll() is not None:
                        raise RuntimeError(f"Grob exited {daemon.returncode}; see grob.log")
                    try:
                        request(port)
                        break
                    except (ConnectionError, OSError):
                        if time.monotonic() >= deadline:
                            raise TimeoutError("Grob did not start")
                        time.sleep(0.1)
                (output / "limits.txt").write_text(Path(f"/proc/{daemon.pid}/limits").read_text())
                for concurrency in (1, 16, 64):
                    with concurrent.futures.ThreadPoolExecutor(max_workers=concurrency) as pool:
                        pending = {pool.submit(request, port) for _ in range(1000)}
                        while pending:
                            sample = status(daemon.pid)
                            if sample.get("VmLck", 0) <= 0 or sample.get("VmSwap", -1) != 0:
                                raise RuntimeError(f"memory protection missing: {sample}")
                            # Small special mappings such as vDSO are not lockable.
                            if sample["VmLck"] + 64 < sample["VmRSS"]:
                                raise RuntimeError(f"resident memory exceeds locked mappings: {sample}")
                            if sample["Uid"] != args.uid or sample["CapEff"] != 0:
                                raise RuntimeError("load ran with unexpected privileges")
                            if sample["VmLck"] > limit // 1024:
                                raise RuntimeError("memlock exceeded configured limit")
                            samples.append({"concurrency": concurrency, **sample})
                            done, pending = concurrent.futures.wait(pending, timeout=0.05,
                                return_when=concurrent.futures.FIRST_COMPLETED)
                            for future in done:
                                future.result()
                                completed += 1
                daemon.send_signal(signal.SIGTERM)
                if daemon.wait(timeout=40) != 0:
                    raise RuntimeError("graceful shutdown failed")
            finally:
                if daemon.poll() is None:
                    daemon.kill()
                    daemon.wait(timeout=10)
                backend.shutdown()
                backend.server_close()
                thread.join(timeout=5)
    report = {"kernel": os.uname().release, "arch": os.uname().machine,
              "memlock_mib": args.memlock_mib, "address_space_mib": 2048,
              "uid": args.uid, "requests": completed, "errors": 0, "payload_bytes": 65536,
              "concurrency": [1, 16, 64], "low_limit": "startup rejected",
              "samples": samples}
    (output / "memory.json").write_text(json.dumps(report, indent=2) + "\n")
    print(f"PASS locked memory: {completed} requests, peak VmLck "
          f"{max(sample['VmLck'] for sample in samples)} KiB")


if __name__ == "__main__":
    main()
