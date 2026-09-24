#!/usr/bin/env python3
"""Crash the production OCI image and recover on a disposable persistent volume."""

import argparse
import concurrent.futures
import datetime
import http.client
import json
import math
import subprocess
import time
import urllib.error
import urllib.request
import uuid
from pathlib import Path

ADMIN = "synthetic-container-admin"
# Ignore host proxy settings: all published endpoints bind to loopback.
HTTP = urllib.request.build_opener(urllib.request.ProxyHandler({}))


def require(condition, message):
    if not condition:
        raise RuntimeError(message)


def request(base, path, body=None, key=ADMIN):
    data = None if body is None else json.dumps(body).encode()
    req = urllib.request.Request(base + path, data=data, headers={
        "Authorization": f"Bearer {key}", "Content-Type": "application/json"})
    try:
        response = HTTP.open(req, timeout=20)
    except urllib.error.HTTPError as error:
        response = error
    with response:
        return response.status, json.loads(response.read())


def rpc(base, method, params=None):
    status, body = request(base, "/rpc", {
        "jsonrpc": "2.0", "id": 1, "method": f"grob/{method}", "params": params or {}})
    require(status == 200 and "result" in body, f"RPC {method} failed: {body}")
    return body["result"]


def chat(base, key=ADMIN, hold=False):
    status, body = request(base, "/v1/chat/completions", {
        "model": "test", "max_tokens": 16,
        "messages": [{"role": "user", "content": "hold-for-crash" if hold else "hello"}],
    }, key)
    if status == 200:
        require(body["choices"][0]["message"]["content"] == "container-ok", "bad completion")
    return status


def eventually(check, description, timeout=30):
    deadline = time.monotonic() + timeout
    while time.monotonic() < deadline:
        try:
            if check():
                return
        except (OSError, urllib.error.URLError, http.client.HTTPException):
            pass
        time.sleep(0.1)
    raise TimeoutError(description)


class Containers:
    """Owns only UUID-named resources created by this test; never prunes the engine."""

    def __init__(self, args):
        self.args = args
        self.prefix = f"grob-recovery-{uuid.uuid4().hex[:12]}"
        self.volume = self.prefix + "-data"
        self.network = self.prefix + "-net"
        self.backend = self.prefix + "-mock"
        self.names = []
        self.created_volume = False
        self.created_network = False
        self.generation = 0

    def cli(self, *args, check=True, timeout=90):
        result = subprocess.run([self.args.engine, *args], capture_output=True,
                                text=True, timeout=timeout)
        if check and result.returncode:
            raise RuntimeError(f"{self.args.engine} {args[0]} failed: {result.stderr}")
        return result

    def endpoint(self, name, port):
        mapping = self.cli("port", name, f"{port}/tcp").stdout.strip()
        require(mapping.startswith("127.0.0.1:"), f"unexpected port binding: {mapping}")
        return "http://" + mapping

    def setup(self):
        self.cli("volume", "create", self.volume)
        self.created_volume = True
        # A regular bridge also supports loopback publishing on remote Podman VMs.
        self.cli("network", "create", self.network)
        self.created_network = True
        self.names.append(self.backend)
        self.cli("create", "--name", self.backend, "--network", self.network,
                 "-p", "127.0.0.1::9000", "-p", "127.0.0.1::8080",
                 "-v", f"{self.volume}:/var/lib/grob", self.args.helper_image,
                 "python3", "/backend.py", timeout=180)
        self.cli("cp", str(Path(__file__).with_name("container-backend.py")),
                 f"{self.backend}:/backend.py")
        self.cli("start", self.backend)
        base = self.endpoint(self.backend, 9000)
        eventually(lambda: request(base, "/state")[0] == 200, "backend did not start")
        return base

    def start(self, ready=True):
        self.generation += 1
        name = f"{self.prefix}-{self.generation}"
        self.names.append(name)
        # Share only networking with the mock, as in a pod. Grob's credential
        # transport policy permits synthetic HTTP only over loopback.
        self.cli("run", "--detach", "--name", name, "--network", f"container:{self.backend}",
                 "--user", "65534:65534", "--read-only",
                 "--cap-drop=ALL", "--security-opt=no-new-privileges",
                 "--memory=512m", "--memory-swap=512m", "--pids-limit=64",
                 "--ulimit", "core=0:0", "--tmpfs", "/tmp:rw,noexec,nosuid,size=16m",
                 "-v", f"{self.volume}:/var/lib/grob", "-e", "GROB_HOME=/var/lib/grob",
                 "-e", "GROB_MEMORY_HARDENING=no-dump", "-e", "TOKIO_WORKER_THREADS=4",
                 "-e", "RUST_LOG=warn", self.args.image,
                 "--config", "/var/lib/grob/config.toml", "run")
        base = self.endpoint(self.backend, 8080)
        if ready:
            eventually(lambda: bool(rpc(base, "server/status")), "Grob did not start")
        return name, base

    def evidence(self, name):
        log = self.cli("logs", name, check=False)
        (self.args.output / f"{name}.log").write_text(log.stdout + log.stderr)
        inspect = self.cli("inspect", name)
        (self.args.output / f"{name}.json").write_text(inspect.stdout)
        return json.loads(inspect.stdout)[0]

    def stop(self, name, signal="KILL"):
        self.cli("kill", "--signal", signal, name)
        code = int(self.cli("wait", name, timeout=45).stdout.strip())
        state = self.evidence(name)["State"]
        require(not state["OOMKilled"], "unexpected OOM rather than injected crash")
        require(code == (137 if signal == "KILL" else 0), f"unexpected exit {code}")
        self.cli("rm", name)
        self.names.remove(name)
        return code

    def cleanup(self):
        errors = []
        for name in reversed(self.names):
            try:
                self.evidence(name)
            except (RuntimeError, subprocess.TimeoutExpired):
                pass
            if self.cli("rm", "--force", name, check=False).returncode:
                errors.append(name)
        if self.created_network and self.cli("network", "rm", self.network, check=False).returncode:
            errors.append(self.network)
        if self.created_volume and self.cli("volume", "rm", self.volume, check=False).returncode:
            errors.append(self.volume)
        require(not errors, f"could not clean test resources: {errors}")


def budget(base):
    total = rpc(base, "budget/current")["total_usd"]
    breakdown = rpc(base, "budget/breakdown")
    count = sum(item["request_count"] for item in breakdown)
    require(total > 0 and count > 0, "baseline accounting missing")
    return total, count


def same_budget(base, expected):
    actual = budget(base)
    require(actual[1] == expected[1] and math.isclose(actual[0], expected[0], abs_tol=1e-9),
            f"spend lost or duplicated: {expected} -> {actual}")
    return actual


def qualify(containers, report):
    backend = containers.setup()
    name, base = containers.start()
    stable = rpc(base, "keys/create", {"name": "stable-agent"})
    require(chat(base, stable["secret"]) == 200, "stable agent cannot route")
    revoked_secrets = []
    for cycle in range(1, 4):
        old = rpc(base, "keys/create", {"name": f"rotate-{cycle}"})
        rotated = rpc(base, "keys/rotate", {"key_id": old["key_id"]})
        revoked = rpc(base, "keys/create", {"name": f"revoke-{cycle}"})
        rpc(base, "keys/revoke", {"key_id": revoked["key_id"]})
        revoked_secrets.extend([old["secret"], revoked["secret"]])
        expected_keys = rpc(base, "keys/list")
        with concurrent.futures.ThreadPoolExecutor(max_workers=16) as pool:
            statuses = list(pool.map(lambda _: chat(base), range(128)))
        require(statuses == [200] * 128, "HTTP load failed before crash")
        before = budget(base)
        require(before[1] == cycle * 128, "completed requests were not all accounted for")
        require(request(backend, "/arm", {})[0] == 200, "cannot arm crash barrier")
        with concurrent.futures.ThreadPoolExecutor(max_workers=8) as pool:
            pending = [pool.submit(chat, base, ADMIN, True) for _ in range(8)]
            eventually(lambda: request(backend, "/state")[1]["held"] == 8,
                       "eight requests did not reach provider")
            require(not any(future.done() for future in pending), "request ended before crash")
            code = containers.stop(name)
            interrupted = 0
            for future in pending:
                try:
                    require(future.result(timeout=25) != 200, "held request succeeded before release")
                except (OSError, urllib.error.URLError, http.client.HTTPException):
                    pass
                interrupted += 1
        request(backend, "/release", {})
        eventually(lambda: request(backend, "/state")[1]["held"] == 0,
                   "backend did not release interrupted requests")
        # A new container has an empty writable layer, but reuses the named volume.
        name, base = containers.start()
        recovered = same_budget(base, before)
        require(sorted(rpc(base, "keys/list"), key=lambda key: key["id"]) ==
                sorted(expected_keys, key=lambda key: key["id"]), "key records changed on restart")
        for secret in revoked_secrets:
            require(chat(base, secret) in (401, 403), "revoked key became usable")
        require(chat(base, rotated["new_secret"]) == 200, "rotated key lost")
        require(chat(base, stable["secret"]) == 200, "stable agent key lost")
        report["cycles"].append({"cycle": cycle, "exit_code": code,
                                 "completed_load_requests": 128, "interrupted_requests": interrupted,
                                 "recovered_spend_usd": recovered[0], "recovered_request_count": recovered[1],
                                 "persisted_keys": len(expected_keys), "revoked_keys_rejected": len(revoked_secrets)})
        print(f"PASS container crash {cycle}: 128 completions, 8 interrupted, keys and spend recovered", flush=True)
    before = budget(base)
    containers.stop(name, "TERM")
    name, base = containers.start()
    same_budget(base, before)
    report["graceful_shutdown"] = "passed"
    containers.stop(name, "TERM")
    require(request(backend, "/corrupt", {})[0] == 200, "could not inject torn journal")
    name, _ = containers.start(ready=False)
    code = int(containers.cli("wait", name, timeout=30).stdout.strip())
    state = containers.evidence(name)["State"]
    log = (containers.args.output / f"{name}.log").read_text()
    require(code != 0 and not state["OOMKilled"] and "unreadable spend journal" in log,
            "corrupt accounting did not reject startup with the expected error")
    report["corrupt_journal"] = "startup rejected"
    print("PASS graceful restart and corrupt-journal rejection", flush=True)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--engine", choices=("docker", "podman"), default="docker")
    parser.add_argument("--image", required=True, help="production image built from the commit under test")
    parser.add_argument("--helper-image", default="docker.io/library/python:3.14-alpine")
    parser.add_argument("--output", type=Path, required=True)
    args = parser.parse_args()
    args.output = args.output.resolve()
    args.output.mkdir(parents=True, exist_ok=True)
    containers = Containers(args)
    report = {"engine": args.engine, "image": args.image, "cycles": [], "status": "failed",
              "started_at": datetime.datetime.now(datetime.timezone.utc).isoformat(),
              "scope": "container SIGKILL; host kernel and disk remain powered"}
    try:
        report["image_id"] = json.loads(containers.cli("image", "inspect", args.image).stdout)[0]["Id"]
        qualify(containers, report)
        report["status"] = "passed"
    except Exception as error:
        report["error"] = str(error)
        raise
    finally:
        try:
            containers.cleanup()
            report["cleanup"] = "passed"
        except (RuntimeError, subprocess.TimeoutExpired) as error:
            report["status"] = "failed"
            report["cleanup"] = str(error)
            raise
        finally:
            (args.output / "container-recovery.json").write_text(json.dumps(report, indent=2) + "\n")


if __name__ == "__main__":
    main()
