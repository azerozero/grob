#!/usr/bin/env python3
"""Reference OCR sidecar for the grob media slice.

Speaks the newline-delimited JSON protocol from
`src/features/media/sidecar/proto.rs` over a unix socket. Deliberately small:
the protocol is meant to be implementable in an afternoon, in any language.

Statelessness is the contract, and this implementation honours it literally:
nothing is written to disk, nothing is kept between requests, and the request
carries no tenant or session that could be logged even by accident.

    python3 ocr_sidecar.py /tmp/grob-ocr.sock

Then in ~/.grob/config.toml:

    [media.sidecar.endpoints.ocr]
    unix = { path = "/tmp/grob-ocr.sock" }

The OCR engine below is a placeholder that reports its absence properly rather
than pretending to work. Swap `extract_text` for a real engine:

  - anywhere (default): ocrs, pure Rust, ~12 MB of models, CPU, no system
    dependency. Measured at ~320 ms on a 900x280 screenshot.
  - macOS: Vision, via pyobjc or a small Swift helper. Nothing to download,
    it is already in the OS.
  - high fidelity: deepseek-ocr.rs (Apache-2.0, pure Rust on candle). Ships an
    OpenAI-compatible server, so it plugs in behind this protocol with a thin
    HTTP adapter rather than a bespoke integration.

ocrs and Vision were measured against the same screenshot fixture and each fed
3 of 4 planted secrets to grob's DLP rules, with *different* failure modes:
Vision lost a character inside `sk_live_`, ocrs lost the underscores. The
choice is therefore a deployment preference, not a capability gap.

A note on the VLM option: a vision-language model reading attacker-supplied
screenshots is exactly the multimodal prompt-injection surface described in
OWASP LLM01. Its output must stay data fed to the DLP engine, never
instructions, which is why this protocol returns text and nothing else.
"""

import base64
import json
import os
import socket
import sys
import threading

PROTOCOL_VERSION = 1


def extract_text(image_bytes: bytes) -> str:
    """Return the text visible in an image.

    Replace this with a real engine. Raising here is deliberate: a sidecar
    that silently returned "" would look healthy while disabling the DLP
    checks that depend on it, which is worse than being unavailable.
    """
    if os.environ.get("GROB_SIDECAR_ECHO"):
        # Interop-test mode: prove the framing without an engine.
        return f"bytes:{len(image_bytes)}"
    raise NotImplementedError(
        "no OCR engine wired in; see the module docstring"
    )


def handle(request: dict) -> dict:
    """Answer one request."""
    if request.get("version") != PROTOCOL_VERSION:
        return {
            "version": PROTOCOL_VERSION,
            "error": f"unsupported protocol version {request.get('version')!r}",
        }

    capability = request.get("capability")
    if capability != "ocr":
        return {
            "version": PROTOCOL_VERSION,
            "error": f"capability {capability!r} not implemented by this sidecar",
        }

    try:
        payload = base64.b64decode(request.get("payload", ""), validate=True)
    except Exception:
        return {"version": PROTOCOL_VERSION, "error": "payload is not valid base64"}

    try:
        return {"version": PROTOCOL_VERSION, "text": extract_text(payload)}
    except Exception as exc:
        # Report the failure rather than the payload: an error string that
        # echoed image content would leak it into the caller's logs.
        return {"version": PROTOCOL_VERSION, "error": f"{type(exc).__name__}: {exc}"}


def serve_connection(conn: socket.socket) -> None:
    """Read one request line, write one response line, close."""
    with conn, conn.makefile("rwb") as stream:
        line = stream.readline()
        if not line:
            return
        try:
            request = json.loads(line)
        except json.JSONDecodeError:
            response = {"version": PROTOCOL_VERSION, "error": "malformed request"}
        else:
            response = handle(request)
        stream.write((json.dumps(response) + "\n").encode())
        stream.flush()


def main() -> int:
    if len(sys.argv) != 2:
        print(f"usage: {sys.argv[0]} <socket-path>", file=sys.stderr)
        return 2

    path = sys.argv[1]
    if os.path.exists(path):
        os.unlink(path)

    server = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
    server.bind(path)
    # Owner-only: the socket carries payloads that may contain secrets.
    os.chmod(path, 0o600)
    server.listen(16)
    print(f"listening on {path}", file=sys.stderr)

    try:
        while True:
            conn, _ = server.accept()
            threading.Thread(target=serve_connection, args=(conn,), daemon=True).start()
    except KeyboardInterrupt:
        return 0
    finally:
        server.close()
        if os.path.exists(path):
            os.unlink(path)


if __name__ == "__main__":
    raise SystemExit(main())
