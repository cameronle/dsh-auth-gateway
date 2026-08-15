#!/usr/bin/env python3
import os
import pathlib
import socket
import subprocess
import sys


ROOT = pathlib.Path(__file__).resolve().parents[1]


def unused_port():
    sock = socket.socket()
    sock.bind(("127.0.0.1", 0))
    port = sock.getsockname()[1]
    sock.close()
    return port


def expect_failure(command, env):
    result = subprocess.run(command, cwd=ROOT, env={**os.environ, **env}, capture_output=True, text=True, timeout=60)
    if result.returncode == 0:
        print(result.stdout)
        print(result.stderr, file=sys.stderr)
        raise SystemExit(f"audit unexpectedly passed: {' '.join(command)}")


port = unused_port()
expect_failure(
    [sys.executable, "scripts/unauth_http_audit.py"],
    {"DSH_AUDIT_HOST": "127.0.0.1", "DSH_AUDIT_PORT": str(port), "DSH_AUDIT_SCHEME": "http"},
)

if os.environ.get("DSH_WS_MODULE"):
    port = unused_port()
    expect_failure(
        ["node", "scripts/unauth_ws_audit.js"],
        {"DSH_AUDIT_HOST": "127.0.0.1", "DSH_AUDIT_PORT": str(port), "DSH_AUDIT_SCHEME": "http"},
    )

print("audit fail-closed tests passed")