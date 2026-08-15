#!/usr/bin/env python3
import http.client
import json
import os
import ssl

HOST = os.environ.get("DSH_AUDIT_HOST", "dsh.example.com")
PORT = int(os.environ.get("DSH_AUDIT_PORT", "443"))
SCHEME = os.environ.get("DSH_AUDIT_SCHEME", "https").lower()
PATHS = [
    "/",
    "/index.html",
    "/manifest.webmanifest",
    "/favicon.svg",
    "/assets/index-Dqw48FrP.js",
    "/plugins/@deepseek-ai/dsh-client-connection/client.js",
    "/api/settings.describe",
    "/api/credentials.describe",
    "/api/host.pickDirectory",
    "/api/llm.discoverModels",
    "/api/events.mux",
    "/api/events.host",
    "//",
    "///api/settings.describe",
    "/%2e/api/settings.describe",
    "/api%2fsettings.describe",
    "/api/settings.describe/",
    "/API/settings.describe",
    "/__dsh_auth/login",
    "/__dsh_auth/session",
    "/__dsh_auth/logout",
    "/healthz",
]
HEADERS = [
    {},
    {"Authorization": "Bearer"},
    {"Authorization": "Bearer wrong"},
    {"Cookie": "dsh_gateway_session=wrong"},
    {"X-Forwarded-For": "127.0.0.1", "CF-Connecting-IP": "127.0.0.1"},
    {"X-Forwarded-Host": "127.0.0.1:3080", "X-Forwarded-Proto": "http"},
    {"Host": "127.0.0.1:3080"},
]


def request(method, path, headers=None, body=None):
    if SCHEME == "https":
        ctx = ssl.create_default_context()
        c = http.client.HTTPSConnection(HOST, PORT, context=ctx, timeout=15)
    elif SCHEME == "http":
        c = http.client.HTTPConnection(HOST, PORT, timeout=15)
    else:
        raise ValueError("DSH_AUDIT_SCHEME must be http or https")
    h = {"User-Agent": "dsh-unauth-audit/1", **(headers or {})}
    c.request(method, path, body=body, headers=h)
    r = c.getresponse()
    data = r.read(256)
    out = (r.status, r.getheader("content-type", ""), len(data), data.decode("utf-8", "replace"))
    c.close()
    return out


failures = []
attempts = 0
responses = 0
for path in PATHS:
    for idx, headers in enumerate(HEADERS):
        method = "GET"
        body = None
        if path.startswith("/api/") and "events." not in path:
            method = "POST"
            rpc = path.rsplit("/", 1)[-1].rstrip("/")
            body = json.dumps({"type": "client-request", "rpcId": "audit", "method": rpc, "payload": {}})
            headers = {"Content-Type": "application/json", **headers}
        elif path == "/__dsh_auth/session":
            method = "POST"
            body = '{"key":"wrong"}'
            headers = {"Content-Type": "application/json", **headers}
        elif path == "/__dsh_auth/logout":
            method = "POST"
        try:
            attempts += 1
            status, ctype, size, preview = request(method, path, headers, body)
        except Exception as e:
            print("ERROR", method, path, idx, type(e).__name__, str(e))
            failures.append((method, path, idx, "ERROR", type(e).__name__, str(e)[:80]))
            continue
        responses += 1
        if path in ("/__dsh_auth/login", "/healthz"):
            allowed = status == 200 if idx not in (4, 6) else status == 403
        elif path == "/__dsh_auth/logout":
            allowed = status == 204 if idx not in (4, 6) else status == 403
        else:
            allowed = status in (400, 401, 403, 404, 405, 429)
        if not allowed:
            failures.append((method, path, idx, status, ctype, preview[:80]))
        print(f"{method:4} {status:3} h{idx} {path}")
print("SUMMARY", json.dumps({"attempts": attempts, "responses": responses}, ensure_ascii=False))
print("FAILURES", json.dumps(failures, ensure_ascii=False))
raise SystemExit(1 if failures or responses != attempts or attempts == 0 else 0)
