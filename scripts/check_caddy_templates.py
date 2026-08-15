#!/usr/bin/env python3
import pathlib


ROOT = pathlib.Path(__file__).resolve().parents[1]
public = (ROOT / "configs/Caddyfile.example").read_text()
private = (ROOT / "configs/Caddyfile.private-http.example").read_text()

for name, text in (("public", public), ("private", private)):
    for required in ("header_up -Authorization", "header_up -Cookie"):
        if required not in text:
            raise SystemExit(f"{name} template does not strip {required.removeprefix('header_up -')}")

if "bind {$DSH_PRIVATE_BIND:127.0.0.1}" not in private:
    raise SystemExit("private template does not fail closed to loopback binding")

print("Caddy template policy checks passed")