# dsh-auth-gateway

A small authentication boundary for exposing a loopback-only DeepSeek Harness Web UI through Caddy and Cloudflare Tunnel—without modifying DeepSeek Harness source code.

## Authentication model

- CLI/automation: `Authorization: Bearer <long-management-key>` on every request.
- Browser: enter the same management key once at `/__dsh_auth/login`; the gateway issues a short-lived `HttpOnly; Secure; SameSite=Strict` cookie.
- Caddy uses `forward_auth` for every DSH page, asset, plugin bundle, API request, and WebSocket upgrade.

The gateway stores only a salted scrypt hash of the long management key. Browser sessions are opaque random tokens stored as hashes in memory and disappear when the gateway restarts.

## Deployment topology

```text
Browser / CLI
  -> Cloudflare Tunnel
  -> Caddy 127.0.0.1:18080
       -> forward_auth 127.0.0.1:18081
       -> DeepSeek Harness 127.0.0.1:3080
```

Do not expose ports 18080, 18081, or 3080 publicly.

## Build and test

```sh
go test -race ./...
go vet ./...
CGO_ENABLED=0 go build -o dsh-auth-gateway ./cmd/dsh-auth-gateway
```

Run the optional deployment audit scripts against your own hostname:

```sh
DSH_AUDIT_HOST=dsh.example.com python3 scripts/unauth_http_audit.py
DSH_AUDIT_HOST=dsh.example.com node scripts/unauth_ws_audit.js
```

The WebSocket audit uses the standard `ws` package. If it is installed at a
non-standard path, set `DSH_WS_MODULE=/absolute/path/to/ws`.

## Generate a management key

```sh
./dsh-auth-gateway -keygen
```

The command prints the plaintext key once plus `KEY_SALT` and `KEY_HASH`. Save the plaintext key in a password manager. Put only the salt and hash in the root-owned production config.

## Configuration

Copy `configs/config.example.env` to `/etc/dsh-auth-gateway/config.env`, replace the generated values, and set mode `0600`.

The packaged systemd service runs as the dedicated `dsh-auth` user. For that
deployment, a root-owned `0640 root:dsh-auth` config is also accepted; group
write/execute and all permissions for other users are rejected.

Validate the Caddy configuration before reload:

```sh
caddy validate --config configs/Caddyfile.example --adapter caddyfile
```

`configs/Caddyfile.example` is the single maintained Caddy source. Copy it to
the production host, replace `dsh.example.com` with the public hostname, and
validate the deployed file before reloading Caddy. Host-specific generated
copies are intentionally not kept in the repository.

Set the Caddy site label and `EXPECTED_HOST` to the one public hostname. The
site still uses `bind 127.0.0.1`, so the socket remains loopback-only, and
`admin off` disables Caddy's local runtime configuration API. The anonymous
allowlist contains exact auth endpoint paths rather than a broad prefix.


After `forward_auth` succeeds, the DSH upstream receives the internal
`Host: 127.0.0.1:3080` and matching Origin. DSH deliberately keeps
`settings.*`, `credentials.*`, native host actions, and model discovery behind
its loopback-authority fence even when a public hostname is trusted. The
external gateway is the authentication boundary, while DSH remains physically
bound to loopback; without this normalization, the Settings UI returns HTTP
403 after an otherwise successful gateway login.

## Security notes

- The application listener must remain loopback-only; non-loopback `LISTEN` values are rejected.
- Rate limiting uses the immediate peer address and does not trust caller-controlled forwarding headers.
- Authorization and Cookie values are never included in audit records.
- Cloudflare challenges must not be applied to `/api/*` or WebSocket paths.
- This boundary does not protect against an attacker who already controls the host.

See [SECURITY.md](SECURITY.md) for the threat model and reporting guidance.
