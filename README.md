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

## Generate a management key

```sh
./dsh-auth-gateway -keygen
```

The command prints the plaintext key once plus `KEY_SALT` and `KEY_HASH`. Save the plaintext key in a password manager. Put only the salt and hash in the root-owned production config.

## Configuration

Copy `configs/config.example.env` to `/etc/dsh-auth-gateway/config.env`, replace the generated values, and set mode `0600`.

## Security notes

- The application listener must remain loopback-only; non-loopback `LISTEN` values are rejected.
- The gateway trusts `CF-Connecting-IP` only when the immediate peer matches `TRUSTED_PROXY_IP`.
- Authorization and Cookie values are never included in audit records.
- Cloudflare challenges must not be applied to `/api/*` or WebSocket paths.
- This boundary does not protect against an attacker who already controls the host.

See [SECURITY.md](SECURITY.md) for the threat model and reporting guidance.
