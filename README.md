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

The packaged systemd service runs as the dedicated `dsh-auth` user. For that
deployment, a root-owned `0640 root:dsh-auth` config is also accepted; group
write/execute and all permissions for other users are rejected.

Validate the Caddy configuration before reload:

```sh
caddy validate --config configs/Caddyfile.example --adapter caddyfile
```

Set the Caddy site label and `EXPECTED_HOST` to the one public hostname. The
site still uses `bind 127.0.0.1`, so the socket remains loopback-only, and
`admin off` disables Caddy's local runtime configuration API. The anonymous
allowlist contains exact auth endpoint paths rather than a broad prefix.

For host deployments, place Caddy, the auth gateway, and DSH in the shared
private network namespace defined by `deploy/dsh-control-plane-netns.service`.
Cloudflared stays in the host namespace and connects only through
`unix:/run/dsh-control-plane/caddy.sock`. This removes ports 80/18081/3080 from
the host network namespace, so an unrelated local process cannot bypass Caddy
by dialing the DSH loopback port directly.

After `forward_auth` succeeds, the DSH upstream receives the internal
`Host: 127.0.0.1:3080` and matching Origin. DSH deliberately keeps
`settings.*`, `credentials.*`, native host actions, and model discovery behind
its loopback-authority fence even when a public hostname is trusted. The
external gateway is the authentication boundary, while DSH remains physically
bound to loopback; without this normalization, the Settings UI returns HTTP
403 after an otherwise successful gateway login.

## Security notes

- The application listener must remain loopback-only; non-loopback `LISTEN` values are rejected.
- The gateway trusts `CF-Connecting-IP` only when the immediate peer matches `TRUSTED_PROXY_IP`.
- Authorization and Cookie values are never included in audit records.
- Cloudflare challenges must not be applied to `/api/*` or WebSocket paths.
- This boundary does not protect against an attacker who already controls the host.

See [SECURITY.md](SECURITY.md) for the threat model and reporting guidance.
