# dsh-auth-gateway

A small authentication boundary for exposing a loopback-only DeepSeek Harness Web UI through a trusted reverse proxy—without modifying DeepSeek Harness source code. Cloudflare Tunnel is one supported ingress, not a runtime dependency.

## Authentication model

- CLI/automation: `Authorization: Bearer <management-key>` on every request.
- Browser: enter the same management key at `/__dsh_auth/login`; the gateway issues an `HttpOnly; SameSite=Strict` session cookie.
- Content negotiation redirect: unauthenticated browser page requests (`GET`/`HEAD` with `Accept: text/html`) automatically redirect (`302 Found`) to `/__dsh_auth/login?redirect=...` with safe deep-link preservation. API, WebSocket, and non-HTML requests continue to receive standard `401 Unauthorized`.
- Sliding session expiration: active sessions extend automatically (when less than half of `SESSION_TTL` remains) so long-running coding and agent workflows are never interrupted mid-session.
- Session state awareness: authenticated users visiting `/__dsh_auth/login` see a status card with one-click actions to continue to Harness or sign out.
- The reverse proxy uses `forward_auth` for every DSH page, asset, plugin bundle, API request, SSE route, and WebSocket upgrade.
- New management keys use a versioned SHA-256 digest. Legacy scrypt material is accepted only as a bounded migration path.
- Sessions are opaque random tokens stored as hashes in memory and disappear when the gateway restarts.

## Deployment topologies

### Cloudflare Tunnel / public HTTPS

```text
Browser / CLI
  -> Cloudflare Tunnel
  -> Caddy 127.0.0.1:18080
       -> forward_auth 127.0.0.1:18081
       -> DeepSeek Harness 127.0.0.1:3080
```

Use `configs/Caddyfile.example`. The Caddy origin is loopback and does not encode the public domain. Changing DNS or the Tunnel public hostname therefore does not require a gateway or Caddy configuration change.

### Trusted LAN or Tailscale HTTP

```text
Browser / CLI
  -> trusted LAN or Tailscale-encrypted path
  -> private Caddy listener :19080
       -> forward_auth 127.0.0.1:19081
       -> DeepSeek Harness 127.0.0.1:3080
```

Use `configs/Caddyfile.private-http.example` as a starting point. It listens on the host's available interfaces so DHCP, LAN, and future Tailscale addresses do not require a Caddy environment variable. Plain HTTP is appropriate only on a trusted LAN or inside a Tailscale/WireGuard encrypted path. Restrict the listener with the host firewall and/or Tailscale ACLs. Never expose it to the public Internet or enable Tailscale Funnel for this mode.

The gateway and DSH listeners remain loopback-only in both topologies.

## Dynamic Host and Origin policy

The only transport setting is:

```env
PUBLIC_SCHEME=https
```

`PUBLIC_SCHEME` defaults to `https` when omitted. It controls three related behaviors: browser Origin validation, default-port normalization (`443` or `80`), and whether the session cookie receives the `Secure` attribute. These behaviors are deliberately derived from one setting so contradictory cookie/protocol configurations are impossible.

The gateway does not need to know the public domain, private IP, MagicDNS name, or external port. For browser state-changing requests, a present `Origin` must use `PUBLIC_SCHEME` and its normalized authority must exactly match the current request `Host`.

Examples accepted by an HTTP private instance:

```text
http://192.168.1.37:19080
http://100.64.12.8:19080
http://dsh-host:19080
```

Optional legacy/extra fixed-host restriction remains available:

```env
EXPECTED_HOST=dsh.example.com
```

When `EXPECTED_HOST` is omitted, any syntactically valid dynamic Host is accepted and browser state changes still require `Origin == Host`. When it is present, the gateway additionally requires that exact hostname. It is not required or recommended for deployments whose domain or address may change.

HTTP mode requires only:

```env
PUBLIC_SCHEME=http
```

The gateway automatically omits the cookie `Secure` attribute in HTTP mode and adds it in HTTPS mode. `SECURE_COOKIE` and `HOST_POLICY` are intentionally not configuration keys.

## Client identity and rate limiting

The gateway trusts the configured client identity header only when the TCP peer is the configured trusted loopback proxy. The proxy must overwrite caller-controlled forwarding headers.

- Cloudflare template: copies Cloudflare's `CF-Connecting-IP` into `X-DSH-Client-IP` before removing alternate identity inputs.
- Private template: copies Caddy's direct TCP peer host into `X-DSH-Client-IP`.
- IPv4 clients are tracked individually; IPv6 clients are normalized to `/64`.
- Wrong credentials consume both a per-client token bucket and a global token bucket.
- Valid cookies and correct keys are checked before wrong-credential budgets.

## Build and test

Go 1.26.6 is the supported build and CI toolchain.

```sh
go test -race ./...
go vet ./...
CGO_ENABLED=0 go build -o dsh-auth-gateway ./cmd/dsh-auth-gateway
go run golang.org/x/vuln/cmd/govulncheck@v1.1.4 ./...
go run honnef.co/go/tools/cmd/staticcheck@2026.1 ./...
go run github.com/securego/gosec/v2/cmd/gosec@v2.28.0 -quiet ./...
caddy validate --config configs/Caddyfile.example --adapter caddyfile
caddy validate --config configs/Caddyfile.private-http.example --adapter caddyfile
```

Run the optional deployment audit scripts against your own hostname:

```sh
DSH_AUDIT_HOST=dsh.example.com python3 scripts/unauth_http_audit.py
DSH_AUDIT_HOST=dsh.example.com node scripts/unauth_ws_audit.js
```

The WebSocket audit uses the standard `ws` package. If installed at a non-standard path, set `DSH_WS_MODULE=/absolute/path/to/ws`.

## Generate a management key

```sh
./dsh-auth-gateway -keygen
```

The command prints the plaintext key once plus a versioned `KEY_HASH=sha256:...`. Save the plaintext key in a password manager. Put only the digest in the root-owned service configuration.

## Configuration and deployment

Copy `configs/config.example.env` to `/etc/dsh-auth-gateway/config.env`, replace generated values, and set mode `0600`. A root-owned `0640 root:dsh-auth` file is also accepted for the packaged service; group write/execute and all permissions for other users are rejected. Unknown, duplicate, removed, and deprecated configuration keys fail startup instead of being silently ignored.

Keep separate gateway processes/configs/cookie names for simultaneous public HTTPS and private HTTP entry points. Both may share the same management-key digest and DSH upstream.

After `forward_auth` succeeds, Caddy normalizes the DSH upstream to `Host: 127.0.0.1:3080` and matching Origin. DSH keeps privileged Settings, Credentials, native actions, and model discovery behind its loopback-authority fence.

## Security notes

- The gateway listener must remain loopback-only; non-loopback `LISTEN` values are rejected.
- Authentication does not encrypt plain HTTP. An on-path LAN attacker can steal the management key or session cookie.
- Network exposure for dynamic private hosts is controlled by interface binding, firewall rules, and optional Tailscale ACLs—not by a hard-coded domain.
- Caddy strips the gateway `Authorization` and `Cookie` credentials before forwarding authenticated requests to DSH.
- Authorization and Cookie values are never included in audit records.
- Cloudflare challenges must not be applied to DSH API or WebSocket paths.
- This boundary does not protect against an attacker who already controls the host.

See [SECURITY.md](SECURITY.md) for the threat model and reporting guidance.
