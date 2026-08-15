# Security

Report vulnerabilities privately to the repository owner. Do not open public issues containing credentials or bypass details before a fix is available.

## Threat model

The gateway protects a loopback-only web service from unauthenticated network access through a trusted local reverse proxy. It does not defend against an attacker who already controls the host, can modify the reverse proxy/systemd configuration, or can read process memory as root.

Accepting a dynamic request Host does not authorize network reachability. The surrounding ingress remains responsible for deciding which interfaces, networks, domains, users, or devices can reach the proxy:

- Cloudflare Tunnel and DNS control public HTTPS ingress.
- A host firewall/interface binding controls physical LAN ingress.
- Tailscale ACLs/grants control tailnet ingress.

For state-changing browser requests, the gateway requires a present Origin to use the configured public scheme and match the normalized current request Host. This preserves CSRF protection without hard-coding a domain, IP address, or external port.

## Plain HTTP mode

`PUBLIC_SCHEME=http` is intended only for a trusted private LAN or an encrypted Tailscale/WireGuard path. In this mode the gateway automatically omits the cookie `Secure` attribute. Application authentication does not provide transport encryption. Anyone capable of passively sniffing or actively modifying an ordinary HTTP network path can steal the management key or session cookie.

Never expose the private HTTP listener to the public Internet, an untrusted Wi-Fi/VLAN, or Tailscale Funnel. Prefer HTTPS if the underlying network cannot be trusted.

The private Caddy example binds to loopback unless `DSH_PRIVATE_BIND` is explicitly set. After `forward_auth` succeeds, both Caddy examples remove `Authorization` and `Cookie` before proxying to DSH so gateway credentials are not disclosed to the upstream application.

## Secrets

Never store the management key, production hash file, session data, Cloudflare token, Tailscale auth key, or request Authorization/Cookie headers in this repository or CI logs.
