# Security

Report vulnerabilities privately to the repository owner. Do not open public issues containing credentials or bypass details before a fix is available.

## Threat model

The gateway protects a loopback-only web service from unauthenticated network access through a trusted local reverse proxy. It does not defend against an attacker who already controls the host, can modify Caddy/systemd configuration, or can read process memory as root.

Never store the management key, production hash file, session data, Cloudflare token, or request Authorization/Cookie headers in this repository or CI logs.
