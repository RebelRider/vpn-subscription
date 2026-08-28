# Best50 VPN Subscription

Automatically builds a **small, quality-focused VPN subscription** for Happ and other Xray/sing-box compatible clients.

The project is intentionally different from large public config dumps:

1. Pull a small set of already-filtered upstreams.
2. Parse and deduplicate configs.
3. Keep only supported protocols.
4. Validate configuration syntax.
5. Use `sing-box` to perform real proxy HTTP checks.
6. Score candidates by latency, success rate and stability history.
7. Publish only the best **50** configurations.
8. Refresh automatically every 15 minutes with GitHub Actions.

## Current upstreams

- 0xRadikal `top100.txt` — already verified and sorted by median delay.
- 0xRadikal `fast/configs.txt` — verified configs under the project's fast tier.

The first release deliberately uses a narrow upstream pool. More sources should only be added after they demonstrate a better signal-to-noise ratio.

## Output

The generated subscription is:

`output/best50.txt`

It contains plain `vless://`, `vmess://`, `trojan://` and `ss://` links where supported.

## Important

This repository does not guarantee anonymity, privacy or long-term availability of public VPN servers. Public nodes are untrusted infrastructure. Do not send sensitive traffic through an unknown node.

## GitHub Pages / raw URL

After pushing this repository, the intended Happ subscription URL is:

`https://raw.githubusercontent.com/<OWNER>/<REPO>/main/output/best50.txt`

GitHub Actions updates the file automatically.

## Local run

Requirements:

- Python 3.11+
- `sing-box` in PATH

```bash
python3 scripts/build.py
```

The GitHub workflow installs a pinned sing-box release automatically.


## Why v1 publishes only VLESS

Public aggregators often mix protocols and transports that require different
conversion logic. This version deliberately publishes only VLESS because it
can be converted deterministically to a sing-box outbound, including the
common Reality/TLS/WS/gRPC/HTTP forms. Unsupported transports are rejected
instead of being guessed.

The tester starts an isolated sing-box instance for each candidate, opens a
local SOCKS5 listener, and performs a real HTTPS request through that tunnel.
A TCP-open test alone is not considered success.

The design follows sing-box's native JSON outbound model and its documented
VLESS, TLS/Reality and V2Ray transport structures. The official sing-box
documentation describes `check`, JSON configuration, VLESS outbound fields,
Reality TLS fields, and V2Ray transports. See:
https://sing-box.sagernet.org/configuration/
https://sing-box.sagernet.org/configuration/outbound/vless/
https://sing-box.sagernet.org/configuration/shared/tls/
https://sing-box.sagernet.org/configuration/shared/v2ray-transport/

## Why this should be better than a TOP-100 dump

The upstream list is only a candidate pool. The published list is rebuilt
from actual HTTP success from the GitHub Actions runner. The rolling history
also gives nodes that survive repeated runs a small stability bonus.

A future v2 can add:
- Russia-based runners;
- download/upload speed tests;
- packet-loss scoring;
- independent probes in multiple countries;
- VMess/Trojan/SS/Hysteria2 conversion;
- TOP-20 / TOP-30 profiles;
- automatic quarantine of unstable nodes.
