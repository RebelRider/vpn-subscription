# Best50 → BestLocal

Public-source discovery and primary proxy testing run in the existing GitHub
Actions workflow. The existing macOS launch agent independently tests Best50,
then publishes to the unchanged Happ subscription:

https://raw.githubusercontent.com/RebelRider/vpn-subscription/regional/output/best-local.txt

## Validation contract

Every published BestLocal entry must pass **ChatGPT AND YouTube AND Instagram**
in every one of five rounds, and its median latency must be **strictly <500 ms**.
Missing, blocked, challenged, rate-limited or malformed responses never qualify.
No padding, fallback candidates or waiver of a service is allowed. Up to twelve
entries are published, preserving the previous small-list policy.

* ChatGPT: `https://chatgpt.com/api/auth/providers`, HTTPS200 JSON containing an
  OpenAI OAuth/OIDC provider and its correct ChatGPT sign-in/callback URLs.
* YouTube: the public oEmbed response for the official iframe API example video
  `M7lc1UVf-VE`, validating provider, video type, title and matching embed URL.
* Instagram: the public login application HTML, requiring its actual login
  module, canonical Instagram metadata and Instagram asset origin. A login
  challenge, generic branded page, consent page or HTTP403/429 is inconclusive.
* Latency: five fresh HTTPS `https://www.gstatic.com/generate_204` requests,
  validating empty204 and using curl `time_total` in milliseconds. This includes
  SOCKS, candidate transport, remote DNS, TLS and request completion. The median
  of all five must be below500; exactly500 fails. Service response transfer
  times are recorded separately from this consistent lightweight measurement.

These are public unauthenticated application reachability checks. They do not
prove account login, video playback or unrestricted authenticated features.

Each candidate has its own sing-box process and authenticated ephemeral loopback
SOCKS port. Only that candidate is an outbound; there is no direct fallback.
Both outbound `bind_interface` and route `default_interface` bind to en0.
Endpoint DNS is checked for public addresses, then pinned; TLS retains original
SNI. Destination DNS is sent through SOCKS/VLESS or the other candidate protocol.
Endpoint lookup uses the existing macOS resolver without changing its settings.
GitHub fetch/push/API commands use a separate ephemeral authenticated SOCKS
proxy with a direct outbound bound to en0 and explicit HTTPS DNS. Its environment
and Git proxy override apply only to the owned command; existing GitHub/keychain
authentication is preserved. This avoids failures in the active system tunnel
without changing that tunnel or any system settings. Candidate HTTPS checks
always override this control proxy with their own candidate connection.
At most four candidates and sixteen HTTPS requests run concurrently. Kernel
locks cover direct validation and scheduled jobs. Watchdogs and cancellation
cleanup target only children/process groups created by this system.

**No TUN interface, NetworkExtension, system route, DNS or proxy configuration is
created or modified. EMB Tools and all other VPN applications are untouched.**

## Protocols and formats

The same extraction, ranking and validation pipeline supports the formats
currently documented by Happ: VLESS, VMess, Trojan, Shadowsocks, Hysteria2
(`hysteria2://` and `hy2://`) and SOCKS5 (`socks://`). Plain and base64 subscriptions
are detected automatically; share URIs embedded in source text are extracted.
VMess JSON presentation is rewritten inside its `ps` field; other URI fragments
are presentation only. Essential credentials, transport, TLS, SNI, ALPN and
obfuscation fields are preserved. Unsupported options fail closed.

The adapter allowlist follows [Happ's official import documentation](https://github.com/HappDev/happ_su/blob/main/faq/adding-configuration-subscription.md).
TUIC and WireGuard are not published because that documentation does not confirm
their import formats. Engine support alone does not establish Happ compatibility.
Unsupported ciphers/transports/plugins, insecure certificate bypasses and private
endpoints are rejected. New protocols need evidence of Happ compatibility and a
reviewed adapter; executing arbitrary externally supplied core JSON is prohibited.

## Discovery and primary testing

Existing source URLs remain seeds. Public unauthenticated GitHub repository
search rotates queries for proxy subscriptions and multiple protocols, examining
recently updated public repository trees. Newly found feeds and links in source
READMEs/subscriptions join a bounded persistent registry. Other public HTTPS
feeds are subject to robots policies. Restrictions, retries and rate-limit
headers are respected; no port scanning or private credential collection occurs.

Sources are canonicalized and track freshness, changes, failure backoff and
measured functional yield. Proven feeds have priority with reserved exploration
capacity. Dead/unproductive discovered feeds retire automatically. Candidate
sampling rotates between runs so a large failing feed cannot permanently starve
alternatives. Source bodies, DNS resolution, redirects, requests and candidate
counts are bounded; external HTTPS targets must resolve entirely to public IPs.

Primary validation retains the existing sing-box/SOCKS engine, repeated rounds,
GeoIP country policy, performance history and infrastructure/country diversity.
Actual HTTPS responses prove proxy functionality: empty204, Cloudflare trace
fields, and exact1MB payload. A 403 from ChatGPT is not global functional proof;
service acceptance belongs exclusively to the authoritative Mac stage.

Recent authoritative Mac results feed back into primary selection. Already
locally rejected candidates move behind untested functional alternatives for a
bounded cooldown; recent local successes receive a small reliability score bonus. Primary HTTPS
validation is always required. This rotates the Best50 pool instead of repeatedly
offering the same globally fast but locally inaccessible endpoints. Protocol
types do not receive artificial preference.

The workflow runs every two hours and on code/config pushes. It caches discovery
reputation even on failed builds. Any positive result may publish up to50;
zero results preserve previous output and its original timestamp. Freshness,
syntax and counts are validated before a non-forced atomic branch update. The
sing-box1.13.19 Linux asset is pinned to its verified official SHA256.

## Unattended local operation

The existing `com.rebelrider.best50-regional-refresh` launch agent polls every
15minutes and starts at login. A dedicated clean runtime at
`~/best50-vpn-regional-runtime` updates by fast-forward under a kernel lock,
without touching the development checkout. It checks input content and code
signatures every poll; changed input triggers validation at the next poll.
Unchanged input is revalidated early enough to allow a15minute poll interval
and90minute job deadline within the six-hour target. Failures use bounded
exponential backoff, automatically released crash locks and owned-child cleanup.

Best50 older than18hours or with invalid timestamps is rejected. Fewer than10
qualifiers or stale input requests a new GitHub build, throttled to six hours.
The15minute poll retries failures; new input bypasses old-input retry backoff.
Weekly exit geography caches remain optional enrichment, with the existing
actual-exit allowed-country policy preserved (GB/US/DE/NL/PL).

Publication validates complete service evidence, sample medians, input membership,
freshness, rank and output consistency. It stages subscription and status in a
separate temporary Git worktree and atomically pushes the regional branch.
Normal non-forced updates protect concurrent writers; bounded retries refetch
before trying again. Empty attempts update health diagnostics only, preserving
subscription bytes and the last successful validation timestamp. Retained output
is explicitly reported as unverified by the latest attempt, never refreshed to
look newly validated. Happ retains its normal hourly update setting.

Installation is automated by `scripts/install_local_automation.py --load` after
the clean runtime contains this version. The installer updates only this
BestLocal launch agent and launcher, preserving existing authentication variables
and refusing to interrupt an active job. No new daemon or VPN component is used.

## Diagnostics and verification

* `~/Library/Logs/best50-vpn/regional-refresh.log` and `...-error.log`: bounded
  rotated logs, candidate hash identifiers, service attempts, latency/reasons.
* `~/Library/Application Support/best50-vpn/regional-scheduler-status.json`:
  scheduler/input freshness, retries, recovery, latest counts and published age.
* `output/local-status.json`: latest local attempt; an empty attempt is not a
  successful publication. `output/best-local.txt` remains the local last good.
* Regional `output/local-status.json`: evidence for the retained published
  subscription. Regional `output/local-health.json`: latest attempted validation,
  including failure/zero results, without replacing the subscription.
* GitHub workflow summary/logs and `output/status.json`: source counts, primary
  gate results, current Best50 generation timestamp and publication status.

Run `python3 -m unittest discover -s tests -v`. Tests include unknown-source
search, disappearance/recovery/replenishment, mixed protocol normalization and
real sing-box config checks, strict service bodies and500ms boundary, isolated
outbounds, crash/timeout/overlap recovery, unchanged-input scheduling, publication
retry, stale-result rejection, and atomic/idempotent publication against a real
local bare Git repository. Tests never require changing a system VPN.

## External constraints

No public pool can guarantee that a currently qualifying server exists. Sources,
GitHub APIs, anti-bot policies and server availability can fail independently.
Failure preserves the last good artifact but explicitly marks it stale/unverified
in health. Automatic search/retries continue; success is never fabricated.

macOS validation requires this Mac awake, logged in and online, en0 available,
a functioning installed sing-box/Python, and valid existing GitHub credentials.
launchd and GitHub schedules can be delayed, especially during sleep/outage;
there is no six-hour execution guarantee while the machine cannot execute.
Credential revocation, breaking service response changes, new undocumented Happ
formats, or engine incompatibilities may require maintenance. The system fails
closed on these events instead of autonomously weakening acceptance or patching
unrelated applications/networking.
