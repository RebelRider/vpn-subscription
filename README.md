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

* ChatGPT: the lightweight HTTPS providers request is a fast path, never the
  sole authority. Cloudflare, changed/empty provider JSON and unavailable auth
  routes remain inconclusive. When other services and a valid latency sample
  work, a stock headed Chromium instance uses that candidate's authenticated
  HTTP CONNECT proxy. Each of five reloads must expose a visible, editable
  ChatGPT composer and a fresh, validated application JSON response (anonymous
  model catalogue or genuine auth-provider metadata). No prompt, login, CAPTCHA
  solving, stealth or copied browser state is used. A challenge never passes.
  The composer uses semantic selectors because current ChatGPT no longer uses
  the old fixed ID. Browser API fetches bypass their own HTTP cache.
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

A separate positive control uses the unchanged active system connection and an
isolated browser profile. It calibrates the method; its result cannot qualify a
candidate. Candidate browser processes are additionally constrained by macOS
Seatbelt to their exact owned loopback proxy TCP port; other TCP and UDP are
denied. A real local isolation self-test must pass before browser checks run.
One global kernel lock serializes browsers. All profiles and processes are owned,
ephemeral and supervised; system networking and existing browser data are untouched.
The pinned browser runtime is installed/repaired only in BestLocal-owned caches.

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
obfuscation fields are preserved. Trojan publication makes `security=tls` explicit
when the source relied on the runtime default, so Happ imports the tested TLS mode. Unsupported options fail closed.

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
Exact URI duplicates do not consume the candidate limit. A seven-day retirement
cooldown prevents research or feed links from immediately reviving persistently
unproductive sources. A bounded dormant URL queue automatically retries up to two
retired feeds per collection after their seven-day cooldown, even if their original
parent disappears; this shares the existing replenishment and HTTP budgets. Resource-budget deferrals do not hurt reputation; malformed
persisted state is normalized and rebuilt automatically.
When the registry is full, up to four weak sources can be replaced per run to
keep discovering alternatives. Configured seeds, the strongest 80% of discovered
sources and trials younger than a day remain protected.

A separate local `com.rebelrider.best50-source-research` launch agent checks hourly
whether daily public-source research is due. It uses the installed Cursor agent's
strongest available Grok Extra High model, verifies the effective model, and runs
in read-only ask mode with a sandbox and disposable empty workspace. It receives
public source URLs, never candidate credentials or repository files. Only bounded
JSON proposals are accepted. Public HTTPS feeds are independently checked for
access policy, safe destinations and compatible configuration syntax, then merged
into regional `sources/primary-sources.json` with an atomic Git push. The existing
builder reads that catalog alongside automatic GitHub discovery; suggestions
never bypass either functional validation stage.

Quota, region, authentication, model or network failures retry after one, two,
four, then at most six hours. A source's longer `Retry-After` is respected up to
the bounded twenty-four-hour source policy limit. A pending successful proposal is replayed without
another model call when feed validation or GitHub publication fails. Catalog
entries expire after thirty days without independent verification. This is a
supplement to discovery, so unavailable Grok never stops the normal pipeline.

Primary validation retains the existing sing-box/SOCKS engine, repeated rounds,
GeoIP country policy, performance history and infrastructure/country diversity.
Actual HTTPS responses prove proxy functionality: empty204, Cloudflare trace
fields, and exact1MB payload. A 403 from ChatGPT is not global functional proof;
service acceptance belongs exclusively to the authoritative Mac stage.

Recent authoritative Mac results feed back into primary selection. Already
locally rejected candidates move behind untested functional alternatives for a
bounded cooldown; recent local successes receive a small reliability score bonus.
Challenges and other inconclusive application responses do not receive a twelve-hour
hard rejection. Service evidence retains HTTP status, challenge/geographic flags,
curl codes and credential-free engine error categories. At most two public endpoint
addresses are attempted after complete transport failure, never after an HTTP denial. Primary HTTPS
validation is always required. This rotates the Best50 pool instead of repeatedly
offering the same globally fast but locally inaccessible endpoints. Protocol
types do not receive artificial preference. Feedback is applied before the
finalist limit, so familiar rejects cannot exclude unseen alternatives from
final testing. Canonical IDs hash the complete protocol engine configuration,
independent of display labels.

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
qualifiers or stale input requests a new GitHub build. Empty pools may request
hourly replenishment; other supplemental requests are throttled to six hours.
The15minute poll retries failures; new input bypasses old-input retry backoff.
With at most two unique qualifiers, unchanged input is revalidated hourly and
cloud replenishment may be requested hourly; pools of three to nine revalidate
every two hours. All failure backoff and source rate limits remain in force.
Exit geography is optional metadata. BestLocal eligibility depends on the three
service proofs and latency; unknown or different exit geography cannot reject an
otherwise qualifying candidate. The existing cloud Best50 geography policy remains.

The Mac also performs independent bounded public-source discovery using the same
safe source collector. Best50 stays first, followed by up to fifty rotating regional
candidates, including up to twelve previous strict publications for rechecking.
Cloud geography, download speed and preliminary cloud failures do not gate these
regional inputs. Source/protocol/endpoint diversity and actual local source yield
guide selection; uncertain challenges never poison source reputation. Discovery
failure still permits Best50 and managed testing. Every input is unverified until
it passes the same complete local checks.

An optional `~/Library/Application Support/best50-vpn/managed-pool.json` must be
user-owned, mode0600, with schema `{"schema":1,"servers":[{"uri":"...","publish_public":false}]}`.
Up to fifty compatible managed entries can be tested independently. Private entries
never enter public status, discovery or GitHub. Public export requires explicit
`publish_public:true`, and a private designation overrides any matching public feed
entry. The exact managed policy hash is checked again at publication so revoked
permission cannot be reused. Private policy also covers equivalent TLS fingerprint
variants of the same authenticated connection. No credentials or synthetic managed servers are created.

Publication validates complete service evidence, sample medians, input membership,
freshness, rank and output consistency. A private frozen manifest pins the original
Best50 commit/content, every independently collected candidate and its export policy.
Its exact digest and current managed policy are checked before publication; the full
manifest is never published because it may contain private managed credentials. It stages subscription and status in a
separate temporary Git worktree and atomically pushes the regional branch.
Normal non-forced updates protect concurrent writers; bounded retries refetch
before trying again. Empty attempts update health and mark the retained profile
title `STALE - no verified servers`, preserving every connection URI, its order,
parameters and original generation time. The cloud workflow also applies this
marker when local evidence expires, including while the Mac cannot run. Fresh
successful publication restores the normal title. A newer successful result is
protected from an older failed attempt. Happ retains its hourly update setting.

Installation is automated by `scripts/install_local_automation.py --load` after
the clean runtime contains this version. The installer updates only this
BestLocal launch agent and launcher, preserving existing authentication variables
and refusing to interrupt an active job. No new daemon or VPN component is used.
Install the additional research job with
`scripts/install_source_research.py --repo ~/best50-vpn-regional-runtime --load --defer-hours 1`.
The initial quota wait affects only new state; subsequent installations preserve
retry and success state. Both jobs use the dedicated runtime and existing auth.

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
* `~/Library/Logs/best50-vpn/source-research.log` and `...-error.log`, plus
  `~/Library/Application Support/best50-vpn/source-research-status.json`:
  research cadence, model, quota/backoff, pending replay and catalog counts.

Run `python3 -m unittest discover -s tests -v`. Tests include unknown-source
search, disappearance/recovery/replenishment, mixed protocol normalization and
real sing-box config checks, strict service bodies and500ms boundary, isolated
outbounds, crash/timeout/overlap recovery, unchanged-input scheduling, publication
retry, stale-result rejection, and atomic/idempotent publication against a real
local bare Git repository. Corrupt state, duplicate-feed exhaustion, finalist
starvation, research quota recovery, pending replay, model verification and stale
profile annotation are covered by controlled simulations. Tests never require
changing a system VPN or spending live Grok quota.

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

## Stability and crash cleanup

Only current complete service evidence can qualify a node. Publication recomputes
the latency median from actual samples, rejects contradictory round evidence,
checks canonical IDs and forbids equivalent connections. Different TLS fingerprints
may be tested independently but consume only one publication slot if every other
connection parameter is identical.

A rolling window of up to twenty definitive local outcomes supplies reliability;
inconclusive results do not count as failures. Reliability bands take priority.
Within a band, previous published order persists until a challenger improves the
current latency by more than 25–50ms. This ordering preference never waives a
service requirement, freshness or the strict <500ms threshold.

Owned temporary files use private, marked directories with kernel leases under
`~/Library/Application Support/best50-vpn/temporary`. Scheduled jobs reclaim old
unlocked remnants after crashes, including only worktrees belonging to the exact
registered repository. Active leases, unmarked data, symlinks and unrelated Git
checkouts are protected. Regional and source-research jobs rotate their own logs;
test logs and one-off diagnostic files are not runtime dependencies.

The joined Grok autonomy simulation covers exhausted quota, restored verified
model output, actual feed parsing/robots validation, real rejected Git pushes,
pending-proposal replay without another model request, catalog publication and
SourcePool ingestion. It exercises production functions against a private local
Git remote without changing live networking or credentials.
