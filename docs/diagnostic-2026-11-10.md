# BestLocal verification, 10 November 2026

All times below are UTC unless explicitly marked MSK (UTC+3). These are
time-specific observations, not guarantees of continued public-server availability.
No active VPN, system routes, DNS or proxy settings were modified. Candidate
children use authenticated loopback SOCKS, pinned public transport addresses,
en0 binding and windowless native WebKit under the existing global probe lock.

## Reported n/a entries

The screenshot's exact publication is regional commit
`e9848f0df2692128464669eaa46085b18063e166`, generated at 04:27:27
(07:27:27 MSK), with four fresh entries and one protected historical entry.
The client download time is not its validation time. Displayed IPs are egress
addresses, which need not be the transport addresses dialed by Happ.

The user's clarification that both n/a entries actually fail was independently
reproduced without switching Happ. All five exact source configurations were
tested again through their own candidate connections, with five-round strict
qualification:

| Displayed exit | Actual tested entry | Current result |
|---|---|---|
| US 201.58.139.66 | 201.58.139.66 | All three services passed; median 530.842 ms, rejected |
| ES 66.163.118.251 | 66.163.118.203 | SOCKS connection failure, rejected |
| DE 93.123.85.230 | 195.206.235.45 | Proxied HTTPS timeout, rejected |
| NL 177.202.64.67 | 177.202.64.67 | All three services passed; median 507.846 ms, rejected |
| NL 193.29.139.198 | 82.38.31.192 | SOCKS failure / engine timeouts, rejected |

Thus zero of this frozen five-entry snapshot qualified in the repeat check.
This does not assert that every entry failed at its original validation time.
The DE record originally had complete current service evidence, median149.176ms
at04:22:09. Current failure alone cannot reconstruct when it stopped working.

The final NL Shadowsocks record is different: its last successful proof is
25October09:30:55, median230.402ms. Explicit protection was appending it indefinitely
to later successful lists, despite failed rechecks. Retention now expires after
72h from the entry's own proof; current definitive FAIL also revokes protection.
Unknown/infrastructure errors remain inconclusive. The immutable last-good archive
and the primary subscription's nonempty failure fallback are preserved.

## Serbia: actual RS exits exist, but did not qualify

The completed scheduled07:31MSK batch tested100 candidates. Two VLESS candidates
(`50f10c893087…`, `80d55e83efe9…`) exited through38.180.101.79, confirmed as RS by
candidate-proxied Cloudflare / country.is / Cloudflare consensus. The first failed
Instagram content validation; the other had Instagram/Spotify transport errors.
Thirteen candidates were observed outside RS; most others had unconfirmed geography.
This is not evidence that discovery found no Serbian exits.

A repeat production four-service check at07:24UTC again confirmed both RS exits.
Both passed YouTube and Instagram in their attempted round but failed Spotify with
SOCKS connection errors. ChatGPT UI proof was not attempted after the independent
Spotify failure. First latency samples were502.267/484.063ms respectively;
neither has five complete passing rounds or a qualifying median. Zero RS entries
were certified or added. A previous three-service diagnostic temporarily observed
Instagram and browser ChatGPT success, but later transport failure prevented full
qualification; it is not a Serbia PASS.

Required geography had reused the optional metadata's4s deadline and discarded
all failure details. It now has a separate bounded8s deadline and records safe
endpoint/status/curl-code/elapsed/reason information plus partial consensus.
All three observers must still pass; disagreement, challenge, timeout and missing
data never count as RS. Optional main-list metadata retains its4s limit.

## Other confirmed corrections

Two REALITY candidates failed before connecting because omitted URI `fp` produced
no uTLS configuration: the real engine reported that uTLS is required by REALITY.
An omitted/empty optional fingerprint now consistently defaults to explicit
`chrome` in parsing, the test outbound and Happ export. Explicit fingerprints stay
unchanged. Actual sing-box configuration checks accept both TCP and gRPC; this
proves configuration compatibility, not those servers' application availability.
The installed Happ Xray core also accepted reconstructed TCP and gRPC REALITY
configurations in offline configuration-test mode. No connection or active Happ
state was changed; this is not a successful end-to-end Happ import/network test.

The scheduler wrote its Serbia child status but rejected that same field on its
next load, emitting an inaccurate state-recovery warning every poll. The bounded
child status schema now survives valid round trips and rejects malformed data.

## Autonomous source research

The independent daily source research last promoted16 feeds on9November; the
shared persisted registry contains64 entries and is consumed by both regional
collection and cloud discovery. Main collection subsequently fetched72 feeds,
collected8000 raw candidates and maintained a2000-entry bounded candidate cache.
No recurring manual source edit is required.

Grok's9November22:30MSK scheduled attempt verified4.7 Extra High standard/non-fast
and hit quota. The10November04:30MSK attempt instead failed at CLI model inventory
before generating a model request. The52-byte stderr was hashed, not persisted;
its exact underlying cause cannot be reconstructed. A fresh read-only worker
attempt at09:48MSK again reached the selected model but hit quota. No successful
Grok search/catalog addition is claimed.

Unknown inventory failure is now distinct from a generic runner failure. Retry
backoff is tracked per error/stage, so a new inventory outage no longer inherits
weeks of quota failures. Persistent failures back off1/2/4/6h, preserve pending
proposals, source Retry-After and daily successful-use limits, and clear on success.
The independent research path runs before Grok eligibility checks. Actual future
quota restoration remains externally unverified.

## Verification and deployment

Implementation commit: `e40da95c0f4e134a8643b791d454507b54e1d0b7`.
The existing production runtime automatically fast-forwarded to it and launchd
started local validation at07:32:23 (10:32:23MSK), without a manual job kick.
At07:35:30 the hourly source researcher independently requested and verified
Grok4.7 ExtraHigh non-fast, then received quota failure at07:35:52; the new
per-stage retry state schedules08:35:52. This proves scheduled retry/model
selection after the inventory outage, not successful quota restoration.

The full macOS suite passed **533 tests in424.144s**. Focused checks passed:
REALITY4, service checks61, source research33, scheduler43 and retention16.
Controlled coverage includes source disappearance/replenishment, previously
unknown source admission to a real local Git registry, unchanged-input
revalidation, interrupted jobs, bounded retries, both atomic/idempotent
publishers, concurrency, RS disagreement/empty results, HTTPS challenges,
strict latency boundaries, IPv4/IPv6 and secret-safe diagnostics.
Synthetic fault tests are not live server availability.

The last complete automatic batch preceding this repair tested100 candidates,
with3PASS/91FAIL/6INCONCLUSIVE, published at06:55:01 (09:55:01MSK).
Its fresh proof generated_at is06:53:50; three fresh nodes had medians
276.325/433.830/382.922ms, plus the now-expiring historical Shadowsocks.
Those counts differ from the deliberately frozen screenshot's repeat test.

[CI42775872716](https://github.com/RebelRider/vpn-subscription/actions/runs/42775872716)
also passed533 tests (90.165s), collected8000 candidates, parsed4390, found620
first-pass working and472 final-stable, and published50Best50 entries in
main commit`8c620fb1386027b412cb0ad7ffdd90288c77736e`. The live local input mix
was38VLESS/20Shadowsocks/13VMess/13Trojan/14Hysteria2/2SOCKS.

The automatic local run completed at07:41:36:100 tested,4PASS/66FAIL/
30INCONCLUSIVE. Four nodes had all five service rounds and medians
276.999/197.258/326.334/394.040ms. Best50 had changed concurrently, so the
07:42:29 publication guard correctly withheld this result and preserved the
existing published subscription. A51s bounded retry was recorded; the existing
serialized Serbia stage completed independently at07:46:33 with100tested,
zeroqualified and a verified empty-result publication. No stale result was
published merely to increase list size.

The next scheduled primary run at07:51 completed at07:59:11 with four strict
qualifiers. Its publication exposed a regression in the new explicit-fingerprint
export: it also moved an existing fp parameter to the end of the query, changing
immutable URI bytes without changing semantics. The historical-evidence guard
correctly blocked publication at08:00:15. Export now preserves every existing
nonempty fingerprint's query position, while still making missing defaults
explicit. The exact live immutable artifact was checked against the corrected
renderer. Regression coverage includes real historical REALITY Git publications.

The first repaired batch also exposed browser admission starvation:18 candidates
never obtained the serialized WebKit slot within45s. They were correctly marked
INCONCLUSIVE, but lacked an actual ChatGPT application test. After the parallel
tranche drains, up to four such nonstarted checks now receive a complete fresh
sequential attempt. Hourly selection rotation avoids permanently favoring the
same subset. The same five service rounds, strict latency threshold, isolation
and (for Serbia) four-service/RS policy still apply; old partial results are
discarded. Additional worst-case work is bounded to4×180s, with one browser.
Executed browser failures, HTTP restrictions and challenges are not blindly
retried. Recovery/cancellation/rotation have controlled regression coverage.

## Evening follow-up and local Qwen research

At19:03:21UTC (22:03:21MSK), an unattended main batch completed100 tests:
0PASS/96FAIL/4INCONCLUSIVE. It contained85 configurations absent from the previous
published batch, so collection/rotation was not stuck on the same small list.
Collection obtained70 of72 feeds and8000 raw candidates; the persistent source
registry contained64 URLs. The three most recent completed BuildBest50 runs
before the new Qwen change were successful, including
[42879047366](https://github.com/RebelRider/vpn-subscription/actions/runs/42879047366).

The retained sole ES entry68.221.177.135 had passed its original five-round check
at17:59:34UTC with median432.111ms and was published at18:01:57UTC. Its latest
rank1 recheck failed YouTube withcurl28, Instagram withcurl97 and the latency
request withcurl28. ChatGPT supplied only provisional HTTP evidence; no full
application PASS was recorded. The nonempty failure fallback preserved the
18:01 artifact and date instead of claiming a fresh successful list.

Of100 current candidates,73 had SOCKS errors and21 had latency-request timeouts.
Only one had any YouTubePASS and two anyInstagramPASS. The sole attempted
browser check was inconclusive and its first latency sample exceeded2000ms;
this batch did not exhibit browser-slot starvation. Physical en0 remained up;
lightweight HTTPS204 controls succeeded through both the unchanged active route
and explicitly bound en0. This is evidence of poor candidate-path availability,
not proof of a globally disconnected physical interface.

The feedback classifier nevertheless hid two independent mandatory-service
transport failures behind provisional ChatGPT evidence. It now classifies this
same frozen evidence as98FAIL/2INCONCLUSIVE, without turning an uncertain service
intoPASS. Explicit shared control/isolation failures remain inconclusive. A
cached top-level outcome no longer overrides underlying current evidence.

Serbia's19:06:32UTC completed batch had0 qualifiers/100:95 unconfirmed exit
countries,2 nonRS exits and3 DNS failures. Two previously observed RS configurations were
separately retested at12:45UTC; all three egress observers and all four required
services failed withcurl35. Earlier RS geography cannot certify a current exit
or service PASS. Fresh public cached inputs with an observed RS history now get
another strict test even when a healthy feed harvest omits them;24h input TTL
and all current functional/geography checks remain mandatory.

Read-only Happ subscription logs confirmed the exact uppercaseSerbia URL is
configured. The zero-URI artifact is fetched but rejected by Happ3.3.6; diagnostic
metadata now explicitly records this confirmed empty-import limitation. No dummy
server or guessed Serbian egress is published.

The new local researcher uses the existing MLX artifact
`mlx-community/Qwen3.8-27B-4bit`, dynamically resolving LMStudio's actual load
handle`qwen3.8-27b`. Loading the artifact path itself failed with model-not-found;
inventory-based resolution fixes that mismatch. Broad natural-language GitHub
AND queries also returned no repositories; bounded successful-empty query
expansion now finds actual repository/feed links without evading rate limits.

A controlled live model/tool run at19:13:28–19:21:48UTC completed in500.13s:
two new public source URLs and two novel candidate fingerprints, after
deterministic deduplication. Model-provided text did not create configurations.
Production subscriptions, source admission and GitHub publication were withheld
for that run. The owned model was unloaded and REST server stopped; live
inventory then showed zero loaded models. Route, VPN-service, DNS and proxy
snapshots exactly matched the pretest hashes. No visible browser was opened.

The full macOS suite passed634 tests in157.732s; after subsequent narrow recovery
and model-input fixes all88 Qwen tests passed separately. Fault coverage includes
timezone/DST changes, missed-slot recovery, duplicate jobs, foreign model/server
ownership, API/authentication failures, malformed model actions, corrupt private
ownership journals, interrupted work, Git retries, data-only branch guards,
durable source-admission budget deferrals and preserved production artifacts.
These simulations do not certify live public VPN functionality or future model
availability. Grok's latest real read-only review attempt still hit quota;
future quota restoration is not claimed as verified.

At19:22:28UTC the same durable, genuinely observed proposal completed the live
data-only integration without reloading the model: two sources were independently
refetched and added to the shared64-entry registry withQwen provenance. The
verified discovery branch contains only`discovery/qwen/candidates.json` in
[PR1](https://github.com/RebelRider/vpn-subscription/pull/1), commit
`6cc7228078d37e90b9b5999914eda6a43442e684`. No subscription URI was published by
the researcher. Successful private discovery/dedup history was adopted as the
operationalQwen state so the next daily run does not repeat this controlled work.

The existing regional bootstrap automatically fast-forwarded the clean runtime
to implementation`2232c89103e5965f461a7b45920cd4756da34013`. The installer then
enabled`com.rebelrider.best50-qwen-discovery`; its real launchdRunAtLoad poll was
recorded at19:27:21UTC and correctly kept today's completed work idle. Its next
daily slot is11November03:01Europe/Moscow (00:01UTC), with explicit timezone
gating and wake/login catch-up. The future daily model invocation itself cannot
be claimed as observed before that time.
