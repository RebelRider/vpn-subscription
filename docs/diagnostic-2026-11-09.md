# BestLocal / Serbia audit — 9 November 2026

Times in this report are Europe/Moscow unless explicitly marked UTC. Counts of
historical tests are events, not distinct endpoints. No credentials or share URIs
are included.

## Confirmed causes of CI failures

At audit entry, of173 workflow runs since30October,166 succeeded, six failed and one was
cancelled. Four failures were the same concurrency-test fixture defect. It
advanced validation time without rerendering the subscription title; crossing a
minute caused validation to fail before the intended competing writer ran. The
generic exception assertion concealed this until a missing winner SHA raised
`KeyError`. Actual Best50 validation/publication had not started.

Examples: [5 November](https://github.com/RebelRider/vpn-subscription/actions/runs/42061684083),
[7 November](https://github.com/RebelRider/vpn-subscription/actions/runs/42398575037).
The fixture now deliberately crosses a minute boundary, updates both files,
requires the actual competing publisher and verifies non-fast-forward rejection.

Two 8 November failures were repeated HTTP504 downloading the official pinned
sing-box release, including [this run](https://github.com/RebelRider/vpn-subscription/actions/runs/42465331240).
The installer now reuses a SHA256-verified immutable archive cache, applies
bounded spaced retries and atomically extracts only the expected regular binary.
An actual official archive was downloaded and verified; a controlled outage then
installed successfully from that cache. A cold cache still requires the official
host eventually to respond. No evidence implicated real publication conflicts.

## Current validation and n/a investigation

At audit entry, the 16:17 local result was 100 candidates: one fresh PASS,
91 FAIL and eight INCONCLUSIVE. The published list also included the explicitly
protected historical Shadowsocks connection last validated on 25 October. It is
not a current PASS; its retention is an existing user-requested exception.

The previous72h history contained65 events:51 publications,13 no-qualifier
cycles and one publication failure. There were6357 candidate-test events:
5848 FAIL,372 INCONCLUSIVE,137 PASS. All six supported protocols were exercised:
849 Hysteria2,1289 Shadowsocks,43 SOCKS,1042 Trojan,2332 VLESS,802 VMess.
The shared source catalog had64 active entries; the sampled regional collection
fetched71 feeds, discovered four sources and tolerated one source failure.

Sampled historical Hysteria/IPv6 records contained genuine five-round service
and browser proof and medians below500ms. Later failure does not establish that
those records were fabricated or false at their original validation time.
Additional isolated live rechecks now rejected multiple old Hysteria/Shadowsocks
connections because actual proxied HTTPS timed out. Other rechecks remained
inconclusive due to incomplete/queued browser proof. A current VLESS control
completed all five rounds with median232.302ms, but a subsequent queued check
was inconclusive; these are time-specific observations, not availability promises.

`n/a` alone remains insufficient to reject a protocol. Displayed bracketed IPs
are observed exit IPs, not necessarily the addresses Happ dials. No protocol or
IPv6 family was excluded. Happ itself was not switched to test these entries.
The6November `ce5ab3dbaedd…` Hysteria2 record actually dialed IPv4
`84.252.100.138`, despite displaying exit
`2a0a:4cc0:c2:ac2d:64e0:3ff:fe9d:f50` (regional commit`7708f10e6c33`).
The7November `5c81df7e8934…` record dialed `steel7.hadsvpn.com` and displayed
exit`2a0d:d940:b210:1099::1` (commit`b4da7ac95a46`); its historical resolved
transport family was not recorded and cannot now be inferred. The protected
Shadowsocks entry dials`82.38.31.192`; its displayed`193.29.139.198` is historical
egress metadata.

A real architectural gap was corrected: the engine tested one pinned resolved
address while Happ previously received the original hostname. Fresh exported
URIs now pin exactly the tested public transport address and preserve original
TLS/SNI, credentials and transport semantics. Reparsed outbounds must be exactly
equivalent to the tested configuration. Source identities stay in provenance;
deduplication and rechecks understand the pinned export. This gap does not by
itself explain failures of configurations with literal entry IPs.

## Independent Serbia policy

The new URL is
`https://raw.githubusercontent.com/RebelRider/vpn-subscription/regional/output/best-local-Serbia.txt`.
The primary URL and regional policy are unchanged. Both reuse production source
discovery, adapters, strict evidence, ranking, physical-interface isolation,
owned resources, Git transport and launchd scheduling.

Serbia additionally requires five Spotify application checks and actual RS
egress. Before application checks, and again after successful checks, candidate-
proxied Cloudflare / country.is / Cloudflare HTTPS observations must all report
public RS exits. Source names, flags and entry IP locations cannot qualify a
node. The same median<500ms threshold applies. The legitimate Spotify homepage
redirect to `open.spotify.com` was exercised on the unchanged current connection
and passed content validation. This control does not qualify any candidate.

Separate manifests, histories, rotation, retries and publication paths isolate
the two profiles. A230-minute due interval reserves90min for the main job,
35min for Serbia and5min polling within six hours of awake/online operation.
The existing global validator lock prevents concurrent candidate pools.
Serbia-only source queries and RS hints supplement a reserved broad exploration
tranche. Unknown geography or infrastructure-only uncertainty preserves the
previous snapshot. Confirmed zero-qualifier results are comment-only subscriptions
with matching diagnostics, never substitute countries or dummy nodes.

Publication writes only Serbia's subscription/status in one immutable Git commit,
checks current input/export authorization again before push, retries branch races,
rejects older/conflicting writers, repairs corrupt/future metadata and verifies
remote bytes. Both profile titles age independently after strictly>72h, including
an empty Serbia result. Failed runs cannot invent a new validation timestamp.

## Verification boundaries

The full local suite passed490 tests; subsequent focused runs passed the new
country-classification regression and41 scheduler tests. Tests include real local bare-Git atomic,
idempotent and concurrent publication; network/source failures; interrupted and
corrupt state; unchanged-input revalidation; late managed-export revocation;
wrong/unknown RS geography; empty results; all supported adapters and IPv4/IPv6;
minute/72h boundaries; and malformed/challenged application responses.
These simulations do not attest live server availability.

No GUI browser was opened and no Happ/VPN, route, DNS or system-proxy setting was
changed. No reboot or network interruption was performed. Public guest access
does not prove account login, message generation, playback or full Safari UX.
GeoIP observers can be unavailable or disagree; such evidence fails closed.
Public source availability and Mac sleep/offline time remain external limits.
Grok4.7 ExtraHigh was verified but quota-exhausted; independent discovery remains
available. Actual quota restoration was not observed in this audit.

## Actual unattended cycles after deployment

The existing launchd job fetched the new code without a manual restart.
At17:05:25,100 candidates produced1 PASS,88 FAIL,11 INCONCLUSIVE. The fresh
node`256957d3e9d4…` passed all three services5/5 at323.833ms. Its exported
authority exactly matched`tested_server_ip=2.26.230.148`. The publication contains
this node plus the protected historical Shadowsocks entry: two entries, not two
fresh passes. The canonical raw subscription was byte-identical to Git and titled
`BL VPN [09Nov2026 17:05]`.

At17:17:42, the next100-candidate cycle produced0 PASS,92 FAIL,8 INCONCLUSIVE.
Three nodes passed all services5/5 but failed the median threshold at502.786,
586.853 and753.3ms. A fourth completed its browser proof but subsequently timed
out. The previously published fresh node was the502.786ms case. The zero result
published health and retained the17:05 artifact; neither a new successful date
nor unverified replacement servers were published.

Serbia ran automatically after the main job. It collected8000 configurations
from72 sources, discovered nine sources, tolerated four source failures, persisted
its discovery/provenance state and tested100 inputs. At17:20:29 its result was
zero qualified: eight confirmed wrong-country exits(NL4,PL1,GB1,DE1,EE1),
92 unconfirmed geography results. No RS exit was established. The four-service
checks therefore did not run for these candidates. This is not evidence that
all public Serbian servers are unavailable; it is evidence that this bounded
sample supplied no confirmed RS candidate. No RS+Spotify positive end-to-end
connection has been verified.

The automatic writer successfully published a comment-only Serbia subscription
and matching status. Both canonical raw URLs returned their exact Git bytes:
primary two entries, Serbia zero, with independent title
`BL VPN Serbia [09Nov2026 17:20]`. Regional commit:
`a6cc10580d9592280fc2cc3126407cc46dfdb458`.

Before/after hashes of macOS VPN configuration, DNS, proxy and default-route
snapshots all matched. The same Happ tunnel process was still present in a
read-only process listing; none of its settings or processes were changed.

## Final CI and committed implementation

All three newly triggered CI runs succeeded:

| Run | Regression tests | Functional cloud qualifiers | Publication |
| --- | ---: | ---: | --- |
| [42630194468](https://github.com/RebelRider/vpn-subscription/actions/runs/42630194468) |490|484|Safely withheld: main advanced|
| [42631423860](https://github.com/RebelRider/vpn-subscription/actions/runs/42631423860) |491|480|Safely withheld: main advanced|
| [42632772161](https://github.com/RebelRider/vpn-subscription/actions/runs/42632772161) |492|477|Actually published at17:28MSK|

The final run exercised the real engine, a checksum-verified cache hit, nonempty
Best50 validation and actual Git push. It published50 Best50 and100 Best100
entries in commit`ddefac77aa3c9c672bbc98d3fcaee45169ae05f4`. The local scheduler
continues reconciling newly generated inputs; a cloud qualifier never becomes a
BestLocal entry without a fresh Mac-side pass.

Implementation commits: `724cf06` (shared Serbia policy, pinning and CI fixes),
`d283afe` (definite country rejection versus uncertainty), `efae0c7` (reserve the
secondary35-minute budget inside the primary six-hour freshness deadline).
The last change prevents a worst-case secondary run from delaying a primary
check beyond six hours; the healthy primary due time is now225minutes. Low-pool
one/two-hour revalidation and bounded retries remain intact.

Controlled bare-Git tests verified both profiles' independent integrity and
recovery. Live tests verified primary publication, retained-output protection,
Serbia empty-result publication, dynamic source collection and canonical raw
bytes. A functional RS+four-service connection and actual Happ import of an empty
profile remain unverified. No such positive result is claimed. Operational
history is retained; audit scratch files/test logs are removed.
