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

Deployment, final regression results and exact published inventory are recorded
below after completion. Synthetic fault tests are not live server availability.
