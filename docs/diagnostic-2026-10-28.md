# BestLocal diagnosis — 28 October 2026

## Scope and evidence limits

The fixed audit window is **25 October 17:26 UTC through 28 October 17:26 UTC**
(**20:26 Moscow time** at both ends). Times below are Moscow time unless marked UTC.
Evidence combines GitHub Actions, `origin/main` and `origin/regional`, persisted
runtime state and retained launchd logs. No live VPN, Happ, routing, DNS or system
proxy setting was modified for this audit. No visible browser was launched.

Local log rotation retained only **27 October 03:35:16 onward**, a missing interval
of approximately **31 hours 9 minutes** at the start of the requested window.
Regional Git history recovers completed, successfully uploaded validation reports
for that interval. It cannot recover every earlier poll, interrupted run or
unpublished error. Counts below are confirmed events, not proof that no unrecorded
attempt existed. Operational logs and current state remain independent evidence.

## Why STALE appeared and why two entries remain

* The last successful strict validation was **25 October 12:35:06.891919**.
  Regional commit `f8eb55a` published its two nodes at **12:35:23**.
* Commit `2703176` enforced headless-only checks at **12:44:03**, following the
  desktop-interruption complaint. This prohibition on visible windows remains.
* The first following zero-result report, `8050ea1`, changed the title to
  `Best Local VPN [STALE - no verified servers]` at **12:53:09**. The earlier result
  was still less than six hours old: the initial marker meant that the latest
  strict attempt had no qualifying nodes, not that a GitHub upload had failed.
* Later commits `37e4b4a` and `75f02d0` changed geography/IP labels and flag encoding.
  They preserved membership, functional proof and validation timestamps.
* No later nonempty strict result replaced the retained artifact. At the audit
  cutoff, its functional evidence was approximately **79 hours 51 minutes old**.
  It is now genuinely beyond the six-hour freshness limit as well.

The retained configurations are Trojan `2d58d65d4aae…` (Haarlem) and Shadowsocks
`b03ebeeb217b…` (Amsterdam). They are two distinct connections, not padding or a
duplicate fingerprint pair. Their original five-round evidence must not be
represented as a current successful revalidation. A working active Happ connection
does not authorize marking a separate challenged probe as successful.

## Recovered 72-hour local chronology

All 82 distinct validation timestamps below have successfully published regional
health reports. Every one recorded zero qualifying nodes.

| Moscow date / portion of window | Completed reports | Candidate tests | Qualifiers | Discovery admission events |
| --- | ---: | ---: | ---: | ---: |
| 25 October, from 20:26 | 4 | 400 | 0 | 16 |
| 26 October | 26 | 2,600 | 0 | 80 |
| 27 October | 28 | 2,800 | 0 | 78 |
| 28 October, through 20:26 | 24 | 2,400 | 0 | 75 |
| Total | **82** | **8,200** | **0** | **249** |

The first/last recovered result timestamps were 25 October **20:47:39.956228** and
28 October **20:20:27.737206**. Tests covered **4,546 distinct canonical candidates**;
repeated extraction across cycles totalled 651,853 entries, not that many unique
servers. Discovery admission events can likewise include recurring sources.

Candidate-test protocols were VLESS 3,606; Trojan 1,412; Shadowsocks 1,368;
VMess 1,023; Hysteria2 715; SOCKS 76. Thus local testing did not freeze on two
historical servers or a VLESS-only pool. Both retained connections were retried in
all 82 recovered cycles.

## Failure distribution and interpretation

Across 7,991 actual HTTP attempts per required service, ChatGPT passed **0**,
YouTube **1,290**, and Instagram **1,213**. Other candidates failed before HTTP.
Candidate outcomes were 6,662 definitive failures and 1,538 inconclusive results.

The principal rejection reasons were SOCKS latency-request failures (3,770),
latency-request timeouts (2,505), destination TLS failures (178), and server DNS
failures (114). Browser diagnostics recorded 620 access-denied results, 393
queue/runtime deadlines, 9 timeouts, 3 process failures and 5 navigation failures;
7,170 candidates did not reach a browser attempt. Reasons can overlap.

The 7,598 insufficient-latency-sample rejections are mainly a **consequence of
stopping after a failed service round**. They do not establish excessive latency.
No recovered report reached a complete five-round result rejected solely by the
500 ms threshold. Missing proof must not be promoted to success.

The retained Trojan had 81 inconclusive outcomes and one failure: YouTube and
Instagram each passed 81 times, while ChatGPT was challenged 81 times. Its browser
checks included 47 access-denied and 33 queue/runtime deadlines. Shadowsocks also
showed real transport/application degradation: 39 definitive failures and 43
inconclusive outcomes. This supports a systematic ChatGPT verification limitation,
alongside genuinely unsuitable public endpoints; it does not prove that every
rejected server would work in Happ.

## Cloud, discovery, scheduling and publication

The window contains **81 GitHub Actions runs**: 12 scheduled and 69 dispatched;
80 succeeded and produced **80 Best50 publication commits**. One failed run,
`40232936415`, stopped in a mocked Node VM regression fixture with a five-second
test timeout, rather than demonstrating a public-server outage.

Latest successful cloud run `40727943690` finished 28 October **19:53:29**.
Best50 was generated **19:53:09**, main commit `ca3bf9e`. Its cloud pipeline recorded
8,000 collected, 4,734 syntax-valid, 509 first-pass, 500 final-tested and 456 stable
candidates. Best50 contained VLESS 31, Trojan 10, Shadowsocks 6, Hysteria2 2, VMess 1.

The current discovery state has 160 active sources (70 GitHub search, 90 feed
links); 109 active records have `first_seen` within the window, 158 were fetched,
144 changed, and 149 have previously yielded candidates. There are 301 dormant
records, including 249 retired within the window. Core discovery remains active
independently of Grok. Latest regional input admitted two sources, collected 5,539
entries and formed 100 inputs; its bounded collection budget left deferred work.

The regional launchd job is loaded with `RunAtLoad` and a **300-second** interval;
source research uses **3,600 seconds**. The retained local logs contain 47 completed
zero-result cycles, 47 successful health uploads and 39 replenishment requests;
no other ERROR category or explicit watchdog/recovery message appears there.

The scheduler's `consecutive_failures=97` is **not evidence of 97 infrastructure
failures**. Completed empty results are currently raised as exit 2 and counted
against that counter. Since the last good result Git contains 95 empty health
reports; the difference cannot be reconstructed fully from rotated logs. Messages
such as “input current” also fail to explain the empty-result retry state clearly.

Source research made 72 observed polls: 60 cooldown skips and 12 failed calls
(7 quota, 1 network, 4 runner failures). No successful research call was observed.
Latest persisted quota failure was 28 October **18:48:20**; next eligibility is
29 October **00:48:42**, followed by the existing hourly poll. These external
failures do not explain the independent core discovery or health-publication
paths stopping: those paths demonstrably continued.

## Corrections and live verification

The facts above describe the baseline at the fixed cutoff. Corrected code now
distinguishes completed empty validation, failed/unconfirmed publication, stale
input and infrastructure failure. Confirmed empty cycles reset the misleading
failure streak and retain hourly low-pool revalidation, without advancing the
last successful subscription timestamp. Each publication stage has its own
persisted outcome; an interrupted or failed push cannot leave a success marker.

A private bounded ledger retains 30 days / 2,000 events / 2 MiB of closed,
credential-free counters. Seven log backups replace the previous single backup.
Underlying DNS/TLS/proxy/timeout causes remain distinguishable from incomplete
latency samples. A confirmed CI fixture flake has a 15-second test-only deadline;
service deadlines and the strict latency threshold are unchanged.

The browser admission bug was an unbounded in-process lock before the timed
cross-process lease. One bounded lease now handles both; queue deferral is
explicitly inconclusive and records whether a browser started. No visible browser
fallback is permitted.

Live controls through the unchanged active connection passed YouTube, Instagram
and the latency endpoint, while both HTTP and stock headless Chromium received
ChatGPT 403/challenge. Native WebKit experiments reached the genuine document and
models API with HTTP 200 through an isolated candidate. A visible optional cookie
dialog blocked the editor, so those experiments are **not qualifying results**.
Post-consent verification, production-adapter acceptance and any new nonempty
publication remain pending; this report does not manufacture them.

### Observed sleep recovery

Read-only power logs show a short sleep/wake sequence on 26 October,
06:37:14–06:37:46. The next completed validation/health publication was 07:31:26,
53.7 minutes after the final wake; the preceding result was 06:32:43. This proves
unattended continuation after that actual sleep, not the exact first-poll time.
The longest completed-report gap in the window was 73.9 minutes. The Mac booted
on 1 October; reboot and prolonged-sleep recovery remain controlled-test and
configuration evidence, not a disruptive live test.

## Safe evidence reproduction

Use existing control-plane networking for Git/gh reads. Inspect only timestamps,
counts, allowlisted diagnostic categories and canonical IDs; never print full
configuration links, proxy credentials or tokens. Relevant sources are:

* `git log origin/regional --since=2026-10-25T17:26:00Z -- output/local-health.json`
* JSON summaries of those commits' `output/local-health.json` and the retained
  `output/local-status.json`, excluding each node's configuration material.
* Actions run metadata and main `output/status.json`; discovery and source-research
  JSON state under the dedicated BestLocal Application Support directory.
* The two retained regional-refresh logs and source-research log. Avoid interpreting
  missing rotated lines as proof that scheduling did not execute.
