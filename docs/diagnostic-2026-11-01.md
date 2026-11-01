# BestLocal audit — 1 November 2026

Operational times below use Moscow time (UTC+3). Subscription title dates use
UTC, consistently with the immutable validation timestamps. No VPN application
or system routing, DNS or proxy configuration was modified.

## Live evidence before deploying this audit's corrections

The existing scheduler completed a new automatic cycle during this audit:

| Event | Moscow time | Evidence |
| --- | --- | --- |
| Last earlier complete validation | 31 Oct 22:13:00 | 100 candidates: 3 pass, 87 fail, 10 inconclusive |
| Its confirmed publication | 31 Oct 22:13:41 | 3 fresh plus 1 protected historical connection |
| Independent source admission | 1 Nov 00:13:12 | 16 new feeds; permanent catalog now 18 unique enabled sources |
| Next automatic validation | 1 Nov 00:19:22 | 100 candidates: 7 pass, 82 fail, 11 inconclusive under the previous service policy |
| Next confirmed publication | 1 Nov 00:20:25 | 7 fresh under that policy plus 1 protected historical connection |

The source admission is real, independently verified at regional commit
`5ad9bf30d36165b2c17963ee3df5a96c22ab0c32`, catalog blob
`35780fd405c29e9bd072e10cafc8fe26d497005e`. It does not qualify any servers.

The initial 72-hour history contained 65 events: 38 publications, 24 complete
zero-result validations, and three infrastructure failures followed by recovery.
Its 6200 candidate-test events comprised 5129 FAIL, 919 INCONCLUSIVE, and 152 PASS;
these are repeated events, not unique servers. Overlapping rejection categories
included proxy/transport 2898, timeout 1903, TLS 145 and DNS 95. The large latency
category also includes missing samples, not just measured medians above 500 ms.
There were 349 browser queue deferrals, 125 visible application errors and 94
access denials. Inconclusive outcomes do not lower source reliability as failures.

The latest completed pool included Hysteria2, VMess, Shadowsocks, VLESS, Trojan,
and SOCKS. The screenshot's six entries and Happ's n/a/2831 ms cannot be mapped
to the initial four-entry or subsequent eight-entry artifacts without their
matching snapshot. Happ timing differs from five fresh HTTPS completion samples;
n/a alone is not a rejection reason.

## Confirmed defects and corrections

* Auth-provider JSON could pass ChatGPT without exercising its actual page.
  It now requires independent same-candidate application proof even on HTTP 200.
* Native browser repeats reused one data store and connection pool. Rounds now
  use independent sessions, retaining the same isolated candidate proxy.
* The publication boundary checked fewer browser proof fields than the service
  validator. Current admission now checks the full required evidence; immutable
  historical proofs remain explicitly separate. The current policy requires
  the main-document/composer, fresh application JSON, HTTP 200, restrictions and
  independent-session proof; the uncalibrated Send-button criterion is excluded.
* A Swift-only verifier change did not change the scheduler input signature.
  Swift sources now participate, forcing revalidation with unchanged Best50.
* Independent discovery persisted its local registry but never promoted feeds
  to the shared permanent catalog. Daily independent promotion now runs before
  Grok quota eligibility, revalidates sources, rotates unknown feeds, records
  rejection reasons, and uses the existing atomic Git publication/retry path.
* Any historical retention automatically put STALE in the title, irrespective
  of its age; failed attempts also marked a recent good artifact stale. Title
  freshness now follows only the last successful published validation, with
  STALE strictly after 72 hours. Per-node retained age stays in diagnostics.
  Internal current-policy and six-hour freshness diagnostics remain separate.
* Rendering errors previously fell back to the current clock for a missing date.
  Malformed, naive and future validation timestamps now fail closed.

## Presentation and preservation

Fresh titles use `BL VPN [30 Oct 2026]`; outdated proof remains visibly STALE.
The date belongs to the completed validation atomically published with the
artifact, not Happ's download time. Names use, for example,
`🇩🇪 DE, Frankfurt am Main  |1|   [47.245.182.206]`. Unknown geography remains
neutral, public IPv6 addresses are compressed, and numbering follows stable rank.
Versioned rendering preserves byte comparisons against old immutable publications.

The protected original connections are never silently removed. A historical
entry is not counted as a current qualifier. The retained Shadowsocks proof at
the start of this audit dates to 25 October; its historical status remains in
diagnostics and does not make a recent subscription title STALE.

## Scheduling and recovery

The existing GitHub workflow runs every two hours and can be expedited after a
low local result. The loaded local launch agent polls every 300 seconds, runs at
login, detects changed input/code, and revalidates unchanged input at least every
six hours, more often for a low pool. Kernel locks exclude overlapping jobs.
Owned process supervision, bounded timeouts, retries and crash cleanup remain in
place. Reboot, offline and stale-input cases are simulated; no real reboot or
network/VPN interruption was performed.

The loaded research agent polls hourly. Grok 4.7 Extra High non-fast is verified,
but an actual request still fails with exhausted quota. Retries require no
manual Cursor launch. Successful resumption after restored quota is simulated,
not yet observed live. Independent daily discovery/catalog admission operates
without Grok and has now been exercised against real GitHub publication.

## Validator calibration boundary

The original native WebKit proof could see the HTML composer and models API
without demonstrating responsive frontend controls. A stronger harmless local
edit/send-control/clear experiment exposed a test-environment limitation:
the windowless control document reports hidden, and requestAnimationFrame does
not fire within 1.5 seconds. Explicit public inactiveSchedulingPolicy.none allows
background JavaScript but did not establish responsive controls. The stock
headless Chromium control returned Cloudflare challenges and remained INCONCLUSIVE.
These results are not evidence that the candidates are dead. A new mandatory
frontend criterion requires a demonstrated positive control before deployment;
the experimental Send-button gate was therefore not deployed. Playback, account
login and message generation are outside the public-resource access policy.

The retained reachability policy subsequently passed an unchanged-system control
at **1 November 08:28:27 MSK**: genuine main document 200, visible/actionable
composer and fresh validated models JSON 200, without challenge acceptance.
One currently published NL/Haarlem configuration then passed the corrected full
five-round candidate validation: **ChatGPT 5/5, YouTube 5/5, Instagram 5/5**;
samples 309.932, 282.090, 302.189, 330.965 and 325.549 ms, median **309.932 ms**.
This directly verifies one qualifying configuration with the corrected method,
not all seven prior-policy results and not the user's logged-in Safari session.

## Deployment and verification

Commit `d70c992` deployed presentation, persistent independent source admission
and Swift-change scheduling. Its isolated committed tree passed **449 tests**.
The existing launch agent automatically fetched it and began another validation.
The already-published eight-connection artifact was also reformatted atomically,
preserving its exact `2026-11-01T03:42:23.530010+00:00` validation timestamp,
all node evidence, all connection identities, and the protected historical entry.
Remote content was verified after push; its title is
`BL VPN [01 Nov 2026]`. The user's clarified title policy was applied: retained
proof age does not trigger STALE; only more than 72 hours since the last successful
published validation does. The exact 72-hour boundary remains fresh.

The final correction additionally closes the auxiliary-API-only admission path,
uses independent sessions, and validates the full browser evidence again at
selection/publication. **451 regression tests passed** before committing this
correction. Controlled tests cover quota/recovery, real bare-Git failed-push
retry, unknown source admission, a second daily batch, invalid feeds, corrupted
state, interrupted jobs, unchanged-input revalidation, duplicate identities,
future timestamps, UTC midnight and the exact 72-hour title boundary.

The optional pinned Playwright WebKit experiment was rejected: its local fixture
triggered the UI guard before any ChatGPT request. Official code creates an
offscreen WindowServer window; the guard did not establish actual visible pixels
or focus changes. That engine was not enabled; its unused downloaded cache was
removed. Normal scheduled probes retain prohibited native activation and never
create a desktop window.

References: [Apple background scheduling](https://developer.apple.com/documentation/webkit/wkpreferences/inactiveschedulingpolicy-swift.property),
[Happ protocol formats](https://github.com/HappDev/happ_su/blob/main/faq/adding-configuration-subscription.md).
