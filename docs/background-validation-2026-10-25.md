# Background-only ChatGPT validation — 2026-10-25

The previous Python adapter defaulted to `headless=False`. Scheduled callers
omitted this option, so the fallback explicitly opened Chrome for Testing despite
launchd's background process setting. This could activate a window and interrupt
normal desktop work.

Both launch boundaries now enforce the opposite invariant:

* Python defaults to literal `True` and rejects every other value before runtime
  lookup or process creation.
* JavaScript unconditionally passes `headless: true`, including when an old or
  direct configuration requests a visible browser or omits the option.
* An unsuccessful headless check never retries with a visible browser.

The existing lightweight HTTP check remains the first path. Its actual ChatGPT
application JSON can establish success without launching Chromium. An ambiguous
HTTP result can use the existing isolated Chromium engine in
[Playwright's new headless mode](https://playwright.dev/docs/browsers#chromium-new-headless-mode).
It creates no desktop window. The fresh rendered/actionable composer and
application JSON requirements, exact candidate proxy, Seatbelt isolation, limits,
cleanup and all three service/latency gates are unchanged. No user browser
profiles, login, CAPTCHA actions, stealth or system network changes are used.

## Verification

Four new regression cases cover Python rejection, default configuration,
JavaScript legacy/missing configuration and no visible retry after a challenge.
The focused browser suite passed 32 tests.

Live checks used only the enforced headless launcher:

* The unchanged system connection received HTTP 403 and insufficient application
  evidence. It was classified as inconclusive, never as working or a definitive
  transport failure.
* One currently published Trojan candidate passed YouTube and Instagram and
  measured a 389.253 ms initial latency sample. ChatGPT's HTTP and headless checks
  were challenged with 403, so the candidate did not qualify in this check. This
  is not a new five-round latency measurement or a claim that the server is dead.
* A read-only WindowServer/process monitor sampled 85 times during that actual
  candidate test. It observed one owned Chromium process with `--headless` and
  zero owned on-screen browser windows; zero non-headless owned browsers.

These observations do not guarantee that Cloudflare will accept every headless
client. If positive application evidence cannot be obtained, the existing
inconclusive/retry and last-known-good/freshness policies apply. A successful
headed result from an earlier cycle must not be represented as a new headless
validation. No inconclusive result is promoted to populate the subscription.

Only BestLocal-owned files and processes were used; the active VPN, system
routing, DNS, proxies and user application settings were not changed.
