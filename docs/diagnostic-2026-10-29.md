# BestLocal follow-up — 29 October 2026

Times are Moscow time (UTC+3). No Happ/VPN, routing, DNS or system-proxy
configuration was modified. The two existing public connections are preserved.

## Baseline verified today

The scheduler is running the deployed `7d0528a` correction. At 15:24 it reported
`health=no_qualifiers`, zero infrastructure failures and a confirmed diagnostic
publication. The actual CDN subscription still contained the same two distinct
Trojan/Shadowsocks configurations; their canonical identities, order and labels
matched the regional status. No padding, duplicate or untested addition was found.

| Completed local run | Candidates | ChatGPT HTTPS passes | YouTube | Instagram | Qualifiers |
| --- | ---: | ---: | ---: | ---: | ---: |
| 12:46:40 | 100 | 0/98 | 23/98 | 24/98 | 0 |
| 13:46:53 | 100 | 0/99 | 13/99 | 13/99 | 0 |
| 14:48:20 | 100 | 0/99 | 15/99 | 16/99 | 0 |

The latest run covered VLESS 40, Shadowsocks 22, Trojan 21, VMess 15, Hysteria2 1
and SOCKS 1. Its outcomes were 83 failures and 17 inconclusive results. Six browser
attempts returned access-denied and eight were deferred by the bounded browser
lease. Deferred work is not a failed network connection or successful access.

The retained Trojan again passed YouTube and Instagram, but its HTTP and headless
Chromium ChatGPT requests received 403/challenge. The retained Shadowsocks also
had an inconclusive YouTube 403 in this run. There were too few completed rounds
to conclude that either connection exceeded the 500 ms latency limit.

The CDN health report confirmed the 14:48:20 completed attempt. A separate CDN
status download timed out; the matching fetched regional commit `ede0630` was
verified instead. Historical server proof remains **25 October 12:35:06.891**,
five successful rounds, medians 450.027 / 230.402 ms. It must not be dated today.

Thus STALE reflects the lack of a new strict positive result, rather than a
stopped scheduler or broken health publication. The user's successful Happ use
and paired controls identify a verifier limitation alongside real candidate
failures. They do not authorize treating a challenge as a successful check.

## Windowless verification investigation

Stock native WebKit with a fresh nonpersistent data store, prohibited application
activation and no explicit window passed five positive-control rounds through
the unchanged active connection. Each required the actual ChatGPT document,
fresh same-origin model-catalog JSON and an unobscured, editable composer with
real DOM focus and hit testing. Existing user browser cookies were not used.

The first isolated native attempt failed before reaching its loopback proxy.
Scoped system denial logs identified blocked UNIX IPC to exactly
`/private/var/run/mDNSResponder`, with an underlying EPERM. This is a verifier
environment error, not evidence of a bad public server. The native policy needs
that existing local resolver socket while retaining the TCP/UDP restrictions.
It does not change any system DNS configuration.

The corrected native policy passed an authenticated forwarding canary and a
closed-proxy negative control. An observed owned WebKit networking helper had
one loopback TCP connection and no other TCP connection. Independent real socket
tests allowed the exact proxy and denied another TCP port, UDP and another UNIX
socket. UI and application proof are rechecked after the asynchronous API request;
a regression fixture introduces an overlay during that request and must fail.

At approximately **15:48**, the retained Trojan passed ChatGPT, YouTube and
Instagram **5/5 each** through its own en0 connection. Its median fresh HTTPS
completion time was **794.867 ms**, so it was correctly rejected on latency.
An independent 50-candidate run completed at **15:56:33** in 188.9 seconds. One
new Trojan passed all three services 5/5, with samples 1684.983, 1049.466,
1535.058, 1556.822 and 806.582 ms; median **1535.058 ms**. It too failed the
unchanged strict threshold. The run produced **zero qualifiers**. Five native
evaluation failures and six queue deferrals remain inconclusive; bounded error
categories now distinguish WebKit evaluation errors without logging page content.

The retained Shadowsocks separately returned no HTTP response from three YouTube
endpoints (SOCKS failures/timeouts). Five latency requests also timed out before
HTTPS, yielding no valid median. That observation cannot establish a YouTube
endpoint false negative. No repeated retries of that unsuitable connection were
scheduled by the diagnostic experiment.

## Publication protection and tests

The old nonempty-result transaction would replace the entire retained list even
if a previously working entry merely lacked fresh proof. The two user-protected
identities are now explicitly configured. A nonempty publication can contain up
to 12 freshly qualified entries plus these two historical entries. Fresh entries
win duplicate connections. Historical entries retain their original payload and
timestamps, with immutable original regional commit/blob references; ancestry,
matching actual subscription content, original evidence, current compatibility
and current private-pool opt-out are verified before commit and push.

Only fresh entries contribute to `nodes` and `stability.qualified`. Retained
entries have separate metadata and counts and keep a descriptive STALE title;
they cannot make the whole artifact currently verified. Both groups continue
automatic revalidation. Empty-result publication remains nondestructive.

The live two-entry historical artifact passed the new provenance validation in
memory, with **zero** fresh entries claimed. **422 tests passed**, including a
controlled bare-Git mixed transaction, idempotence, remote hash verification,
forged historical evidence rejection, private-pool opt-out, recheck inclusion and
protection of a mixed title from cloud annotation. Swift compilation and real
network-isolation checks passed. No unverified candidate was published by tests.

## External dependencies

Grok research remains quota-limited. The 12:49 failed attempt scheduled its next
eligibility for 18:49, followed by the existing hourly launchd poll. A separate
read-only worker invocation also returned quota exhaustion. Independent source
discovery, candidate testing and diagnostic publication continue without Grok.

No actual reboot, network interruption or VPN switch is used as a test. External
server availability and future service anti-automation changes remain outside the
pipeline's control; no unattended design can guarantee a positive public pool.
