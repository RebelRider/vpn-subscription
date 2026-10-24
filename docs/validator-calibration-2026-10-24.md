# Validator calibration — 2026-10-24

## Measured result

At 2026-10-24T07:58:49.595014+00:00, two public candidates passed five rounds each of ChatGPT, YouTube and Instagram from this Mac, using isolated candidate processes bound to en0. Their median completion times for fresh HTTPS gstatic 204 requests (including proxy, transport and TLS) were:

| Canonical ID prefix | Protocol | Median ms | Three service proofs |
| --- | --- | ---: | --- |
| `2a0f8b831547dfb9` | VLESS | 283.378 | 5/5 each |
| `d2950709f879b118` | VLESS | 352.537 | 5/5 each |

The exact subscription and evidence were atomically published to the existing `regional` branch; remote Git blobs matched the local files. These are measured results, not a guarantee that a public server will remain available.

## Root causes and controls

* A seven-candidate shortlist from earlier local YouTube/Instagram successes produced two complete passes. Two other candidates failed SOCKS transport; three timed out. These failures were not converted into successful application access.
* The old ChatGPT providers-only check encountered Cloudflare challenges and could return empty HTTP 200 JSON even through a usable connection. A challenge is inconclusive, never a pass.
* A fresh stock headed browser must expose the editable ChatGPT composer and retrieve validated application JSON for every round. Semantic selectors accommodate the current composer. The exact API fetch rejects redirects, bypasses HTTP caches, blocks service workers, and validates the HTTPS origin/path, status, content type and bounded body. Passive responses do not qualify.
* The user confirmed the current functional connection is Mango. The unchanged-system-route positive control passed 5/5 rounds at 07:55:32 UTC. EMB was already disconnected; no VPN was switched or modified. This control cannot qualify any candidate.
* Candidate browsers are OS-restricted to one authenticated loopback proxy port. A real local isolation test allowed that TCP port and denied another TCP port and UDP. Candidate sing-box processes use only the selected public server with en0 binding.
* Cloud Best50 remains unchanged as a contract. Mac discovery adds a bounded independent regional tranche, without cloud geography/performance exclusion. Previous strict publications are reintroduced only as unverified inputs for complete rechecking, including if a public source disappears.
* Explicit private managed-pool entries are never exported, including canonical duplicates in public feeds. Frozen manifests bind input identity and current export permission, rechecked before publication.

## Evidence boundaries

These are unauthenticated application-level reachability checks. No account was logged in, no prompt submitted and no video playback initiated. Import and actual tunnel activation inside Happ were not exercised because the current working VPN must remain untouched. Subscription syntax and engine compatibility are checked; unsupported protocols are rejected. Private raw diagnostics and manifests remain in the user-owned mode-600 BestLocal state directory.
