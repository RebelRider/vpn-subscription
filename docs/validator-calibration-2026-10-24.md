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
* At the time of this calibration a fresh stock headed browser exposed the editable ChatGPT composer and retrieved validated application JSON for every round. **Superseded on 2026-10-25:** desktop windows are prohibited; the adapter and launcher now enforce headless-only checks. The functional evidence requirements remain unchanged. Semantic selectors accommodate the current composer. The exact API fetch rejects redirects, bypasses HTTP caches, blocks service workers, and validates the HTTPS origin/path, status, content type and bounded body. Passive responses do not qualify.
* The user confirmed the current functional connection is Mango. The unchanged-system-route positive control passed 5/5 rounds at 07:55:32 UTC. EMB was already disconnected; no VPN was switched or modified. This control cannot qualify any candidate.
* Candidate browsers are OS-restricted to one authenticated loopback proxy port. A real local isolation test allowed that TCP port and denied another TCP port and UDP. Candidate sing-box processes use only the selected public server with en0 binding.
* Cloud Best50 remains unchanged as a contract. Mac discovery adds a bounded independent regional tranche, without cloud geography/performance exclusion. Previous strict publications are reintroduced only as unverified inputs for complete rechecking, including if a public source disappears.
* Explicit private managed-pool entries are never exported, including canonical duplicates in public feeds. Frozen manifests bind input identity and current export permission, rechecked before publication.

## Evidence boundaries

These are unauthenticated application-level reachability checks. No account was logged in, no prompt submitted and no video playback initiated. The existing Happ profile automatically imported and displayed the two new Frankfurt VLESS/TCP/REALITY entries at 11:04 Moscow time. The automation did not activate or switch any tunnel. A later read-only observation found Happ already connected to the first newly imported Frankfurt entry; no Happ controls had been clicked. Subscription syntax and engine compatibility are checked; unsupported protocols are rejected. Private raw diagnostics and manifests remain in the user-owned mode-600 BestLocal state directory.

## Unattended production cycle

The installed launchd job independently completed a full cycle at 2026-10-24T08:07:09.130846+00:00: 100 unverified inputs, four strict qualifiers, then verified atomic GitHub publication (regional subscription commit `75480b922ca0f2a0d686567a7733f66cb05ba01a`). The scheduler finished with health `published`, zero consecutive failures and no pending retry.

| Canonical ID prefix | Input origin | Median ms | ChatGPT / YouTube / Instagram |
| --- | --- | ---: | --- |
| `00176d3865a7d030` | regional-exploration | 288.736 | 5/5 each |
| `2a0f8b831547dfb9` | local-recheck | 395.177 | 5/5 each |
| `d2950709f879b118` | local-recheck | 463.501 | 5/5 each |
| `2895192fe875a502` | best50 | 492.652 | 5/5 each |

The inputs spanned all six documented compatible protocols: 47 VLESS, 15 Shadowsocks, 10 Hysteria2, 10 VMess, 10 Trojan and 8 SOCKS. All four measured qualifiers happened to be VLESS. One newly discovered regional candidate qualified without cloud admission; one came from current Best50; the two earlier publications were fully revalidated.

Regional collection found 35 additional sources, fetched 50 sources, recorded six source failures and extracted 8,000 bounded inputs before strict parsing/selection. Source feedback updated 33 source records. Of 100 local attempts, 94 were definitive failures and two remained inconclusive. Observed latency-probe failures included 53 SOCKS errors, 35 timeouts, four destination TLS failures and two endpoint DNS failures. Engine diagnostics also distinguished authentication, refused connections, certificate errors and TLS handshakes; unclassified errors remain explicitly unclassified. No inconclusive candidate was published.

All 279 automated tests passed, including real sing-box configuration checks and bare-Git publication/revocation tests. The existing 15-minute scheduler, revalidation before six hours even for unchanged Best50, bounded retries, failure recovery and last-known-good preservation remain in place. Tests simulate source replacement/disappearance, regional replenishment, unchanged-input scheduling, interrupted jobs, publication failure/retry, stale evidence and private export revocation.

## Existing Happ client connection control

At 08:20:39 UTC, a fresh browser using the unchanged current system route passed ChatGPT 5/5: real visible/editable composer and exact fresh application JSON, with no guest navigation, UI clicks, login, prompt or CAPTCHA actions. Separate system-route controls passed YouTube 5/5 and Instagram 5/5; fresh HTTPS gstatic 204 median was 383.357 ms. The route was `utun5`, macOS system proxies were disabled, Happ visibly reported CONNECTED, and Mango was disconnected. This connection attribution is observational; the automation never selected or activated any VPN. The original five-round Mango calibration evidence remains separate. Neither system-route control can qualify a candidate.

## Remaining external constraints

Local measurements require the Mac and its logged-in GUI session to be available. Public endpoints may disappear or change restrictions between validations, so current evidence expires and inconclusive/failed runs retain an explicitly stale last-known-good artifact rather than fabricate success. Account login, authenticated features and video playback were not tested.

At the earlier calibration snapshot, the supplementary Grok research job reported `authentication` failure and retains automatic retry; core GitHub/source-link discovery does not depend on it and independently found the 35 additional sources above. Restoring an external account session is outside credential-preserving automation. The new commit's complete GitHub Actions run `40076520509` passed, including real-engine regression tests, Best50 regeneration and validated cloud publication (`a1c60b0`). All local validation and regional publication described above were exercised end to end.

The later [operational audit](autonomy-audit-2026-10-24.md) supersedes that transient Grok diagnosis: the installed job continued retrying automatically and now reports exhausted quota, with a joined restoration/publication simulation verified. Subscription counts in this document are dated measurements; later autonomous cycles may publish a different current count.
