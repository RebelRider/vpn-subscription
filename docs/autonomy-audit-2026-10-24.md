# BestLocal operational audit — 2026-10-24

## Five entries versus the earlier report of four

The report of four described validation completed at 11:07 Moscow time, published
in regional commit `75480b9`. The next unattended cycle completed at 11:26 and
published five in `2824734` at 11:27. All five had five successful local rounds for
ChatGPT, YouTube and Instagram and measured medians below 500 ms. Happ's hourly
refresh and its own ping-based sort can display a different snapshot/order.

The two Haarlem Trojan entries were separate full fingerprints, but their parsed
outbounds differed only in `tls.utls`. Both targeted the same authenticated
connection. One source omitted `security=tls`; the runtime supplied TLS by default,
while Happ displayed that URI as Trojan/WS. The missing explicit parameter is an
import ambiguity, not proof of the reason for Happ's `n/a`. No Happ setting or
active connection was changed to investigate it.

The corrected publisher makes Trojan TLS explicit, tests fingerprint variants
individually, then publishes only one otherwise-equivalent connection. Canonical
IDs and connection uniqueness are rechecked before publication. Raw credentials
and complete configuration URIs are intentionally absent from this report.

## Automatic lifecycle and failure recovery

| Stage | Automatic trigger | Deadline, recovery and serialization | Freshness |
| --- | --- | --- | --- |
| Public discovery and primary validation | Existing GitHub Actions schedule every two hours, code changes and bounded low-pool dispatch | Job group serializes writers; 90-minute build watchdog inside a 120-minute job; persistent source backoff/reputation; next scheduled run retries | Source timestamps and functional history; empty/invalid cloud output cannot replace valid data |
| Cursor/Grok source research | Loaded hourly launchd job; one successful research proposal per day | Strongest available verified Grok Extra High; 15-second inventory and 30-minute research bounds; kernel lock; quota/network failures back off 1, 2, 4, then at most 6 hours | No daily-success timestamp after quota failure; source Retry-After remains authoritative |
| Source promotion | Successful proposal or replayable pending proposal | Real HTTPS/robots/syntax checks; independent catalog lock; atomic non-forced Git transaction and three bounded retries; pending replay does not spend model quota again | Independently verified catalog entries expire after 30 days; proposals expire after 24 hours |
| Regional exploration | Every local validation cycle | Best50 plus bounded independent public and optional managed inputs; cloud geography/performance cannot exclude regional trials; local source yield affects reputation | Frozen private manifest pins exact input and export policy; managed privacy covers equivalent fingerprint variants |
| Mac validation | Loaded launchd poll every 15 minutes; changed Best50 or validator; unchanged input is due after 4h15m to leave completion time before 6h | At most four candidate engines, one browser; 180-second candidate and bounded HTTP/browser deadlines; 90-minute outer supervisor; kernel lock skips overlap | All three services must pass every round and actual sample median must be strictly below 500 ms |
| Regional publication | Successful fresh local selection | Freshness, identities, unique connections, complete round proof, current manifest and managed permission checked; detached owned worktree; ordinary atomic push and verification; bounded retries | Older results cannot overwrite a valid newer result; malformed/far-future previous status cannot poison recovery |
| Happ | Existing subscription auto-update interval of one hour | Existing URL and import formats remain; no settings changed | Validation timestamp/health are independent of Happ fetch time or its ping measurement |

A crashed process loses its kernel leases. On the next launchd interval or login
(`RunAtLoad`), persisted interrupted state is recovered and retries continue.
No real Mac reboot, network disconnection or VPN interruption was used as a test.
After a long outage, retries, source cooldowns and freshness checks remain bounded;
publication waits for GitHub rather than inventing a successful upload.

Retired feeds now retain a bounded dormant URL queue. Up to two due feeds per
collection automatically return after seven days without requiring rediscovery of
their vanished parent. This shares the existing source/replacement/HTTP budgets.
Old hash-only tombstones cannot reconstruct URLs that were previously discarded;
ordinary rediscovery and current seeds/catalogs continue to replenish that history.

## Corrected selection and safety defects

* Visible challenge overlays must not pass merely because an editor and API exist
  behind them. Browser evidence now requires an actionable editor, no visible
  restriction and a consistent actual main-frame document.
* A normal browser 403-to-200 navigation can succeed without a CAPTCHA action;
  subresources, subframes or a later 403 cannot masquerade as the valid document.
* Inert JavaScript/translation strings in Instagram HTML and ordinary video titles
  are not active access restrictions. Actual visible/structured errors still fail.
* Unrelated endpoint paths, contradictory per-round evidence, missing services,
  malformed identities and sample medians at exactly 500 ms are rejected.
* Legacy uncertain failures and new inconclusive checks do not receive a false
  twelve-hour rejection or worsen the definitive reliability window.
* Reliability uses up to twenty definitive outcomes. Within a reliability band,
  ordering only changes for a material 25–50 ms improvement; history never waives
  any current service, latency or freshness requirement.
* Private managed policy also suppresses public fingerprint variants of the same
  authenticated connection, including when an older manifest permits one.

Candidate engines bind only to en0 and their public pinned endpoint, with no
fallback outbound. Candidate browsers can reach only their authenticated owned
loopback proxy; the real local Seatbelt allow/deny test remains mandatory. No VPN,
NetworkExtension, routing, DNS or system proxy configuration is modified.

## Controlled autonomy proof

The joined simulation uses production research state, proposal parser, robots and
feed validation, protocol parser, catalog publisher, loader and SourcePool. Only
model transport and public HTTP are simulated. It starts with exhausted quota,
restores the verified model, rejects three real pushes through a private bare-Git
receive hook, persists the proposal, and later succeeds without another model
request. The new source is actually loaded and its configurations extracted; the
retained subscription remains intact.

Other tests cover unchanged-input/time-based scheduling, interruption, overlap,
source disappearance and autonomous revival, malformed state/configurations,
rate limits, stale/invalid publication, managed permission revocation, latency
boundaries, browser restrictions and owned process cleanup.

## Owned resource cleanup and limits

Private marked temporary directories have kernel leases. Cleanup only considers
old unlocked resources inside the dedicated BestLocal root. It protects active
work, symlinks, unmarked data and unrelated Git repositories; detached worktrees
must belong to the exact authorized repository. Each scheduler rotates its own
operational logs. Test logs and one-off scratch files are not dependencies.

Local application checks require the Mac and its GUI session to be available.
External accounts, GitHub availability, public endpoint survival and future
incompatible service changes cannot be guaranteed by local automation. Such
failures remain explicit and fail closed. Account login, prompt submission and
video playback are outside the resource-access acceptance test.

Browser assets now repair partial/corrupt installations through pinned verified
staging, with installation and browser locks. Missing bundled packages can use the
existing Node npm CLI and the official registry, with exact versions, scripts
disabled and isolated empty configuration. The actual Chromium executable version
is checked. A durable swap transaction recovers before installer-only cleanup;
failed rollback preserves its transaction and backups. Generic janitors cannot
reap those backups. No global package installation or user browser profile is used.

The dedicated runtime also recovers verified orphan Git transaction locks. Only
seven exact metadata paths older than two hours are eligible; system lsof must
confirm no open handle, and inode/mtime must remain unchanged. Active, fresh,
symlinked, ambiguous or foreign locks are retained. Dirty working files and Git
history are never reset. Reliability history is byte-bounded to its reader's limit
so full twenty-result windows cannot eventually erase history through oversize.

A critical pool of at most two unique servers now triggers hourly local revalidation and bounded hourly cloud replenishment. Three to nine qualifiers use two-hour local revalidation; healthier pools retain the 4h15m lead time before the six-hour freshness limit. Retry deadlines and source policies always apply.

GitHub can disable public scheduled workflows after prolonged inactivity
([official documentation](https://docs.github.com/en/actions/how-tos/manage-workflow-runs/disable-and-enable-workflows?tool=cli)).
If a replenishment dispatch fails, the Mac checks the workflow state. Only
`disabled_inactivity` permits bounded re-enabling with existing authentication and
one repeated dispatch. A deliberately manually disabled workflow is respected;
network/permission failures retain ordinary backoff without advancing success.
