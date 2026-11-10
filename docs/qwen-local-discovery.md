# Local Qwen discovery

This supplements the existing BestLocal source discovery. It cannot certify a
working proxy or write either production subscription. Both subscriptions still
require fresh local application/latency proof; Serbia additionally requires
Spotify and independently observed RS egress. An empty Serbia result is allowed.
Happ3.3.6 currently reports a parse error for the comment-only zero-URI artifact;
HTTP200 and successful empty publication do not imply a usable Happ profile.

## Schedule and recovery

LaunchAgent: `com.rebelrider.best50-qwen-discovery`.

The intended daily slot is **03:01 Europe/Moscow**, currently00:01UTC. The plist
contains a calendar hint converted to the machine's timezone, `RunAtLoad` and a
60-second lightweight poll. The Python gate uses explicit IANA Moscow time,
not launchd's wall-clock timezone or the shell's TZ. Changing the Mac timezone or
DST therefore does not change the intended slot. launchd is not a real-time
scheduler: an awake/available session normally starts within the scheduled minute.

The Mac cannot execute while powered off. Sleep/login recovery coalesces missed
days into **one latest due slot**, not a backlog of heavy jobs. An installation
marker preserves the first missed slot even if the Mac sleeps before its first
poll. Initial afternoon installation otherwise waits for the next03:01.

Kernel locks prevent duplicate Qwen jobs and overlap with authoritative local
validation. Research waits for a quiet window with enough time before the next
validation due time; busy windows retry after5minutes. Inference never requires
an interactive confirmation. Foreign loaded LM Studio models or insufficient
reclaimable memory also cause safe deferral. Network/model/Git failures use
bounded15/30/60/120/240/360-minute retry delays. Successful daily work is not
repeated by minute polls. A supervised process has a20-minute maximum runtime.

## Existing model and ownership

The installed artifact is `mlx-community/Qwen3.8-27B-4bit`, approximately16.08GB,
with MLX safetensors. The live LM Studio CLI load handle is `qwen3.8-27b`.
The adapter resolves `modelKey` from `lms ls --json` using the fixed installed
artifact path; the filesystem/index identifier is not necessarily a load handle.
No download/get command, alternative model or Ollama installation is used.

LM Studio0.4.28's installed CLI can start its supported background service using
`lms daemon up`; the installed desktop backend runs with `--run-as-service`.
No GUI automation or foreground browser is used. Own REST startup binds only
127.0.0.1:12431. An existing server is preserved and is reused only when no
foreign model workload is loaded. Request HTTP bypasses ambient proxy variables
and rejects redirects; optional existing local API authentication is never logged.

Each owned load receives a unique `bestlocal-qwen-…` identifier, context16384,
parallel1 and idle TTL300seconds. At least20GiB estimated reclaimable memory is
required before loading. Generation has bounded output/context/request budgets;
truncated/reasoning-only/invalid answers are not tool decisions. Configuration
parameters apply only to this load, not saved user model settings.

A private journal records intent before startup/loading. Cleanup unloads only
the exact verified owned instance and stops only a verified owned server. Foreign
instances/services are never unloaded, evicted or reconfigured. If a desktop
backend's later GUI adoption cannot be ruled out, it may remain idle after the
large model and owned REST server are stopped. The explicit model TTL and
cleanup-only recovery cover interrupted workers without starting new services.

References: [LM Studio headless operation](https://lmstudio.ai/docs/developer/core/headless),
[CLI](https://lmstudio.ai/docs/cli),
[model inventory](https://lmstudio.ai/docs/developer/rest/list),
[idle TTL](https://lmstudio.ai/docs/developer/core/ttl-and-auto-evict).

## Discovery and production admission

Qwen has no native internet or shell/filesystem tools. It may request exactly
`search(query)`, `fetch(url)` or `finish`. Deterministic tools perform public
GitHub repository search and policy-gated public web search, enumerate one actual
repository from search results and extract configurations from actual fetched
bodies. Country-first queries use Serbian/Russian/English variants. Successful
empty GitHub searches are broadened to practical protocol/aggregator queries;
outages/rate limits are not evaded with another query. Public search denial is
diagnostic, not proof that no sources exist.

Existing `SourcePool` policies enforce public DNS, HTTPS, robots/access rules,
response/request limits and rate handling. At most32 public requests and two
concurrent fetches are allowed. The project parser/canonical fingerprints handle
all currently supported URI formats, reject malformed/private endpoints and
deduplicate configurations. Model text never creates a configuration. Context
contains bounded scrubbed public summaries and links, not URI credentials.

Shared-catalog URLs, current project candidate identities and prior acknowledged
Qwen findings are compared before reporting novelty. Query/source cooldowns and
bounded histories prevent repeated exhausted searches. Actual source observations
are checkpointed before further inference; same-day retries retain safe tool
context. Git retries replay durable proposals without another model load.

Confirmed source **syntax/content**, not server functionality, is admitted by
the existing `source_catalog.process_research_result` path. It independently
refetches sources and writes only `regional:sources/primary-sources.json`.
At most8 new URLs per Moscow day are activated. Deferred source admissions remain
in a bounded FIFO even after PR acknowledgement, so review/publication cannot
silently discard the remaining URLs. The cloud builder and both local profiles
already consume this persistent registry, including when the Mac is offline.

A stable `discovery/qwen` branch and automated PR contain only
`discovery/qwen/candidates.json`: public source/evidence URLs, body hashes,
candidate fingerprints/protocols and explicitly unverified RS hints. Actual
configuration URIs remain in a private bounded cache. The writer rejects extra
paths, symlink escapes, malformed metadata and non-data branch changes. Ordinary
non-forced pushes, refetch/retries and verification protect concurrent writers.
No new identities means no data commit. The PR is an audit trail; manual approval
is not required for deterministic source admission. Neither workflow code nor
`regional/output/best-local*.txt` is writable through a model decision.

## Operation

Use the existing checkout/runtime; the installer never clones a replacement:

```sh
python3 scripts/install_qwen_discovery.py --repo "$HOME/best50-vpn-regional-runtime" --load
python3 scripts/install_qwen_discovery.py --status
```

Controlled manual discovery, with publication withheld:

```sh
python3 scripts/qwen_discovery.py --run-now --dry-run --iterations 8 \
  --repo "$HOME/best50-vpn-subscription" \
  --state-dir "$HOME/Library/Application Support/best50-vpn/qwen-debug"
```

`--run-now` without `--dry-run` permits normal deterministic admission/data-PR
publication. Resource locks, safety windows, deadlines and ownership still apply.
Manual invocation can therefore return a deferred status while validation is busy.

Operational state lives in `~/Library/Application Support/best50-vpn/qwen/`:
`scheduler-status.json`, `worker-result.json`, `execution-history.json`,
`discovery-state.json`, `tool-observations.json`, `admission-backlog.json`,
`pending-discovery.json` and the `lmstudio/` ownership journal. Public proxy URIs
in `qwen-candidates-private.json` are unverified inputs, mode600. Do not publish
this directory. Logs are bounded/rotated under
`~/Library/Logs/best50-vpn/qwen-discovery.log` and `qwen-discovery-error.log`.

Read-only diagnostics:

```sh
launchctl print "gui/$(id -u)/com.rebelrider.best50-qwen-discovery"
"$HOME/.lmstudio/bin/lms" daemon status --json
"$HOME/.lmstudio/bin/lms" server status --json
```

Server status probes do not cold-start LM Studio. Avoid running other CLI
inventory/load commands blindly while investigating ownership: some can start
the selected LM Studio backend. API authentication failures require the existing
authorized local token (`BESTLOCAL_LMSTUDIO_TOKEN` or `LM_STUDIO_API_KEY`);
the worker does not disable authentication or generate replacement credentials.
