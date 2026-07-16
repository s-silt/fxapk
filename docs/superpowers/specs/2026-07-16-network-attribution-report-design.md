# network_attribution Report Output Design

**Date:** 2026-07-16
**Scope:** PR9 only (the roadmap finale)

## Objective

Surface the infrastructure attribution built in PR3–PR8 into the report as an
**additive**, schema-compatible `report.meta["network_attribution"]` section:
the PR7 infrastructure graph plus per-endpoint role candidates, **assembled
deterministically from facts already on the report** — no new network I/O, no
re-enrichment. The load-bearing rule is **no over-inference**: the bridge is a
fact-to-signal *compiler*, not an inference engine; a cloud/ASN/CDN membership is
a resource fact, never an operator/actor claim.

## Boundaries

PR9 does **not**: perform any network / enricher / file I/O (it reads only
`endpoint.enrichment` / `meta` / `evidences` already on the `Report`); import
`apkscan.core.enrichment`, the intel providers, `requests`, or `socket`; re-run
`core/attribution.build_endpoint_attribution` (it loads rules — file I/O);
modify the frozen PR3–PR8 modules (`attribution/{graph,models,roles,scorer}.py`,
`network/converters.py`) or the wired `core/attribution.py`; change a top-level
`Report` field or bump `REPORT_SCHEMA_VERSION`; feed `evaluate_closure` gaps/gates
or create/mutate any `Lead`/advice/exit code; emit any `operator`/`actor`/`owner`
field. New code lives in `apkscan/attribution/assemble.py` + tests, with thin
wiring in `pipeline.py`, `closure.py`, `report/digest.py` (+ the
`_EXPECTED_STAGES` test).

## Module

`apkscan/attribution/assemble.py` — one pure function:

```python
def build_network_attribution(
    endpoints: Sequence[Endpoint], *, artifact_id: str, phase: str
) -> dict | None: ...
```

Reads `endpoint.value/kind/enrichment/evidences`, bridges facts to
`AttributionEvidence` + `RoleFeature`, scores roles, builds the graph, and returns
a plain-JSON dict (or `None` when no `domain`/`ip` endpoint yields any evidence).
It never raises: derivation is wrapped **per endpoint** (skip + record, logged at
`debug` with `exc_info`, never a silent swallow); the caller wraps it again.

### The fact → AttributionEvidence bridge

Only `kind in {"domain", "ip"}` endpoints (parity with `build_endpoint_attribution`).
Evidence ids are **fact-only**: `stable_digest("apkscan.attribution/report-bridge",
{source, type, target_type, target_value(normalized), value(normalized)})` —
excluding confidence/timestamp, so re-runs over the same report are byte-identical
and corroboration merges as provenance rather than conflicting. Values pass
`normalize_ip`/`normalize_domain`/strict-ASN-parse **before** hashing; a parse
failure is a bounded skip recorded under `bridge_issues`, never a crash.

| report fact | evidence type | target → value | source | conf |
|---|---|---|---|---|
| `dns.ips` ∪ `dns.hosting[].ip` (order-preserving union) | `resolved_ip` | DOMAIN(endpoint) → IP | `dns` | 0.8 |
| `dns.cname` (per hop) | `dns_alias` | DOMAIN(endpoint) → DOMAIN(hop) | `dns` | 0.8 |
| `asn.asn` / `dns.hosting[].asn` / `shodan.asn` / `attribution.ips[].origin_network.asn` | `asn` | IP → ASN(`AS<int>`) | `asn`/`dns`/`shodan`/`attribution` | 0.6 |
| `certs.related_hostnames` / `shodan.hostnames` | `related_hostname` | (endpoint) → DOMAIN | `certs`/`shodan` | 0.7/0.6 |
| a **domain** endpoint's `runtime.remote_endpoints[].ip`, guarded by the domain ∈ `runtime.sni` | `tls_sni` | DOMAIN(endpoint) → IP | `runtime` | 0.95 |
| an **ip** endpoint with a peer-observing runtime source (`evidences[].source` ∈ {`runtime`, `runtime-pcap`}) | `network_flow` | IP(endpoint) target (APK contacted) | `runtime` | 0.95 |

**Runtime bridging** (the last two rows) is the strongest signal — dynamic ground
truth that the app actually spoke to this IP / sent this SNI to this IP at capture
time. It reads ONLY the structured `enrichment["runtime"]` pairing written by
`capture._annotate_runtime_endpoints` (`remote_endpoints` = sorted `"ip:port"`
strings, IPv6-safe split on the last colon requiring a valid decimal port; `sni` =
observed SNI names); the free-text evidence snippet is never parsed. `graph.py`
already routes both types in its closed `_EDGE_HANDLERS` (`tls_sni` → APK `contacted`
DOMAIN + DOMAIN `served_at` IP; `network_flow` → APK `contacted` IP, lazily minting
the APK node), so no frozen-module change is needed. Four guards keep it passive and
non-over-inferring: (1) `tls_sni` is emitted only from the **domain** side and only
when the endpoint's own domain is among the observed SNI (so `remote_endpoints`
really are IPs THIS domain's TLS went to — never a co-hosted third-party name listed
on an ip endpoint); (2) `network_flow` and the
`direct_connection` signal are licensed ONLY by a source that observed the actual
peer IP — `runtime` (mitm upstream) / `runtime-pcap` (pcap `dst_ip`) — via an allowlist
`_OBSERVED_CONTACT_SOURCES`; a value derived from an HTTP Host / `:authority` header
(`runtime-tshark`), a decrypted request/body (`*-decrypted`), or a tool probe does not
prove the app contacted THAT IP (a spoofed IP-literal `Host` header could otherwise mint
a top-confidence false edge), so it is excluded — allowlist, so a new content-derived
source is excluded by default; (3) known anti-fraud interception
nodes (`is_known_intercept_ip`, hoisted to `network.fingerprints`) are excluded from
both edges — an intercept page is never a domain's serving IP nor a business contact,
matching the pcap ingest's own drop; (4) a mismatched / absent / malformed runtime
pairing (e.g. mitm-only runs) simply yields no `tls_sni`.

**Confidence is a constant per `(source, type)` and `timestamp` is `None`** — the
fact-only id excludes them, so a varying confidence/timestamp would make two
runs' same-id evidence differ in payload and trip the `_evidence_pool` /
`_normalize_feature_bucket` conflict guard (a crash-on-rerun, not a style choice).

**No cert_san_dns / CERTIFICATE node**: crt.sh data carries no leaf-cert SHA-256
(`certs.py` returns `related_hostnames`/`issuers` only), and a graph
`CERTIFICATE` value must be `sha256:<64hex>` — synthesizing a cert identity would
invent a fact. `cert_san_dns` is reserved for a future source with a real
fingerprint (pcap TLS capture). Registration facts (`icp`/`whois`/`rdap`/
`ip_rdap`) and org/country strings produce **no edge evidence** — they feed
RoleFeatures only. A statically-extracted endpoint enters the graph solely
through its dns/asn/related facts (`RESOLVES_TO`/`IN_ASN`/`INTEL_RELATED`), never
an APK `CONTACTED` edge — contact was not observed.

### The fact → RoleSignal compiler (no over-inference)

Each `RoleSignal` is licensed by **one named, already-collected fact**, one fact
licenses **at most one** signal (no fan-out), and every signal not backed by an
observed fact **stays absent**. Given the frozen role requirements, this keeps
all four roles ineligible for ordinary CDN endpoints and bare cloud IPs.

v1 derives exactly four signals (each backed by an `AttributionEvidence` whose id
is the feature's provenance):

- **`direct_connection`** — `endpoint.kind == "ip"` **and** the endpoint has an
  evidence whose `source` starts `runtime` (the exact `closure.py` predicate). A
  merely static-string or dns-target IP does **not** qualify.
- **`domestic_network`** (jurisdiction, not nationality) — any one of: `asn.country
  == "CN"`; per-IP `attribution` country `CN`; `origin_network.category ==
  "telecom"` with `CN`; a domain's `icp` filing present. **Refuse** matching an org
  string to a Chinese company name (that is inference).
- **`public_cdn`** — the per-IP `attribution.edge_provider.tier` is `confirmed` or
  `probable` (any category — the wired five-layer already did the ≥2-signal edge
  work; **reuse its verdict, never re-derive**), or `hosting_provider`/
  `origin_network` category `cdn`.
- **`non_public_cdn`** (honest weaker inference) — `hosting_provider.category in
  {cloud, idc}` **and** no `public_cdn` for the same target (public wins) **and**
  edge tier is `None` (a positive classification, not "enrichment was empty");
  confidence ≤ 0.5.

**Must stay absent in static mode** (never synthesized): `redirect` (needs an
observed 30x — a CNAME is `dns_alias`, not a redirect), `cookie_challenge`,
`content_difference` (apkscan never probes — de-weaponized), `shared_tls`,
`subsequent_overseas_connection`, `historical_dns`, `stable_ip`,
`many_shared_domains`, and (deferred) `business_api`/`login_endpoint`/
`business_certificate`. Consequently **no static-only report can ever produce an
eligible `cloaking_edge_node`** (or edge/relay/origin) — an explicit invariant
test pins this. Roles surface as **ineligible-but-explainable** (matched
`public_cdn`/`domestic_network`, missing the behavioral signals); eligible
candidates appear only when richer behavioral facts (dynamic/HAR, roadmap D)
arrive — with no further wiring.

### Scoring & graph feed

For each bridged target with ≥1 RoleFeature: run `RoleClassifier().assess` +
`EvidenceScorer().score`. Emit a `RoleScore` in the endpoint summary for every
role where ≥1 present signal is in that role's `supporting|context|blockers`
(skip roles whose every signal is merely missing); ineligible assessments **are**
emitted (full trace). Only **eligible** `RoleScore`s are passed to
`build_infrastructure_graph(role_scores=...)` as node annotations; ineligible
explanations live only in the endpoint summary. The graph is fed the deduped
bridge evidence via `extra_evidence=`.

## Output shape (`report.meta["network_attribution"]`)

A plain-JSON dict (the bridge `.to_dict()`s everything — never a dataclass/enum/
set/`NetworkEntity` in `meta`), key order fixed literally in code:

```json
{
  "version": 1,
  "phase": "analyze" | "close",
  "artifact_id": "<meta.sample_sha256, else pkg:<package_name>>",
  "disclaimer": "<fixed English constant: a cloud/ASN/CDN membership is a resource fact, not an operator claim; roles are multi-evidence candidates, never accusations>",
  "graph": { ...InfrastructureGraph.to_dict() verbatim... },
  "evidence": [ ...AttributionEvidence.to_dict(), sorted by id... ],
  "endpoints": [
    {
      "endpoint": "...", "kind": "domain|ip",
      "ips": [
        {
          "ip": "...",
          "resource_context": {"origin_asn", "origin_category", "hosting_category", "edge_provider", "edge_tier"},
          "roles": [
            {"role", "eligible", "score", "confidence", "matched_signals", "context_signals", "negative_signals", "missing_signals", "evidence": ["<id>", ...]}
          ]
        }
      ]
    }
  ],
  "skipped": [ {"endpoint": "...", "error": "<ExcTypeName>"} ]
}
```

`version` is a section-local field (`REPORT_SCHEMA_VERSION` stays `"1.0"`). The
five-layer `enrichment["attribution"]` is **referenced** (a scalar
`resource_context` snapshot), never duplicated, and the `service_operator` layer
is never copied. No `operator`/`actor`/`owner` key at any level. Determinism:
endpoints sorted by `(kind, value)`, ips by ip, roles by role name, evidence by
id. The whole payload round-trips `json.dumps`.

## Wiring

- **pipeline** (`core/pipeline.py`): a new `_stage_network_attribution(state)` run
  via `_run_stage(state, "network_attribution", …)` **after `credibility`** (8 core
  stages), writing `state.meta["network_attribution"] = build_network_attribution(
  state.endpoints, artifact_id=str(state.meta.get("sample_sha256") or "") or
  f"pkg:{state.ctx.package_name or 'unknown'}", phase="analyze")` (only when
  non-`None`). `tests/test_pipeline_stages.py::_EXPECTED_STAGES` is updated in the
  same PR.
- **closure** (`core/closure.py`): right after `report.meta["closure"] = closure`,
  in its **own** `try/except` (logs, writes a minimal deterministic error marker,
  never raises, never mutates the returned `closure`), populate `phase="close"`
  from `report.meta.get("sample_sha256")` / `report.package_name`. Close overwrites
  any analyze-produced blob with the richer post-closure facts.
- **digest** (`report/digest.py`): a compact block via `meta.get("network_attribution")`
  (mirroring the `closure` compaction, defensive `.get` + isinstance guards, never
  the raw graph): `{"counts": {nodes, edges, issues, eligible, ineligible, by_role},
  "role_candidates": [ {entity, kind, role, score, confidence} for eligible only,
  sorted by (role_rank, -score, entity), capped ]}`, plus one
  `summary.attributed_role_candidates` counter. Degrades to an empty block on any
  malformed input; never raises.
- **CLI**: no new flag. The stage is cheap (no network) and `_run_stage`-guarded;
  `fxapk digest` surfaces the block once `build_digest` reads it. `--redact` is a
  no-op for this block (entities are IOCs, ids/roles carry no secrets;
  `raw_reference` is a report-internal pointer, never a URL/key).

## Tests

`tests/test_network_attribution.py` (+ a `tests/test_digest.py` case, +
`_EXPECTED_STAGES`): each enrichment field → its expected evidence (types, ids,
constant confidence); each derivable signal from its licensing fact; each
non-derivable signal **absent**; the **cloaking-never-static** invariant; the
acceptance negatives — an ordinary Cloudflare endpoint yields **no eligible
origin/relay** and no operator field; two IPs sharing only an ASN produce
`IN_ASN` edges to one ASN node and **no cross edge/cluster**; a bare cloud IP gets
no operator claim; a report round-trip (the `meta` key survives write/read and
`json.dumps`); a determinism test (permuted endpoint order → byte-identical
`network_attribution`); a passive test (a `socket`-blocking guard + an import
assertion that the module imports no enricher/intel/requests/socket); and a
no-frozen-diff assertion (only the new module + thin wiring changed).
