# Serialized, self-correcting zone writes

> Make DNS-01 challenges reliable on the mijn.host API by serializing all
> writes per zone across webhook pods, keeping the desired challenge records in
> durable cluster state, cleaning up leftovers automatically, and logging every
> step.

## 1. Problem

The mijn.host DNS API has no per-record operations. Every change is
"download the whole zone, change it, upload the whole zone" (full-zone PUT).
On top of that the API is not read-your-writes consistent: a GET shortly after
a PUT can return the zone as it was before the PUT.

The current implementation (0.5.x) defends against this with an in-process
mutex and an in-memory cache of the records it wrote. That defence only works
inside a single process. Since the chart runs two replicas (needed so the
aggregated APIService does not flap), and the kube-apiserver picks a random
pod per request, the mutex and cache no longer protect anything:

- Pod B cleans up a record pod A wrote. B's cache does not know the record,
  mijn.host returns a stale zone without it, B decides there is nothing to do
  and returns success. The record stays behind forever.
- Pod B presents or cleans up while mijn.host returns a stale zone that lacks
  a record pod A just wrote. B's PUT drops that record. Let's Encrypt then only
  finds old values and the order fails.
- A pod restart empties the cache, so the same happens on one replica.

Observed on the user's cluster on 2026-09-12: seven leftover
`_acme-challenge` TXT values across the labhq.nl and factueel.nl zones while no
challenge was active. The webhook logs contained no line about any Present or
CleanUp, so none of this was visible.

cert-manager itself is not the source of parallelism here: its scheduler never
processes two challenges with the same DNS name and type at once (a wildcard
challenge carries the bare domain as DNS name), and the cluster already runs
`--max-concurrent-challenges=1`. Parallel challenges would otherwise come from
different certificates in the same zone.

## 2. Goals

1. At most one writer per zone at any time, across all webhook pods.
2. No write may lose a challenge record that is still needed, regardless of
   stale reads.
3. Leftover challenge records are removed automatically, without a new
   certificate request, even after crashes.
4. Every step is logged with enough context to follow a challenge end to end.
5. Two or more replicas remain supported. No leader election, every pod can
   serve every request.

Non-goals: protecting non-challenge records from concurrent edits made in the
mijn.host control panel while the webhook writes (impossible without a
consistent API), and supporting other ACME clients on the same zones at the
same time (see 4.3).

## 3. Building blocks

### 3.1 Per-zone lock: a Kubernetes Lease

A `coordination.k8s.io/v1` Lease in the webhook's own namespace, one per zone,
named `mijn-host-zone-<zone with dots replaced by dashes>`.

- Acquire: get the Lease; if it does not exist, create it with our holder
  identity. If it exists and is unheld or expired, update it with our identity.
  Both are atomic: create fails on AlreadyExists, update fails on a
  resourceVersion conflict, and either failure means "retry the loop".
- Holder identity is `<pod name>/<random token>` so a release only clears a
  lease this very acquisition owns.
- `leaseDurationSeconds` is 60. A crashed holder is taken over after that.
- Waiting is polling at 500 ms up to 25 s. The kube-apiserver aggregator cuts
  the request at 60 s, so a bounded wait plus a bounded operation stays under
  it. On timeout the webhook returns an error and cert-manager retries.
- Release: clear the holder identity. Failure to release is logged; the lease
  expires on its own.

### 3.2 Desired state: a ConfigMap per zone

A ConfigMap in the webhook's namespace, `mijn-host-zone-<sanitized zone>`,
labelled `app.kubernetes.io/managed-by=mijn-host-webhook` and
`mijn-host.vanefferenonline.nl/zone=<sanitized zone>`, with an annotation
holding the raw zone name. Data key `state` holds JSON:

```json
{
  "zone": "labhq.nl",
  "apiKeySecretRef": {"namespace": "cert-manager", "name": "mijn-host-api-key", "key": "api-key"},
  "records": [
    {"name": "_acme-challenge.hike-app.labhq.nl.", "value": "22gQ...", "ttl": 300,
     "addedAt": "2026-09-12T10:00:00Z", "challengeUID": "…", "dnsName": "hike-app.labhq.nl"}
  ]
}
```

- `records` is the complete set of challenge TXT records the webhook wants in
  that zone right now.
- `apiKeySecretRef` remembers where the API key for this zone lives so the
  sweep (3.4) can run without a challenge request.
- Entries older than `maxRecordAge` (default 24 h) are dropped when the state
  is loaded. cert-manager always calls CleanUp, but if the cluster died
  mid-challenge this is the safety net.
- Writes use Update with the resourceVersion read under the lock, so a bug
  that writes outside the lock fails loudly instead of racing.

### 3.3 Payload rule

Given the records mijn.host returned (`api`) and the desired list (`desired`):

```
challenge(r)  := r.type == "TXT" && r.name starts with "_acme-challenge."
payload       := [r in api if !challenge(r)] ++ desired
changed       := set(challenge records in api) != set(desired)
```

The PUT is skipped when `changed` is false. This rule makes both stale-read
directions harmless: a needed record missing from a stale GET is re-added from
`desired`; a removed record still present in a stale GET is dropped because it
is not in `desired`. Records that are not challenge records are passed
through untouched.

Safety guard: if the GET returns no non-challenge records at all, the
reconcile fails with `ErrEmptyZone` and nothing is written. A real zone always
has A, AAAA, MX or NS records, so an empty answer is a broken or truncated API
response, and a PUT built from it would wipe the zone. The stored intent is
kept, so the next request or sweep completes the write once the API answers
sanely.

Change check between read and write: the mijn.host HTTP API exposes no
version, ETag or conditional write, but the zone's SOA serial (a Unix
timestamp of the last change, served by ns1/ns2/ns3.mijn.host) moves on every
API write. The reconcile reads the serial before the GET and again just
before the PUT. If it moved, the upload was built from an outdated copy and
the attempt starts over with a fresh GET, up to `MaxWriteAttempts` (5); then
the request fails with `ErrZoneChanging` and cert-manager retries later. The
webhook never writes over a change it has observed. If no nameserver
answers, the check is skipped and the write proceeds (chart value
`zone.serialCheck`: `best-effort`, `required`, `off`). Limits: the serial has
one-second resolution, and the check is not a true compare-and-swap; the
unprotected window is the few milliseconds between the last serial read and
the PUT. Measured on 2026-09-12: mijn.host stamps the serial with the PUT
time but its nameservers served the new serial 54 s later, so the zone is
published in batches roughly a minute after a write. Hence there is no wait
for the serial after our own PUT (it would exceed the request budget), and
an external edit made in the minute before our read can still be published
after our write. Deliberately not stored across operations: the webhook must
keep working through external DNS edits, which are normal.

Chart option `ownAcmeRecords` (default `true`) enables dropping challenge
records the webhook does not know. With `false`, unknown challenge records
are kept, which means stale reads can resurrect removed records; documented
as the trade-off for sharing a zone with another ACME client.

### 3.4 Operations

All three run the same reconcile under the zone lock:

```
lock(zone)
  state  := load ConfigMap (drop expired entries)
  mutate(state)                       # Present adds, CleanUp removes, Sweep does nothing
  save ConfigMap                      # intent is durable before touching mijn.host
  api    := GET zone
  payload, changed := rule(api, state.records)
  if changed: PUT payload
unlock(zone)
```

- **Present** adds `{name, value, ttl}` if not already listed and always runs
  the GET and compare, so a retried Present repairs a lost record instead of
  treating it as a cache hit.
- **CleanUp** removes the entry and always runs the GET and compare, so a
  record that a stale read hides is still removed on the next write.
- **Sweep** runs at startup and every `sweepInterval` (default 15 m) on every
  pod. It lists the zone ConfigMaps, and for each zone runs the reconcile with
  no mutation. Because of the lock only one pod writes; the other finds
  nothing changed. The API key comes from the stored `apiKeySecretRef`. A
  zone whose lock is held is skipped until the next sweep. The first sweep
  after deploying this version removes existing leftovers.

Saving the ConfigMap before the PUT is deliberate. If the PUT fails, the entry
is still listed and the retry, or the sweep, completes the write. If CleanUp's
PUT fails, the entry is already gone and the sweep removes the record.

### 3.5 mijn.host client

Becomes stateless: `GetRecords(zone)` and `PutRecords(zone, records)` only.
The in-memory cache and mutex are removed. Every call is logged with zone,
method, record count, duration and outcome.

## 4. Logging

Logging uses the structured logger cert-manager's webhook library already
wires up (klog through logr), so `-v` controls verbosity like today.

### 4.1 What cert-manager tells the webhook

Each request carries: challenge UID, action (Present/CleanUp), DNS name, the
resolved FQDN and zone, the resource namespace, and the key. This is always
logged at the start and end of a request:

```
challenge action=Present uid=… dnsName=hike-app.labhq.nl fqdn=_acme-challenge.hike-app.labhq.nl zone=labhq.nl namespace=app-hike-app pod=mijn-host-webhook-xyz
```

### 4.2 Trigger context (which certificate caused this)

The request does not say which Certificate is behind it. The webhook can find
out: list Challenges in the resource namespace, match the UID, follow the
owner reference to the Order, and the Order's owner reference to the
Certificate. This needs `get`/`list` on `challenges` and `orders` in
`acme.cert-manager.io`. It is best effort: if lookup fails (RBAC, timing) the
request is still handled and the log line just lacks those fields. Chart
option `triggerContext.enabled` (default `true`) controls the RBAC and the
lookup.

Resulting line:

```
challenge … certificate=app-hike-app/wildcard-hike-app-labhq-nl order=wildcard-hike-app-labhq-nl-2-2232304168 challenge=wildcard-hike-app-labhq-nl-2-2232304168-123456
```

### 4.3 Steps inside a request

At default verbosity, one line per step:

- lock: `zone lock acquired zone=… waited=120ms` and `zone lock released`
- state: `zone state loaded records=3 expired=1`
- API: `mijn.host GET zone=… records=31 challengeRecords=4 duration=…`
- decision: `zone in sync, no write needed` or
  `zone write add=[…] remove=[…] keep=…`
- API: `mijn.host PUT zone=… records=28 duration=…`
- errors with the step they happened in.

Sweeps log a summary per zone and a single line when nothing changed.

### 4.4 Where else to look

cert-manager records Kubernetes Events on each Challenge (`Presented`,
`PresentError`, `CleanUpError`, "Waiting for DNS-01 challenge propagation").
Those cover the cert-manager side of the flow; the webhook logs now cover
the DNS side. `kubectl describe challenge -A` plus the webhook logs give the
full picture. Events expire after an hour, webhook logs do not.

## 5. Deployment changes (Helm chart)

- Role in the release namespace: `leases` (get, create, update),
  `configmaps` (get, list, create, update), bound to the webhook service
  account. The chart already grants the secret read.
- Optional ClusterRole for `challenges` and `orders` (get, list) when
  `triggerContext.enabled`.
- Downward API env `POD_NAME` and `POD_NAMESPACE`.
- New values: `ownAcmeRecords`, `sweepInterval`, `maxRecordAge`,
  `lockWaitTimeout`, `triggerContext.enabled`, passed as env vars.
- The chart's replica count stays at 2.

## 6. Testing

- Pure unit tests for the payload rule (stale reads in both directions,
  foreign records kept or dropped by option, no-op detection).
- Lock tests against the fake Kubernetes client with a reactor that enforces
  resourceVersion conflicts, covering contention, expiry take-over, release
  of own lease only, and wait timeout.
- Reconciler tests with an in-memory DNS API that can serve stale reads,
  covering Present, CleanUp, retry-repairs-lost-record, sweep removing
  leftovers, and age expiry.
- Existing solver tests adapted to the new reconciler seam.
- The conformance suite stays as is (build tag `conformance`).

## 7. Rollout

1. Merge, tag, let the release workflow publish image and chart.
2. `helm upgrade` with the new chart (needs approval, it changes RBAC).
3. The startup sweep removes the seven leftovers. Verify with the mijn.host
   API GET and the webhook logs.
4. Trigger one staging certificate to watch a full Present/CleanUp cycle in
   the logs.
