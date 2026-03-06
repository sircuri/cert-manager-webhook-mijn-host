# cert-manager-webhook-mijn-host — Project Specification

> A DNS01 ACME webhook solver for cert-manager, enabling wildcard TLS certificates via the mijn.host DNS API.

---

## 1. Goal & Context

### Problem

cert-manager's default HTTP-01 ACME challenge requires a per-subdomain certificate request. Every cert issued for a subdomain (e.g. `mr-120.developer.mydomain.nl`) creates a permanent, publicly searchable entry in Certificate Transparency (CT) logs. Bots scrape CT logs in near real-time and immediately start probing newly discovered hostnames.

### Solution

A single wildcard cert (`*.developer.mydomain.nl`) resolves this: one CT log entry regardless of how many ephemeral environments are deployed. Wildcard certs require DNS-01 challenge, which in turn requires cert-manager to manipulate DNS records via a provider-specific webhook.

mijn.host is not a supported provider today. This project adds that support as a community webhook.

---

## 2. Reference Material

| Source | URL | Purpose |
|--------|-----|---------|
| mijn.host DNS API | `https://mijn.host/api/doc/` | Authoritative API reference |
| certbot-dns-mijn-host | `https://github.com/mijnhost/certbot-dns-mijn-host` | Official Python plugin, reference for API behaviour |
| libdns/mijnhost | `https://github.com/libdns/mijnhost` | Existing Go API wrapper — **use as the API client** |
| cert-manager webhook-example | `https://github.com/cert-manager/webhook-example` | Interface contract and boilerplate structure |
| cert-manager-webhook-transip | `https://github.com/demeesterdev/cert-manager-webhook-transip` | Best-in-class community webhook — use as structural reference |
| cert-manager DNS01 webhook docs | `https://cert-manager.io/docs/configuration/acme/dns01/webhook/` | Integration contract |

---

## 3. Key Discovery: libdns/mijnhost

There is already a Go package that wraps the mijn.host API in a clean interface:

```
github.com/libdns/mijnhost
```

It implements `GetRecords`, `AppendRecords`, `SetRecords`, and `DeleteRecords` against `https://mijn.host/api/v2`. **This means you do not need to write a raw HTTP client.** You import this package and call it from the webhook solver.

---

## 4. mijn.host API Behaviour

### Authentication

All requests carry an `API-Key` header. The key is obtained from the mijn.host control panel.

```
API-Key: <your-api-key>
```

### Critical limitation: PUT replaces all records

The mijn.host DNS API uses a **full-replace model** for the primary PUT endpoint:

```
PUT /api/v2/domains/{domain}/dns
```

This replaces **all** DNS records in the zone. This means `Present()` and `CleanUp()` must:

1. **GET** the current full record set
2. **Modify** it in memory (add or remove the TXT record)
3. **PUT** the modified full record set back

A PATCH endpoint also exists for updating a single record:

```
PATCH /api/v2/domains/{domain}/dns
```

However, there is no atomic "add single record" endpoint. The safest approach is GET → modify → PUT, as used by the certbot plugin. The `libdns/mijnhost` package already handles this correctly.

### Relevant endpoints

| Method | Path | Purpose |
|--------|------|---------|
| GET | `/api/v2/domains/{domain}/dns` | Fetch all DNS records |
| PUT | `/api/v2/domains/{domain}/dns` | Replace all DNS records |
| PATCH | `/api/v2/domains/{domain}/dns` | Update a single record |

### TXT record format for ACME challenge

```json
{
  "type": "TXT",
  "name": "_acme-challenge.subdomain.",
  "value": "<token-from-cert-manager>",
  "ttl": 300
}
```

Note the trailing dot in the `name` field — this is required by the mijn.host API.

---

## 5. Repository Structure

```
cert-manager-webhook-mijn-host/
├── main.go                          # Webhook entrypoint, wires solver into cert-manager
├── solver.go                        # Core solver: Present(), CleanUp(), Initialize(), Name()
├── config.go                        # Config struct, JSON unmarshalling from ClusterIssuer spec
├── mijnhost/
│   └── client.go                    # Thin wrapper around libdns/mijnhost, exposes AddTXTRecord / RemoveTXTRecord
├── testdata/
│   └── mijn-host/
│       ├── config.json              # Test config (gitignored values, template committed)
│       └── secret.yaml              # API key secret for integration tests
├── deploy/
│   └── mijn-host-webhook/           # Helm chart
│       ├── Chart.yaml
│       ├── values.yaml
│       └── templates/
│           ├── deployment.yaml
│           ├── service.yaml
│           ├── serviceaccount.yaml
│           ├── rbac.yaml            # Role + RoleBinding to read API key Secret
│           ├── pki.yaml             # Self-signed CA + serving cert for webhook TLS
│           └── apiservice.yaml      # Registers webhook with cert-manager
├── Dockerfile
├── Makefile
├── go.mod
├── go.sum
├── LICENSE                          # Apache 2.0
└── README.md
```

---

## 6. The Solver Interface

cert-manager requires implementing this Go interface (`github.com/cert-manager/cert-manager/pkg/acme/webhook`):

```go
type Solver interface {
    Name() string
    Present(ch *acme.ChallengeRequest) error
    CleanUp(ch *acme.ChallengeRequest) error
    Initialize(kubeClientConfig *rest.Config, stopCh <-chan struct{}) error
}
```

### 6.1 Name()

```go
func (s *Solver) Name() string {
    return "mijn-host"
}
```

### 6.2 Initialize()

Called once at webhook startup. Store the Kubernetes client for later Secret lookups.

```go
func (s *Solver) Initialize(kubeClientConfig *rest.Config, stopCh <-chan struct{}) error {
    cl, err := kubernetes.NewForConfig(kubeClientConfig)
    if err != nil {
        return err
    }
    s.kubeClient = cl
    return nil
}
```

### 6.3 Present()

Called when cert-manager needs to place the DNS-01 TXT challenge record.

```
_acme-challenge.<domain>  TXT  <key>
```

Logic:
1. Parse config from `ch.Config`
2. Read API key from Kubernetes Secret referenced in config
3. Determine zone root from `ch.ResolvedZone` (e.g. `mydomain.nl`)
4. Determine record name from `ch.ResolvedFQDN` (e.g. `_acme-challenge.developer.mydomain.nl`)
5. Call `libdns/mijnhost` AppendRecords to add the TXT record
6. Return nil or error

**Important:** `Present()` must be idempotent — cert-manager may call it multiple times for the same challenge.

### 6.4 CleanUp()

Called after challenge verification (success or failure). Removes the TXT record.

Logic:
1. Parse config and read API key (same as Present)
2. Call `libdns/mijnhost` DeleteRecords matching the TXT record name and value
3. Return nil or error

**Important:** If the record is already gone, CleanUp must not return an error.

---

## 7. Configuration Design

### Config struct (config.go)

```go
type Config struct {
    // TTL for the TXT record in seconds. Default: 300.
    TTL int `json:"ttl"`

    // Reference to the Kubernetes Secret containing the API key.
    APIKeySecretRef SecretRef `json:"apiKeySecretRef"`
}

type SecretRef struct {
    Name string `json:"name"`
    Key  string `json:"key"`
}
```

### ClusterIssuer example

```yaml
apiVersion: cert-manager.io/v1
kind: ClusterIssuer
metadata:
  name: letsencrypt-prod
spec:
  acme:
    email: you@example.com
    server: https://acme-v02.api.letsencrypt.org/directory
    privateKeySecretRef:
      name: letsencrypt-prod-key
    solvers:
    - dns01:
        webhook:
          groupName: acme.mijn.host
          solverName: mijn-host
          config:
            ttl: 300
            apiKeySecretRef:
              name: mijnhost-api-key
              key: api-key
```

### API Key Secret

```yaml
apiVersion: v1
kind: Secret
metadata:
  name: mijnhost-api-key
  namespace: cert-manager
type: Opaque
stringData:
  api-key: "your-mijn-host-api-key-here"
```

---

## 8. Helm Chart Design

The Helm chart handles all Kubernetes resources. Key design decisions, taken from the TransIP webhook as a model:

### values.yaml defaults

```yaml
groupName: acme.mijn.host

image:
  repository: ghcr.io/<your-github-username>/cert-manager-webhook-mijn-host
  tag: latest
  pullPolicy: IfNotPresent

certManager:
  namespace: cert-manager
  serviceAccountName: cert-manager

secretName: mijnhost-api-key
```

### RBAC (rbac.yaml)

The webhook pod needs permission to read the API key Secret. A Role + RoleBinding scoped to the cert-manager namespace is the correct pattern — not a ClusterRole. This is the locked-down approach used by the TransIP webhook.

```yaml
apiVersion: rbac.authorization.k8s.io/v1
kind: Role
metadata:
  name: {{ include "webhook.fullname" . }}:secret-reader
  namespace: cert-manager
rules:
- apiGroups: [""]
  resources: ["secrets"]
  resourceNames: ["{{ .Values.secretName }}"]
  verbs: ["get", "watch"]
```

### PKI (pki.yaml)

cert-manager itself is used to issue the webhook's serving certificate (self-signed within the cluster). This is the standard pattern:

1. A self-signed `Issuer` in the cert-manager namespace
2. A `Certificate` for the webhook's serving TLS
3. The `APIService` references the CA bundle via a `caBundle` annotation managed by cert-manager's `cainjector`

---

## 9. Testing Strategy

This is where most community webhooks fall short. This project will do it properly.

### 9.1 Unit tests (no cluster needed)

Mock the mijn.host API with an `httptest.Server`. Test:

- `Present()` correctly constructs the TXT record name
- `Present()` handles the trailing dot requirement
- `Present()` is idempotent when called twice
- `CleanUp()` removes only the matching TXT record, leaving others intact
- `CleanUp()` does not error when the record is already absent
- Config parsing handles missing fields with sane defaults
- API errors are propagated correctly

### 9.2 Conformance tests (requires a real domain + API key)

cert-manager provides a conformance test suite that all DNS01 webhooks must pass:

```go
// In suite_test.go
var _ = BeforeSuite(func() {
    f.SetupOrDie()
})

func TestConformance(t *testing.T) {
    fixture := dns.NewFixture(&mijnHostSolver{},
        dns.SetResolvedZone("mydomain.nl."),
        dns.SetAllowAmbientCredentials(false),
        dns.SetManifestPath("testdata/mijn-host"),
    )
    fixture.RunConformance(t)
}
```

Run with:

```bash
TEST_ZONE_NAME=mydomain.nl. make test
```

The test will add and remove a real TXT record against your mijn.host zone. This requires:

- `testdata/mijn-host/config.json` with your account config
- `testdata/mijn-host/secret.yaml` with your API key (never commit the real key)

### 9.3 Local end-to-end (kind cluster)

For full end-to-end testing without touching production:

```bash
# Start a local cluster
kind create cluster

# Install cert-manager
helm install cert-manager jetstack/cert-manager \
  --namespace cert-manager --create-namespace \
  --set installCRDs=true

# Build and load the webhook image locally
docker build -t cert-manager-webhook-mijn-host:dev .
kind load docker-image cert-manager-webhook-mijn-host:dev

# Install the webhook chart
helm install mijn-host-webhook ./deploy/mijn-host-webhook \
  --namespace cert-manager \
  --set image.repository=cert-manager-webhook-mijn-host \
  --set image.tag=dev

# Apply a ClusterIssuer and test Certificate
kubectl apply -f examples/clusterissuer.yaml
kubectl apply -f examples/certificate.yaml
kubectl describe certificate test-wildcard -n cert-manager
```

---

## 10. CI/CD (GitHub Actions)

### Workflows

**`.github/workflows/test.yml`** — runs on every push and PR:
```
- go vet
- go test ./... (unit tests only, no real API key needed)
- golangci-lint
```

**`.github/workflows/release.yml`** — runs on tag push (`v*`):
```
- Run full test suite
- docker buildx build (amd64 + arm64)
- Push to ghcr.io
- helm package
- Publish Helm chart to GitHub Pages (gh-pages branch)
```

### Multi-arch builds

```dockerfile
FROM --platform=$BUILDPLATFORM golang:1.22 AS builder
ARG TARGETOS TARGETARCH
RUN GOOS=$TARGETOS GOARCH=$TARGETARCH go build -o webhook .

FROM gcr.io/distroless/static:nonroot
COPY --from=builder /app/webhook /webhook
USER nonroot:nonroot
ENTRYPOINT ["/webhook"]
```

Use `distroless/static:nonroot` as the base — rootless, read-only filesystem, no shell. This matches the security posture of the TransIP webhook.

---

## 11. Development Phases

### Phase 1 — Skeleton & API client (Day 1)

- [ ] Create GitHub repo `cert-manager-webhook-mijn-host`
- [ ] Copy structure from `demeesterdev/cert-manager-webhook-transip` as scaffold
- [ ] Replace TransIP references with mijn.host throughout
- [ ] Import `github.com/libdns/mijnhost` as the API client
- [ ] Implement `mijnhost/client.go` wrapper with `AddTXTRecord` and `RemoveTXTRecord`
- [ ] Write unit tests for the client wrapper using `httptest.Server`

### Phase 2 — Solver implementation (Day 1–2)

- [ ] Implement `config.go` with JSON parsing and defaults
- [ ] Implement `solver.go` — all four interface methods
- [ ] Wire up `main.go`
- [ ] Run `go build` clean

### Phase 3 — Tests (Day 2)

- [ ] Unit tests for Present/CleanUp edge cases
- [ ] Configure conformance test suite
- [ ] Run conformance tests against a real mijn.host test domain
- [ ] Fix any issues found

### Phase 4 — Helm chart & deployment (Day 3)

- [ ] Write Helm chart templates
- [ ] Test full deploy on kind cluster
- [ ] Write `examples/` directory with working ClusterIssuer and Certificate manifests

### Phase 5 — Polish & release (Day 3–4)

- [ ] Write README (see Section 12)
- [ ] Set up GitHub Actions
- [ ] Tag v0.1.0
- [ ] Publish to `github.com/topics/cert-manager-webhook` (add topic to repo)
- [ ] Open a PR or issue on the cert-manager docs to list it as a community webhook

---

## 12. README Structure

The README is a first-class deliverable. Based on gaps seen in other webhooks, it must include:

1. **What this is and why you need it** (the CT log problem, one paragraph)
2. **Prerequisites** (cert-manager installed, mijn.host API key, Helm)
3. **Installation** — Helm commands, copy-pasteable
4. **Configuration** — full working ClusterIssuer and Secret YAML
5. **Requesting a wildcard certificate** — full Certificate manifest example
6. **Testing locally** — kind-based walkthrough
7. **Running the conformance tests** — step by step
8. **Troubleshooting** — common errors (TLS handshake, RBAC, propagation delay)
9. **Contributing**

---

## 13. Known Pitfalls to Avoid

| Pitfall | Mitigation |
|---------|-----------|
| mijn.host PUT replaces all records | Always GET first, modify in memory, then PUT. Use libdns/mijnhost which handles this. |
| Trailing dot in record names | mijn.host requires `_acme-challenge.domain.nl.` — strip or normalise carefully |
| Propagation delay | Default TTL 300s is fine; consider a note in README about `--dns01-recursive-nameservers` for split-brain DNS |
| cert-manager calls Present() multiple times | Implement idempotency check: if TXT record with same value already exists, return nil |
| Webhook TLS bootstrapping | Use pki.yaml pattern from TransIP webhook — cert-manager cainjector handles this cleanly |
| API key permissions | Scope to only DNS operations in mijn.host control panel |
| Namespace scoping | The webhook should only be able to read its own Secret — use Role, not ClusterRole |

---

## 14. Versioning & Maintenance Commitment

- Semantic versioning: `v0.1.0` for initial release
- Go dependency updates via Dependabot
- cert-manager compatibility: target v1.12+ (current stable)
- Multi-arch: `linux/amd64` and `linux/arm64` from day one

---

*Generated: March 2026 — based on mijn.host API v2, cert-manager v1.14, libdns/mijnhost Go package*
