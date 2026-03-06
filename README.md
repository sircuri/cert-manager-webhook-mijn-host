# cert-manager-webhook-mijn-host

A [cert-manager](https://cert-manager.io/) webhook solver for [mijn.host](https://mijn.host/) DNS.
It lets cert-manager automatically obtain wildcard and SAN certificates from
Let's Encrypt (or any ACME CA) by completing DNS-01 challenges through the
mijn.host API. Wildcard certificates require DNS-01 validation and are never
logged to Certificate Transparency logs, keeping internal hostnames private.

---

> **WARNING — WORK IN PROGRESS — USE AT YOUR OWN RISK**
>
> This project is in active development and is **not yet considered stable**.
> There are no guarantees of correctness or safety. **Use it at your own risk.**
>
> **Important: how the mijn.host API works (and why you should care)**
>
> The mijn.host API **does not support adding, modifying, or deleting individual
> DNS records**. Instead, every update works like this:
>
> 1. **Read** — the webhook fetches *all* DNS records for the zone from
>    mijn.host.
> 2. **Modify in memory** — the required change (e.g. adding or removing an
>    ACME challenge TXT record) is applied in memory using the Go DNS library.
> 3. **Write back** — the *entire* modified record set is pushed back to
>    mijn.host, **replacing all existing records**.
>
> This means that **if something goes wrong during the process — a bug, an
> unexpected API response, or a malformed record — you could lose DNS records
> for your entire zone**. There is no atomic "add one record" or "delete one
> record" operation; every write is a full overwrite.
>
> The authors of this project accept **no liability** for lost or corrupted DNS
> records. Make sure you have a backup of your DNS zone before using this
> webhook, and test thoroughly in a non-production environment first.

---

## Prerequisites

- A Kubernetes cluster (v1.24+)
- [cert-manager](https://cert-manager.io/docs/installation/) v1.12+ installed
- [Helm](https://helm.sh/docs/intro/install/) v3
- A [mijn.host](https://mijn.host/) account with an API key

## Installation

Add the webhook to your cluster using Helm:

```bash
helm install mijn-host-webhook ./deploy/mijn-host-webhook \
  --namespace cert-manager
```

To customize settings (e.g. image tag, secret name), pass `--set` flags or
provide a custom `values.yaml`:

```bash
helm install mijn-host-webhook ./deploy/mijn-host-webhook \
  --namespace cert-manager \
  --set image.tag=v0.1.0
```

## Configuration

### 1. Create the API key Secret

Store your mijn.host API key in a Kubernetes Secret in the `cert-manager`
namespace:

```yaml
apiVersion: v1
kind: Secret
metadata:
  name: mijn-host-api-key
  namespace: cert-manager
type: Opaque
stringData:
  api-key: "your-mijn-host-api-key-here"
```

Apply it:

```bash
kubectl apply -f examples/secret.yaml
```

### 2. Create a ClusterIssuer

Create a ClusterIssuer that uses Let's Encrypt with the mijn-host DNS solver:

```yaml
apiVersion: cert-manager.io/v1
kind: ClusterIssuer
metadata:
  name: letsencrypt-prod
spec:
  acme:
    email: your-email@example.com
    server: https://acme-v2.api.letsencrypt.org/directory
    privateKeySecretRef:
      name: letsencrypt-prod-account-key
    solvers:
      - dns01:
          webhook:
            groupName: acme.mijn-host.vanefferenonline.nl
            solverName: mijn-host
            config:
              apiKeySecretRef:
                name: mijn-host-api-key
                key: api-key
              ttl: 300
```

Apply it:

```bash
kubectl apply -f examples/clusterissuer.yaml
```

### Solver config reference

| Field | Type | Default | Description |
|-------|------|---------|-------------|
| `apiKeySecretRef.name` | string | *required* | Name of the Secret containing the API key |
| `apiKeySecretRef.key` | string | *required* | Key within the Secret |
| `ttl` | int | `300` | TTL in seconds for the DNS TXT record |

## Requesting a wildcard certificate

Create a Certificate resource referencing the ClusterIssuer:

```yaml
apiVersion: cert-manager.io/v1
kind: Certificate
metadata:
  name: wildcard-example-com
  namespace: default
spec:
  secretName: wildcard-example-com-tls
  issuerRef:
    name: letsencrypt-prod
    kind: ClusterIssuer
  dnsNames:
    - "*.example.com"
    - "example.com"
```

Apply it:

```bash
kubectl apply -f examples/certificate.yaml
```

Monitor progress:

```bash
kubectl describe certificate wildcard-example-com -n default
kubectl describe order -n default
kubectl describe challenge -n default
```

## Testing locally

You can test the full flow locally using [kind](https://kind.sigs.k8s.io/).

### 1. Create a kind cluster

```bash
kind create cluster --name webhook-test
```

### 2. Install cert-manager

```bash
helm repo add jetstack https://charts.jetstack.io --force-update
helm install cert-manager jetstack/cert-manager \
  --namespace cert-manager --create-namespace \
  --set crds.enabled=true
```

### 3. Build and load the webhook image

```bash
docker build -t mijn-host-webhook:dev .
kind load docker-image mijn-host-webhook:dev --name webhook-test
```

### 4. Install the webhook

```bash
helm install mijn-host-webhook ./deploy/mijn-host-webhook \
  --namespace cert-manager \
  --set image.repository=mijn-host-webhook \
  --set image.tag=dev \
  --set image.pullPolicy=Never
```

### 5. Apply the Secret, ClusterIssuer, and Certificate

```bash
kubectl apply -f examples/secret.yaml    # edit with your real API key first
kubectl apply -f examples/clusterissuer.yaml
kubectl apply -f examples/certificate.yaml
```

### 6. Verify

```bash
kubectl get certificate -A
kubectl get challenges -A
```

### Cleanup

```bash
kind delete cluster --name webhook-test
```

## Running conformance tests

The cert-manager project provides a conformance test suite for webhook solvers.

### 1. Clone and prepare

```bash
git clone https://github.com/cert-manager/cert-manager.git
cd cert-manager
```

### 2. Set up test fixtures

Create a `testdata/` directory in the webhook project with the required fixture
files for the solver conformance suite. Refer to the
[cert-manager webhook testing docs](https://cert-manager.io/docs/configuration/acme/dns01/webhook/#running-the-test-suite)
for the expected structure.

### 3. Run the tests

```bash
go test -v ./... -run TestRunsSuite
```

The suite will exercise `Present` and `CleanUp` against a real or simulated DNS
provider. Ensure your API key is configured for the test environment.

## Troubleshooting

### TLS handshake errors

```
remote error: tls: internal error
```

The webhook's serving certificate may not be ready yet. Check that cert-manager
has issued the internal TLS certificate:

```bash
kubectl get certificate -n cert-manager
kubectl describe certificate -n cert-manager
```

If the certificate is not `Ready`, check the cert-manager controller logs:

```bash
kubectl logs -n cert-manager -l app.kubernetes.io/name=cert-manager
```

### RBAC / forbidden errors

```
secrets "mijn-host-api-key" is forbidden
```

The webhook needs permission to read the API key Secret in the `cert-manager`
namespace. Verify the Role and RoleBinding exist:

```bash
kubectl get role -n cert-manager | grep secret-reader
kubectl get rolebinding -n cert-manager | grep secret-reader
```

If missing, ensure you installed the Helm chart (which creates RBAC resources
automatically). If using a custom `secretName` in `values.yaml`, make sure it
matches the actual Secret name.

### DNS propagation delay

cert-manager may report the challenge as failed if the DNS record hasn't
propagated before verification. The default TTL is 300 seconds. You can:

- Wait and let cert-manager retry automatically
- Lower the `ttl` value in the solver config (minimum depends on your DNS
  provider)
- Check that the TXT record was actually created:

```bash
dig TXT _acme-challenge.example.com
```

### Webhook not reachable

```
failed calling webhook
```

Verify the webhook pod is running and the Service is correctly configured:

```bash
kubectl get pods -n cert-manager -l app.kubernetes.io/name=mijn-host-webhook
kubectl get svc -n cert-manager
kubectl get apiservice v1alpha1.acme.mijn-host.vanefferenonline.nl
```

The APIService should show `Available: True`. If not, check that the
`cert-manager.io/inject-ca-from` annotation on the APIService points to the
correct Certificate resource.

## Contributing

Contributions are welcome! To get started:

1. Fork the repository
2. Create a feature branch (`git checkout -b feature/my-change`)
3. Make your changes and add tests where applicable
4. Run `go test ./...` to verify
5. Commit and open a pull request

Please follow the existing code style and ensure all tests pass before
submitting.
