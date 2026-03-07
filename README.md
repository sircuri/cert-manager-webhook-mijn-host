<a href="https://mijn.host" target="_blank">
    <center>
        <img src="https://assets.eu.apidog.com/app/apidoc-image/custom/20240626/f1508b02-a360-4b89-b7a9-b939a9180c0e.png"
        alt="mijn.host"
        />
    </center>
</a>

# cert-manager-webhook-mijn-host

A [cert-manager](https://cert-manager.io/) webhook solver for [mijn.host](https://mijn.host/) DNS.
It lets cert-manager automatically obtain wildcard and SAN certificates from
Let's Encrypt (or any ACME CA) by completing DNS-01 challenges through the
mijn.host API. Wildcard certificates require DNS-01 validation and are never
logged to Certificate Transparency logs, keeping internal hostnames private.

---

> **Note — use at your own risk**
>
> This project is functional but still maturing. Use it at your own risk.
>
> **How the mijn.host API works**
>
> The mijn.host API does not support adding or deleting individual DNS records.
> Every update is a read-modify-write cycle: the webhook fetches all records for
> the zone, applies the change in memory, and writes the entire record set back.
> This means a bug or unexpected API response could potentially affect other
> records in the zone.
>
> **Recommendation:** test with Let's Encrypt staging first, and keep a backup
> of your DNS zone before using this webhook in production.

---

## Prerequisites

- A Kubernetes cluster (v1.24+)
- [cert-manager](https://cert-manager.io/docs/installation/) v1.12+ installed
- [Helm](https://helm.sh/docs/intro/install/) v3
- A [mijn.host](https://mijn.host/) account with an API key

## Installation

Add the Helm repository and install the webhook:

```bash
helm repo add mijn-host https://sircuri.github.io/cert-manager-webhook-mijn-host
helm repo update
helm install mijn-host-webhook mijn-host/mijn-host-webhook \
  --namespace cert-manager
```

To customize settings (e.g. secret name), pass `--set` flags or provide a
custom `values.yaml`:

```bash
helm install mijn-host-webhook mijn-host/mijn-host-webhook \
  --namespace cert-manager \
  --values my-values.yaml
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

### 2. Create a ClusterIssuer

It is recommended to start with Let's Encrypt **staging** to verify everything
works before switching to production:

```yaml
apiVersion: cert-manager.io/v1
kind: ClusterIssuer
metadata:
  name: letsencrypt-staging
spec:
  acme:
    email: your-email@example.com
    server: https://acme-staging-v02.api.letsencrypt.org/directory
    privateKeySecretRef:
      name: letsencrypt-staging-account-key
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

Once staging works, create a production issuer by changing the server URL and
secret name:

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

Monitor progress:

```bash
kubectl describe certificate wildcard-example-com -n default
kubectl describe order -n default
kubectl describe challenge -n default
```

### Known limitation: concurrent challenges

When a certificate includes both a wildcard and a bare domain (e.g.
`*.example.com` and `example.com`), cert-manager creates two DNS-01 challenges
for the same `_acme-challenge` TXT record. Because the mijn.host API replaces
the entire record set on every write, concurrent challenge updates can
occasionally overwrite each other, causing the first attempt to fail.

cert-manager will automatically retry with a new order after a backoff period
(up to an hour), and the retry typically succeeds. If you don't want to wait,
you can speed things up by deleting and recreating the Certificate resource:

```bash
kubectl delete certificate <name> -n <namespace>
kubectl apply -f certificate.yaml
```

## Development

### Running unit tests

```bash
go test ./...
```

### Testing locally with kind

You can test the full flow locally using [kind](https://kind.sigs.k8s.io/).
This builds the image from source and installs the chart from the local checkout.

#### 1. Create a kind cluster

```bash
kind create cluster --name webhook-test
```

#### 2. Install cert-manager

```bash
helm repo add jetstack https://charts.jetstack.io --force-update
helm install cert-manager jetstack/cert-manager \
  --namespace cert-manager --create-namespace \
  --set crds.enabled=true
```

#### 3. Build and load the webhook image

```bash
docker build -t mijn-host-webhook:dev .
kind load docker-image mijn-host-webhook:dev --name webhook-test
```

#### 4. Install the webhook from the local chart

```bash
helm install mijn-host-webhook ./deploy/mijn-host-webhook \
  --namespace cert-manager \
  --set image.repository=mijn-host-webhook \
  --set image.tag=dev \
  --set image.pullPolicy=Never
```

#### 5. Apply the Secret, ClusterIssuer, and Certificate

```bash
kubectl apply -f examples/secret.yaml    # edit with your real API key first
kubectl apply -f examples/clusterissuer.yaml
kubectl apply -f examples/certificate.yaml
```

#### 6. Verify

```bash
kubectl get certificate -A
kubectl get challenges -A
```

#### Cleanup

```bash
kind delete cluster --name webhook-test
```

### Running conformance tests

The cert-manager conformance test suite exercises `Present` and `CleanUp`
against the real mijn.host API. Use a dedicated test domain — not one with
important DNS records.

```bash
TEST_ZONE_NAME=yourtestdomain.nl. go test -tags=conformance -v -run TestConformance
```

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
