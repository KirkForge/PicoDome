# Runbook: Certificate Rotation for Admission Controller

## Overview

The IronDome admission controller requires a TLS certificate to serve the validating webhook. Kubernetes validates the webhook's CA bundle, so certificate rotation must update both the TLS secret and the webhook's `caBundle`.

With cert-manager, this process is largely automatic. This runbook covers both automated and manual rotation.

## Certificate lifecycle

| Phase | Duration | Action |
|---|---|---|
| Issued | 0–80% of duration | No action needed |
| Renewal window | Last 20% of duration | cert-manager auto-renews |
| Pod reload | Within minutes of renew | Pod picks up new cert from mounted secret |
| CA bundle update | Within minutes of renew | cert-manager inject-ca-from annotation updates webhook |

## Automated rotation (cert-manager)

### Configuration

The Helm chart configures cert-manager via `values.yaml`:

```yaml
tls:
  certManager:
    enabled: true
    issuerRef:
      name: selfsigned    # or your ClusterIssuer
      kind: ClusterIssuer
```

The `certificate.yaml` template sets:

```yaml
spec:
  duration: 8760h    # 1 year
  renewBefore: 720h  # 30 days before expiry
```

### How auto-rotation works

1. cert-manager monitors the `Certificate` CRD
2. When `renewBefore` threshold is reached, cert-manager reissues the certificate
3. The new TLS cert is written to the same `Secret` (in-place update)
4. The `cert-manager.io/inject-ca-from` annotation on the `ValidatingWebhookConfiguration` triggers CA bundle injection
5. The admission controller pod reloads the cert from the mounted volume

### Rolling update on cert renewal

When `certRotation.rollingUpdateOnRenew: true` (default):

- cert-manager annotates the Secret with `cert-manager.io/rotate-ca-in-ocp: "true"`
- A `Reloader` or annotation-based rollout trigger restarts the pods
- This ensures pods always serve the latest certificate

Without rolling updates, pods may serve stale certificates until manually restarted.

### Monitoring certificate expiry

```bash
# Check certificate status
kubectl get certificate -n <namespace> irondome-admission-cert -o yaml

# Check notAfter date
kubectl get secret irondome-admission-tls -n <namespace> -o jsonpath='{.data.tls\.crt}' | base64 -d | openssl x509 -noout -enddate

# Check renewal status
kubectl describe certificate -n <namespace> irondome-admission-cert
```

### Prometheus alert for certificate expiry

```yaml
- alert: IronDomeAdmissionCertExpiringSoon
  expr: cert_manager_certificate_expiration_timestamp_seconds{certificate="irondome-admission-cert"} - time() < 86400 * 14
  for: 1h
  labels:
    severity: warning
  annotations:
    summary: "IronDome admission certificate expires in less than 14 days"
```

## Manual rotation

Use this procedure if cert-manager is not available or cert-manager rotation fails.

### Step 1: Generate new certificate

```bash
# Generate CA key and cert (first time only)
openssl genrsa -out ca.key 4096
openssl req -new -x509 -days 3650 -key ca.key -out ca.crt -subj "/CN=IronDome Admission CA"

# Generate server key
openssl genrsa -out server.key 2048

# Generate CSR with SANs
cat > san.cnf << EOF
[req]
distinguished_name = req_distinguished_name
req_extensions = v3_req
prompt = no

[req_distinguished_name]
CN = irondome-admission

[v3_req]
subjectAltName = @alt_names

[alt_names]
DNS.1 = irondome-admission
DNS.2 = irondome-admission.irondome.svc
DNS.3 = irondome-admission.irondome.svc.cluster.local
EOF

openssl req -new -key server.key -out server.csr -config san.cnf -extensions v3_req

# Sign certificate
openssl x509 -req -days 365 -in server.csr -CA ca.crt -CAkey ca.key \
  -CAcreateserial -out server.crt -extensions v3_req -extfile san.cnf
```

### Step 2: Update TLS secret

```bash
kubectl create secret tls irondome-admission-tls \
  --namespace <namespace> \
  --cert=server.crt \
  --key=server.key \
  --dry-run=client -o yaml | kubectl apply -f -
```

### Step 3: Update webhook CA bundle

```bash
CA_BUNDLE=$(cat ca.crt | base64 | tr -d '\n')

kubectl patch validatingwebhookconfiguration irondome-admission \
  --type='json' \
  -p="[{"op":"replace","path":"/webhooks/0/clientConfig/caBundle","value":"${CA_BUNDLE}"}]"
```

### Step 4: Restart admission controller

```bash
kubectl rollout restart deployment -n <namespace> irondome-admission
```

### Step 5: Verify

```bash
# Check new cert is served
kubectl exec -n <namespace> -c admission <pod-name> -- \
  openssl s_client -connect localhost:8443 -showcerts </dev/null 2>/dev/null | \
  openssl x509 -noout -dates

# Test webhook
kubectl apply -f test-pod.yaml
```

## High-security rotation

For environments requiring short-lived certificates:

```yaml
# In values.yaml:
certRotation:
  duration: "720h"     # 30 days
  renewBefore: "168h"  # 7 days before expiry
```

Set up alerting to catch rotation failures early with shorter windows.

## Troubleshooting

| Symptom | Cause | Fix |
|---|---|---|
| `x509: certificate signed by unknown authority` | CA bundle mismatch | Update webhook `caBundle` with current CA |
| `tls: failed to verify certificate` | SAN mismatch | Regenerate cert with correct DNS SANs |
| `certificate expired` | Rotation failed | Manual rotation procedure above |
| Webhook down after cert-manager upgrade | Issuer ref broken | Verify `issuerRef` matches installed ClusterIssuer |
