# Runbook: Admission Webhook Outage

## Severity: **Critical**

The IronDome admission webhook is a `ValidatingWebhookConfiguration` that intercepts pod creation and update requests. If the webhook service becomes unavailable, the behavior depends on the configured `failurePolicy`.

## Failure policy tradeoffs

| Policy | When webhook is down | Risk | Recommended for |
|---|---|---|---|
| `Fail` | All pod creations/updates are **blocked** | Cluster-wide outage — no workloads can start | High-security clusters where unauthorized pods are unacceptable |
| `Ignore` | Pod creations/updates **succeed** without validation | Unvalidated pods may run (security gap) | Availability-first clusters where uptime is more critical than policy enforcement |
| `Fail` with namespace exclusions | Pod creation blocked only in protected namespaces | Balanced — critical namespaces protected, others available | Most production environments |

## Symptoms

- `kubectl apply` or `kubectl create` for pods returns: `Internal error occurred: failed calling webhook ... Post "https://...": dial tcp ...: connect: connection refused`
- Pod events show `FailedScheduling` or webhook timeout errors
- Admission controller pods show `CrashLoopBackOff`, `OOMKilled`, or 0 ready replicas

## Diagnosis

### Step 1: Check webhook configuration

```bash
kubectl get validatingwebhookconfiguration irondome-admission -o yaml
```

Verify:
- `failurePolicy` matches your intended policy
- `webhooks[].clientConfig.service` points to the correct namespace and port
- `namespaceSelector` excludes system namespaces if needed

### Step 2: Check admission controller pods

```bash
kubectl get pods -n <irondome-namespace> -l app.kubernetes.io/name=irondome-admission
```

Look for:
- 0/1 ready replicas
- CrashLoopBackOff
- OOMKilled
- ImagePullBackOff

### Step 3: Check admission controller logs

```bash
kubectl logs -n <irondome-namespace> -l app.kubernetes.io/name=irondome-admission --tail=100
```

Common errors:
- `tls.crt: no such file` → TLS certificate missing
- `connection refused` → Daemon backend unreachable
- `OOMKilled` → Increase memory limits

### Step 4: Check TLS certificate

```bash
kubectl get secret -n <irondome-namespace> irondome-admission-tls -o yaml
```

Verify `tls.crt` and `tls.key` are present and not empty.

### Step 5: Check service connectivity

```bash
kubectl run curl-test --image=curlimages/curl -it --rm -- \
  curl -sk https://irondome-admission.<namespace>.svc:443/healthz
```

## Remediation

### Immediate: Unblock cluster (emergency break-glass)

If the webhook is blocking all pod creation and you need to restore cluster function immediately:

1. **Delete the webhook configuration** (most aggressive):
   ```bash
   kubectl delete validatingwebhookconfiguration irondome-admission
   ```
   ⚠️ This removes all pod security validation until re-installed.

2. **Switch to Ignore policy** (preserves config):
   ```bash
   kubectl patch validatingwebhookconfiguration irondome-admission \
     --type='json' -p='[{"op":"replace","path":"/webhooks/0/failurePolicy","value":"Ignore"}]'
   ```
   ⚠️ Pods will be created without validation until the webhook recovers.

3. **Exclude critical namespaces** (surgical):
   ```bash
   kubectl patch validatingwebhookconfiguration irondome-admission \
     --type='json' -p='[{"op":"replace","path":"/webhooks/0/namespaceSelector","value":{"matchExpressions":[{"key":"irondome-scan","operator":"In","values":["enabled"]}]}}]'
   ```
   Only namespaces with label `irondome-scan=enabled` will be validated.

### Fix: Restart admission controller

```bash
kubectl rollout restart deployment -n <irondome-namespace> irondome-admission
```

### Fix: Re-provision TLS certificate

If cert-manager is installed:
```bash
kubectl annotate certificate -n <irondome-namespace> irondome-admission-cert \
  cert-manager.io/issue-incoming-request-
kubectl annotate certificate -n <irondome-namespace> irondome-admission-cert \
  cert-manager.io/issue-incoming-request=
```

### Fix: Re-install webhook via Helm

```bash
helm upgrade irondome-admission deploy/helm/irondome-admission/ \
  --namespace <irondome-namespace> --reuse-values
```

## Prevention

1. **Always deploy 2+ replicas** with PDB `minAvailable: 1`
2. **Use `Ignore` policy in dev/staging** and `Fail` only in production
3. **Exclude `kube-system` and critical namespaces** from webhook matching
4. **Monitor webhook latency and error rate** via Prometheus alerts
5. **Test cert rotation** before certificates approach expiry
6. **Set resource requests/limits** to prevent OOM kills
7. **Use `startupProbe`** with longer initial delay for slow-starting environments

## Escalation

1. Check #irondome-alerts Slack channel
2. Page on-call if cluster-wide pod creation is blocked for > 5 minutes
3. If break-glass applied, file incident and schedule policy re-enforcement
