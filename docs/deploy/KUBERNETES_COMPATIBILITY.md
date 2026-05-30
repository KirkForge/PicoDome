# Kubernetes Compatibility Matrix

PicoDome is tested and supported on the following Kubernetes versions.

## Supported versions

| Kubernetes | PicoDome Daemon | PicoDome Admission Controller | Status |
|---|---|---|---|
| 1.27 | ✅ | ✅ | Supported |
| 1.28 | ✅ | ✅ | Supported |
| 1.29 | ✅ | ✅ | Supported |
| 1.30 | ✅ | ✅ | Supported |
| 1.31 | ✅ | ✅ | Supported |
| 1.32 | ✅ | ✅ | Supported |

## Versioning policy

- **N-2 support**: PicoDome supports the 2 most recent Kubernetes minor versions plus the current release.
- **Deprecated API versions**: PicoDome uses `admissionregistration.k8s.io/v1` (stable since K8s 1.19). No `v1beta1` usage.
- **API deprecation notice**: If Kubernetes removes an API version that PicoDome depends on, we will announce migration guidance at least one release cycle before dropping support.

## Required cluster add-ons

| Add-on | Version | Required for | Notes |
|---|---|---|---|
| cert-manager | ≥ 1.11 | Admission controller TLS | Required if `tls.certManager.enabled=true` |
| metrics-server | ≥ 0.6 | HPA autoscaling | Required if `autoscaling.enabled=true` |
| Prometheus | ≥ 2.40 | Metrics scraping | Required for `/metrics` endpoint |
| CoreDNS | ≥ 1.9 | Service discovery | Standard in all supported K8s versions |

## Admission controller API compatibility

PicoDome's admission webhook uses:

- `admissionregistration.k8s.io/v1` — `ValidatingWebhookConfiguration`
- `admissionReviewVersions: ["v1"]`

The webhook does **not** use any beta or alpha Kubernetes APIs.

## Helm chart compatibility

| Chart | Helm Version | K8s Version |
|---|---|---|
| picodome | ≥ 3.12 | ≥ 1.27 |
| picodome-admission | ≥ 3.12 | ≥ 1.27 |

## Breaking changes policy

- **Patch releases** (0.5.x): No K8s compatibility changes.
- **Minor releases** (0.x.0): May drop support for the oldest K8s version, with release notes.
- **Major releases** (x.0.0): May change minimum K8s version with migration guide.

## Testing

PicoDome's CI tests against the Kubernetes versions listed above using `kind` (Kubernetes IN Docker) clusters. The admission controller integration test suite validates webhook registration, certificate provisioning, and pod validation across all supported versions.
