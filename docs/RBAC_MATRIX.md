# RBAC Matrix and Tenant Model

## Tenant model

PicoDome supports a **namespace-scoped** multi-tenant model where each tenant is identified by a tenant ID. Tenant isolation is enforced at the application layer in the `TenantAwareScanJobStore`.

### Tenant scope levels

| Level | Isolation boundary | Use case |
|---|---|---|
| **Namespace** | Kubernetes namespace | Each tenant gets their own PicoDome deployment |
| **Cluster** | Shared deployment, tenant header | Multiple tenants share one deployment, isolated by `X-Tenant` header |
| **Organization** | Logical grouping across clusters | Enterprise accounts with multiple clusters |

### Default configuration

The Helm chart deploys with namespace-level isolation by default. For cluster-scoped multi-tenancy:

```yaml
# values.yaml
enterprise:
  enabled: true

auth:
  createSecret: true
```

### Tenant identity resolution

The tenant ID is resolved in the following order:

1. `X-Tenant` HTTP header (API requests)
2. Token-to-tenant mapping (configured in auth)
3. Default tenant (unauthenticated or single-tenant mode)

## RBAC matrix

PicoDome has three built-in roles:

### Role definitions

| Role | Scan | Read Results | Policy | Admin | Audit |
|---|---|---|---|---|---|
| **viewer** | ❌ | ✅ Own tenant | ❌ | ❌ | ✅ Own tenant (read-only) |
| **submitter** | ✅ | ✅ Own tenant | ❌ | ❌ | ✅ Own tenant (read-only) |
| **admin** | ✅ | ✅ All tenants | ✅ Create/Update/Rollback | ✅ Config/Keys | ✅ All tenants |

### Permission details

#### viewer

- `GET /api/v1/scan/:id` — Own tenant only
- `GET /api/v1/scans` — Own tenant only
- `GET /api/v1/policies` — Read-only
- `GET /api/v1/audit` — Own tenant only
- `GET /health`, `GET /ready` — Unauthenticated
- `GET /metrics` — Unauthenticated

#### submitter

- All viewer permissions, plus:
- `POST /api/v1/scan` — Submit scan jobs
- Scan results are tagged with the submitter's tenant ID

#### admin

- All submitter permissions, plus:
- `GET /api/v1/scan/:id` — Any tenant
- `GET /api/v1/scans` — Any tenant
- `POST /api/v1/policies` — Create/update policies
- `GET /api/v1/audit` — Any tenant
- `DELETE /api/v1/scan/:id` — Delete scan results
- `POST /api/v1/retention/trigger` — Trigger retention cleanup

### Kubernetes RBAC

The Helm chart creates a `Role` and `RoleBinding` with minimal permissions:

```yaml
rules:
  - apiGroups: [""]
    resources: ["configmaps"]
    verbs: ["get", "list"]
  - apiGroups: [""]
    resources: ["secrets"]
    verbs: ["get"]
    resourceNames: ["picodome-tokens", "picodome-tls"]
```

For the admission controller, the service account needs no special RBAC permissions — it only receives webhook calls from the Kubernetes API server.

### Token-to-role mapping

Tokens are mapped to roles via the `IRONDOME_API_TOKENS` environment variable or the tokens file:

```
# Format: token:role
picodome-admin-xxx:admin
picodome-submit-xxx:submitter
picodome-view-xxx:viewer
```

Or via Kubernetes Secret:

```yaml
apiVersion: v1
kind: Secret
metadata:
  name: picodome-tokens
data:
  api-tokens: <base64-encoded token list>
```

## Cross-tenant access prevention

The `TenantAwareScanJobStore` enforces:

1. **Write isolation**: Jobs are tagged with the tenant ID at creation
2. **Read isolation**: `get()` and `list_recent()` filter by tenant ID
3. **Cross-tenant denial**: Attempting to access another tenant's data returns `None` / empty
4. **Audit logging**: Cross-tenant access attempts are logged with `WARNING` level

### Property-based isolation tests

The test suite (`tests/test_tenant_isolation.py`) includes property tests that verify:

- A tenant cannot read another tenant's scan results
- A tenant cannot modify another tenant's scan jobs
- Admin role can access all tenants' data
- Default tenant is used when no tenant header is provided
- Cross-tenant access attempts are logged in the audit trail

## Kubernetes namespace isolation

For strict isolation, deploy separate PicoDome instances per tenant namespace:

```yaml
# Tenant A
helm install picodome-tenant-a deploy/helm/picodome/ \
  --namespace tenant-a --set auth.createSecret=true

# Tenant B
helm install picodome-tenant-b deploy/helm/picodome/ \
  --namespace tenant-b --set auth.createSecret=true
```

With `NetworkPolicy` enabled, tenants cannot access each other's PicoDome instances.
