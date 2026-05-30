# Enterprise Identity Provider Integration

PicoDome supports mapping enterprise identity provider (IdP) groups to internal RBAC roles. This enables Single Sign-On (SSO) with Okta, Azure AD, Ping Identity, and other OIDC/SAML providers through Kubernetes-native authentication.

## Architecture

```
┌──────────┐     ┌─────────────────────┐     ┌──────────────┐
│  IdP     │────▶│  Kubernetes API     │────▶│  PicoDome    │
│ (OIDC/   │     │  Server (oidc-      │     │  Daemon      │
│  SAML)   │     │  issuer flags)      │     │  (token auth)│
└──────────┘     └─────────────────────┘     └──────────────┘
                        │
                        ▼
                 ┌──────────────┐
                 │  Service     │
                 │  Account     │
                 │  (bound to   │
                 │   IdP group) │
                 └──────────────┘
```

## OIDC integration (recommended)

### Kubernetes API server configuration

Configure the Kubernetes API server to trust your OIDC provider:

```bash
# /etc/kubernetes/manifests/kube-apiserver.yaml
--oidc-issuer-url=https://login.example.com
--oidc-client-id=picodome-k8s
--oidc-username-claim=email
--oidc-groups-claim=groups
--oidc-ca-file=/etc/kubernetes/oidc-ca.pem
```

### Group-to-role mapping via ClusterRoleBinding

```yaml
# Map IdP group "security-admins" to PicoDome admin role
apiVersion: rbac.authorization.k8s.io/v1
kind: ClusterRoleBinding
metadata:
  name: picodome-admin-binding
subjects:
  - kind: Group
    name: security-admins  # OIDC group claim value
    apiGroup: rbac.authorization.k8s.io
roleRef:
  kind: ClusterRole
  name: picodome-admin
  apiGroup: rbac.authorization.k8s.io
---
apiVersion: rbac.authorization.k8s.io/v1
kind: ClusterRole
metadata:
  name: picodome-admin
rules:
  - apiGroups: [""]
    resources: ["pods"]
    verbs: ["get", "list", "delete"]
  - apiGroups: ["admissionregistration.k8s.io"]
    resources: ["validatingwebhookconfigurations"]
    verbs: ["get", "list", "patch"]
  - apiGroups: [""]
    resources: ["secrets"]
    verbs: ["get"]
    resourceNames: ["picodome-tokens"]
---
# Map IdP group "platform-engineers" to PicoDome submitter role
apiVersion: rbac.authorization.k8s.io/v1
kind: RoleBinding
metadata:
  name: picodome-submitter-binding
  namespace: picodome
subjects:
  - kind: Group
    name: platform-engineers
    apiGroup: rbac.authorization.k8s.io
roleRef:
  kind: Role
  name: picodome-submitter
  apiGroup: rbac.authorization.k8s.io
---
apiVersion: rbac.authorization.k8s.io/v1
kind: Role
metadata:
  name: picodome-submitter
  namespace: picodome
rules:
  - apiGroups: [""]
    resources: ["pods"]
    verbs: ["get", "list"]
  - apiGroups: [""]
    resources: ["configmaps"]
    verbs: ["get"]
```

### PicoDome API token generation from OIDC

For programmatic access, generate PicoDome API tokens from OIDC:

```bash
# Get OIDC token from IdP
OIDC_TOKEN=$(curl -s https://login.example.com/oauth/token \
  -d client_id=picodome-cli \
  -d client_secret="$CLIENT_SECRET" \
  -d grant_type=client_credentials \
  -d scope="picodome:submit" | jq -r .access_token)

# Use OIDC token to authenticate with PicoDome API
curl -H "Authorization: Bearer $OIDC_TOKEN" \
  https://picodome:8443/api/v1/scan \
  -d '{"command": ["npm", "install"], "policy": "strict"}'
```

## SAML integration

For SAML-based IdPs, use a SAML-to-OIDC bridge or configure the Kubernetes API server with a SAML webhook authenticator.

### Using dex as OIDC proxy

```yaml
# dex ConfigMap
apiVersion: v1
kind: ConfigMap
metadata:
  name: dex
data:
  config.yaml: |
    issuer: https://dex.example.com
    storage:
      type: kubernetes
      config:
        inCluster: true
    connectors:
      - type: saml
        name: corporate-saml
        config:
          ssoURL: https://saml.example.com/sso
          ca: /etc/dex/saml-ca.pem
          redirectURI: https://dex.example.com/callback
          entityIssuer: https://dex.example.com
    staticClients:
      - id: picodome-k8s
        redirectURIs:
          - https://picodome.example.com/callback
        secretEnv: DEX_CLIENT_SECRET
```

## Identity provider examples

### Okta

```yaml
# Kubernetes API server flags for Okta
--oidc-issuer-url=https://dev-xxx.okta.com/oauth2/default
--oidc-client-id=picodome-k8s
--oidc-username-claim=email
--oidc-groups-claim=groups
```

Okta group assignments:
- `picodome-admins` → admin role
- `picodome-submitters` → submitter role
- `picodome-viewers` → viewer role

### Azure AD (Entra ID)

```yaml
# Kubernetes API server flags for Azure AD
--oidc-issuer-url=https://login.microsoftonline.com/<tenant-id>/v2.0
--oidc-client-id=<app-registration-id>
--oidc-username-claim=upn
--oidc-groups-claim=groups
```

Azure AD group mapping:
- Create an App Registration for PicoDome
- Assign enterprise groups to app roles
- Map app roles to Kubernetes ClusterRoleBindings

### GitHub Teams (via dex)

```yaml
# dex connector for GitHub
connectors:
  - type: github
    name: github
    config:
      clientID: <github-oauth-app-id>
      clientSecret: <github-oauth-app-secret>
      orgs:
        - name: KirkForge
          teams:
            - picodome-admins
            - picodome-operators
```

## Token rotation

When using IdP-managed tokens:

1. **Short-lived tokens**: IdP tokens typically expire in 1 hour
2. **Automatic refresh**: Client libraries handle token refresh
3. **PicoDome API tokens**: Long-lived tokens stored in Kubernetes Secrets; rotate via:
   ```bash
   kubectl create secret generic picodome-tokens \
     --from-literal=api-tokens="new-token:admin" \
     --dry-run=client -o yaml | kubectl apply -f -
   kubectl rollout restart deployment picodome
   ```

## Audit integration

All authenticated requests include the actor identity in audit logs:

```json
{
  "event_type": "scan_submit",
  "actor": "user@example.com",
  "groups": ["security-admins", "platform-engineers"],
  "tenant_id": "org-123",
  "timestamp": "2026-05-27T12:00:00Z",
  "detail": "Scanned npm package evil-pkg@1.0.0"
}
```
