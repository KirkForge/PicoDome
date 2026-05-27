# Enterprise Identity Provider Integration

IronDome supports mapping enterprise identity provider (IdP) groups to internal RBAC roles. This enables Single Sign-On (SSO) with Okta, Azure AD, Ping Identity, and other OIDC/SAML providers through Kubernetes-native authentication.

## Architecture

```
┌──────────┐     ┌─────────────────────┐     ┌──────────────┐
│  IdP     │────▶│  Kubernetes API     │────▶│  IronDome    │
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
--oidc-client-id=irondome-k8s
--oidc-username-claim=email
--oidc-groups-claim=groups
--oidc-ca-file=/etc/kubernetes/oidc-ca.pem
```

### Group-to-role mapping via ClusterRoleBinding

```yaml
# Map IdP group "security-admins" to IronDome admin role
apiVersion: rbac.authorization.k8s.io/v1
kind: ClusterRoleBinding
metadata:
  name: irondome-admin-binding
subjects:
  - kind: Group
    name: security-admins  # OIDC group claim value
    apiGroup: rbac.authorization.k8s.io
roleRef:
  kind: ClusterRole
  name: irondome-admin
  apiGroup: rbac.authorization.k8s.io
---
apiVersion: rbac.authorization.k8s.io/v1
kind: ClusterRole
metadata:
  name: irondome-admin
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
    resourceNames: ["irondome-tokens"]
---
# Map IdP group "platform-engineers" to IronDome submitter role
apiVersion: rbac.authorization.k8s.io/v1
kind: RoleBinding
metadata:
  name: irondome-submitter-binding
  namespace: irondome
subjects:
  - kind: Group
    name: platform-engineers
    apiGroup: rbac.authorization.k8s.io
roleRef:
  kind: Role
  name: irondome-submitter
  apiGroup: rbac.authorization.k8s.io
---
apiVersion: rbac.authorization.k8s.io/v1
kind: Role
metadata:
  name: irondome-submitter
  namespace: irondome
rules:
  - apiGroups: [""]
    resources: ["pods"]
    verbs: ["get", "list"]
  - apiGroups: [""]
    resources: ["configmaps"]
    verbs: ["get"]
```

### IronDome API token generation from OIDC

For programmatic access, generate IronDome API tokens from OIDC:

```bash
# Get OIDC token from IdP
OIDC_TOKEN=$(curl -s https://login.example.com/oauth/token \
  -d client_id=irondome-cli \
  -d client_secret="$CLIENT_SECRET" \
  -d grant_type=client_credentials \
  -d scope="irondome:submit" | jq -r .access_token)

# Use OIDC token to authenticate with IronDome API
curl -H "Authorization: Bearer $OIDC_TOKEN" \
  https://irondome:8443/api/v1/scan \
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
      - id: irondome-k8s
        redirectURIs:
          - https://irondome.example.com/callback
        secretEnv: DEX_CLIENT_SECRET
```

## Identity provider examples

### Okta

```yaml
# Kubernetes API server flags for Okta
--oidc-issuer-url=https://dev-xxx.okta.com/oauth2/default
--oidc-client-id=irondome-k8s
--oidc-username-claim=email
--oidc-groups-claim=groups
```

Okta group assignments:
- `irondome-admins` → admin role
- `irondome-submitters` → submitter role
- `irondome-viewers` → viewer role

### Azure AD (Entra ID)

```yaml
# Kubernetes API server flags for Azure AD
--oidc-issuer-url=https://login.microsoftonline.com/<tenant-id>/v2.0
--oidc-client-id=<app-registration-id>
--oidc-username-claim=upn
--oidc-groups-claim=groups
```

Azure AD group mapping:
- Create an App Registration for IronDome
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
            - irondome-admins
            - irondome-operators
```

## Token rotation

When using IdP-managed tokens:

1. **Short-lived tokens**: IdP tokens typically expire in 1 hour
2. **Automatic refresh**: Client libraries handle token refresh
3. **IronDome API tokens**: Long-lived tokens stored in Kubernetes Secrets; rotate via:
   ```bash
   kubectl create secret generic irondome-tokens \
     --from-literal=api-tokens="new-token:admin" \
     --dry-run=client -o yaml | kubectl apply -f -
   kubectl rollout restart deployment irondome
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
