"""Tests for admission controller Helm chart — B19.

Covers:
- Chart.yaml has correct fields
- values.yaml has all required sections
- Deployment template has TLS, env vars, security context
- Service template exposes HTTPS
- ValidatingWebhookConfiguration targets /validate
- Certificate template for cert-manager
- Secret template for TLS
"""

from __future__ import annotations

from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parent.parent
CHART_DIR = REPO_ROOT / "deploy" / "helm" / "irondome-admission"


class TestChartYaml:
    def test_chart_exists(self):
        assert (CHART_DIR / "Chart.yaml").is_file()

    def test_chart_name(self):
        content = (CHART_DIR / "Chart.yaml").read_text()
        assert "irondome-admission" in content

    def test_chart_type(self):
        content = (CHART_DIR / "Chart.yaml").read_text()
        assert "application" in content


class TestValuesYaml:
    def test_values_exists(self):
        assert (CHART_DIR / "values.yaml").is_file()

    def test_admission_config(self):
        content = (CHART_DIR / "values.yaml").read_text()
        assert "scanEnabled" in content
        assert "scanMinSeverity" in content
        assert "daemonUrl" in content

    def test_security_config(self):
        content = (CHART_DIR / "values.yaml").read_text()
        assert "denyPrivileged" in content
        assert "denyRunAsRoot" in content
        assert "requireSecurityContext" in content
        assert "denyHostPath" in content
        assert "denyHostNetwork" in content

    def test_tls_config(self):
        content = (CHART_DIR / "values.yaml").read_text()
        assert "certManager" in content
        assert "existingSecret" in content

    def test_webhook_config(self):
        content = (CHART_DIR / "values.yaml").read_text()
        assert "failurePolicy" in content
        assert "rules" in content

    def test_replica_count(self):
        content = (CHART_DIR / "values.yaml").read_text()
        assert "replicaCount" in content


class TestDeploymentTemplate:
    def test_deployment_exists(self):
        assert (CHART_DIR / "templates" / "deployment.yaml").is_file()

    def test_tls_volume(self):
        content = (CHART_DIR / "templates" / "deployment.yaml").read_text()
        assert "tls" in content
        assert "/tls" in content

    def test_env_vars(self):
        content = (CHART_DIR / "templates" / "deployment.yaml").read_text()
        assert "IRONDOME_ADMISSION_SCAN_ENABLED" in content
        assert "IRONDOME_ADMISSION_DAEMON_URL" in content

    def test_security_context(self):
        content = (CHART_DIR / "templates" / "deployment.yaml").read_text()
        assert "runAsNonRoot" in content
        assert "allowPrivilegeEscalation" in content
        assert "capabilities" in content

    def test_health_probes(self):
        content = (CHART_DIR / "templates" / "deployment.yaml").read_text()
        assert "livenessProbe" in content
        assert "readinessProbe" in content


class TestServiceTemplate:
    def test_service_exists(self):
        assert (CHART_DIR / "templates" / "service.yaml").is_file()

    def test_https_port(self):
        content = (CHART_DIR / "templates" / "service.yaml").read_text()
        assert "https" in content


class TestWebhookTemplate:
    def test_webhook_exists(self):
        assert (CHART_DIR / "templates" / "webhook.yaml").is_file()

    def test_validate_path(self):
        content = (CHART_DIR / "templates" / "webhook.yaml").read_text()
        assert "/validate" in content

    def test_validating_webhook_configuration(self):
        content = (CHART_DIR / "templates" / "webhook.yaml").read_text()
        assert "ValidatingWebhookConfiguration" in content

    def test_failure_policy(self):
        content = (CHART_DIR / "templates" / "webhook.yaml").read_text()
        assert "failurePolicy" in content


class TestCertificateTemplate:
    def test_certificate_exists(self):
        assert (CHART_DIR / "templates" / "certificate.yaml").is_file()

    def test_cert_manager_reference(self):
        content = (CHART_DIR / "templates" / "certificate.yaml").read_text()
        assert "cert-manager" in content


class TestSecretTemplate:
    def test_secret_exists(self):
        assert (CHART_DIR / "templates" / "secret.yaml").is_file()

    def test_tls_type(self):
        content = (CHART_DIR / "templates" / "secret.yaml").read_text()
        assert "kubernetes.io/tls" in content


class TestServiceAccountTemplate:
    def test_serviceaccount_exists(self):
        assert (CHART_DIR / "templates" / "serviceaccount.yaml").is_file()


class TestHelpersTemplate:
    def test_helpers_exists(self):
        assert (CHART_DIR / "templates" / "_helpers.tpl").is_file()

    def test_name_template(self):
        content = (CHART_DIR / "templates" / "_helpers.tpl").read_text()
        assert "irondome-admission.name" in content

    def test_labels_template(self):
        content = (CHART_DIR / "templates" / "_helpers.tpl").read_text()
        assert "irondome-admission.labels" in content
