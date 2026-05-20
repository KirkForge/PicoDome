"""Tests for L3 sandbox execution."""

import json
import pytest
from irondome.l3.engine import sandbox_run, SandboxEngine
from irondome.l3.models import Policy, PolicyRule, RuleTarget, SyscallAction, Verdict
from irondome.l3.policy import default_policy, load_policy
from irondome.l3.backends.subprocess_backend import SubprocessBackend


class TestPolicy:
    def test_default_policy_loads(self):
        policy = default_policy()
        assert policy.name == "iron-dome-default"
        assert policy.default_action == SyscallAction.DENY
        assert len(policy.rules) > 0

    def test_policy_rules_have_ids(self):
        policy = default_policy()
        rule_ids = [r.rule_id for r in policy.rules]
        assert "L3-FILE-R-001" in rule_ids
        assert "L3-NET-OUT-001" in rule_ids

    def test_policy_to_dict_roundtrip(self):
        policy = default_policy()
        d = policy.to_dict()
        assert d["name"] == policy.name
        assert len(d["rules"]) == len(policy.rules)


class TestSubprocessBackend:
    def test_backend_available(self):
        backend = SubprocessBackend()
        assert backend.is_available() is True
        assert backend.name == "subprocess"

    def test_run_simple_command(self):
        result = sandbox_run(["echo", "hello"])
        assert result.overall_verdict == Verdict.ALLOW
        assert result.exit_code == 0
        assert result.duration_ms > 0
        assert "hello" in result.stdout

    def test_run_with_timeout(self):
        result = sandbox_run(["sleep", "10"], timeout=0.1)
        assert result.overall_verdict == Verdict.KILL

    def test_run_detects_network(self):
        result = sandbox_run(["python3", "-c", "print('connect to 93.184.216.34')"])
        assert len(result.events) > 0
        assert any(e.operation == "network_outbound" for e in result.events)

    def test_run_detects_suspicious(self):
        result = sandbox_run(["python3", "-c", "print('eval(compile(open(\"/etc/passwd\")))')"])
        assert len(result.events) > 0
        assert any(e.rule_id == "L3-SUS-001" for e in result.events)  # eval
        assert any(e.rule_id == "L3-SUS-003" for e in result.events)  # /etc/passwd

    def test_run_safe_command_passes(self):
        result = sandbox_run(["python3", "-c", "print('hello world')"])
        assert result.overall_verdict == Verdict.ALLOW

    def test_run_command_not_found(self):
        result = sandbox_run(["nonexistent_command_xyzzy"])
        assert result.exit_code == -1
        assert any(e.rule_id == "L3-EXEC-001" for e in result.events)

    def test_result_to_dict(self):
        result = sandbox_run(["echo", "test"])
        d = result.to_dict()
        assert "run_id" in d
        assert d["command"] == ["echo", "test"]
        assert "events" in d


class TestSandboxEngine:
    def test_engine_uses_backend(self):
        engine = SandboxEngine(backend=SubprocessBackend())
        result = engine.run(["echo", "from_engine"])
        assert "from_engine" in result.stdout

    def test_sandbox_run_with_restrictive_policy(self):
        policy_rules = [
            PolicyRule(
                rule_id="TEST-001",
                target=RuleTarget.NETWORK_OUT,
                action=SyscallAction.DENY,
                description="Deny all network",
            ),
        ]
        policy = Policy(name="test-restrictive", rules=policy_rules)
        result = sandbox_run(
            ["python3", "-c", "print('1.2.3.4')"],
            policy=policy,
        )
        assert any(
            e.verdict == Verdict.DENY and e.operation == "network_outbound"
            for e in result.events
        )
