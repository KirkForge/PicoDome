"""Tests for shared data models (models.py, l3/models.py, l4/models.py)."""

import json
from dataclasses import FrozenInstanceError

import pytest

from irondome.l3.models import (
    Policy,
    PolicyRule,
    RuleTarget,
    SandboxEvent,
    SandboxResult,
    SyscallAction,
)
from irondome.l4.models import (
    AnalysisResult,
    DnsQuery,
    DriftResult,
    FileOperation,
    NetworkCall,
    ProcessSpawn,
    TimingPoint,
)
from irondome.models import (
    BehavioralVerdict,
    Finding,
    ScanStats,
    Severity,
    Verdict,
)

# ─── Severity enum ────────────────────────────────────────────────────────────


class TestSeverity:
    def test_all_values(self):
        assert Severity.CRITICAL.value == "CRITICAL"
        assert Severity.HIGH.value == "HIGH"
        assert Severity.MEDIUM.value == "MEDIUM"
        assert Severity.LOW.value == "LOW"
        assert Severity.INFO.value == "INFO"

    def test_severity_count(self):
        assert len(Severity) == 5

    def test_severity_is_string_enum(self):
        assert isinstance(Severity.CRITICAL, str)
        assert Severity.CRITICAL == "CRITICAL"

    def test_severity_ordering(self):
        # String enums don't have numeric ordering, but values are accessible
        assert Severity.CRITICAL.value == "CRITICAL"


# ─── Verdict enum ─────────────────────────────────────────────────────────────


class TestVerdict:
    def test_all_values(self):
        assert Verdict.ALLOW.value == "ALLOW"
        assert Verdict.DENY.value == "DENY"
        assert Verdict.KILL.value == "KILL"

    def test_verdict_count(self):
        assert len(Verdict) == 3

    def test_verdict_is_string_enum(self):
        assert isinstance(Verdict.ALLOW, str)


# ─── BehavioralVerdict enum ───────────────────────────────────────────────────


class TestBehavioralVerdict:
    def test_all_values(self):
        assert BehavioralVerdict.CLEAN.value == "CLEAN"
        assert BehavioralVerdict.SUSPICIOUS.value == "SUSPICIOUS"
        assert BehavioralVerdict.MALICIOUS.value == "MALICIOUS"

    def test_behavioral_verdict_count(self):
        assert len(BehavioralVerdict) == 3

    def test_behavioral_verdict_is_string_enum(self):
        assert isinstance(BehavioralVerdict.CLEAN, str)


# ─── Finding ──────────────────────────────────────────────────────────────────


class TestFinding:
    def test_finding_creation(self, clean_finding):
        f = clean_finding
        assert f.rule_id == "TEST-001"
        assert f.severity == Severity.HIGH
        assert f.message == "Test finding"
        assert f.location == "/tmp/test"
        assert f.evidence == {"key": "value"}

    def test_finding_frozen(self, clean_finding):
        with pytest.raises(FrozenInstanceError):
            clean_finding.rule_id = "changed"

    def test_finding_to_dict(self, clean_finding):
        d = clean_finding.to_dict()
        assert d["rule_id"] == "TEST-001"
        assert d["severity"] == "HIGH"
        assert d["message"] == "Test finding"
        assert d["location"] == "/tmp/test"
        assert d["evidence"] == {"key": "value"}

    def test_finding_to_dict_has_no_finding_id(self, clean_finding):
        d = clean_finding.to_dict()
        assert "finding_id" not in d

    def test_finding_default_evidence(self):
        f = Finding(rule_id="R1", severity=Severity.LOW, message="m")
        assert f.evidence == {}

    def test_finding_default_location(self):
        f = Finding(rule_id="R1", severity=Severity.LOW, message="m")
        assert f.location == ""

    def test_finding_deterministic_default(self):
        """Finding finding_id defaults to empty string (deterministic mode)."""
        f1 = Finding(rule_id="R1", severity=Severity.LOW, message="m")
        f2 = Finding(rule_id="R1", severity=Severity.LOW, message="m")
        # In deterministic mode, finding_id is empty by default
        assert f1.finding_id == ""
        assert f2.finding_id == ""
        # Use _generate_finding_id() for non-deterministic IDs
        from irondome.models import _generate_finding_id

        id1 = _generate_finding_id()
        id2 = _generate_finding_id()
        assert id1 != id2

    def test_finding_severity_levels(self):
        for sev in Severity:
            f = Finding(rule_id="X", severity=sev, message="m")
            assert f.severity == sev


# ─── ScanStats ────────────────────────────────────────────────────────────────


class TestScanStats:
    def test_scanstats_creation(self):
        s = ScanStats(
            packages_scanned=5,
            files_scanned=100,
            duration_ms=250,
            findings_by_severity={"HIGH": 2, "LOW": 1},
            findings_by_rule={"R1": 2, "R2": 1},
        )
        assert s.packages_scanned == 5
        assert s.files_scanned == 100
        assert s.duration_ms == 250

    def test_scanstats_defaults(self):
        s = ScanStats()
        assert s.packages_scanned == 0
        assert s.files_scanned == 0
        assert s.duration_ms == 0
        assert s.findings_by_severity == {}
        assert s.findings_by_rule == {}

    def test_scanstats_to_dict(self):
        s = ScanStats(
            packages_scanned=3,
            files_scanned=50,
            duration_ms=100,
            findings_by_severity={"CRITICAL": 1},
            findings_by_rule={"L4-EXFIL-001": 1},
        )
        d = s.to_dict()
        assert d["packages_scanned"] == 3
        assert d["files_scanned"] == 50
        assert d["duration_ms"] == 100
        assert d["findings_by_severity"] == {"CRITICAL": 1}
        assert d["findings_by_rule"] == {"L4-EXFIL-001": 1}

    def test_scanstats_frozen(self):
        s = ScanStats()
        with pytest.raises(FrozenInstanceError):
            s.packages_scanned = 99


# ─── SandboxEvent ─────────────────────────────────────────────────────────────


class TestSandboxEvent:
    def test_sandbox_event_creation(self):
        e = SandboxEvent(
            rule_id="L3-NET-001",
            verdict=Verdict.DENY,
            operation="network_outbound",
            detail="IP found: 1.2.3.4",
            address="1.2.3.4",
        )
        assert e.rule_id == "L3-NET-001"
        assert e.verdict == Verdict.DENY
        assert e.operation == "network_outbound"
        assert e.address == "1.2.3.4"

    def test_sandbox_event_defaults(self):
        e = SandboxEvent(
            rule_id="R1",
            verdict=Verdict.ALLOW,
            operation="test",
            detail="test",
        )
        assert e.path == ""
        assert e.address == ""
        assert e.timestamp_ms == 0

    def test_sandbox_event_to_dict(self):
        e = SandboxEvent(
            rule_id="L3-NET-001",
            verdict=Verdict.DENY,
            operation="network_outbound",
            detail="IP found: 1.2.3.4",
            path="/etc/hosts",
            address="1.2.3.4",
        )
        d = e.to_dict()
        assert d["rule_id"] == "L3-NET-001"
        assert d["verdict"] == "DENY"
        assert d["operation"] == "network_outbound"
        assert d["path"] == "/etc/hosts"
        assert d["address"] == "1.2.3.4"

    def test_sandbox_event_frozen(self):
        e = SandboxEvent(rule_id="R1", verdict=Verdict.ALLOW, operation="t", detail="t")
        with pytest.raises(FrozenInstanceError):
            e.rule_id = "changed"


# ─── SandboxResult ─────────────────────────────────────────────────────────────


class TestSandboxResult:
    def test_sandbox_result_creation(self, clean_sandbox_result):
        r = clean_sandbox_result
        assert r.command == ["echo", "hello"]
        assert r.overall_verdict == Verdict.ALLOW
        assert r.exit_code == 0
        assert r.duration_ms == 42

    def test_sandbox_result_frozen(self, clean_sandbox_result):
        with pytest.raises(FrozenInstanceError):
            clean_sandbox_result.exit_code = 99

    def test_sandbox_result_to_dict(self, clean_sandbox_result):
        d = clean_sandbox_result.to_dict()
        assert d["command"] == ["echo", "hello"]
        assert d["overall_verdict"] == "ALLOW"
        assert d["exit_code"] == 0
        assert d["duration_ms"] == 42
        assert d["policy_name"] == "test-policy"
        assert "events" in d

    def test_sandbox_result_to_dict_json_serializable(self, clean_sandbox_result):
        d = clean_sandbox_result.to_dict()
        json_str = json.dumps(d)
        assert isinstance(json_str, str)

    def test_sandbox_result_deterministic_mode(self):
        """With explicit run_id and timestamp, output is deterministic."""
        r = SandboxResult(
            run_id="fixed-id",
            timestamp="2025-01-01T00:00:00Z",
            command=["echo", "test"],
            overall_verdict=Verdict.ALLOW,
            exit_code=0,
            duration_ms=10,
        )
        d = r.to_dict()
        assert d["run_id"] == "fixed-id"
        assert d["timestamp"] == "2025-01-01T00:00:00Z"

    def test_sandbox_result_auto_fields(self):
        """SandboxResult run_id and timestamp default to empty (deterministic mode).
        Use _generate_run_id() and _generate_timestamp() for non-deterministic IDs."""
        r = SandboxResult(command=["test"])
        # In deterministic mode, run_id and timestamp are empty
        assert r.run_id == ""
        assert r.timestamp == ""
        # Non-deterministic mode uses helper functions
        from irondome.models import _generate_run_id, _generate_timestamp

        run_id = _generate_run_id()
        ts = _generate_timestamp()
        assert len(run_id) > 0
        assert len(ts) > 0

    def test_sandbox_result_with_events(self, suspicious_sandbox_result):
        d = suspicious_sandbox_result.to_dict()
        assert len(d["events"]) == 1
        assert d["events"][0]["rule_id"] == "L3-SUS-001"


# ─── L4 models ────────────────────────────────────────────────────────────────


class TestNetworkCall:
    def test_creation(self):
        nc = NetworkCall(address="1.2.3.4", port=443, protocol="tcp")
        assert nc.address == "1.2.3.4"
        assert nc.port == 443
        assert nc.protocol == "tcp"

    def test_defaults(self):
        nc = NetworkCall(address="10.0.0.1")
        assert nc.port == 0
        assert nc.protocol == "tcp"
        assert nc.bytes_sent == 0
        assert nc.bytes_received == 0

    def test_to_dict(self):
        nc = NetworkCall(address="1.2.3.4", port=80, bytes_sent=1024)
        d = nc.to_dict()
        assert d["address"] == "1.2.3.4"
        assert d["port"] == 80
        assert d["bytes_sent"] == 1024

    def test_frozen(self):
        nc = NetworkCall(address="1.2.3.4")
        with pytest.raises(FrozenInstanceError):
            nc.address = "changed"


class TestDnsQuery:
    def test_creation(self):
        dq = DnsQuery(hostname="example.com", resolved_ips=["1.2.3.4"])
        assert dq.hostname == "example.com"
        assert dq.resolved_ips == ["1.2.3.4"]

    def test_defaults(self):
        dq = DnsQuery(hostname="example.com")
        assert dq.resolved_ips == []
        assert dq.timestamp_ms == 0

    def test_to_dict(self):
        dq = DnsQuery(hostname="example.com", resolved_ips=["1.2.3.4"])
        d = dq.to_dict()
        assert d["hostname"] == "example.com"
        assert d["resolved_ips"] == ["1.2.3.4"]


class TestFileOperation:
    def test_creation(self):
        fo = FileOperation(path="/tmp/test", operation="write", success=True)
        assert fo.path == "/tmp/test"
        assert fo.operation == "write"
        assert fo.success is True

    def test_defaults(self):
        fo = FileOperation(path="/tmp/test", operation="read")
        assert fo.success is True
        assert fo.bytes_transferred == 0

    def test_to_dict(self):
        fo = FileOperation(path="/tmp/test", operation="write", bytes_transferred=100)
        d = fo.to_dict()
        assert d["path"] == "/tmp/test"
        assert d["operation"] == "write"
        assert d["bytes_transferred"] == 100


class TestProcessSpawn:
    def test_creation(self):
        ps = ProcessSpawn(executable="/bin/bash", args=["-c", "echo hi"])
        assert ps.executable == "/bin/bash"
        assert ps.args == ["-c", "echo hi"]

    def test_defaults(self):
        ps = ProcessSpawn(executable="ls")
        assert ps.args == []
        assert ps.pid == 0
        assert ps.exit_code is None

    def test_to_dict(self):
        ps = ProcessSpawn(executable="/bin/bash", args=["-c", "echo"], pid=1234)
        d = ps.to_dict()
        assert d["executable"] == "/bin/bash"
        assert d["args"] == ["-c", "echo"]
        assert d["pid"] == 1234
        assert d["exit_code"] is None


class TestTimingPoint:
    def test_creation(self):
        tp = TimingPoint(label="init", elapsed_ms=50)
        assert tp.label == "init"
        assert tp.elapsed_ms == 50

    def test_to_dict(self):
        tp = TimingPoint(label="init", elapsed_ms=50)
        d = tp.to_dict()
        assert d["label"] == "init"
        assert d["elapsed_ms"] == 50


# ─── BehavioralProfile ────────────────────────────────────────────────────────


class TestBehavioralProfile:
    def test_creation(self, clean_profile):
        assert clean_profile.package == "python"
        assert clean_profile.entrypoint == "python"
        assert clean_profile.total_runtime_ms == 100

    def test_to_dict(self, clean_profile):
        d = clean_profile.to_dict()
        assert d["package"] == "python"
        assert d["entrypoint"] == "python"
        assert d["total_runtime_ms"] == 100
        assert d["timing_points_count"] == 0
        assert d["network_calls_count"] == 0

    def test_to_dict_with_data(self, suspicious_profile):
        d = suspicious_profile.to_dict()
        assert d["network_calls_count"] == 1
        assert d["dns_queries_count"] == 1
        assert d["fs_ops_count"] == 2
        assert d["spawns_count"] == 1

    def test_frozen(self, clean_profile):
        with pytest.raises(FrozenInstanceError):
            clean_profile.package = "changed"


# ─── Baseline ──────────────────────────────────────────────────────────────────


class TestBaseline:
    def test_creation(self, python_baseline):
        assert python_baseline.name == "python-script"
        assert python_baseline.package == "python"

    def test_to_dict(self, python_baseline):
        d = python_baseline.to_dict()
        assert d["name"] == "python-script"
        assert d["package"] == "python"
        assert d["expected_runtime_ms_range"] == [10, 30000]
        assert d["allowed_domains"] == []
        assert d["allowed_paths"] == ["**"]

    def test_frozen(self, python_baseline):
        with pytest.raises(FrozenInstanceError):
            python_baseline.name = "changed"


# ─── DriftResult ───────────────────────────────────────────────────────────────


class TestDriftResult:
    def test_creation(self):
        dr = DriftResult(
            baseline_name="python-script",
            score=0.2,
            network_drift=True,
            dns_drift=False,
            details="Network drift detected",
        )
        assert dr.baseline_name == "python-script"
        assert dr.score == 0.2
        assert dr.network_drift is True
        assert dr.dns_drift is False

    def test_defaults(self):
        dr = DriftResult(baseline_name="test", score=0.0)
        assert dr.network_drift is False
        assert dr.dns_drift is False
        assert dr.fs_drift is False
        assert dr.spawn_drift is False
        assert dr.timing_drift is False
        assert dr.details == ""

    def test_to_dict(self):
        dr = DriftResult(
            baseline_name="python-script",
            score=0.4,
            network_drift=True,
            dns_drift=True,
            details="Network and DNS drift",
        )
        d = dr.to_dict()
        assert d["baseline_name"] == "python-script"
        assert d["score"] == 0.4
        assert d["network_drift"] is True
        assert d["dns_drift"] is True
        assert d["fs_drift"] is False
        assert d["details"] == "Network and DNS drift"


# ─── AnalysisResult ────────────────────────────────────────────────────────────


class TestAnalysisResult:
    def test_creation(self, clean_profile):
        ar = AnalysisResult(
            target="python",
            profile=clean_profile,
            overall_verdict=BehavioralVerdict.CLEAN,
        )
        assert ar.target == "python"
        assert ar.overall_verdict == BehavioralVerdict.CLEAN
        assert ar.findings == []

    def test_to_dict(self, clean_profile, clean_finding):
        ar = AnalysisResult(
            target="python",
            findings=[clean_finding],
            profile=clean_profile,
            overall_verdict=BehavioralVerdict.CLEAN,
        )
        d = ar.to_dict()
        assert d["target"] == "python"
        assert d["overall_verdict"] == "CLEAN"
        assert len(d["findings"]) == 1
        assert d["profile"] is not None

    def test_to_dict_no_profile(self):
        ar = AnalysisResult(
            target="test",
            overall_verdict=BehavioralVerdict.CLEAN,
        )
        d = ar.to_dict()
        assert d["profile"] is None

    def test_frozen(self, clean_profile):
        ar = AnalysisResult(
            target="python",
            profile=clean_profile,
            overall_verdict=BehavioralVerdict.CLEAN,
        )
        with pytest.raises(FrozenInstanceError):
            ar.target = "changed"


# ─── Deterministic output ──────────────────────────────────────────────────────


class TestDeterministicOutput:
    def test_finding_no_uuid_in_dict(self, clean_finding):
        """Finding to_dict should not include finding_id."""
        d = clean_finding.to_dict()
        # finding_id is internal; to_dict does not expose it
        assert "finding_id" not in d

    def test_scanstats_dict_is_sorted(self):
        """ScanStats dict keys should be present and consistent."""
        s = ScanStats(
            findings_by_severity={"Z_HIGH": 1, "A_LOW": 2, "M_MED": 3},
            findings_by_rule={"rule_b": 1, "rule_a": 2},
        )
        d = s.to_dict()
        # Values preserved correctly
        assert d["findings_by_severity"]["Z_HIGH"] == 1
        assert d["findings_by_rule"]["rule_a"] == 2

    def test_sandbox_result_deterministic_with_explicit_ids(self):
        """With explicit run_id/timestamp, output is fully deterministic."""
        r1 = SandboxResult(
            run_id="fixed",
            timestamp="2025-01-01T00:00:00Z",
            command=["echo"],
            overall_verdict=Verdict.ALLOW,
            exit_code=0,
        )
        r2 = SandboxResult(
            run_id="fixed",
            timestamp="2025-01-01T00:00:00Z",
            command=["echo"],
            overall_verdict=Verdict.ALLOW,
            exit_code=0,
        )
        assert r1.to_dict() == r2.to_dict()

    def test_analysis_result_json_roundtrip(self, clean_profile, clean_finding):
        """AnalysisResult should serialize to JSON and back."""
        ar = AnalysisResult(
            target="python",
            findings=[clean_finding],
            profile=clean_profile,
            overall_verdict=BehavioralVerdict.CLEAN,
        )
        json_str = json.dumps(ar.to_dict())
        parsed = json.loads(json_str)
        assert parsed["target"] == "python"
        assert parsed["overall_verdict"] == "CLEAN"


# ─── SyscallAction and RuleTarget enums ────────────────────────────────────────


class TestSyscallAction:
    def test_all_values(self):
        assert SyscallAction.ALLOW.value == "allow"
        assert SyscallAction.DENY.value == "deny"
        assert SyscallAction.KILL.value == "kill"
        assert SyscallAction.TRACE.value == "trace"

    def test_count(self):
        assert len(SyscallAction) == 4


class TestRuleTarget:
    def test_all_values(self):
        targets = [
            "file_read",
            "file_write",
            "file_exec",
            "network_out",
            "network_in",
            "network_bind",
            "process_spawn",
            "process_kill",
            "dns_query",
            "signal_send",
            "syscall_generic",
        ]
        for t in targets:
            assert RuleTarget(t) is not None

    def test_count(self):
        assert len(RuleTarget) == 11


# ─── PolicyRule ─────────────────────────────────────────────────────────────────


class TestPolicyRule:
    def test_creation(self):
        pr = PolicyRule(
            rule_id="TEST-001",
            target=RuleTarget.NETWORK_OUT,
            action=SyscallAction.DENY,
            description="Deny network",
        )
        assert pr.rule_id == "TEST-001"
        assert pr.target == RuleTarget.NETWORK_OUT
        assert pr.action == SyscallAction.DENY

    def test_defaults(self):
        pr = PolicyRule(
            rule_id="TEST-001",
            target=RuleTarget.FILE_READ,
            action=SyscallAction.ALLOW,
        )
        assert pr.paths == []
        assert pr.addresses == []
        assert pr.syscalls == []
        assert pr.description == ""

    def test_frozen(self):
        pr = PolicyRule(rule_id="R", target=RuleTarget.NETWORK_OUT, action=SyscallAction.DENY)
        with pytest.raises(FrozenInstanceError):
            pr.rule_id = "changed"


# ─── Policy ─────────────────────────────────────────────────────────────────────


class TestPolicy:
    def test_creation(self):
        p = Policy(name="test", rules=[])
        assert p.name == "test"
        assert p.version == "1.0"
        assert p.default_action == SyscallAction.DENY

    def test_to_dict(self, default_policy):
        d = default_policy.to_dict()
        assert d["name"] == "iron-dome-default"
        assert d["version"] == "1.0"
        assert d["default_action"] == "deny"
        assert len(d["rules"]) > 0
        assert "rule_id" in d["rules"][0]

    def test_frozen(self):
        p = Policy(name="test")
        with pytest.raises(FrozenInstanceError):
            p.name = "changed"
