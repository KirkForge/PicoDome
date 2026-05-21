from __future__ import annotations

import json

from irondome.l3.engine import sandbox_run


def test_sandbox_json_is_deterministic_for_same_command(tmp_path) -> None:
    # Use a stable command; avoid reading env or time.
    r1 = sandbox_run(["python3", "-c", "print('hello')"], timeout=5)
    r2 = sandbox_run(["python3", "-c", "print('hello')"], timeout=5)

    j1 = json.dumps(r1.to_dict(), sort_keys=True)
    j2 = json.dumps(r2.to_dict(), sort_keys=True)

    assert j1 == j2
    # Ensure run_id/timestamp are not part of the dict
    assert "run_id" not in r1.to_dict()
    assert "timestamp" not in r1.to_dict()


def test_sandbox_json_includes_policy_hash_and_backend() -> None:
    r = sandbox_run(["python3", "-c", "print('hello')"], timeout=5)
    d = r.to_dict()
    assert "policy_hash" in d
    assert "backend" in d
