from __future__ import annotations

from irondome.l3.policy import default_policy
from irondome.l3.policy_hash import policy_hash


def test_policy_hash_is_stable() -> None:
    p = default_policy()
    h1 = policy_hash(p)
    h2 = policy_hash(p)
    assert h1 == h2
    assert len(h1) == 64


def test_policy_hash_changes_when_policy_changes() -> None:
    p = default_policy()
    h1 = policy_hash(p)

    # Create a modified policy by changing the name (should affect hash)
    p2 = p.__class__(
        name=p.name + "-x",
        version=p.version,
        default_action=p.default_action,
        rules=p.rules,
    )
    h2 = policy_hash(p2)
    assert h1 != h2
