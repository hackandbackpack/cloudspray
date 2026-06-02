"""Tests for spray shuffle strategies."""
from cloudspray.spray.shuffle import standard_shuffle, aggressive_shuffle


def test_standard_shuffle_groups_by_password():
    users = ["alice", "bob", "charlie"]
    passwords = ["pass1", "pass2"]
    pairs = standard_shuffle(users, passwords)
    # All pairs present
    assert len(pairs) == 6
    # First 3 should all be pass1, next 3 all pass2
    first_round = {p for _, p in pairs[:3]}
    second_round = {p for _, p in pairs[3:6]}
    assert first_round == {"pass1"}
    assert second_round == {"pass2"}


def test_standard_shuffle_preserves_all_users():
    users = ["alice", "bob", "charlie"]
    passwords = ["pass1"]
    pairs = standard_shuffle(users, passwords)
    assert set(u for u, _ in pairs) == set(users)


def test_aggressive_shuffle_has_all_pairs():
    users = ["alice", "bob"]
    passwords = ["pass1", "pass2"]
    pairs = aggressive_shuffle(users, passwords)
    assert len(pairs) == 4
    assert set(pairs) == {
        ("alice", "pass1"), ("alice", "pass2"),
        ("bob", "pass1"), ("bob", "pass2"),
    }


def test_single_user_single_password():
    pairs = standard_shuffle(["user"], ["pass"])
    assert pairs == [("user", "pass")]
