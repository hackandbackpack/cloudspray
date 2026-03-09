"""Credential pair shuffling strategies for password spray campaigns.

Password spraying against Azure AD requires careful ordering of authentication
attempts to avoid triggering account lockouts. Azure AD's smart-lockout tracks
failed attempts per user and can lock an account after a configurable threshold
(typically 10 failures in a short window). The ordering strategy directly
affects how many passwords can be tested before lockouts occur.

**Why shuffle at all?**
Spraying the same password against all users before moving to the next password
(a "horizontal" spray) is the safest approach -- each user only sees one failed
attempt per round. Randomizing the user order within each round prevents
sequential-IP detection patterns where Azure AD or a SIEM could notice
alphabetical or list-ordered login attempts.

This module provides two strategies:

- **Standard shuffle** (default): Preserves password-round structure so each
  user sees at most one attempt per round. Within each round, users are
  randomly ordered. Combined with the engine's per-user delay (typically 30s),
  this stays well under lockout thresholds. Best for cautious engagements.

- **Aggressive shuffle**: Generates the full cartesian product of (user, password)
  pairs and randomizes everything. This can interleave multiple passwords for
  the same user in quick succession. The engine's per-user delay tracking
  prevents back-to-back attempts against the same user, but this mode is
  inherently riskier for lockouts. Best when speed matters and the lockout
  policy is known to be lenient.
"""

import random


def standard_shuffle(
    users: list[str], passwords: list[str]
) -> list[tuple[str, str]]:
    """Generate credential pairs in password-round order with shuffled users.

    For each password in the list, all users are shuffled into a random order
    and paired with that password. This ensures every user is tested with
    password N before any user is tested with password N+1.

    Example output for 3 users and 2 passwords::

        [(user3, pass1), (user1, pass1), (user2, pass1),
         (user2, pass2), (user3, pass2), (user1, pass2)]

    This is the safest strategy because each user accumulates at most one
    failed attempt per password round. With a 30-second per-user delay and
    100 users, each round takes ~50 minutes -- well within typical 30-minute
    lockout reset windows.

    Args:
        users: List of target UPNs (e.g., ``["user@contoso.com", ...]``).
        passwords: List of passwords to spray, in priority order.

    Returns:
        Ordered list of ``(username, password)`` tuples ready for the engine
        to process sequentially.
    """
    pairs: list[tuple[str, str]] = []
    for password in passwords:
        # Copy the user list so we don't mutate the caller's list, then
        # randomize the order within this password round.
        shuffled_users = list(users)
        random.shuffle(shuffled_users)
        for user in shuffled_users:
            pairs.append((user, password))
    return pairs


def aggressive_shuffle(
    users: list[str], passwords: list[str]
) -> list[tuple[str, str]]:
    """Generate all credential pairs and fully randomize their order.

    Creates the cartesian product of users x passwords, then applies a
    Fisher-Yates shuffle to the entire list. This provides maximum
    randomization but abandons the password-round guarantee -- the same user
    might appear back-to-back with different passwords.

    The spray engine's per-user delay tracking (see ``SprayEngine._enforce_user_delay``)
    prevents rapid-fire attempts against the same user, but this mode still
    carries higher lockout risk than standard shuffle because the ordering
    cannot guarantee even distribution across users.

    Use this mode when:
    - The target's lockout policy is known to be lenient or disabled.
    - Speed is more important than stealth.
    - You want maximum traffic-pattern randomization for detection evasion.

    Args:
        users: List of target UPNs.
        passwords: List of passwords to spray.

    Returns:
        Randomly ordered list of ``(username, password)`` tuples.
    """
    pairs = [(user, password) for user in users for password in passwords]
    random.shuffle(pairs)
    return pairs
