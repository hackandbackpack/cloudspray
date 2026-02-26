import random


def standard_shuffle(
    users: list[str], passwords: list[str]
) -> list[tuple[str, str]]:
    """Standard mode: for each password, randomize user order.

    Produces pairs like: [(user3, pass1), (user1, pass1), (user2, pass1), ...]
    Each password is tried against all users before moving to the next password.
    Users are shuffled within each round to avoid sequential targeting.
    """
    pairs: list[tuple[str, str]] = []
    for password in passwords:
        shuffled_users = list(users)
        random.shuffle(shuffled_users)
        for user in shuffled_users:
            pairs.append((user, password))
    return pairs


def aggressive_shuffle(
    users: list[str], passwords: list[str]
) -> list[tuple[str, str]]:
    """Aggressive mode: create all (user, password) pairs and fully randomize.

    No guarantee of password-round ordering. Relies entirely on per-user delay
    tracking in the spray engine to prevent rapid attempts against the same user.
    """
    pairs = [(user, password) for user in users for password in passwords]
    random.shuffle(pairs)
    return pairs
