"""Tests for client ID constants integrity."""

from cloudspray.constants.client_ids import (
    ALL_CLIENT_IDS,
    FOCI_CLIENT_IDS,
    NON_FOCI_CLIENT_IDS,
)


def test_no_duplicate_client_ids_in_foci():
    """Every FOCI entry must map to a unique client ID."""
    values = list(FOCI_CLIENT_IDS.values())
    assert len(values) == len(set(values)), (
        f"Duplicate client IDs in FOCI_CLIENT_IDS: "
        f"{[v for v in values if values.count(v) > 1]}"
    )


def test_no_overlap_between_foci_and_non_foci():
    """FOCI and NON_FOCI dicts must not share any client IDs."""
    foci_ids = set(FOCI_CLIENT_IDS.values())
    non_foci_ids = set(NON_FOCI_CLIENT_IDS.values())
    overlap = foci_ids & non_foci_ids
    assert not overlap, f"Client IDs appear in both FOCI and NON_FOCI: {overlap}"


def test_all_client_ids_is_full_union():
    """ALL_CLIENT_IDS must contain every entry from both FOCI and NON_FOCI."""
    expected = {**FOCI_CLIENT_IDS, **NON_FOCI_CLIENT_IDS}
    assert ALL_CLIENT_IDS == expected
