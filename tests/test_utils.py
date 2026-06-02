"""Tests for utility functions."""
from cloudspray.utils import normalize_email, random_suffix


def test_normalize_email_adds_domain():
    assert normalize_email("jdoe", "example.com") == "jdoe@example.com"


def test_normalize_email_preserves_full():
    assert normalize_email("jdoe@example.com", "other.com") == "jdoe@example.com"


def test_normalize_email_preserves_case():
    """normalize_email does not alter case -- it only appends domain if needed."""
    result = normalize_email("JDoe@Example.COM", "other.com")
    assert result == "JDoe@Example.COM"


def test_random_suffix_length():
    s = random_suffix()
    assert len(s) == 8
    assert s.isalnum()


def test_random_suffix_unique():
    results = {random_suffix() for _ in range(100)}
    assert len(results) == 100


def test_random_suffix_custom_length():
    s = random_suffix(length=16)
    assert len(s) == 16
    assert s.isalnum()
