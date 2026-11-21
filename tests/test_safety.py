import pytest

from netscope.safety import enforce_scope, is_internal, public_targets


def test_internal_addresses():
    assert is_internal("127.0.0.1")
    assert is_internal("192.168.0.5")
    assert is_internal("10.1.2.3")
    assert is_internal("172.16.0.1")
    assert is_internal("169.254.1.1")


def test_public_addresses():
    assert not is_internal("8.8.8.8")
    assert not is_internal("1.1.1.1")


def test_public_targets_filters():
    ips = ["192.168.0.1", "8.8.8.8", "10.0.0.1", "1.1.1.1"]
    assert public_targets(ips) == ["8.8.8.8", "1.1.1.1"]


def test_enforce_allows_private():
    enforce_scope(["192.168.0.1", "10.0.0.5"], allow_public=False)


def test_enforce_blocks_public():
    with pytest.raises(ValueError):
        enforce_scope(["192.168.0.1", "8.8.8.8"], allow_public=False)


def test_enforce_allows_public_with_flag():
    enforce_scope(["8.8.8.8"], allow_public=True)