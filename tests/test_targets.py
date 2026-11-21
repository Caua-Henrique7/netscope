import pytest

from netscope.targets import expand_target, parse_targets


def test_single_ipv4():
    assert expand_target("192.168.0.10") == ["192.168.0.10"]


def test_cidr_skips_network_and_broadcast():
    assert parse_targets(["192.168.1.0/30"]) == ["192.168.1.1", "192.168.1.2"]


def test_cidr_31_keeps_both():
    assert parse_targets(["10.0.0.0/31"]) == ["10.0.0.0", "10.0.0.1"]


def test_short_range():
    assert parse_targets(["10.0.0.8-10"]) == ["10.0.0.8", "10.0.0.9", "10.0.0.10"]


def test_full_range_crossing_octet():
    assert parse_targets(["10.0.0.254-10.0.1.1"]) == [
        "10.0.0.254", "10.0.0.255", "10.0.1.0", "10.0.1.1",
    ]


def test_comma_list_and_dedup():
    assert parse_targets(["10.0.0.1,10.0.0.1,10.0.0.2"]) == ["10.0.0.1", "10.0.0.2"]


def test_exclude():
    assert parse_targets(["10.0.0.1,10.0.0.2,10.0.0.3"], exclude=["10.0.0.2"]) == [
        "10.0.0.1", "10.0.0.3",
    ]


def test_network_too_large():
    with pytest.raises(ValueError):
        parse_targets(["10.0.0.0/8"])


def test_reversed_range():
    with pytest.raises(ValueError):
        parse_targets(["10.0.0.50-10"])


def test_localhost_resolves():
    assert "127.0.0.1" in parse_targets(["localhost"])