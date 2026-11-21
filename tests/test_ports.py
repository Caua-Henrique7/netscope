import pytest

from netscope.ports import TOP_PORTS, parse_ports


def test_top_keyword():
    assert parse_ports("top") == list(TOP_PORTS)


def test_full_keyword():
    assert len(parse_ports("full")) == 65535


def test_single_list():
    assert parse_ports("22,80,443") == [22, 80, 443]


def test_range():
    assert parse_ports("1-3,10") == [1, 2, 3, 10]


def test_sorted_and_dedup():
    assert parse_ports("443,80,80,22") == [22, 80, 443]


def test_top_mixed_with_numbers():
    result = parse_ports("top, 8085")
    assert 8085 in result and 22 in result


@pytest.mark.parametrize("bad", ["0", "70000", "abc", "10-5", "", "22-"])
def test_invalid(bad):
    with pytest.raises(ValueError):
        parse_ports(bad)