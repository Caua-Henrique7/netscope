import pytest

from netscope.storage import Store


def _scan(name="t", hosts_up=1, open_ports=2):
    return {
        "started_at": "2026-01-01T00:00:00+00:00",
        "finished_at": "2026-01-01T00:00:05+00:00",
        "name": name,
        "targets_input": ["127.0.0.1"],
        "ports_spec": "top",
        "stats": {"hosts_up": hosts_up, "open_ports": open_ports},
        "hosts": [],
    }


def test_save_and_get_by_id(tmp_path):
    store = Store(tmp_path / "db.sqlite")
    scan_id = store.save_scan(_scan())
    loaded = store.get_scan(scan_id)
    assert loaded["id"] == scan_id
    assert loaded["name"] == "t"
    store.close()


def test_last_and_prev(tmp_path):
    store = Store(tmp_path / "db.sqlite")
    first = store.save_scan(_scan(name="primeiro"))
    second = store.save_scan(_scan(name="segundo"))
    assert store.get_scan("last")["id"] == second
    assert store.get_scan("prev")["id"] == first
    store.close()


def test_list_scans_newest_first(tmp_path):
    store = Store(tmp_path / "db.sqlite")
    store.save_scan(_scan(name="a"))
    store.save_scan(_scan(name="b"))
    rows = store.list_scans()
    assert [r["name"] for r in rows] == ["b", "a"]
    assert rows[0]["hosts_up"] == 1
    store.close()


def test_missing_and_invalid(tmp_path):
    store = Store(tmp_path / "db.sqlite")
    with pytest.raises(LookupError):
        store.get_scan(999)
    with pytest.raises(LookupError):
        store.get_scan("abc")
    store.close()


def test_persists_across_connections(tmp_path):
    db = tmp_path / "db.sqlite"
    store = Store(db)
    scan_id = store.save_scan(_scan(name="persistente"))
    store.close()

    reopened = Store(db)
    assert reopened.get_scan(scan_id)["name"] == "persistente"
    reopened.close()