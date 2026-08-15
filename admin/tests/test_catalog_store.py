import json
import threading

import pytest

import catalog_store

MANIFEST_DOC = {
    "profile": "agent-embassy/0.1-draft",
    "last_updated": "2026-08-08",
    "entity": {"name": "Example Company", "tax_id": "NIF/CIF", "website": "https://example.com", "country": "ES"},
    "public_catalog": {"products": "/catalog/products.json"},
    "access_tiers": [
        {"tier": 0, "auth": "none", "rate_limit": "60/h"},
        {
            "tier": 1,
            "auth": "domain-challenge",
            "resources": {"contact": "/catalog/contact.json"},
            "session_ttl_seconds": 3600,
        },
    ],
    "security": {"gateway_required": True, "direct_llm_exposure": False, "audit_logging": True},
}

PRODUCT_DOC = {
    "@context": "https://schema.org",
    "@type": "ItemList",
    "itemListElement": [{"@type": "Product", "name": "Example product", "description": "Placeholder"}],
}


@pytest.fixture
def store(tmp_path, monkeypatch):
    products_path = tmp_path / "products.json"
    products_path.write_text(json.dumps(PRODUCT_DOC))
    manifest_path = tmp_path / "manifest.json"
    manifest_path.write_text(json.dumps(MANIFEST_DOC))

    monkeypatch.setattr(catalog_store, "FILES", {"products": products_path})
    monkeypatch.setattr(catalog_store, "MANIFEST_PATH", manifest_path)
    return catalog_store


def test_list_items_reads_current_file(store):
    items = store.list_items("products")
    assert items[0]["name"] == "Example product"


def test_list_items_unknown_kind_raises(store):
    with pytest.raises(store.UnknownKind):
        store.list_items("not-a-kind")


def test_add_item_appends_and_persists(store):
    store.add_item("products", {"@type": "Product", "name": "New one"})
    items = store.list_items("products")
    assert len(items) == 2
    assert items[1]["name"] == "New one"


def test_written_file_stays_world_readable(store):
    # tempfile.mkstemp() defaults to mode 0600 (owner-only) — confirmed live
    # against the real stack to break nginx's read access after a write,
    # since the `static` container's nginx worker runs as a different user
    # than `admin`. os.replace() does not inherit the original file's
    # permissions, so this must be set explicitly on every write.
    store.add_item("products", {"@type": "Product", "name": "New one"})
    mode = store.FILES["products"].stat().st_mode
    assert mode & 0o044 == 0o044, f"file is not group/other-readable: {oct(mode)}"


def test_update_item_replaces_in_place(store):
    store.update_item("products", 0, {"@type": "Product", "name": "Renamed"})
    items = store.list_items("products")
    assert items[0]["name"] == "Renamed"


def test_update_item_bad_index_raises(store):
    with pytest.raises(IndexError):
        store.update_item("products", 5, {"@type": "Product", "name": "x"})


def test_delete_item_removes(store):
    store.add_item("products", {"@type": "Product", "name": "Second"})
    store.delete_item("products", 0)
    items = store.list_items("products")
    assert len(items) == 1
    assert items[0]["name"] == "Second"


def test_atomic_write_leaves_original_untouched_on_failure(store, monkeypatch):
    original = store.MANIFEST_PATH.read_text()

    def boom(src, dst):
        raise OSError("simulated failure mid-write")

    monkeypatch.setattr(store.os, "replace", boom)
    with pytest.raises(OSError):
        store.update_manifest(lambda doc: doc.__setitem__("last_updated", "2099-01-01"))

    assert store.MANIFEST_PATH.read_text() == original


def test_atomic_write_does_not_leave_a_temp_file_on_failure(store, monkeypatch):
    def boom(src, dst):
        raise OSError("simulated failure mid-write")

    monkeypatch.setattr(store.os, "replace", boom)
    with pytest.raises(OSError):
        store.update_manifest(lambda doc: doc.__setitem__("last_updated", "2099-01-01"))

    leftover = [p for p in store.MANIFEST_PATH.parent.iterdir() if p.name.startswith(".manifest.json.")]
    assert leftover == []


def test_cleanup_stale_temp_files_removes_leftovers_from_a_killed_run(store):
    # Simulates what a SIGKILL/`docker kill` mid-write leaves behind:
    # mkstemp() succeeded but the process died before os.replace() ran, so
    # the `except BaseException: os.unlink(tmp_path)` cleanup in
    # _atomic_write never got a chance to run either. Confirmed live during
    # adversarial review (`docker kill` on the admin container during a
    # write burst left a real 0600 `.products.json.<rand>.tmp` file in
    # static/catalog/ that nothing ever cleaned up).
    stale = store.FILES["products"].parent / ".products.json.abc123.tmp"
    stale.write_text('{"broken": tru')  # content is irrelevant, only its presence matters
    other_file = store.FILES["products"].parent / "not-a-tmp-file.json"
    other_file.write_text("{}")

    store._cleanup_stale_temp_files()

    assert not stale.exists()
    assert other_file.exists()  # only .*.tmp files are swept, nothing else
    assert store.FILES["products"].exists()  # the real file is untouched
    assert store.list_items("products") == [PRODUCT_DOC["itemListElement"][0]]


def test_concurrent_writes_do_not_corrupt_the_file(store):
    # Real threads, not simulated — hammer add_item concurrently and confirm
    # every write lands (no lost update) via the per-file lock.
    def add(n):
        store.add_item("products", {"@type": "Product", "name": f"item-{n}"})

    threads = [threading.Thread(target=add, args=(n,)) for n in range(20)]
    for t in threads:
        t.start()
    for t in threads:
        t.join()

    items = store.list_items("products")
    assert len(items) == 1 + 20  # original + 20 concurrent adds, none lost
    doc = json.loads(store.FILES["products"].read_text())
    assert doc["itemListElement"] == items  # file itself is valid, matching JSON


def test_manifest_update_preserves_tier1_entry_untouched(store):
    def mutate(doc):
        doc["entity"]["name"] = "New Name"

    doc = store.update_manifest(mutate)
    tier1 = next(t for t in doc["access_tiers"] if t["tier"] == 1)
    assert tier1 == MANIFEST_DOC["access_tiers"][1]
