import pytest

from integrations import cache


@pytest.fixture(autouse=True)
def isolated_cache(tmp_path, monkeypatch):
    """Every test gets an empty in-memory and on-disk fetch cache, never the analyst's dt_cache/."""
    monkeypatch.setattr(cache, "CACHE_DIR", tmp_path / "dt_cache")
    cache.clear_all_caches()
    yield
    cache.clear_all_caches()
