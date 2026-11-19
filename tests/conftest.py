import pytest

from integrations import cache


@pytest.fixture(autouse=True)
def isolated_cache(tmp_path, monkeypatch):
    """Every test gets an empty in-memory and on-disk fetch cache, never the analyst's dt_cache/."""
    monkeypatch.setattr(cache, "CACHE_DIR", tmp_path / "dt_cache")
    cache.clear_all_caches()
    yield
    cache.clear_all_caches()


@pytest.fixture(autouse=True)
def every_key_present(monkeypatch):
    """Collection tests mock the fetchers: they must not depend on the analyst's real API keys (a service without a
    key is skipped). test_stages_without_keys_are_skipped checks the skipping itself."""
    from integrations import collector
    monkeypatch.setattr(collector, "stages_without_keys", lambda: set())
