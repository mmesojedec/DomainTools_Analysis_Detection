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


@pytest.fixture(autouse=True)
def no_real_bgpdb(monkeypatch, tmp_path):
    """The analyst's BGPDB host (~/.bgpdbq.conf, $BGPDB_HOST) never reaches a test: BGPDB lookups go to the network."""
    from integrations import credentials
    for name in ("BGPDB_HOST", "BGPDB_API_KEY"):
        monkeypatch.delenv(name, raising=False)
    monkeypatch.setattr(credentials, "BGPDB_CONF_FILE", tmp_path / ".bgpdbq.conf")
    credentials._bgpdb_conf.cache_clear()
    credentials.bgpdb_credential.cache_clear()
    yield
    credentials._bgpdb_conf.cache_clear()
    credentials.bgpdb_credential.cache_clear()


@pytest.fixture(autouse=True)
def no_real_ripestat(monkeypatch):
    """
    RIPEstat never reaches the network from a test, and runs use BGPDB without RIPEstat registration (as before
    RIPEstat), whatever the analyst's Settings say; RIPEstat tests set their own settings and mock the calls.
    """
    from integrations import ripestat, ripestat_stage
    from integrations.http import FetchResult

    monkeypatch.setattr(ripestat_stage, "_settings", lambda: {"bgp_source": "bgpdb", "ripestat_registration": False})
    monkeypatch.setattr(ripestat, "_query", lambda call, resource, **extra: FetchResult(
        ripestat.SOURCE, ripestat.target_of(call, resource, **extra), error="RIPEstat is not called in tests"))
