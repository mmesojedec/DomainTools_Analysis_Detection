import os
import stat
import sys
import tomllib
import types

import pytest

from integrations import credentials

ENV_VARS = ("DT_API_USERNAME", "DT_API_KEY", "DOMAINTOOLS_USERNAME", "DOMAINTOOLS_API_KEY", "DNSDB_API_KEY",
            "DT_CERT_API_KEY", "DT_CREDENTIALS_FILE", "VPNDB_API_KEY", "VPNDB_URL")


@pytest.fixture(autouse=True)
def isolated(tmp_path, monkeypatch):
    """No real environment or home-directory credentials leak into these tests."""
    for name in ENV_VARS:
        monkeypatch.delenv(name, raising=False)
    monkeypatch.setattr(credentials, "CREDENTIALS_FILE", tmp_path / "credentials.toml")
    monkeypatch.setattr(credentials, "DTAPI_FILE", tmp_path / ".dtapi")
    monkeypatch.setattr(credentials, "DNSDB_KEY_FILE", tmp_path / ".dtdnsdb")
    monkeypatch.setattr(credentials, "CERT_API_KEY_FILE", tmp_path / ".dtcertapi")
    monkeypatch.setattr(credentials, "VPNDB_KEY_FILE", tmp_path / ".dtvpndb")
    credentials.clear_credential_cache()
    yield tmp_path
    credentials.clear_credential_cache()


def write(path, text, mode=0o600):
    path.write_text(text)
    os.chmod(path, mode)
    return path


TOML = '[domaintools]\nusername = "toml-user"\napi_key = "toml-key"\n\n[dnsdb]\napi_key = "toml-dnsdb"\n'


def test_nothing_configured():
    assert credentials.load_dtapi_credentials() is None
    assert credentials.load_dnsdb_key() is None
    assert credentials.load_cert_api_key() is None
    overview = credentials.credential_overview()
    assert [r["Found"] for r in overview["services"]] == [False, False, False, False]
    assert overview["toml"]["error"] is None and not overview["toml"]["exists"]
    assert not any(o["Configured"] for opts in overview["options"].values() for o in opts)


def test_files_work(isolated):
    write(isolated / ".dtapi", "file-user\nfile-key\n")
    write(isolated / ".dtdnsdb", "file-dnsdb\n")
    write(isolated / ".dtcertapi", "file-cert\n")
    assert credentials.load_dtapi_credentials() == ("file-user", "file-key")
    assert credentials.load_dnsdb_key() == "file-dnsdb"
    assert credentials.load_cert_api_key() == "file-cert"


def test_toml_beats_files(isolated):
    write(isolated / "credentials.toml", TOML)
    write(isolated / ".dtapi", "file-user\nfile-key\n")
    write(isolated / ".dtdnsdb", "file-dnsdb\n")
    assert credentials.load_dtapi_credentials() == ("toml-user", "toml-key")
    assert credentials.load_dnsdb_key() == "toml-dnsdb"
    assert credentials.dnsdb_credential().source.endswith("credentials.toml [dnsdb]")


def test_environment_beats_toml(isolated, monkeypatch):
    write(isolated / "credentials.toml", TOML)
    monkeypatch.setenv("DT_API_USERNAME", "env-user")
    monkeypatch.setenv("DT_API_KEY", "env-key")
    monkeypatch.setenv("DNSDB_API_KEY", "env-dnsdb")
    assert credentials.load_dtapi_credentials() == ("env-user", "env-key")
    assert credentials.load_dnsdb_key() == "env-dnsdb"
    assert credentials.dnsdb_credential().source == "$DNSDB_API_KEY"


def test_half_set_environment_pair_is_ignored_with_warning(isolated, monkeypatch):
    write(isolated / "credentials.toml", TOML)
    monkeypatch.setenv("DT_API_KEY", "env-key")
    credential = credentials.dtapi_credential()
    assert credential.value == ("toml-user", "toml-key")
    assert credential.warnings[0] == (f"$DT_API_KEY is set without $DT_API_USERNAME, so it is ignored; "
                                      f"using {credential.source} instead.")


def test_half_set_environment_pair_names_file_or_missing(isolated, monkeypatch):
    monkeypatch.setenv("DT_API_USERNAME", "env-user")
    assert credentials.dtapi_credential().warnings == (
        "$DT_API_USERNAME is set without $DT_API_KEY, so it is ignored; no other DomainTools credentials were found.",)
    write(isolated / ".dtapi", "file-user\nfile-key\n")
    credentials.clear_credential_cache()
    assert credentials.dtapi_credential().warnings == (
        f"$DT_API_USERNAME is set without $DT_API_KEY, so it is ignored; using {credentials.display_path(isolated / '.dtapi')} instead.",)


def test_cert_api_falls_back_to_domaintools_key(isolated):
    write(isolated / ".dtapi", "file-user\nfile-key\n")
    assert credentials.load_cert_api_key() == "file-key"
    assert credentials.cert_api_credential().source.startswith("DomainTools API key (")


def test_cert_api_specific_key_wins_over_fallback(isolated, monkeypatch):
    write(isolated / "credentials.toml", TOML + '\n[cert_api]\napi_key = "toml-cert"\n')
    assert credentials.load_cert_api_key() == "toml-cert"
    monkeypatch.setenv("DT_CERT_API_KEY", "env-cert")
    credentials.clear_credential_cache()
    assert credentials.load_cert_api_key() == "env-cert"


def test_credentials_file_override(isolated, monkeypatch):
    custom = write(isolated / "custom.toml", TOML)
    monkeypatch.setenv("DT_CREDENTIALS_FILE", str(custom))
    assert credentials.load_dnsdb_key() == "toml-dnsdb"


def test_invalid_toml_reports_error_and_falls_back(isolated):
    write(isolated / "credentials.toml", "[domaintools\nusername = ")
    write(isolated / ".dtdnsdb", "file-dnsdb\n")
    assert credentials.load_dnsdb_key() == "file-dnsdb"
    error = credentials.credential_overview()["toml"]["error"]
    assert error and "could not be read" in error and "falling back to the files" in error


def test_world_readable_file_warns(isolated):
    write(isolated / "credentials.toml", TOML, mode=0o644)
    assert any("chmod 600" in w for w in credentials.dnsdb_credential().warnings)
    os.chmod(isolated / "credentials.toml", 0o600)
    credentials.clear_credential_cache()
    assert credentials.dnsdb_credential().warnings == ()


def test_status_never_contains_secret_values(isolated, monkeypatch):
    write(isolated / "credentials.toml", TOML)
    monkeypatch.setenv("DNSDB_API_KEY", "env-dnsdb")
    overview = credentials.credential_overview()
    rows = overview["services"]
    text = repr(overview)
    for secret in ("toml-user", "toml-key", "toml-dnsdb", "env-dnsdb"):
        assert secret not in text
    assert [r["Found"] for r in rows] == [True, True, True, False]   # VPNDB not set


def options_by_label(overview):
    return {o["Option"]: o for opts in overview["options"].values() for o in opts}


def test_overview_marks_used_overridden_and_unset_options(isolated, monkeypatch):
    write(isolated / "credentials.toml", TOML)
    write(isolated / ".dtapi", "file-user\nfile-key\n")
    write(isolated / ".dtdnsdb", "file-dnsdb\n")
    monkeypatch.setenv("DNSDB_API_KEY", "env-dnsdb")
    overview = credentials.credential_overview()
    options = options_by_label(overview)
    assert set(overview["options"]) == {"Environment", "credentials.toml", "Files"}

    assert options["$DNSDB_API_KEY"]["Used for"] == ["DNSDB Scout"]
    assert options["[dnsdb] api_key"]["Configured"] and not options["[dnsdb] api_key"]["Used for"]
    assert "DNSDB Scout uses $DNSDB_API_KEY" in options["[dnsdb] api_key"]["Note"]
    assert options["[domaintools] username"]["Used for"] == ["DomainTools API"]
    # the Certificate API falls back to the DomainTools key, not the username
    assert options["[domaintools] api_key"]["Used for"] == ["DomainTools API", "Certificate API"]
    dtapi = next(o for o in overview["options"]["Files"] if o["Option"].endswith(".dtapi"))
    assert dtapi["Configured"] and not dtapi["Used for"]
    assert not options["$DT_CERT_API_KEY"]["Configured"] and options["$DT_CERT_API_KEY"]["Note"] == ""
    kinds = {r["Service"]: r["Kind"] for r in overview["services"]}
    assert kinds == {"DomainTools API": "credentials.toml", "DNSDB Scout": "Environment", "Certificate API": "credentials.toml",
                     "VPNDB": ""}


def test_overview_half_set_env_and_incomplete_dtapi(isolated, monkeypatch):
    write(isolated / ".dtapi", "only-user\n")
    monkeypatch.setenv("DT_API_KEY", "env-key")
    options = options_by_label(credentials.credential_overview())
    assert options["$DT_API_KEY"]["Configured"] and not options["$DT_API_KEY"]["Used for"]
    assert "must both be set" in options["$DT_API_KEY"]["Note"]
    dtapi = next(o for label, o in options.items() if label.endswith(".dtapi"))
    assert not dtapi["Configured"] and "incomplete" in dtapi["Detail"]


def test_overview_file_options_carry_permission_warnings(isolated):
    write(isolated / ".dtdnsdb", "k\n", mode=0o644)
    options = options_by_label(credentials.credential_overview())
    dnsdb = next(o for label, o in options.items() if label.endswith(".dtdnsdb"))
    assert dnsdb["Used for"] == ["DNSDB Scout"] and any("chmod 600" in w for w in dnsdb["Warnings"])


def test_matrix_shows_source_per_service(isolated, monkeypatch):
    write(isolated / "credentials.toml", TOML)
    write(isolated / ".dtapi", "file-user\nfile-key\n")
    monkeypatch.setenv("DT_API_KEY", "env-key")   # half-set pair: configured, but not used
    matrix = {row["Service"]: row for row in credentials.credential_overview()["matrix"]}
    assert matrix["DomainTools API"] == {"Service": "DomainTools API", "Environment": "set, not used",
                                         "credentials.toml": "in use", "Files": "set, not used"}
    assert matrix["DNSDB Scout"]["credentials.toml"] == "in use" and matrix["DNSDB Scout"]["Files"] == "not set"
    # the Certificate API falls back to the DomainTools key, so it follows the DomainTools source
    assert matrix["Certificate API"]["credentials.toml"] == "in use"


def test_environment_credentials_reach_the_sdk_client(isolated, monkeypatch):
    """$DT_API_USERNAME / $DT_API_KEY are what get_dt_api() passes to domaintools.API (the SDK reads no env vars itself)."""
    calls = []
    fake_sdk = types.ModuleType("domaintools")
    fake_sdk.API = lambda username, key, **kwargs: calls.append((username, key)) or "client"
    monkeypatch.setitem(sys.modules, "domaintools", fake_sdk)
    write(isolated / ".dtapi", "file-user\nfile-key\n")
    monkeypatch.setenv("DT_API_USERNAME", "env-user")
    monkeypatch.setenv("DT_API_KEY", "env-key")
    assert credentials.get_dt_api() == "client"
    assert calls == [("env-user", "env-key")]
    assert credentials.load_cert_api_key() == "env-key"


def fake_sdk(monkeypatch):
    calls = []
    module = types.ModuleType("domaintools")
    module.API = lambda username, key, **kwargs: calls.append((username, key)) or "client"
    monkeypatch.setitem(sys.modules, "domaintools", module)
    return calls


def test_sdk_docs_variable_names_are_accepted(isolated, monkeypatch):
    write(isolated / "credentials.toml", TOML)
    calls = fake_sdk(monkeypatch)
    monkeypatch.setenv("DOMAINTOOLS_USERNAME", "docs-user")
    monkeypatch.setenv("DOMAINTOOLS_API_KEY", "docs-key")
    credential = credentials.dtapi_credential()
    assert credential.value == ("docs-user", "docs-key") and credential.kind == "Environment"
    assert credential.source == "$DOMAINTOOLS_USERNAME / $DOMAINTOOLS_API_KEY" and credential.warnings == ()
    credentials.get_dt_api()
    assert calls == [("docs-user", "docs-key")]
    assert credentials.load_cert_api_key() == "docs-key"
    options = options_by_label(credentials.credential_overview())
    assert options["$DOMAINTOOLS_USERNAME"]["Used for"] == ["DomainTools API"]
    assert options["$DOMAINTOOLS_API_KEY"]["Used for"] == ["DomainTools API", "Certificate API"]


def test_dt_api_pair_wins_over_sdk_docs_pair(isolated, monkeypatch):
    for name, value in (("DT_API_USERNAME", "dt-user"), ("DT_API_KEY", "dt-key"),
                        ("DOMAINTOOLS_USERNAME", "docs-user"), ("DOMAINTOOLS_API_KEY", "docs-key")):
        monkeypatch.setenv(name, value)
    assert credentials.load_dtapi_credentials() == ("dt-user", "dt-key")
    options = options_by_label(credentials.credential_overview())
    docs_key = options["$DOMAINTOOLS_API_KEY"]
    assert docs_key["Configured"] and not docs_key["Used for"]
    assert "DomainTools API uses $DT_API_USERNAME / $DT_API_KEY" in docs_key["Note"]


def test_half_set_dt_pair_falls_through_to_sdk_docs_pair(isolated, monkeypatch):
    monkeypatch.setenv("DT_API_KEY", "dt-key")
    monkeypatch.setenv("DOMAINTOOLS_USERNAME", "docs-user")
    monkeypatch.setenv("DOMAINTOOLS_API_KEY", "docs-key")
    credential = credentials.dtapi_credential()
    assert credential.value == ("docs-user", "docs-key")
    assert credential.warnings == ("$DT_API_KEY is set without $DT_API_USERNAME, so it is ignored; "
                                   "using $DOMAINTOOLS_USERNAME / $DOMAINTOOLS_API_KEY instead.",)
    assert "must both be set" in options_by_label(credentials.credential_overview())["$DT_API_KEY"]["Note"]


def test_variables_from_different_pairs_are_not_combined(isolated, monkeypatch):
    write(isolated / ".dtapi", "file-user\nfile-key\n")
    monkeypatch.setenv("DT_API_USERNAME", "dt-user")
    monkeypatch.setenv("DOMAINTOOLS_API_KEY", "docs-key")
    credential = credentials.dtapi_credential()
    assert credential.value == ("file-user", "file-key")
    assert len(credential.warnings) == 2 and all("so it is ignored" in w for w in credential.warnings)


def test_saved_keys_are_read_back_and_the_file_is_private(isolated):
    path = credentials.save_credentials({credentials.DOMAINTOOLS: {"username": "me", "api_key": "k1"},
                                         credentials.DNSDB: {"api_key": " k2 "}})
    assert path.endswith("credentials.toml")
    assert credentials.load_dtapi_credentials() == ("me", "k1")
    assert credentials.load_dnsdb_key() == "k2"
    assert credentials.load_cert_api_key() == "k1"
    assert stat.S_IMODE((isolated / "credentials.toml").stat().st_mode) == 0o600
    assert credentials.saved_sections() == [credentials.DOMAINTOOLS, credentials.DNSDB]


def test_saving_keeps_other_entries_and_empty_fields_keep_saved_values(isolated):
    write(isolated / "credentials.toml", TOML + '\n[other]\nname = "x \\"quoted\\""\nport = 8\n', mode=0o644)
    credentials.save_credentials({credentials.DOMAINTOOLS: {"username": "", "api_key": "new-key"}})
    assert credentials.load_dtapi_credentials() == ("toml-user", "new-key")
    assert credentials.load_dnsdb_key() == "toml-dnsdb"
    data = tomllib.loads((isolated / "credentials.toml").read_text())
    assert data["other"] == {"name": 'x "quoted"', "port": 8}
    assert stat.S_IMODE((isolated / "credentials.toml").stat().st_mode) == 0o600


def test_removing_a_service_drops_only_its_table(isolated):
    write(isolated / "credentials.toml", TOML)
    credentials.save_credentials({}, remove=(credentials.DNSDB,))
    assert credentials.load_dnsdb_key() is None
    assert credentials.load_dtapi_credentials() == ("toml-user", "toml-key")


def test_environment_still_wins_over_saved_keys(isolated, monkeypatch):
    monkeypatch.setenv("DNSDB_API_KEY", "env-key")
    credentials.save_credentials({credentials.DNSDB: {"api_key": "saved"}})
    assert credentials.load_dnsdb_key() == "env-key"


def test_an_unreadable_file_is_never_overwritten(isolated):
    path = write(isolated / "credentials.toml", "[dnsdb\napi_key = ")
    with pytest.raises(credentials.CredentialFileError):
        credentials.save_credentials({credentials.DNSDB: {"api_key": "k"}})
    assert path.read_text() == "[dnsdb\napi_key = "


def test_vpndb_key_and_url_follow_the_same_order(isolated, monkeypatch):
    assert credentials.load_vpndb_key() is None and credentials.vpndb_base_url() == "https://vpndb.io/api/v1"
    write(isolated / ".dtvpndb", "vpndb_file\n")
    credentials.clear_credential_cache()
    assert credentials.load_vpndb_key() == "vpndb_file"
    write(isolated / "credentials.toml", '[vpndb]\napi_key = "vpndb_toml"\nurl = "http://localhost:3000/api/v1/"\n')
    credentials.clear_credential_cache()
    assert credentials.load_vpndb_key() == "vpndb_toml" and credentials.vpndb_base_url() == "http://localhost:3000/api/v1"
    monkeypatch.setenv("VPNDB_API_KEY", "vpndb_env")
    credentials.clear_credential_cache()
    assert credentials.vpndb_credential().source == "$VPNDB_API_KEY"
    path = credentials.save_credentials({credentials.VPNDB: {"api_key": "vpndb_saved"}})
    assert tomllib.loads((isolated / "credentials.toml").read_text())["vpndb"]["api_key"] == "vpndb_saved" and path
    rows = {o["Option"]: o for o in credentials.credential_overview()["options"][credentials.TOML]}
    assert rows["[vpndb] api_key"]["Note"].startswith("Not used")
