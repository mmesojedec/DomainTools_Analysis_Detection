import io
import json
import zipfile

import pandas as pd

from core.data_export import (
    EXPORT_SETS,
    ExportContext,
    build_zip,
    export_counts,
    export_files,
    manifest,
    to_csv,
    to_ndjson,
)
from core.dataset import Dataset
from integrations.collector import CollectedData


def context():
    ds = Dataset(selected_domains=["example.com"], timezone="UTC", pdns_provider="DNSDB Scout")
    ds.pdns_utc = pd.DataFrame([{"Domain": "example.com", "RRName": "www.example.com", "Field": "A",
                                 "Value": "1.2.3.4", "First Seen": pd.Timestamp("2026-10-01 08:00"), "Count": 3}])
    ds.enrichment = {"example.com": {"domain": "example.com", "ip": [{"address": {"value": "1.2.3.4"}}]}}
    alerts = pd.DataFrame([{"Domain": "example.com", "Finding": "New IP", "Evidence": [{"IP": "1.2.3.4"}]}])
    collected = CollectedData(targets=["example.com"], domain_targets=["example.com"])
    collected.statuses = [{"Source": "DNSDB Scout", "Target": "example.com", "Status": "OK", "Records": 1, "Detail": ""}]
    return ExportContext(ds, collected, alerts, pd.DataFrame(), "2026-10-28T09:00:00+00:00")


def test_ndjson_keeps_nested_values_and_iso_times():
    rows = [json.loads(line) for line in to_ndjson(pd.DataFrame([
        {"When": pd.Timestamp("2026-10-01 08:00"), "Missing": pd.NaT, "Count": pd.Series([3]).iloc[0], "List": ["a", "b"]},
    ])).splitlines()]
    assert rows == [{"When": "2026-10-01T08:00:00", "Missing": None, "Count": 3, "List": ["a", "b"]}]


def test_csv_writes_nested_values_as_json():
    text = to_csv(pd.DataFrame([{"Domain": "example.com", "Evidence": [{"IP": "1.2.3.4"}],
                                 "Seen": pd.Timestamp("2026-10-01 08:00")}]))
    frame = pd.read_csv(io.StringIO(text))
    assert json.loads(frame.loc[0, "Evidence"]) == [{"IP": "1.2.3.4"}] and frame.loc[0, "Seen"] == "2026-10-01T08:00:00"


def test_export_files_skips_empty_sets_and_keeps_raw_json_as_ndjson():
    ctx = context()
    files, counts = export_files(ctx, ["detections", "passive_dns", "certificates", "iris_investigate",
                                       "data_source_status"], "csv")
    assert set(files) == {"detections.csv", "passive_dns.csv", "iris_investigate.ndjson", "data_source_status.csv"}
    assert counts["passive_dns.csv"] == 1
    iris = json.loads(files["iris_investigate.ndjson"])
    assert iris["domain"] == "example.com" and iris["ip"][0]["address"]["value"] == "1.2.3.4"
    files, _ = export_files(ctx, ["detections"], "ndjson")
    assert json.loads(files["detections.ndjson"])["Evidence"] == [{"IP": "1.2.3.4"}]


def test_every_set_builds_on_an_empty_run():
    ctx = context()
    for item in EXPORT_SETS:
        item.build(ctx)


def test_zip_holds_the_files_and_a_manifest():
    ctx = context()
    files, counts = export_files(ctx, ["passive_dns", "iocs"], "ndjson")
    archive = zipfile.ZipFile(io.BytesIO(build_zip(files, manifest(ctx, counts, "ndjson"))))
    assert set(archive.namelist()) == set(files) | {"manifest.json"}
    meta = json.loads(archive.read("manifest.json"))
    assert meta["targets"] == ["example.com"] and meta["timestamps"] == "UTC" and meta["files"] == counts


def test_counts_match_the_files_without_formatting_them():
    ctx = context()
    keys = ["detections", "passive_dns", "certificates", "iris_investigate"]
    assert export_counts(ctx, keys, "csv") == export_files(ctx, keys, "csv")[1] == {
        "detections.csv": 1, "passive_dns.csv": 1, "iris_investigate.ndjson": 1}


def test_iocs_are_built_once_per_dataset(monkeypatch):
    import core.export as export
    ctx, calls = context(), []
    real = export.collect_iocs
    monkeypatch.setattr(export, "collect_iocs", lambda ds, intel=None: calls.append(1) or real(ds, intel))
    first, _ = export_files(ctx, ["iocs"], "csv")
    second, _ = export_files(ctx, ["iocs"], "ndjson")
    assert len(calls) == 1 and "iocs.csv" in first and "iocs.ndjson" in second
