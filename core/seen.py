"""
Indicator Sightings: finds an indicator (IP, domain or hostname, name server, MX, certificate SHA-256, web
tracker code, email) in every saved run (dt_runs/, their per-domain artifacts) and every offline dataset (dt_offline/,
rebuilt from the saved data). Local files only: no API query.
"""
import re

import pandas as pd

from core.offline import list_offline_datasets, load_offline_dataset
from core.persistence import collect_run_artifacts, load_all_runs
from core.run_history import snapshot_alerts

RUN, DATASET = "Run", "Offline dataset"
COLUMNS = ["Found in", "When", "Name", "Target list", "Domain", "Kind", "Value", "Alerts on domain", "key", "id"]
MIN_PARTIAL = 3                     # characters a partial search needs, so "1" does not match everything
_DEFANG = (("[.]", "."), ("(.)", "."), ("{.}", "."), ("[dot]", "."), ("(dot)", "."), ("[:]", ":"), ("[@]", "@"),
           ("[at]", "@"))
_dataset_cache = {}                 # (dataset id, size) -> {domain: {kind: [values]}}


def normalize(query):
    """The indicator as stored: refanged, lower case, no scheme, path or trailing dot ("hxxps://a[.]com/x" -> "a.com")."""
    text = str(query or "").strip().lower()
    for token, plain in _DEFANG:
        text = text.replace(token, plain)
    match = re.match(r"^(?:hxxps?|https?|ftp)://([^/?#]+)", text)
    if match:
        text = match.group(1).rsplit("@", 1)[-1]
    return text.strip().rstrip(".")


def matches(value, query, partial=False):
    """Whether a stored value is the indicator: the same value, a tracker's code ("GA4: G-ABC" for "g-abc"), or with
    `partial`, any value containing it."""
    value = str(value or "").lower()
    if value == query or value.split(": ", 1)[-1] == query:
        return True
    return partial and len(query) >= MIN_PARTIAL and query in value


def _hits(artifacts, targets, query, partial):
    """(domain, kind, value) of every match among a run's targets and per-domain artifacts."""
    found = [(target, "Target", target) for target in targets or [] if matches(target, query, partial)]
    for domain, kinds in (artifacts or {}).items():
        for kind, values in (kinds or {}).items():
            found += [(domain, kind, value) for value in values or [] if matches(value, query, partial)]
    return found


def _label(targets, limit=3):
    targets = list(targets or [])
    return ", ".join(targets[:limit]) + (f" (+{len(targets) - limit} more)" if len(targets) > limit else "")


def search_runs(query, partial=False):
    """Matches in every saved run, one row per (run, domain, kind, value)."""
    rows = []
    for key, snapshot in load_all_runs():
        hits = _hits(snapshot.get("artifacts"), snapshot.get("targets"), query, partial)
        if not hits:
            continue
        alerts = snapshot_alerts(snapshot)
        per_domain = alerts["Domain"].astype(str).str.lower().value_counts().to_dict() if not alerts.empty else {}
        for domain, kind, value in hits:
            rows.append({"Found in": RUN, "When": snapshot.get("created"), "Name": snapshot.get("name") or "",
                         "Target list": _label(snapshot.get("targets")), "Domain": domain, "Kind": kind,
                         "Value": value, "Alerts on domain": int(per_domain.get(str(domain).lower(), 0)),
                         "key": key, "id": snapshot.get("id")})
    return rows


def dataset_artifacts(manifest):
    """A dataset's per-domain artifacts, built once per dataset (and its size) from the saved data."""
    cache_key = (manifest["id"], manifest.get("size_bytes"))
    if cache_key not in _dataset_cache:
        try:
            collected, _ = load_offline_dataset(manifest["id"])
            _dataset_cache[cache_key] = collect_run_artifacts(collected)
        except (OSError, ValueError, KeyError):   # a dataset deleted or damaged since it was listed
            _dataset_cache[cache_key] = {}
    return _dataset_cache[cache_key]


def search_datasets(query, partial=False, datasets=None):
    """Matches in every offline dataset, one row per (dataset, domain, kind, value)."""
    rows = []
    for manifest in list_offline_datasets() if datasets is None else datasets:
        for domain, kind, value in _hits(dataset_artifacts(manifest), manifest.get("targets"), query, partial):
            rows.append({"Found in": DATASET, "When": manifest.get("created"), "Name": manifest.get("name") or "",
                         "Target list": _label(manifest.get("targets")), "Domain": domain, "Kind": kind,
                         "Value": value, "Alerts on domain": None, "key": manifest.get("run_key"),
                         "id": manifest["id"]})
    return rows


def search(query, partial=False, include_datasets=True):
    """Every match, newest first, as a DataFrame (COLUMNS; When as UTC timestamps)."""
    query = normalize(query)
    if not query:
        return pd.DataFrame(columns=COLUMNS)
    rows = search_runs(query, partial) + (search_datasets(query, partial) if include_datasets else [])
    frame = pd.DataFrame(rows, columns=COLUMNS)
    frame["When"] = pd.to_datetime(frame["When"], errors="coerce", utc=True)
    frame["Alerts on domain"] = frame["Alerts on domain"].astype("Int64")
    return frame.sort_values("When", ascending=False, kind="stable").reset_index(drop=True)


def summary(frame):
    """{"runs", "datasets", "target_lists", "domains", "first", "last"} of a search result."""
    if frame.empty:
        return {"runs": 0, "datasets": 0, "target_lists": 0, "domains": 0, "first": None, "last": None}
    runs, datasets = frame[frame["Found in"] == RUN], frame[frame["Found in"] == DATASET]
    return {"runs": runs["id"].nunique(), "datasets": datasets["id"].nunique(),
            "target_lists": frame["key"].dropna().nunique(), "domains": frame["Domain"].str.lower().nunique(),
            "first": frame["When"].min(), "last": frame["When"].max()}
