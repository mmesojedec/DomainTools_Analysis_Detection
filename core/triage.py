"""
Triage status: the analyst's decision on an alert (domain + finding) or on a whole domain, with a short note. Kept in
dt_triage.json, so a later run of the same domains shows what was already reviewed instead of everything as new.
"""
from datetime import datetime, timezone

import pandas as pd

from config import TRIAGE_FILE
from core.persistence import load_json, save_json

STATUSES = ["New", "Investigating", "Benign", "Malicious"]
OPEN = ("New", "Investigating")          # still needs a look
REVIEWED = ("Benign", "Malicious")
DOMAIN = "*"                             # threat type of a verdict on the whole domain
STATUS_HELP = ("**New**: not looked at yet. **Investigating**: someone is on it. **Benign**: checked, expected or "
               "harmless. **Malicious**: confirmed bad; its indicators go into the confirmed-indicator export.")
STATUS_COLORS = {"New": "gray", "Investigating": "blue", "Benign": "green", "Malicious": "red"}


def _key(domain, threat_type):
    return f"{domain}|{threat_type}"


def load_triage(path=None):
    """{"domain|threat type": {"domain", "threat_type", "status", "note", "updated"}}."""
    data = load_json(path or TRIAGE_FILE, {})
    return data if isinstance(data, dict) else {}


def set_status(items, status, note="", path=None):
    """Sets `status` (and `note`) for each (domain, threat type) in `items`; New removes the entry."""
    if status not in STATUSES:
        raise ValueError(f"Unknown status: {status!r}")
    path = path or TRIAGE_FILE
    entries = load_triage(path)
    now = datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")
    for domain, threat_type in dict.fromkeys(items):
        if status == "New" and not note.strip():
            entries.pop(_key(domain, threat_type), None)
        else:
            entries[_key(domain, threat_type)] = {"domain": domain, "threat_type": threat_type, "status": status,
                                                  "note": note.strip()[:1000], "updated": now}
    save_json(path, entries)
    return entries


def status_of(entries, domain, threat_type=DOMAIN):
    entry = entries.get(_key(domain, threat_type)) or {}
    return entry.get("status", "New"), entry.get("note", "")


def attach_status(alerts, entries):
    """`alerts` with Status and Triage Note columns from `entries` (New when nothing was decided)."""
    if alerts is None or alerts.empty:
        return alerts if alerts is not None else pd.DataFrame()
    found = [entries.get(_key(d, t)) or {} for d, t in zip(alerts["Domain"].astype(str), alerts["Threat Type"].astype(str))]
    return alerts.assign(Status=[entry.get("status", "New") for entry in found],
                         **{"Triage Note": [entry.get("note", "") for entry in found]})


def domain_verdicts(entries, domains=None):
    """{domain: status} of the domain-level verdicts, optionally only for `domains`."""
    verdicts = {entry["domain"]: entry["status"] for entry in entries.values() if entry.get("threat_type") == DOMAIN}
    return {d: s for d, s in verdicts.items() if domains is None or d in set(domains)}


def triage_counts(alerts):
    """{status: alert count} for an alert frame with a Status column (every status present, 0 when none)."""
    counts = alerts["Status"].value_counts().to_dict() if alerts is not None and "Status" in alerts else {}
    return {status: int(counts.get(status, 0)) for status in STATUSES}


def open_alerts(alerts):
    if alerts is None or alerts.empty or "Status" not in alerts:
        return alerts
    return alerts[alerts["Status"].isin(OPEN)]
