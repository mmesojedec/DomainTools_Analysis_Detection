"""Per-domain evaluation context shared by all detection rules."""
import re
from dataclasses import dataclass, field

import pandas as pd

from core.caa import CaaPolicy
from core.intel_data import RULE_METADATA

ALERT_COLUMNS = [
    "Domain", "Risk", "Risk Evidence", "Threat Type", "Severity", "Confidence", "Category", "MITRE ATT&CK", "Threat Logic", "Triggering IOCs",
    "Evidence", "Occurrences",
]
EVIDENCE_KEYS = ("Time", "Field", "Value", "Artifact")

IP_FIELDS = {"A", "IP", "A RECORD", "AAAA"}
NS_FIELDS = {"NS", "NAME_SERVER"}
MAX_IOC_LINES = 25
MAX_EVIDENCE = 200
_EVENT_LINE_RE = re.compile(r"^\[(?P<time>[^\]]+)\]\s*(?P<field>.*?)\s*➔\s*(?P<value>.*)$")
_KEY_VALUE_RE = re.compile(r"^(?P<field>[A-Za-z][\w /&().'-]{0,40}):\s*(?P<value>.+)$")
_TIME_FIELD_RE = re.compile(r"date|issued|created|seen|start|before|after", re.IGNORECASE)


@dataclass
class DomainContext:
    """Everything a rule needs to evaluate one domain/IP. Rules append alerts via `add()`."""
    domain: str
    is_ip: bool
    thresholds: dict
    risk_display: object = "N/A"
    numeric_risk: float = None
    risk_evidence: str = "None"
    events: pd.DataFrame = field(default_factory=pd.DataFrame)
    ssl: pd.DataFrame = field(default_factory=pd.DataFrame)
    enrichment: dict = None
    tracker_occurrences: dict = field(default_factory=dict)
    caa_policy: CaaPolicy = field(default_factory=CaaPolicy)
    profile: dict = field(default_factory=dict)
    ip_intel: dict = field(default_factory=dict)
    cert_events: pd.DataFrame = field(default_factory=pd.DataFrame)
    cname_map: pd.DataFrame = field(default_factory=pd.DataFrame)   # the domain's rows of core.cname.build_cname_map
    anonymizers: dict = field(default_factory=dict)   # ip -> VPNDB row (core.anonymizers.by_ip) of the run's IPs
    exit_weeks: dict = field(default_factory=dict)    # ip -> the weeks VPNDB has exit evidence for (history)
    neighbours: dict = field(default_factory=dict)    # /24 -> VPNDB verdict row (core.anonymizers.neighbour_frame)
    asn_verdicts: dict = field(default_factory=dict)  # ASN -> VPNDB row (core.anonymizers.asn_frame)
    tor_networks: dict = field(default_factory=dict)  # ASN -> Tor exit network (VPNDB /tor exitNetworks)
    tor_prefixes: list = field(default_factory=list)  # [(ip_network, exitPrefixes entry)] (VPNDB /tor)
    brands: tuple = ()
    official_domains: tuple = ()
    now: pd.Timestamp = field(default_factory=lambda: pd.Timestamp.now(tz="UTC").tz_localize(None))
    entropy: float = 0.0
    flags: set = field(default_factory=set)
    alerts: list = field(default_factory=list)
    evidence_scope: list = None    # default evidence while rules evaluate one object (e.g. the current certificate)

    @property
    def risk_known(self):
        return self.numeric_risk is not None

    @property
    def is_high_risk(self):
        return self.risk_known and self.numeric_risk >= self.thresholds["high_risk_score"]

    def add(self, threat_type, severity, mitre, logic, iocs, flag=None, confidence=None, evidence=None):
        """
        Records an alert; `flag` marks a behavioral finding that later compound rules can consume.
        `evidence` is a list of evidence records (see `evidence_record`); without it the current `evidence_scope`
        is used, and failing that the records are parsed from the IOC text.
        """
        category, default_confidence = RULE_METADATA.get(threat_type, ("Other", "Medium"))
        if evidence is None:
            evidence = self.evidence_scope if self.evidence_scope is not None else evidence_from_iocs(iocs)
        self.alerts.append({
            "Domain": self.domain,
            "Risk": self.risk_display,
            "Risk Evidence": self.risk_evidence,
            "Threat Type": threat_type,
            "Severity": severity,
            "Confidence": confidence or default_confidence,
            "Category": category,
            "MITRE ATT&CK": mitre,
            "Threat Logic": logic,
            "Triggering IOCs": iocs,
            "Evidence": list(evidence)[:MAX_EVIDENCE],
            "Occurrences": 1,
        })
        if flag:
            self.flags.add(flag)


def fmt_ts(value, fmt="%Y-%m-%d %H:%M"):
    """Formats a timestamp for IOC text, tolerating missing values."""
    if value is None or pd.isna(value):
        return "unknown time"
    try:
        return pd.Timestamp(value).strftime(fmt)
    except (TypeError, ValueError):
        return str(value)


def evidence_record(time=None, field="", value="", artifact=None):
    """One structured evidence record: when it happened, what was observed, and the pivotable artifact (hash, IP, ...)."""
    time = pd.to_datetime(time, errors="coerce") if time is not None else pd.NaT
    if pd.notna(time) and time.tzinfo is not None:
        time = time.tz_convert("UTC").tz_localize(None)
    return {"Time": time, "Field": str(field or ""), "Value": str(value if value is not None else ""), "Artifact": artifact}


def event_record(row, value_col="Value", max_len=None, label=None):
    """Structured twin of `event_line`."""
    value = str(row.get(value_col, ""))
    if max_len:
        value = value[:max_len]
    return evidence_record(row.get("Date"), label or row.get("Field", ""), value)


def evidence_from_iocs(iocs):
    """Best-effort records from IOC text: `[ts] FIELD ➔ value` and `Key: value` lines; anything else is kept as a value."""
    records = []
    for line in str(iocs or "").splitlines():
        line = line.strip()
        if not line or line.startswith("..."):
            continue
        match = _EVENT_LINE_RE.match(line)
        if match:
            records.append(evidence_record(match["time"], match["field"], match["value"]))
            continue
        match = _KEY_VALUE_RE.match(line)
        if match:
            time = match["value"] if _TIME_FIELD_RE.search(match["field"]) else None
            if time is not None and pd.isna(pd.to_datetime(time, errors="coerce")):
                time = None
            records.append(evidence_record(time, match["field"], match["value"]))
            continue
        records.append(evidence_record(value=line))
    return records


def event_line(row, value_col="Value", max_len=None, label=None):
    """Formats a single event as `[timestamp] FIELD ➔ value` for IOC listings."""
    value = str(row.get(value_col, ""))
    if max_len:
        value = value[:max_len]
    return f"[{fmt_ts(row.get('Date'))}] {label or row.get('Field', '')} ➔ {value}"


def upper_fields(events):
    """Upper-cased record type names with any `pDNS:`/`DH:` display prefix removed."""
    return events["Field"].astype(str).str.upper().str.replace(r"^(?:PDNS|DH):\s*", "", regex=True)
