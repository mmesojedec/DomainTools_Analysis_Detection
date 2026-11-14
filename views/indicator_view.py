"""
One indicator in focus (a dialog): everything the run knows about a certificate, JA4X, IP, host or other value that
a suggestion names, the alerts that name it and where earlier investigations saw it, with the next steps already
pointed at it (the Certificates page narrowed to it, Analyze, Find in Iris, a CertsQL search, its sightings). Opening
it makes no API call.
"""
import pandas as pd
import streamlit as st

from core import certsql
from core.helpers import is_ip_address
from core.hunt_plan import alert_mentions
from core.seen import normalize, search_runs
from core.triage import open_alerts
from views import navigation
from views.hunt_actions import analyze_button, iris_button
from views.pivot_view import dataset_pivots
from views.query_editor import set_query
from views.recent_view import open_sightings
from views.ssl_view import CERT_FOCUS_KEY

IP_KINDS = {"IP", "IP address", "Name server IP", "Mail server IP"}
HOST_KINDS = {"Host", "Name server", "Mail server", "Redirect domain", "Target"}
CERT_COLUMNS = ["Domain", "Common Name", "Issuer", "Not Before", "Not After", "Duration", "JA4X", "Has Embedded SCTs",
                "Source"]
PDNS_COLUMNS = ["Domain", "RRName", "Field", "Value", "Count", "First Seen", "Last Seen"]
MAX_ROWS = 200


def kind_of(kind, value):
    """Certificate, JA4X, IP, Host or Value for a start step kind or a Pivot Ranking type."""
    text = str(value).lower()
    if kind == "JA4X" or (len(text) == 38 and text.count("_") == 2):
        return "JA4X"
    if kind in ("Certificate", "SSL certificate (SHA-1)") or (len(text) in (40, 64) and
                                                              all(c in "0123456789abcdef" for c in text)):
        return "Certificate"
    if kind in IP_KINDS or is_ip_address(text):
        return "IP"
    if kind in HOST_KINDS:
        return "Host"
    return "Value"


def _cert_rows(ds, value):
    ssl = ds.ssl
    if ssl is None or ssl.empty:
        return pd.DataFrame()
    text = str(value).lower()
    mask = pd.Series(False, index=ssl.index)
    for column in ("Hash", "SHA1", "JA4X"):
        if column in ssl.columns:
            mask |= ssl[column].astype(str).str.lower() == text
    rows = ssl[mask].drop_duplicates(subset=[c for c in ("Domain", "Hash") if c in ssl.columns])
    return rows[[c for c in CERT_COLUMNS if c in rows.columns]]


def _pdns_rows(ds, value, host=False):
    pdns = ds.pdns
    if pdns is None or pdns.empty or "Value" not in pdns.columns:
        return pd.DataFrame()
    text = str(value).lower().rstrip(".")
    values = pdns["Value"].astype(str).str.lower().str.rstrip(".")
    mask = values == text
    if host and "RRName" in pdns.columns:
        mask |= pdns["RRName"].astype(str).str.lower().str.rstrip(".") == text
    return pdns[mask][[c for c in PDNS_COLUMNS if c in pdns.columns]].head(MAX_ROWS)


def _alerts_naming(alerts, value):
    alerts = open_alerts(alerts)
    if alerts is None or alerts.empty:
        return pd.DataFrame()
    named = alerts[[alert_mentions(alert, value) for alert in alerts.to_dict("records")]]
    return named[[c for c in ("Domain", "Threat Type", "Severity", "Confidence") if c in named.columns]]


def _pivot(ds, value):
    pivots = dataset_pivots(ds)
    if pivots is None or pivots.empty:
        return None
    match = pivots[pivots["Value"].astype(str).str.lower() == str(value).lower()]
    return match.iloc[0] if not match.empty else None


def focus_certificates(value):
    """Opens the Certificates page showing only this certificate (or JA4X)."""
    navigation.go("certs", **{CERT_FOCUS_KEY: str(value).lower()})


def _certsql_search(field, value):
    set_query("certsql_query", f'{certsql.HEADER}\n{field} equals "{str(value).lower()}"')
    navigation.go("certsql")


def _render_actions(ds, kind, value, certs, pivot, key):
    lead_search = pivot["Iris Search"] if pivot is not None else ""
    with st.container(horizontal=True, vertical_alignment="center"):
        if kind in ("Certificate", "JA4X") and not certs.empty:
            if st.button("Show on Certificates (only this)", key=f"{key}::certs", icon=":material/verified_user:",
                         type="primary", help="Opens the Certificates page with every tab narrowed to it"):
                focus_certificates(value)
        if kind == "Certificate":
            field = "sha256" if len(value) == 64 else "sha1"
            target = f"{field}:{str(value).lower()}"
            analyze_button([target], f"Certificate {value}", key=f"{key}::analyze", label="Analyze its domains")
            if st.button("Search CertsQL", key=f"{key}::certsql", icon=":material/badge:",
                         help="Opens CertsQL with this certificate's query (run it there)"):
                _certsql_search(field, value)
            sha1 = next((s for s in certs["SHA1"] if s), "") if "SHA1" in certs else ""
            search = lead_search or (f"ssl_hash={str(sha1).lower()}" if sha1 else "")
            if field == "sha1" and not search:
                search = f"ssl_hash={str(value).lower()}"
            if search:
                iris_button(search, key=f"{key}::iris")
        elif kind == "JA4X":
            if st.button("Search CertsQL", key=f"{key}::certsql", icon=":material/badge:",
                         help="Opens CertsQL with every certificate of this JA4X (run it there)"):
                _certsql_search("ja4x", value)
        elif kind in ("IP", "Host"):
            analyze_button([value], f"{kind} {value}", key=f"{key}::analyze", label="Analyze")
            search = lead_search or (f"ip={value}" if kind == "IP" else "")
            if search:
                iris_button(search, key=f"{key}::iris")
        elif lead_search:
            iris_button(lead_search, key=f"{key}::iris")
        if st.button("Where else was it seen?", key=f"{key}::seen", icon=":material/visibility:",
                     help="Recent runs → Indicator Sightings for this value"):
            open_sightings(value)


@st.dialog("Indicator", width="large")
def show_indicator(ds, alerts, kind, value):
    """Everything the run knows about one indicator, and its next steps."""
    kind = kind_of(kind, value)
    st.markdown(f"#### {kind}: `{value}`")
    certs = _cert_rows(ds, value) if kind in ("Certificate", "JA4X") else pd.DataFrame()
    records = _pdns_rows(ds, value, host=kind == "Host") if kind in ("IP", "Host") else pd.DataFrame()
    named = _alerts_naming(alerts, value)
    pivot = _pivot(ds, value)
    earlier = pd.DataFrame(search_runs(normalize(value)))
    if not earlier.empty:
        earlier = earlier[~earlier["Domain"].astype(str).str.lower().isin({d.lower() for d in ds.selected_domains})]
    domains = sorted(set(certs.get("Domain", [])) | set(records.get("Domain", [])) | set(named.get("Domain", [])))
    columns = st.columns(4)
    columns[0].metric("Your domains", f"{len(domains):,}", help=", ".join(domains) or None)
    columns[1].metric("Open alerts naming it", f"{len(named):,}")
    columns[2].metric("Iris domains", f"{int(pivot['Iris Domains']):,}" if pivot is not None
                      and pd.notna(pivot["Iris Domains"]) else "—", help="Domains in Iris Investigate that share it")
    columns[3].metric("Earlier investigations", f"{earlier['key'].nunique() if not earlier.empty else 0:,}",
                      help="Saved runs of other domains where it was seen")
    _render_actions(ds, kind, value, certs, pivot, key=f"indicator::{value}")
    if not named.empty:
        st.markdown("**Open alerts that name it**")
        st.dataframe(named, hide_index=True, width="stretch")
    if not certs.empty:
        st.markdown(f"**Certificates in this run** ({len(certs):,})")
        st.dataframe(certs, hide_index=True, width="stretch")
    if not records.empty:
        st.markdown(f"**Passive DNS records with it** ({len(records):,}{'+' if len(records) >= MAX_ROWS else ''})")
        st.dataframe(records, hide_index=True, width="stretch")
    if ds.anonymizers is not None and not ds.anonymizers.empty and kind == "IP" and "IP" in ds.anonymizers.columns:
        verdict = ds.anonymizers[ds.anonymizers["IP"] == value]
        if not verdict.empty:
            st.markdown("**VPNDB**")
            st.dataframe(verdict, hide_index=True, width="stretch")
    if not earlier.empty:
        st.markdown(f"**Seen in earlier investigations** ({earlier['key'].nunique():,})")
        st.dataframe(earlier[["When", "Target list", "Domain", "Kind", "Alerts on domain"]].head(50), hide_index=True,
                     width="stretch")
    if certs.empty and records.empty and named.empty and earlier.empty:
        st.caption("The run has no records of it beyond the lead itself.")
