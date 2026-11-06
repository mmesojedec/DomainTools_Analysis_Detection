"""Data Export lens: choose IOCs, tables and raw records and download them as CSV or NDJSON (no charts)."""
import json
from datetime import datetime, timezone

import streamlit as st

from core.data_export import EXPORT_SETS, GROUPS, ExportContext, build_zip, export_counts, export_files, manifest
from core.export import confirmed_indicators, dataset_iocs, to_misp_event, to_stix_bundle
from core.pivots import iris_queries
from core.triage import domain_verdicts, load_triage
from views.pivot_view import dataset_pivots


def render_export_lens(ds, collected, alerts, profiles, created=None):
    st.header("Data Export", help="Data to share with other teams: indicators, the tables the lenses show and the raw "
                                  "collected records. No charts; every timestamp is UTC.")
    st.caption("Raw data follows the analysis window and the Global View Filters; the hostname inventory and its "
               "certificate links cover the full collected history. Detections leave out suppressed alerts.")
    render_confirmed_export(ds, alerts, expanded=True)
    _render_export_choices(ExportContext(ds, collected, alerts, profiles, created))


def render_confirmed_export(ds, alerts, expanded=False):
    """Indicators of what the analyst marked Malicious, as CSV, MISP and STIX, plus the Iris searches to hunt on."""
    verdicts = domain_verdicts(load_triage(), ds.selected_domains)
    indicators = confirmed_indicators(dataset_iocs(ds), alerts, verdicts, ds.anonymizers)
    with st.expander(f"Confirmed indicators ({len(indicators):,}): what you marked Malicious", expanded=expanded,
                     icon=":material/gpp_bad:"):
        if indicators.empty:
            st.caption("Nothing is marked Malicious yet. Mark alerts on the Alerts page (in each group) or a whole "
                       "domain on its Domain profile; their indicators show up here.")
            return
        shared = int(indicators["Shared Exit"].sum())
        if shared and not st.checkbox(f"Include shared VPN / proxy exits ({shared})", key=f"confirmed_shared_{expanded}",
                                      help="IPs VPNDB rates as shared exits (IOC value LOW or sharing HIGH): many "
                                           "people leave through them, so they identify the service, not the actor, "
                                           "and blocking them hits everyone using it. Left out by default; included, "
                                           "they are not marked for detection (MISP to_ids false)."):
            indicators = indicators[~indicators["Shared Exit"]]
            st.caption(f"{shared} shared VPN / proxy exit(s) left out.")
        stamp = datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%SZ")
        c_csv, c_misp, c_stix = st.columns(3)
        c_csv.download_button("CSV", indicators.to_csv(index=False).encode(), f"{stamp}_confirmed_iocs.csv",
                              "text/csv", width="stretch", on_click="ignore")
        c_misp.download_button("MISP event (JSON)", to_misp_event(indicators).encode(), f"{stamp}_misp_event.json",
                               "application/json", width="stretch", on_click="ignore",
                               help="MISP's JSON import format: one attribute per indicator (Event → Add → Import)")
        marked = alerts[alerts["Status"] == "Malicious"] if "Status" in alerts.columns else alerts.iloc[0:0]
        c_stix.download_button("STIX 2.1 bundle", to_stix_bundle(indicators, marked).encode(),
                               f"{stamp}_confirmed_stix.json", "application/json", width="stretch", on_click="ignore")
        st.dataframe(indicators, hide_index=True, width="stretch", height=min(320, 35 * (len(indicators) + 1) + 3))
        domains = set(indicators["Domain"].str.split(", ").explode())
        queries = iris_queries(dataset_pivots(ds), domains)
        if queries:
            st.markdown("**Iris Investigate searches** for the rare values these domains have: run them to find "
                        "more of the same infrastructure.")
            st.code("\n".join(queries), language=None)


@st.fragment
def _render_export_choices(context):
    """A fragment: ticking items or switching the format reruns only this part, and files are built on download."""
    chosen = []
    for column, group in zip(st.columns(len(GROUPS)), GROUPS):
        column.markdown(f"**{group}**")
        for item in (s for s in EXPORT_SETS if s.group == group):
            st.session_state.setdefault(f"export_{item.key}", item.default)   # a link may have ticked it already
            if column.checkbox(item.label, help=item.help, key=f"export_{item.key}"):
                chosen.append(item.key)
    fmt = st.radio("Format", ["csv", "ndjson"], horizontal=True, key="export_format",
                   format_func={"csv": "CSV (one file per table)", "ndjson": "NDJSON (one JSON object per line)"}.get,
                   help="CSV opens in a spreadsheet; lists and nested values are written as JSON text. NDJSON keeps "
                        "nested values and loads into SIEMs, jq and most data tools. Iris Investigate responses are "
                        "nested, so they are always NDJSON.")
    if not chosen:
        st.info("Tick at least one item to export.")
        return
    counts = export_counts(context, chosen, fmt)
    if not counts:
        st.info("The chosen items have no rows for the current filters.")
        return
    st.dataframe([{"File": name, "Rows": rows} for name, rows in counts.items()], hide_index=True)
    stamp = datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%SZ")
    if len(counts) == 1:
        name = next(iter(counts))
        st.download_button(f"Download {name}", lambda: export_files(context, chosen, fmt)[0][name].encode(),
                           f"{stamp}_{name}", "text/csv" if name.endswith(".csv") else "application/x-ndjson",
                           type="primary", on_click="ignore", help="The file is built when you click")
    else:
        def zipped():
            files, built = export_files(context, chosen, fmt)
            return build_zip(files, manifest(context, built, fmt))
        st.download_button(f"Download {len(counts)} files (ZIP)", zipped, f"dt_export_{stamp}.zip", "application/zip",
                           type="primary", on_click="ignore",
                           help="One file per table plus manifest.json (targets, analysis window, row counts); built "
                                "when you click")
    with st.expander("Manifest"):
        st.code(json.dumps(manifest(context, counts, fmt), indent=2), language="json")
