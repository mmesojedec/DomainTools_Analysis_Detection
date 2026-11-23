"""Data Export lens: choose IOCs, tables and raw records and download them as CSV or NDJSON (no charts)."""
import json
from datetime import datetime, timezone

import pandas as pd
import streamlit as st

from core import similarity as sim
from core.analysis_report import COMPLETE, HIGH, LEVELS, PARTS, SECTIONS, ReportContext, build_analysis_report
from core.data_export import EXPORT_SETS, GROUPS, ExportContext, build_zip, export_counts, export_files, manifest
from core.export import confirmed_indicators, dataset_iocs, to_misp_event, to_stix_bundle
from core.persistence import load_all_runs
from core.pivots import iris_queries
from core.report_html import CHARTS_CDN, CHARTS_EMBED, CHARTS_NONE
from core.triage import domain_verdicts, load_triage
from views.alert_tools import render_exports
from views.pivot_view import dataset_pivots


def render_export_lens(ctx, created=None):
    ds, collected, profiles, correlation = ctx.ds, ctx.collected, ctx.profiles, ctx.threats.correlation
    alerts = ctx.view.active.reset_index(drop=True)
    st.header("Export & report", help="Data to share with other teams: indicators, the tables the lenses show and the raw "
                                  "collected records. No charts; every timestamp is UTC.")
    st.caption("Raw data follows the analysis window and the sidebar view filters; the hostname inventory and its "
               "certificate links cover the full collected history. Detections leave out suppressed alerts.")
    render_analysis_report(ctx, created)
    render_exports(ds, alerts, profiles, correlation)
    render_confirmed_export(ds, alerts, expanded=True)
    _render_export_choices(ExportContext(ds, collected, alerts, profiles, created))


REPORT_KEY = "report_sec_"
CHART_CHOICES = {CHARTS_EMBED: "Interactive, embedded (works offline, about 5 MB)",
                 CHARTS_CDN: "Interactive, loaded from the internet (small file)",
                 CHARTS_NONE: "No charts (tables only)"}


def _hunt_context(timezone, run_id):
    """The hunt map (SVG) and its runs for the report, when the loaded run belongs to a saved hunt."""
    from core.hunt_report import _Hunt, hunt_map_svg
    from core.hunt_result import start_links
    from core.hunt_tree import hunt_members, hunt_root
    from views.hunt_map_view import run_items
    runs = load_all_runs()
    root_id = hunt_root(runs, run_id) if run_id else None
    if not root_id:
        return None
    members = hunt_members(runs, root_id)
    if len(members) < 2:
        return None
    hunt = _Hunt(members, run_items(members), timezone)
    links = start_links(hunt.snapshots, hunt.snapshots[0])
    rows = [{"Run": hunt.label(s), "When": hunt.when(s), "Depth": depth, "Targets": len(s.get("targets") or []),
             "Alerts": len(s.get("alerts") or []), "Target list": ", ".join((s.get("targets") or [])[:10])}
            for _, s, depth in members]
    return {"svg": hunt_map_svg(hunt, links), "runs": pd.DataFrame(rows)}


def _report_inputs():
    """What the report needs from the session, read during the page run: the report itself is built on the download
    click, on a thread without Streamlit's script context, so it must not touch st.session_state."""
    from views.hunt_actions import current_run_id
    from views.similarity_view import RARE_KEY, THRESHOLD_KEY, current_weights
    origin = st.session_state.get("data_origin") or {}
    return {"origin": "offline dataset" if origin.get("mode") == "offline" else "live lookups",
            "window": st.session_state.get("window_label") or "", "run_id": current_run_id(),
            "weights": dict(current_weights()), "threshold": st.session_state.get(THRESHOLD_KEY, sim.DEFAULT_THRESHOLD),
            "min_rare": st.session_state.get(RARE_KEY, 1)}


def _report_context(ctx, created, level, ioc_limit, inputs):
    """The report's context from the run and `inputs` (_report_inputs); no Streamlit call, so it runs on the click."""
    return ReportContext(
        ds=ctx.ds, collected=ctx.collected, alerts=ctx.view.active.reset_index(drop=True), profiles=ctx.profiles,
        correlation=ctx.threats.correlation, created=created, window=inputs["window"],
        thresholds=ctx.thresholds or {}, verdicts=domain_verdicts(load_triage(), ctx.ds.selected_domains),
        hunt=_hunt_context(ctx.timezone, inputs["run_id"]),
        similarity={"weights": inputs["weights"], "runs": load_all_runs(), "threshold": inputs["threshold"],
                    "min_rare": inputs["min_rare"]},
        origin=inputs["origin"],
        timezone=ctx.timezone, view=ctx.view, threats=ctx.threats, level=LEVELS[level], ioc_limit=ioc_limit)


def render_analysis_report(ctx, created=None):
    """The analysis report: the run as one HTML page with the sections the analyst picks (print it to PDF)."""
    targets = list(ctx.ds.selected_domains)
    with st.expander("Analysis report: the run as a page to share (HTML, print to PDF)", expanded=True,
                     icon=":material/description:"):
        st.caption("One HTML file structured like the app: high level, overview (summary, domain profiles, alerts), "
                   "infrastructure, hunt and supporting evidence, with the app's charts, then the IOCs and lookups if "
                   "you tick them. A sidebar jumps to any section; sections fold, tables sort and filter. It follows "
                   "the analysis window and the view filters and leaves out suppressed alerts. Print it from the "
                   "browser (Save as PDF) for a PDF; other raw data is under Data export below.")
        level = st.segmented_control("Report type", list(LEVELS), format_func=lambda k: LEVELS[k].label,
                                     key="report_level", default="detailed", on_change=_level_changed,
                                     help="Every type offers every section; the type sets how much each one writes.")
        level = level or "detailed"
        st.caption(LEVELS[level].help)
        default_title = "Analysis report: " + ", ".join(targets[:3]) + (f" (+{len(targets) - 3} more)"
                                                                         if len(targets) > 3 else "")
        c_title, c_analyst, c_case = st.columns([3, 2, 2])
        title = c_title.text_input("Title", value=default_title, key="report_title", max_chars=200)
        analyst = c_analyst.text_input("Analyst", key="report_analyst", max_chars=120, placeholder="Your name or team")
        case = c_case.text_input("Organisation / case", key="report_case", max_chars=120,
                                 placeholder="Customer, ticket or case id")
        summary = st.text_area("Description / summary", key="report_notes", height=110, max_chars=8000,
                               placeholder="What was investigated, what you concluded, and what you recommend "
                                           "(e.g. takedown, block, keep monitoring). Shown at the top of the report.")
        st.markdown("**Sections**")
        keys = [REPORT_KEY + section.key for section in SECTIONS]
        select_all_none(keys, "report_sections")
        chosen = []
        for column, part in zip(st.columns(len(PARTS)), PARTS):
            column.markdown(f"*{part}*")
            for section in (s for s in SECTIONS if s.part == part):
                st.session_state.setdefault(REPORT_KEY + section.key, section.default)
                if column.checkbox(section.label, key=REPORT_KEY + section.key, help=section.help):
                    chosen.append(section.key)
        c_charts, c_top, c_iocs = st.columns([4, 1, 1], vertical_alignment="bottom")
        charts = c_charts.radio("Charts", list(CHART_CHOICES), format_func=CHART_CHOICES.get, horizontal=True,
                                key="report_charts", help="Charts are interactive Plotly, as in the app. Graphs "
                                                          "(AS paths, CNAME chains, similarity clusters) are drawn "
                                                          "by viz.js from the internet; offline their tables stay.")
        spec = LEVELS[level]
        if spec.alerts:
            top = c_top.number_input("Alerts listed", min_value=5, max_value=5000, value=spec.alerts, step=5,
                                     key=f"report_top_{level}",
                                     help="Alerts listed in Alerts (most severe first)"
                                          + ("; also the detections in Supporting evidence" if level == HIGH else
                                             "; Supporting evidence lists every alert"))
        else:
            top = None
            c_top.caption("Every alert")
        if spec.iocs and "iocs" in chosen:
            ioc_limit = c_iocs.number_input("IOCs listed", min_value=10, max_value=100_000, value=spec.iocs, step=50,
                                            key=f"report_iocs_{level}",
                                            help="IOCs in the IOCs appendix, most severe first"
                                                 + (" (only those behind critical and high alerts)"
                                                    if level == HIGH else ""))
        else:
            ioc_limit = None
            if "iocs" in chosen:
                c_iocs.caption("Every IOC")
        if not chosen:
            st.info("Tick at least one section.")
            return
        meta = {"title": title.strip() or default_title, "analyst": analyst.strip(), "case": case.strip(),
                "summary": summary.strip()}

        inputs = _report_inputs()

        def report():   # built on the click (outside the script run: no Streamlit call in here)
            return build_analysis_report(_report_context(ctx, created, level, int(ioc_limit) if ioc_limit else None,
                                                         inputs),
                                         meta, chosen, charts=charts,
                                         top_alerts=int(top) if top else None).encode("utf-8")
        stamp = datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%SZ")
        st.download_button(f"Download the {LEVELS[level].label.lower()} ({len(chosen)} sections, HTML)", report,
                           f"{stamp}_{level}_report.html", "text/html", type="primary", icon=":material/download:",
                           on_click="ignore", help="The report is built when you click")


def _level_changed():
    """The Complete report ticks every section (every IOC and lookup with it)."""
    if st.session_state.get("report_level") == COMPLETE:
        _tick([REPORT_KEY + section.key for section in SECTIONS], True)


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
        c_misp.download_button("MISP event (JSON)", lambda: to_misp_event(indicators).encode(), f"{stamp}_misp_event.json",
                               "application/json", width="stretch", on_click="ignore",
                               help="MISP's JSON import format: one attribute per indicator (Event → Add → Import)")
        marked = alerts[alerts["Status"] == "Malicious"] if "Status" in alerts.columns else alerts.iloc[0:0]
        c_stix.download_button("STIX 2.1 bundle", lambda: to_stix_bundle(indicators, marked).encode(),
                               f"{stamp}_confirmed_stix.json", "application/json", width="stretch", on_click="ignore")
        st.dataframe(indicators, hide_index=True, width="stretch", height=min(320, 35 * (len(indicators) + 1) + 3))
        domains = set(indicators["Domain"].str.split(", ").explode())
        queries = iris_queries(dataset_pivots(ds), domains)
        if queries:
            st.markdown("**Iris Investigate searches** for the rare values these domains have: run them to find "
                        "more of the same infrastructure.")
            st.code("\n".join(queries), language=None)


def _tick(keys, value):
    for key in keys:
        st.session_state[key] = value


def select_all_none(keys, prefix):
    """All / None buttons that tick or clear every checkbox in `keys` (used by the data export and the report)."""
    c_all, c_none, _ = st.columns([1, 1, 6])
    c_all.button("Select all", key=f"{prefix}_all", type="tertiary", icon=":material/select_all:",
                 on_click=_tick, args=(keys, True))
    c_none.button("Select none", key=f"{prefix}_none", type="tertiary", icon=":material/deselect:",
                  on_click=_tick, args=(keys, False))


@st.fragment
def _render_export_choices(context):
    """A fragment: ticking items or switching the format reruns only this part, and files are built on download."""
    select_all_none([f"export_{item.key}" for item in EXPORT_SETS], "export")
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
