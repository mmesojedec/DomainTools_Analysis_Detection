"""
Data sources page: how every lookup of the run went. The run in numbers, lookups per source by outcome, then tabs
with statistics per source and per target, the lookups that need attention, the API queries per product next to
what is left, and every lookup with filters.
"""
import pandas as pd
import plotly.express as px
import streamlit as st

from core.api_usage import (
    DOMAINTOOLS,
    STATUSES,
    attention_rows,
    remaining,
    run_overview,
    run_usage,
    source_stats,
    status_frame,
    target_stats,
)
from integrations.account import known_products
from views.api_usage_view import service_quotas
from views.collection_progress import clock
from views.common import chart, table

STATUS_COLORS = {"OK": "#16A34A", "Partial": "#F59E0B", "No data": "#9CA3AF", "Error": "#DC2626"}
STATUS_HELP = ("**OK**: records returned. **Partial**: stopped at a limit (cap, page limit) or failed after some "
               "records, so older records may be missing. **No data**: the source had nothing for the target. "
               "**Error**: the lookup failed; *Retry failed lookups* under Cached details queries only those again.")
COUNT = st.column_config.NumberColumn(format="localized")
ANSWERED = st.column_config.ProgressColumn("Answered", format="percent", min_value=0, max_value=1,
                                           help="Share of the lookups that got an answer (all but errors)")


def collection_time(progress_rows):
    """Seconds from the first lookup's start to the last one's end of the last Analyze in this session, else None."""
    rows = [r for r in progress_rows or [] if getattr(r, "began", None) is not None
            and getattr(r, "ended", None) is not None]
    return max(r.ended for r in rows) - min(r.began for r in rows) if rows else None


def slowest_lookups(progress_rows, limit=3):
    rows = sorted((r for r in progress_rows or [] if r.took() >= 1), key=lambda r: r.took(), reverse=True)
    return ", ".join(f"{r.lookup} ({clock(r.took())})" for r in rows[:limit])


def render_overview(statuses, progress_rows=None):
    """The run in numbers, and a bar per source of its lookups by outcome."""
    stats = run_overview(statuses)
    if not stats["Lookups"]:
        return
    seconds = collection_time(progress_rows)
    recorded = any("Queries" in row for row in statuses)
    metrics = [
        ("Targets", f"{stats['Targets']:,}", "Distinct targets the lookups ran for (domains, IPs, hostnames; a bulk "
                                             "lookup counts as one)"),
        ("Lookups", f"{stats['Lookups']:,}", f"Across {stats['Sources']} sources"),
        ("Answered", f"{stats['Answered']:.0%}", f"{stats['OK']:,} OK, {stats['Partial']:,} partial, "
                                                 f"{stats['No data']:,} with no data, {stats['Errors']:,} failed"),
        ("Records", f"{stats['Records']:,}", "Records the lookups returned (changes, DNS records, certificates...)"),
        ("API queries", f"{stats['Queries']:,}" if recorded else "–",
         "Queries that reached an API, including the pages of long answers and retries; cached lookups cost none"
         + ("" if recorded else ". Not recorded: this run was saved before query counts were kept")),
        ("From cache", f"{stats['From cache']:,} ({stats['From cache'] / stats['Lookups']:.0%})",
         "Lookups answered from the lookup cache, with no API query"),
    ]
    if seconds is not None:
        slow = slowest_lookups(progress_rows)
        metrics.append(("Collection time", clock(seconds), "From the first lookup to the last of the last Analyze "
                                                           "in this session" + (f". Slowest: {slow}" if slow else "")))
    for col, (name, value, help_text) in zip(st.columns(len(metrics)), metrics):
        col.metric(name, value, help=help_text)
    if stats["Errors"] or stats["Partial"]:
        st.caption(f":red[{stats['Errors']:,} failed] · :orange[{stats['Partial']:,} partial]: see the *Needs "
                   "attention* tab.")

    frame = status_frame(statuses)
    counts = frame.groupby(["Source", "Status"]).size().reset_index(name="Lookups")
    order = counts.groupby("Source")["Lookups"].sum().sort_values().index.tolist()
    fig = px.bar(counts, x="Lookups", y="Source", color="Status", orientation="h",
                 color_discrete_map=STATUS_COLORS, category_orders={"Status": list(STATUSES), "Source": order})
    fig.update_layout(legend_title_text="", margin={"l": 0, "r": 0, "t": 10, "b": 0}, yaxis_title=None,
                      legend={"orientation": "h", "y": -0.15})
    chart(fig, key="sources_status_chart", height=max(220, 26 * len(order) + 90))


def _render_by_source(statuses):
    stats = source_stats(statuses)
    st.caption("Sources with errors or partial lookups come first. *Avg* and *Max records* are per lookup: a source "
               "near its limit on many targets may need a higher limit in Settings → Collection options.")
    table(stats, column_config={"Answered": ANSWERED, "Records": COUNT, "Queries": COUNT,
                                "Product": st.column_config.Column(help="The DomainTools product or service the "
                                                                        "lookups count against")})


def _render_by_target(statuses):
    stats = target_stats(statuses)
    st.caption("One row per target, the ones with failed or partial lookups first. *Sources*: how many sources "
               "looked it up.")
    table(stats, column_config={"Records": COUNT, "Queries": COUNT,
                                "Needs attention": st.column_config.Column(width="large")})


def _render_attention(statuses):
    rows = attention_rows(statuses)
    if rows.empty:
        st.success("Every lookup finished: no errors and nothing stopped at a limit.", icon=":material/check_circle:")
        return
    st.caption(STATUS_HELP)
    table(rows, column_config={"Detail": st.column_config.Column(width="large")})


def _render_queries(statuses):
    usage = run_usage(statuses)
    if usage.empty:
        st.caption("This run has no query counts (saved before they were recorded).")
        return
    products, quotas = known_products(), service_quotas()
    usage["Left"] = pd.array([remaining(products, p) if s == DOMAINTOOLS else quotas.get(s)
                              for s, p in zip(usage["Service"], usage["Product"])], dtype="Int64")
    total, cached = int(usage["Queries"].sum()), int(usage["From cache"].sum())
    st.caption(f"{total:,} API queries; {cached:,} lookup(s) answered from the lookup cache. Every HTTP request "
               "that reached an API counts, including the pages of a long answer and retries after a rate limit or "
               "server error. VPNDB counts each address of a bulk request as one query.")
    table(usage, column_config={
        "Queries": COUNT, "From cache": st.column_config.NumberColumn("Cached lookups"),
        "Left": st.column_config.NumberColumn(format="localized", help=(
            "Left this month (DomainTools, from the Account page), in the current quota period (DNSDB, after *Check "
            "DNSDB quota* on the Account page) or today (VPNDB, from its last answer); empty when not known yet. No "
            "query is made for it here."))})


def _render_all(statuses):
    frame = pd.DataFrame(statuses).drop(columns="Request", errors="ignore")   # requests: Lookup Queries page
    if "Cached At" in frame.columns:   # older datasets keep it as text ("NaT")
        frame["Cached At"] = pd.to_datetime(frame["Cached At"], errors="coerce")
    c_status, c_source, c_target = st.columns([1, 2, 2])
    picked = c_status.multiselect("Status", list(STATUSES), key="sources_all_status", placeholder="All")
    sources = c_source.multiselect("Source", sorted(frame["Source"].dropna().unique()), key="sources_all_source",
                                   placeholder="All")
    text = c_target.text_input("Target contains", key="sources_all_target", placeholder="e.g. example.com")
    if picked:
        frame = frame[frame["Status"].isin(picked)]
    if sources:
        frame = frame[frame["Source"].isin(sources)]
    if text.strip():
        frame = frame[frame["Target"].astype(str).str.contains(text.strip(), case=False, regex=False)]
    st.caption(f"{len(frame):,} lookup(s).")
    table(frame.sort_values(["Status", "Source"], kind="stable"),
          column_config={"Cached At": st.column_config.DatetimeColumn("Cached at (UTC)", format="YYYY-MM-DD HH:mm"),
                         "Detail": st.column_config.Column(width="large")})


def render_data_sources(statuses, progress_rows=None):
    """Data sources page body: overview, then the tabs."""
    if not statuses:
        st.info("This run has no lookup status.")
        return
    render_overview(statuses, progress_rows)
    attention = len(attention_rows(statuses))
    tabs = st.tabs(["By source", "By target", f"Needs attention ({attention:,})", "API queries", "All lookups"])
    for tab, render in zip(tabs, (_render_by_source, _render_by_target, _render_attention, _render_queries,
                                  _render_all)):
        with tab:
            render(statuses)
