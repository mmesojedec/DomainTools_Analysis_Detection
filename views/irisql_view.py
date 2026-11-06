"""
IrisQL page (top menu, or Data source *IrisQL* in the sidebar): step 1 runs an IrisQL query (Iris Investigate) and lists the matching domains with their basic
facts and hosting IPs; step 2 picks domains and IPs from the list and a use case, and analyzes them as a new run.
"""
import json

import plotly.express as px
import streamlit as st

from config import IRISQL_DEFAULT_RESULTS, IRISQL_MAX_RESULTS, IRISQL_PAGE_SIZE, SEED_DEFAULT_TARGETS, SEED_MAX_TARGETS
from core.irisql import (
    EXAMPLES,
    HEADER,
    SORT_FIELDS,
    commands,
    domain_frame,
    error_hint,
    ip_frame,
    normalize,
    problems,
    query_cost,
    selected,
)
from core.persistence import load_settings
from core.use_cases import PROFILES_SETTING, find_case
from integrations.enrichment import fetch_irisql
from views.analyze_selection import render_analyze_selection
from views.common import chart
from views.query_editor import query_editor, set_query
from views.sidebar import add_to_targets, apply_use_case, start_hunt

QUERY_KEY = "irisql_query"
EXAMPLE_KEY = "irisql_example"
STATE_KEY = "irisql_search"   # {"query", "max_results", "sort_by", "result", "domains", "ips", "version"}
CASE_KEY = "irisql_use_case"
ORIGIN_KEY = "irisql_origin"   # the search's Data sources row, attached to the next run (Lookup Queries → IrisQL)
MAX_KEY, SORT_KEY, PRESELECT_KEY = "irisql_max_results", "irisql_sort", "irisql_preselect"   # sticky (sidebar.py): kept off the page
DOC_URL = "https://docs.domaintools.com/api/iris/investigate/irisql/"
QUERY_HELP = (f"One condition per line: `FIELD OPERATOR value` (case-insensitive), with `AND` on its own line between "
              "conditions. Conditions on the same field without `AND` between them are OR'ed. Values are JSON: "
              "`\"text\"`, numbers, `true`/`false`, `[\"a\", \"b\"]`. The `# IrisQL-1.0` line is added when missing. "
              f"Fields and operators: [IrisQL reference]({DOC_URL}).")


def _load_example():
    name = st.session_state.get(EXAMPLE_KEY)
    if name:
        set_query(QUERY_KEY, f"{HEADER}\n{EXAMPLES[name]}")


def _search(query, max_results, sort_by, preselect):
    result = fetch_irisql(query, int(max_results), sort_by)
    domains = domain_frame(result.data, preselect)
    if not sort_by and not domains.empty:   # Iris default order: riskiest first, so the pre-selected rows lead
        domains = domains.sort_values("Risk Score", ascending=False, na_position="last").reset_index(drop=True)
    previous = st.session_state.get(STATE_KEY) or {}
    st.session_state[STATE_KEY] = {
        "query": query, "max_results": int(max_results), "sort_by": sort_by, "result": result,
        "domains": domains, "ips": ip_frame(result.data),
        "version": previous.get("version", 0) + 1}


def _tick(table, how, count=0):
    """Button callback: ticks the `count` riskiest domains / busiest IPs, all of them (up to the run limit), or none."""
    state = st.session_state[STATE_KEY]
    frame = state[table].copy()
    frame["Analyze"] = False
    if how != "none" and not frame.empty:
        order = frame.sort_values("Risk Score", ascending=False, na_position="last").index if table == "domains" \
            else frame.index
        frame.loc[order[:count or SEED_MAX_TARGETS], "Analyze"] = True
    state[table] = frame
    state["version"] += 1


def _label(query):
    condition = next((line.strip() for line in query.splitlines()[1:] if line.strip()), "")
    return f"IrisQL: {condition}" + (" …" if query.count("\n") > 1 else "")


def search_status(state):
    """The search as a Data sources row of the run it leads to; `Request` lets Lookup Queries rebuild it."""
    result = state["result"]
    total = result.extras.get("total") or len(result.data)
    pages = result.extras.get("pages", 1)   # a cached search counts no request (Lookup Queries)
    row = {**result.status_row(), "Source": "IrisQL", "Target": _label(state["query"])[len("IrisQL: "):]}
    if not result.error:   # more matches than fetched is the search's scope, not a gap in the run's data
        row["Status"] = "OK" if result.data else "No data"
        row["Detail"] = (f"{len(result.data):,} of {total:,} matching domains fetched"
                         + (f"; {row['Detail']}" if row["Detail"] else ""))
    row["Request"] = {"query": state["query"], "max_results": state["max_results"], "sort_by": state["sort_by"],
                      "pages": pages}
    return row


def _remember_search(state):
    st.session_state[ORIGIN_KEY] = search_status(state)


def _analyze(targets, case_key, state):
    """Button callback: applies the use case and analyzes the picked targets as a new run (linked to the query)."""
    case = find_case(case_key, load_settings().get(PROFILES_SETTING))
    if case is not None:
        apply_use_case(case)
    _remember_search(state)
    start_hunt(targets, _label(state["query"]))


def _add(targets, state):
    _remember_search(state)
    add_to_targets(targets)


def render_irisql_page():
    st.header("IrisQL", help="Find domains in Iris Investigate with an IrisQL query, then analyze the ones you pick "
                             "with a use case.")
    st.caption("**Step 1:** write an IrisQL query and search: the matching domains are listed with their risk score, "
               "dates, registrar and hosting. **Step 2:** tick the domains and IPs to look into, choose whether to analyze "
               "the domains, the IPs or both, pick a use case and click Analyze: they are analyzed like targets entered in "
               "the sidebar.")
    st.session_state.setdefault(QUERY_KEY, f"{HEADER}\n{EXAMPLES['Domain name contains a word']}")
    st.session_state.setdefault(MAX_KEY, IRISQL_DEFAULT_RESULTS)
    st.session_state.setdefault(PRESELECT_KEY, SEED_DEFAULT_TARGETS)
    st.selectbox("Start from an example", [""] + list(EXAMPLES), key=EXAMPLE_KEY, on_change=_load_example,
                 format_func=lambda name: name or "Choose an example to replace the query…")
    text = query_editor("irisql", QUERY_KEY, "IrisQL query", help=QUERY_HELP)
    query = normalize(text)
    issues = problems(query)
    c1, c2, c3 = st.columns(3)
    max_results = c1.number_input("Domains to fetch", min_value=1, max_value=IRISQL_MAX_RESULTS, step=100,
                                  key=MAX_KEY,
                                  help=f"Pages of {IRISQL_PAGE_SIZE} domains are requested until this many (each page "
                                       "is one Iris Investigate query). The total in Iris is shown either way.")
    sort_by = c2.selectbox("Sort by", SORT_FIELDS, key=SORT_KEY, format_func=lambda f: f or "Iris default",
                           help="Iris sorts before paging, so with more matches than fetched this decides which "
                                "domains you get.")
    preselect = c3.number_input("Pre-select the riskiest", min_value=0, max_value=SEED_MAX_TARGETS, step=5,
                                key=PRESELECT_KEY,
                                help="Domains ticked for analysis right after the search (highest risk score first).")
    for issue in issues:
        st.warning(issue, icon=":material/edit_note:")
    cost = query_cost(max_results, IRISQL_PAGE_SIZE)
    if st.button("Search", type="primary", icon=":material/manage_search:", disabled=bool(issues),
                 help=f"Up to {cost} Iris Investigate quer{'y' if cost == 1 else 'ies'}; the same search again within "
                      "the cache lifetime costs none."):
        with st.spinner("Searching Iris Investigate..."):
            _search(query, max_results, sort_by, int(preselect))
    with st.expander("The same search outside the app (CLI, curl, Python SDK)", icon=":material/terminal:"):
        for name, command in commands(query, min(int(max_results), IRISQL_PAGE_SIZE), sort_by).items():
            st.markdown(f"**{name}**")
            st.code(command, language="python" if name == "Python SDK" else "bash")
    state = st.session_state.get(STATE_KEY)
    if state:
        st.divider()
        _render_results(state)


def _render_results(state):
    result = state["result"]
    st.subheader("Results", help="The query these results came from is shown below; edit the query above and search "
                                 "again to change them.")
    st.code(state["query"], language="text")
    if result.error:
        st.error(f"Iris Investigate: {result.error}" + (f" ({len(result.data):,} domains fetched before it)"
                                                         if result.data else ""))
        if hint := error_hint(result.error):
            st.info(hint, icon=":material/tips_and_updates:")
        if not result.data:
            return
    total = result.extras.get("total") or 0
    c1, c2, c3, c4 = st.columns(4)
    c1.metric("Matching domains in Iris", f"{total:,}")
    c2.metric("Fetched", f"{len(result.data):,}")
    c3.metric("Hosting IPs", f"{len(state['ips']):,}")
    c4.metric("Iris queries", "cached" if result.cached_at else f"{result.extras.get('pages', 1):,}",
              help="From the lookup cache: this search was run before within the cache lifetime." if result.cached_at
              else None)
    if result.truncated:
        st.info(f"Iris has {total:,} matching domains; the first {len(result.data):,} "
                f"({state['sort_by'] or 'Iris default order'}) are listed. Narrow the query or raise *Domains to "
                "fetch*.", icon=":material/info:")
    if result.extras.get("message"):
        st.caption(f"Iris: {result.extras['message']}")
    if not result.data:
        st.info("No domain matches this query.")
        return

    domains, ips = state["domains"], state["ips"]
    tabs = st.tabs([f"Domains ({len(domains):,})", f"IPs ({len(ips):,})", "Breakdown", "Raw JSON"],
                   key="irisql_tabs", on_change="rerun")
    with tabs[0]:
        domains = _editor(state, "domains", domains, {
            "Risk Score": st.column_config.ProgressColumn("Risk Score", min_value=0, max_value=100, format="%d"),
            "Create Date": st.column_config.DateColumn("Create Date"),
            "First Seen": st.column_config.DateColumn("First Seen"),
            "Expiration Date": st.column_config.DateColumn("Expiration Date")})
    with tabs[1]:
        st.caption("The domains' current hosting IPs in Iris. *Result Domains*: how many listed domains use the IP; "
                   "*Iris Domains*: how many domains Iris has on it in total (a large number is shared hosting).")
        ips = _editor(state, "ips", ips, {
            "Result Domains": st.column_config.NumberColumn("Result Domains", format="%d"),
            "Iris Domains": st.column_config.NumberColumn("Iris Domains", format="%d")})
    with tabs[2]:
        _breakdown(domains, ips)
    with tabs[3]:
        st.download_button("Download the Iris answer (JSON)", json.dumps(result.data, indent=1, default=str),
                           file_name="irisql_results.json", mime="application/json", icon=":material/download:")
        st.json(result.data[:20], expanded=False)
        if len(result.data) > 20:
            st.caption(f"The first 20 of {len(result.data):,} records; the download has all of them.")
    render_analyze_selection("irisql", selected(domains, "Domain"), selected(ips, "IP"), _analyze, _add, state)


def _editor(state, table, frame, column_config):
    with st.container(horizontal=True, vertical_alignment="center"):
        st.caption("Tick:", width="content")
        top = "riskiest" if table == "domains" else "busiest"
        st.button(f"{SEED_DEFAULT_TARGETS} {top}", key=f"irisql_top_{table}", on_click=_tick,
                  args=(table, "top", SEED_DEFAULT_TARGETS), type="tertiary", icon=":material/done_all:",
                  help="Highest risk score first" if table == "domains" else "Most listed domains first")
        st.button(f"First {SEED_MAX_TARGETS}" if len(frame) > SEED_MAX_TARGETS else "All", key=f"irisql_all_{table}",
                  on_click=_tick, args=(table, "all"), type="tertiary", icon=":material/select_all:",
                  help=f"A run analyzes at most {SEED_MAX_TARGETS} targets")
        st.button("None", key=f"irisql_none_{table}", on_click=_tick, args=(table, "none"), type="tertiary",
                  icon=":material/deselect:")
    edited = st.data_editor(
        frame, key=f"irisql_editor::{table}::{state['version']}", hide_index=True, width="stretch",
        disabled=[c for c in frame.columns if c != "Analyze"],
        column_config={"Analyze": st.column_config.CheckboxColumn("Analyze", help="Include in the analysis run"),
                       **column_config})
    return edited


def _breakdown(domains, ips):
    if domains["Risk Score"].notna().any():
        fig = px.histogram(domains.dropna(subset=["Risk Score"]), x="Risk Score", nbins=20,
                           color_discrete_sequence=["#7b4fd6"])
        fig.update_layout(margin=dict(t=10, l=10, r=10, b=10), yaxis_title="Domains", bargap=0.05)
        chart(fig, key="irisql_risk", height=220)
    c1, c2 = st.columns(2)
    for column, (name, values) in zip((c1, c2, c1, c2), (
            ("Registrar", domains["Registrar"]), ("TLD", domains["TLD"]),
            ("ASN", ips["ASN"].astype("string") + " " + ips["ISP"]), ("Country", ips["Country"]))):
        counts = values[values.fillna("").str.strip() != ""].value_counts().head(10)
        if counts.empty:
            continue
        fig = px.bar(counts.sort_values().rename_axis(name).reset_index(name="Count"), x="Count", y=name,
                     orientation="h", color_discrete_sequence=["#7b4fd6"])
        fig.update_layout(margin=dict(t=30, l=10, r=10, b=10), showlegend=False, title=f"Top {name}",
                          yaxis_title=None, xaxis_title=None)
        with column:
            chart(fig, key=f"irisql_top_{name}", height=260)
