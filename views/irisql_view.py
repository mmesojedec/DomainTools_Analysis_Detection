"""
IrisQL page (top menu): step 1 runs an IrisQL query (Iris Investigate) and lists the matching domains with their basic
facts and hosting IPs; step 2 picks domains and IPs from the list and a use case, and analyzes them as a new run.
"""
import json

import plotly.express as px
import streamlit as st

from config import IRISQL_DEFAULT_RESULTS, IRISQL_MAX_RESULTS, IRISQL_PAGE_SIZE, SEED_DEFAULT_TARGETS, SEED_MAX_TARGETS
from core.irisql import (
    EXAMPLES,
    HEADER,
    NARROWING,
    SORT_FIELDS,
    TOO_MANY,
    commands,
    domain_frame,
    error_hint,
    ip_frame,
    narrow,
    normalize,
    problems,
    query_cost,
    selected,
)
from core.persistence import load_settings
from core.query_breakdown import concentration, iris_summary, monthly, risk_band, risk_bands, top_values
from core.query_watch import add_watch, check_watch, list_watches, remove_watch
from core.use_cases import PROFILES_SETTING, find_case
from integrations.enrichment import fetch_irisql
from views.analyze_selection import hunt_parent, render_analyze_selection
from views.common import chart
from views.query_editor import query_actions, query_editor, set_query
from views.query_layout import code_panel, last_search_card, split, tiles
from views.sidebar import apply_use_case, current_thresholds, start_hunt

QUERY_KEY = "irisql_query"
WATCH_OPEN_KEY = "irisql_watches_open"
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


def _check_watch(watch):
    """Button callback: runs a watched query again and ticks only the domains that are new since the last check."""
    _search(watch["query"], watch["max_results"], watch["sort_by"], 0)
    state = st.session_state[STATE_KEY]
    if state["result"].error:
        return
    new, previous = check_watch(watch["name"], list(state["domains"]["Domain"]))
    frame = state["domains"].copy()
    frame["Analyze"] = frame["Domain"].isin(new[:SEED_MAX_TARGETS])
    state.update(domains=frame, watch={"name": watch["name"], "new": new, "previous": previous})
    state["version"] += 1
    set_query(QUERY_KEY, watch["query"])


def _render_watches():
    watches = list_watches()
    if not watches:
        return
    with st.expander(f"Watched queries ({len(watches)})", icon=":material/visibility:",
                     expanded=bool(st.session_state.get(WATCH_OPEN_KEY))):
        st.caption("Each check runs the query again (Iris Investigate queries, as a search) and ticks only the domains "
                   "that are new since the last check.")
        for watch in watches:
            with st.container(horizontal=True, vertical_alignment="center"):
                st.markdown(f"**{watch['name']}** · {len(watch.get('seen') or []):,} domains seen · last checked "
                            f"{str(watch.get('checked', ''))[:16].replace('T', ' ')} UTC")
                cost = query_cost(watch["max_results"], IRISQL_PAGE_SIZE)
                st.button("Check now", key=f"watch_check::{watch['name']}", on_click=_check_watch, args=(watch,),
                          icon=":material/refresh:", help=f"Up to {cost} Iris Investigate quer{'y' if cost == 1 else 'ies'}")
                st.button("Stop watching", key=f"watch_rm::{watch['name']}", on_click=remove_watch,
                          args=(watch["name"],), type="tertiary", icon=":material/visibility_off:")


def _render_watch_controls(state):
    """Watch the query of these results, or what a check just found."""
    found = state.get("watch")
    if found:
        since = f" since {str(found['previous'])[:16].replace('T', ' ')} UTC" if found.get("previous") else ""
        if found["new"]:
            st.success(f"**{len(found['new']):,} new domain(s)** for *{found['name']}*{since}; they are ticked below.",
                       icon=":material/fiber_new:")
        else:
            st.info(f"No new domains for *{found['name']}*{since}.", icon=":material/check:")
        return
    with st.popover("Watch this query", icon=":material/visibility:"):
        name = st.text_input("Name", value=_label(state["query"])[len("IrisQL: "):][:60], key="watch_name")
        st.caption("Saves the query with today's domains as seen; *Watched queries* above checks it again later and "
                   "shows only the new ones.")
        if st.button("Save watch", key="watch_save", type="primary", disabled=not name.strip()):
            add_watch(name.strip(), state["query"], state["max_results"], state["sort_by"],
                      list(state["domains"]["Domain"]))
            st.session_state[WATCH_OPEN_KEY] = True
            st.toast(f"Watching '{name.strip()}'.")


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
    start_hunt(targets, _label(state["query"]), hunt_parent("irisql"))


def render_irisql_page():
    st.header("IrisQL", help="Find domains in Iris Investigate with an IrisQL query, then analyze the ones you pick "
                             "with a use case.")
    st.caption("**Step 1:** write an IrisQL query and search: the matching domains are listed with their risk score, "
               "dates, registrar and hosting. **Step 2:** tick the domains and IPs to look into, choose whether to analyze "
               "the domains, the IPs or both, pick a use case and click Analyze: they are analyzed as a new run, like "
               "targets entered on the Start page.")
    st.session_state.setdefault(QUERY_KEY, f"{HEADER}\n")   # empty until an example is picked or typed
    st.session_state.setdefault(MAX_KEY, IRISQL_DEFAULT_RESULTS)
    st.session_state.setdefault(PRESELECT_KEY, SEED_DEFAULT_TARGETS)
    left, right = split()
    with left:
        st.selectbox("Start from an example", [""] + list(EXAMPLES), key=EXAMPLE_KEY, on_change=_load_example,
                     format_func=lambda name: name or "Choose an example to load it into the query…")
        text = query_editor("irisql", QUERY_KEY, "IrisQL query", help=QUERY_HELP)
        query = normalize(text)
        issues = problems(query)
        c1, c2 = st.columns(2)
        max_results = c1.number_input("Domains to fetch", min_value=1, max_value=IRISQL_MAX_RESULTS, step=100,
                                      key=MAX_KEY,
                                      help=f"Pages of {IRISQL_PAGE_SIZE} domains are requested until this many (each "
                                           "page is one Iris Investigate query). The total in Iris is shown either way.")
        sort_by = c2.selectbox("Sort by", SORT_FIELDS, key=SORT_KEY, format_func=lambda f: f or "Iris default",
                               help="Iris sorts before paging, so with more matches than fetched this decides which "
                                    "domains you get.")
        preselect = c1.number_input("Pre-select the riskiest", min_value=0, max_value=SEED_MAX_TARGETS, step=5,
                                    key=PRESELECT_KEY,
                                    help="Domains ticked for analysis right after the search (highest risk score "
                                         "first).")
        if issues and not query.splitlines()[1:]:   # nothing typed yet: a hint, not a warning
            st.caption(":material/edit_note: Pick an example above, or start typing a field name on line 2: "
                       "suggestions appear as you type.")
        else:
            for issue in issues:
                st.warning(issue, icon=":material/edit_note:")
        cost = query_cost(max_results, IRISQL_PAGE_SIZE)
        if query_actions(QUERY_KEY, HEADER, f"Up to {cost} Iris Investigate quer{'y' if cost == 1 else 'ies'}; the "
                         "same search again within the cache lifetime costs none.", (STATE_KEY, EXAMPLE_KEY)):
            if not query.splitlines()[1:]:
                st.warning("Type a query or pick an example first.", icon=":material/edit_note:")
            elif issues:
                st.warning("Fix the query first (see above): nothing was searched.", icon=":material/edit_note:")
            else:
                with st.spinner("Searching Iris Investigate..."):
                    _search(query, max_results, sort_by, int(preselect))
    state = st.session_state.get(STATE_KEY)
    with right:
        code_panel(commands(query, min(int(max_results), IRISQL_PAGE_SIZE), sort_by), "irisql")
        if state:
            last_search_card(state, query, _facts(state), _label(state["query"])[len("IrisQL: "):])
        _render_watches()
    if state:
        st.divider()
        _render_results(state)


def _facts(state):
    result = state["result"]
    facts = [f"{result.extras.get('total') or 0:,} matching", f"{len(result.data):,} fetched",
             "from the cache" if result.cached_at else f"{result.extras.get('pages', 1):,} Iris quer"
             f"{'y' if result.extras.get('pages', 1) == 1 else 'ies'}"]
    return facts + (["error"] if result.error else [])


def _narrowing_buttons(query):
    """After a too-many-matches answer: one button per NARROWING condition, adding it to the query (no search)."""
    with st.container(horizontal=True, wrap=True):
        for label in NARROWING:
            if NARROWING[label].upper() in query.upper():
                continue
            if st.button(f"Add: {label}", key=f"irisql_narrow::{label}", type="tertiary", icon=":material/add:",
                         help=f"Adds `AND` / `{NARROWING[label]}` to the query above; then Search (nothing is "
                              "queried until you do)"):
                set_query(QUERY_KEY, narrow(query, [label]))
                st.rerun()


def _render_results(state):
    result = state["result"]
    st.subheader("Results", help="The query these results came from is under *Last search* above; edit the query and "
                                 "search again to change them.")
    if result.error:
        st.error(f"Iris Investigate: {result.error}" + (f" ({len(result.data):,} domains fetched before it)"
                                                         if result.data else ""))
        if hint := error_hint(result.error):
            st.info(hint, icon=":material/tips_and_updates:")
        if TOO_MANY in str(result.error):
            _narrowing_buttons(state["query"])
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
    _render_watch_controls(state)

    domains, ips = state["domains"], state["ips"]
    # Fixed tab names: the open tab is remembered by its name (a count in it would reopen the first tab when it changes)
    tabs = st.tabs(["Domains", "IPs", "Breakdown", "Raw JSON"], key="irisql_tabs", on_change="rerun")
    with tabs[0]:
        st.caption(f"**{len(domains):,} domain(s).**")
        domains = _editor(state, "domains", domains, {
            "Risk Score": st.column_config.ProgressColumn("Risk Score", min_value=0, max_value=100, format="%d"),
            "Create Date": st.column_config.DateColumn("Create Date"),
            "First Seen": st.column_config.DateColumn("First Seen"),
            "Expiration Date": st.column_config.DateColumn("Expiration Date")})
    with tabs[1]:
        st.caption(f"**{len(ips):,} IP(s).** The domains' current hosting IPs in Iris. *Result Domains*: how many listed domains use the IP; "
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
    render_analyze_selection("irisql", selected(domains, "Domain"), selected(ips, "IP"), _analyze, state)


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


BAND_COLORS = {"0–39": "#c9b8f0", "40–69": "#a58be3", "70–89": "#7b4fd6", "90–100": "#4b2a99", "Unknown": "#d9d9d9"}


def _bar(counts, name, key, title=None):
    if counts.empty:
        return
    fig = px.bar(counts.sort_values().rename_axis(name).reset_index(name="Count"), x="Count", y=name,
                 orientation="h", color_discrete_sequence=["#7b4fd6"])
    fig.update_layout(margin=dict(t=30, l=10, r=10, b=10), showlegend=False, title=title or f"Top {name}",
                      yaxis_title=None, xaxis_title=None)
    chart(fig, key=key, height=260)


def _breakdown(domains, ips):
    high = current_thresholds()["high_risk_score"]
    summary = iris_summary(domains, ips, high_risk=high)
    median = summary["median_risk"]
    tiles([
        ("Median risk score", "–" if median is None else f"{median:.0f}", None),
        (f"Risk {high}+", f"{summary['high_risk']:,}", "At or above the high-risk score cutoff (Settings)."),
        ("Created in the last 30 days", f"{summary['new']:,}", None),
        ("Expiring in the next 30 days", f"{summary['expiring']:,}", None),
        ("Active / inactive", f"{summary['active']:,} / {summary['inactive']:,}", "Iris's *active* flag."),
        ("Registrars", f"{summary['registrars']:,}", "Distinct registrars among the listed domains."),
        ("ASNs", f"{summary['asns']:,}", "Distinct ASNs of the hosting IPs."),
        ("Countries", f"{summary['countries']:,}", "Distinct countries of the hosting IPs."),
    ])
    bands = [risk_band(score) for score in domains["Risk Score"]]
    c1, c2 = st.columns([3, 2])
    with c1:
        if domains["Risk Score"].notna().any():
            fig = px.histogram(domains.dropna(subset=["Risk Score"]), x="Risk Score", nbins=20,
                               color_discrete_sequence=["#7b4fd6"])
            fig.update_layout(margin=dict(t=30, l=10, r=10, b=10), yaxis_title="Domains", bargap=0.05,
                              title="Risk score")
            chart(fig, key="irisql_risk", height=240)
    with c2:
        counts = risk_bands(domains["Risk Score"])
        if any(counts.values()):
            fig = px.bar(x=list(counts), y=list(counts.values()), color=list(counts),
                         color_discrete_map=BAND_COLORS)
            fig.update_layout(margin=dict(t=30, l=10, r=10, b=10), showlegend=False, title="Risk bands",
                              xaxis_title=None, yaxis_title="Domains")
            chart(fig, key="irisql_bands", height=240)
    created = monthly(domains["Create Date"], bands)
    if not created.empty:
        fig = px.bar(created, x="Month", y="Count", color="Band", color_discrete_map=BAND_COLORS,
                     category_orders={"Band": [*BAND_COLORS]})
        fig.update_layout(margin=dict(t=30, l=10, r=10, b=10), title="Created per month (by risk band)",
                          xaxis_title=None, yaxis_title="Domains", legend_title_text="Risk")
        chart(fig, key="irisql_created", height=260)
    ip_share, top_ips = concentration(domains["IPs"])
    ns_share, top_ns = concentration(domains["Name Servers"], top=1)
    if top_ips or top_ns:
        st.caption(" · ".join(part for part in (
            f"**{ip_share:.0%}** of the domains are on the top {len(top_ips)} IPs ({', '.join(top_ips)})"
            if top_ips else "",
            f"**{ns_share:.0%}** use the top name server ({top_ns[0]})" if top_ns else "") if part)
            + ". A high share points to one operator or one shared host.")
    c1, c2 = st.columns(2)
    blank = lambda values: values[values.fillna("").astype(str).str.strip() != ""]   # noqa: E731
    with c1:
        _bar(blank(domains["Registrar"]).value_counts().head(10), "Registrar", "irisql_top_Registrar")
        _bar(blank(ips["ASN"].astype("string") + " " + ips["ISP"].fillna("")).value_counts().head(10), "ASN",
             "irisql_top_ASN")
        _bar(top_values(domains["Name Servers"]), "Name server", "irisql_top_ns")
        _bar(top_values(domains["Tags"]), "Tag", "irisql_top_tags")
    with c2:
        _bar(blank(domains["TLD"]).value_counts().head(10), "TLD", "irisql_top_TLD")
        _bar(blank(ips["Country"]).value_counts().head(10), "Country", "irisql_top_Country")
        _bar(blank(domains["Registrant Org"]).value_counts().head(10), "Registrant org", "irisql_top_org")
