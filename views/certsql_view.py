"""
CertsQL page (top menu, or Data source *CertsQL* in the sidebar): step 1 runs a CertsQL query (Certificate Search) and
lists the matching certificates with the domains, IPs and hostnames they name; step 2 picks domains and IPs (from the
certificates ticked *Use*) and a use case, and analyzes them as a new run.
"""
import json

import plotly.express as px
import streamlit as st

from config import CERTSQL_DEFAULT_RESULTS, CERTSQL_MAX_RESULTS, CERTSQL_PAGE_SIZE, SEED_DEFAULT_TARGETS, SEED_MAX_TARGETS
from core.certsql import (
    DEFAULT_SORT,
    HEADER,
    SORT_FIELDS,
    SORT_ORDERS,
    certificate_frame,
    commands,
    error_hint,
    examples,
    normalize,
    order_label,
    problems,
    query_cost,
    selected,
    sort_term,
    sort_text,
    target_frames,
    used_hits,
)
from core.persistence import load_settings
from core.use_cases import PROFILES_SETTING, find_case
from integrations.certificates import fetch_certsql
from views.analyze_selection import render_analyze_selection
from views.common import chart
from views.query_editor import query_editor, set_query
from views.sidebar import add_to_targets, apply_use_case, start_hunt

QUERY_KEY = "certsql_query"
EXAMPLE_KEY = "certsql_example"
STATE_KEY = "certsql_search"   # {"query", "max_results", "sort", "result", "certs", "domains", "ips", "hosts", ...}
CASE_KEY = "certsql_use_case"
ORIGIN_KEY = "certsql_origin"   # the search's Data sources row, attached to the next run (Lookup Queries → CertsQL)
MAX_KEY, SORT_KEY, PRESELECT_KEY = "certsql_max_results", "certsql_sort", "certsql_preselect"   # sticky (sidebar.py)
ORDER_KEY = "certsql_sort_order"   # sticky (sidebar.py)
COLOR = "#2e8b57"
QUERY_HELP = ("One predicate per line: `field operator value` (lowercase), with `AND` on its own line between clauses. "
              "Lines in one clause are OR'ed. Values are JSON: `\"text\"`, numbers, `true` / `false`, `[\"a\", \"b\"]`; "
              "dates are `\"YYYY-MM-DD\"`. Comments start with `#` or `//`. The `# CertsQL-1.0` line is added when "
              "missing. Fields and operators: Documentation → CertsQL.")


def _load_example():
    name = st.session_state.get(EXAMPLE_KEY)
    if name:
        set_query(QUERY_KEY, f"{HEADER}\n{examples()[name]}")


def _derive(state, preselect):
    """Domain / IP / hostname tables from the certificates ticked *Use*."""
    state["domains"], state["ips"], state["hosts"] = target_frames(used_hits(state["result"].data, state["certs"]),
                                                                    preselect)
    state["version"] = state.get("version", 0) + 1


def _search(query, max_results, sort, preselect):
    result = fetch_certsql(query, int(max_results), (sort["field"], sort["order"]) if sort else ())
    previous = st.session_state.get(STATE_KEY) or {}
    state = {"query": query, "max_results": int(max_results), "sort": sort, "result": result,
             "certs": certificate_frame(result.data), "preselect": preselect,
             "version": previous.get("version", 0), "cert_version": previous.get("cert_version", 0) + 1}
    _derive(state, preselect)
    st.session_state[STATE_KEY] = state


def _tick(table, how, count=0):
    """Button callback: ticks the `count` most-named targets, all of them (up to the run limit), or none."""
    state = st.session_state[STATE_KEY]
    frame = state[table].copy()
    frame["Analyze"] = False
    if how != "none" and not frame.empty:
        frame.loc[frame.index[:count or SEED_MAX_TARGETS], "Analyze"] = True
    state[table] = frame
    state["version"] += 1


def _use_all(value):
    state = st.session_state[STATE_KEY]
    state["certs"] = state["certs"].assign(Use=value)
    state["cert_version"] += 1
    _derive(state, state["preselect"] if value else 0)


def _label(query):
    lines = [line.strip() for line in query.splitlines()[1:] if line.strip() and not line.strip().startswith(("#", "//"))]
    return f"CertsQL: {lines[0] if lines else ''}" + (" …" if len(lines) > 1 else "")


def search_status(state):
    """The search as a Data sources row of the run it leads to; `Request` lets Lookup Queries rebuild it."""
    result = state["result"]
    total = result.extras.get("total") or len(result.data)
    plus = "+" if result.extras.get("relation") == "gte" else ""
    row = {**result.status_row(), "Source": "CertsQL", "Target": _label(state["query"])[len("CertsQL: "):]}
    if not result.error:
        row["Status"] = "OK" if result.data else "No data"
        row["Detail"] = (f"{len(result.data):,} of {total:,}{plus} matching certificates fetched"
                         + (f"; {row['Detail']}" if row["Detail"] else ""))
    row["Request"] = {"query": state["query"], "max_results": state["max_results"], "sort": state["sort"],
                      "pages": result.extras.get("pages", 1)}
    return row


def _analyze(targets, case_key, state):
    case = find_case(case_key, load_settings().get(PROFILES_SETTING))
    if case is not None:
        apply_use_case(case)
    st.session_state[ORIGIN_KEY] = search_status(state)
    start_hunt(targets, _label(state["query"]))


def _add(targets, state):
    st.session_state[ORIGIN_KEY] = search_status(state)
    add_to_targets(targets)


def render_certsql_page():
    st.header("CertsQL", help="Find certificates with a CertsQL query (DomainTools Certificate Search, technology "
                              "preview), then analyze the domains and IPs they name with a use case.")
    st.caption("**Step 1:** write a CertsQL query and search: the matching certificates are listed with the domains, "
               "IPs and hostnames they cover. **Step 2:** untick certificates you don't want under *Use*, tick the "
               "domains and IPs to look into, choose whether to analyze the domains, the IPs or both, pick a use case "
               "and click Analyze.")
    sample = examples()
    st.session_state.setdefault(QUERY_KEY, f"{HEADER}\n{next(iter(sample.values()))}")
    st.session_state.setdefault(MAX_KEY, CERTSQL_DEFAULT_RESULTS)
    st.session_state.setdefault(PRESELECT_KEY, SEED_DEFAULT_TARGETS)
    if st.session_state.get(SORT_KEY) not in SORT_FIELDS or st.session_state.get(ORDER_KEY) not in SORT_ORDERS:
        st.session_state[SORT_KEY], st.session_state[ORDER_KEY] = DEFAULT_SORT   # also replaces an old one-box choice
    st.selectbox("Start from an example", [""] + list(sample), key=EXAMPLE_KEY, on_change=_load_example,
                 format_func=lambda name: name or "Choose an example to replace the query…",
                 help="Dates in the examples are relative to today (CertsQL has no relative dates such as *within*).")
    text = query_editor("certsql", QUERY_KEY, "CertsQL query", help=QUERY_HELP)
    query = normalize(text)
    issues = problems(query)
    c1, c2, c3, c4 = st.columns([1, 1.2, 1.2, 1])
    max_results = c1.number_input("Certificates to fetch", min_value=1, max_value=CERTSQL_MAX_RESULTS, step=100,
                                  key=MAX_KEY,
                                  help=f"Pages of {CERTSQL_PAGE_SIZE} certificates are requested until this many (each "
                                       "page is one Certificate Search request). The total is shown either way "
                                       "(exact up to 10,000).")
    sort_field = c2.selectbox(
        "Sort by", list(SORT_FIELDS), key=SORT_KEY, format_func=lambda f: SORT_FIELDS[f][0],
        help="A field of each certificate, not a date in your query: the API orders every matching certificate by it "
             "before paging, so when more match than you fetch, it decides which ones you get (e.g. issue date, newest "
             "first: the most recently issued). Sent as `sort`: issue date = `validity_not_before`, expiry date = "
             "`validity_not_after`, validity length = `validity_duration_days`, key size = `public_key_bits`.")
    order = c3.selectbox("Order", SORT_ORDERS, key=ORDER_KEY, format_func=lambda o: order_label(sort_field, o),
                         help="The direction, worded for the field: newest, latest, longest or largest first is "
                              "descending (`desc`); oldest, soonest, shortest or smallest first is ascending (`asc`).")
    sort = sort_term(sort_field, order)
    preselect = c4.number_input("Pre-select the most named", min_value=0, max_value=SEED_MAX_TARGETS, step=5,
                                key=PRESELECT_KEY,
                                help="Domains and IPs ticked for analysis right after the search (named by the most "
                                     "certificates first).")
    for issue in issues:
        st.warning(issue, icon=":material/edit_note:")
    cost = query_cost(max_results, CERTSQL_PAGE_SIZE)
    if st.button("Search", type="primary", icon=":material/manage_search:", disabled=bool(issues),
                 help=f"Up to {cost} Certificate Search request{'' if cost == 1 else 's'}; the same search again "
                      "within the cache lifetime costs none."):
        with st.spinner("Searching certificates..."):
            _search(query, max_results, sort, int(preselect))
    with st.expander("The same search outside the app (curl, Python)", icon=":material/terminal:"):
        for name, command in commands(query, min(int(max_results), CERTSQL_PAGE_SIZE), sort).items():
            st.markdown(f"**{name}**")
            st.code(command, language="python" if name.startswith("Python") else "bash")
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
        st.error(f"Certificate Search: {result.error}" + (f" ({len(result.data):,} certificates fetched before it)"
                                                          if result.data else ""))
        if hint := error_hint(result.error):
            st.info(hint, icon=":material/tips_and_updates:")
        if not result.data:
            return
    total = result.extras.get("total") or 0
    plus = "+" if result.extras.get("relation") == "gte" else ""
    c1, c2, c3, c4, c5 = st.columns(5)
    c1.metric("Matching certificates", f"{total:,}{plus}",
              help="Exact up to 10,000; 10,000+ means at least that many." if plus else None)
    c2.metric("Fetched", f"{len(result.data):,}")
    c3.metric("Domains", f"{len(state['domains']):,}")
    c4.metric("IPs", f"{len(state['ips']):,}")
    c5.metric("Requests", "cached" if result.cached_at else f"{result.extras.get('pages', 1):,}",
              help="From the lookup cache: this search was run before within the cache lifetime." if result.cached_at
              else None)
    if result.truncated:
        st.info(f"{total:,}{plus} certificates match; the first {len(result.data):,} (by {sort_text(state['sort'])}) "
                "are listed. Narrow the query or raise *Certificates to fetch*.", icon=":material/info:")
    if not result.data:
        st.info("No certificate matches this query.")
        return

    certs, domains, ips, hosts = state["certs"], state["domains"], state["ips"], state["hosts"]
    used = int(certs["Use"].sum())
    tabs = st.tabs([f"Domains ({len(domains):,})", f"IPs ({len(ips):,})", f"Hostnames ({len(hosts):,})",
                    f"Certificates ({used:,} of {len(certs):,} used)", "Breakdown", "Raw JSON"],
                   key="certsql_tabs", on_change="rerun")
    target_help = {
        "Via": st.column_config.Column("Via", help="SAN DNS / SAN IP: named in a certificate's Subject Alternative "
                                                   "Names; CN: its common name (only when it has no SANs)."),
        "Hostnames": st.column_config.NumberColumn("Hostnames", help="Hostnames under this domain in the certificates"),
        "Certificates": st.column_config.NumberColumn("Certificates", help="Certificates (ticked Use) naming it")}
    with tabs[0]:
        st.caption("Registered domains the used certificates name, most named first. Shared CDN names (Cloudflare SNI, "
                   "Akamai, …) are left out.")
        domains = _editor(state, "domains", domains, target_help)
    with tabs[1]:
        st.caption("Public IPs in the used certificates' SANs.")
        ips = _editor(state, "ips", ips, target_help)
    with tabs[2]:
        st.caption("Every hostname (wildcards included) in the used certificates, with its registered domain. Analyzing "
                   "a domain looks up all of its subdomains.")
        st.dataframe(hosts, hide_index=True, width="stretch")
    with tabs[3]:
        _render_certificates(state, certs)
    with tabs[4]:
        _breakdown(certs, domains)
    with tabs[5]:
        st.download_button("Download the certificates (JSON)", json.dumps(result.data, indent=1, default=str),
                           file_name="certsql_results.json", mime="application/json", icon=":material/download:")
        st.json(result.data[:20], expanded=False)
        if len(result.data) > 20:
            st.caption(f"The first 20 of {len(result.data):,} records; the download has all of them.")
    render_analyze_selection("certsql", selected(domains, "Target"), selected(ips, "Target"), _analyze, _add, state)


def _render_certificates(state, certs):
    with st.container(horizontal=True, vertical_alignment="center"):
        st.caption("Use:", width="content")
        st.button("All", key="certsql_use_all", on_click=_use_all, args=(True,), type="tertiary",
                  icon=":material/select_all:")
        st.button("None", key="certsql_use_none", on_click=_use_all, args=(False,), type="tertiary",
                  icon=":material/deselect:")
    edited = st.data_editor(
        certs, key=f"certsql_editor::certs::{state['cert_version']}", hide_index=True, width="stretch",
        disabled=[c for c in certs.columns if c != "Use"],
        column_config={
            "Use": st.column_config.CheckboxColumn("Use", help="Untick to leave this certificate's names out of the "
                                                               "Domains, IPs and Hostnames tabs"),
            "Not Before": st.column_config.DateColumn("Not Before"),
            "Not After": st.column_config.DateColumn("Not After"),
            "Days": st.column_config.NumberColumn("Days", help="Validity period in days", format="%d")})
    if edited["Use"].tolist() != certs["Use"].tolist():   # the used set changed: re-derive the target tables
        state["certs"] = edited
        _derive(state, state["preselect"])
        st.rerun()


def _editor(state, table, frame, column_config):
    with st.container(horizontal=True, vertical_alignment="center"):
        st.caption("Tick:", width="content")
        st.button(f"{SEED_DEFAULT_TARGETS} most named", key=f"certsql_top_{table}", on_click=_tick,
                  args=(table, "top", SEED_DEFAULT_TARGETS), type="tertiary", icon=":material/done_all:",
                  help="Named by the most certificates first")
        st.button(f"First {SEED_MAX_TARGETS}" if len(frame) > SEED_MAX_TARGETS else "All", key=f"certsql_all_{table}",
                  on_click=_tick, args=(table, "all"), type="tertiary", icon=":material/select_all:",
                  help=f"A run analyzes at most {SEED_MAX_TARGETS} targets")
        st.button("None", key=f"certsql_none_{table}", on_click=_tick, args=(table, "none"), type="tertiary",
                  icon=":material/deselect:")
    return st.data_editor(
        frame, key=f"certsql_editor::{table}::{state['version']}", hide_index=True, width="stretch",
        disabled=[c for c in frame.columns if c != "Analyze"],
        column_config={"Analyze": st.column_config.CheckboxColumn("Analyze", help="Include in the analysis run"),
                       **column_config})


def _breakdown(certs, domains):
    used = certs[certs["Use"].astype(bool)]
    if used.empty:
        st.info("No certificate is ticked *Use*.")
        return
    months = used["Not Before"].str[:7].replace("", None).dropna()
    if not months.empty:
        fig = px.histogram(months.sort_values().rename("Issued").to_frame(), x="Issued",
                           color_discrete_sequence=[COLOR])
        fig.update_layout(margin=dict(t=30, l=10, r=10, b=10), yaxis_title="Certificates", xaxis_title=None,
                          title="Issued per month (not before)", bargap=0.05)
        chart(fig, key="certsql_issued", height=220)
    c1, c2 = st.columns(2)
    series = (("Issuer", used["Issuer"]), ("Validation", used["Validation"]), ("Key", used["Key"]),
              ("Domain", domains.set_index("Target")["Certificates"] if not domains.empty else None))
    for column, (name, values) in zip((c1, c2, c1, c2), series):
        if values is None:
            continue
        counts = values.head(10) if name == "Domain" else \
            values[values.fillna("").astype(str).str.strip() != ""].value_counts().head(10)
        if counts.empty:
            continue
        fig = px.bar(counts.sort_values().rename_axis(name).reset_index(name="Count"), x="Count", y=name,
                     orientation="h", color_discrete_sequence=[COLOR])
        fig.update_layout(margin=dict(t=30, l=10, r=10, b=10), showlegend=False,
                          title=f"Top {name}" + (" (certificates naming it)" if name == "Domain" else ""),
                          yaxis_title=None, xaxis_title=None)
        with column:
            chart(fig, key=f"certsql_top_{name}", height=260)
