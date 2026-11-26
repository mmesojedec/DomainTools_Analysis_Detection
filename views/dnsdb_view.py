"""
DNSDB page (top menu): type a domain, a wildcard, an IP, a CIDR, an address range, a regex or a glob; the DNSDB query
it makes is shown on the right (curl, dnsdbq / dnsdbflex, a DNSDB Scout share link) before anything is sent. Search
runs it (one DNSDB query); the records are listed with the domains and IPs they name, to analyze as a new run.
"""
import datetime as dt
import json

import pandas as pd
import plotly.express as px
import streamlit as st

from config import DNSDB_DEFAULT_LIMIT, DNSDB_LIMIT_OPTIONS, SEED_DEFAULT_TARGETS, SEED_MAX_TARGETS
from core import dnsdb_search as ds
from core.certsql import selected
from core.persistence import load_settings
from core.use_cases import PROFILES_SETTING, find_case
from integrations.dnsdb import SEARCH_SOURCE, fetch_dnsdb_search
from views import navigation
from views.analyze_selection import hunt_parent, render_analyze_selection
from views.common import chart
from views.query_layout import last_search_card, split, tiles
from views.sidebar import apply_use_case, start_hunt

PAGE = "dnsdb_search"
VALUE_KEY = "dnsdb_search_value"
MODE_KEY = "dnsdb_search_mode"          # "auto" or a ds.SEARCHES key
FIELD_KEY = "dnsdb_search_field"
EXCLUDE_KEY = "dnsdb_search_exclude"
RRTYPE_KEY = "dnsdb_search_rrtype"
BAILIWICK_KEY = "dnsdb_search_bailiwick"
LIMIT_KEY = "dnsdb_search_limit"
AFTER_KEY, BEFORE_KEY = "dnsdb_search_after", "dnsdb_search_before"
STRICT_KEY = "dnsdb_search_strict"
AGGR_KEY = "dnsdb_search_aggregated"
PRESELECT_KEY = "dnsdb_search_preselect"
SHOW_KEY = "dnsdb_search_show"
STATE_KEY = "dnsdb_search_state"        # {"search", "query", "result", "records", "domains", "ips", "version"}
ORIGIN_KEY = "dnsdb_search_origin"      # the search's Data sources row, attached to the next run
STICKY = (VALUE_KEY, MODE_KEY, FIELD_KEY, RRTYPE_KEY, LIMIT_KEY, PRESELECT_KEY, AGGR_KEY, "dnsdb_analyze_scope")
SHOW_AS = ("curl", "dnsdbq", "dnsdbflex", "Scout share link")
COLOR = "#1f77b4"
VALUE_HELP = ("What to look for. **example.com**: its records. **\\*.example.com**: every name under it. "
              "**www.example.\\***: every name starting with it (any TLD). **203.0.113.7**, **203.0.113.0/24** or "
              "**203.0.113.1-203.0.113.50**: names that resolved into it. A regex (`^login[0-9]*\\.`) or a glob "
              "(`*paypal*`): Flexible Search. *Search type* follows what you type (Auto) or can be set.\n\n"
              "**Several values, one per line** (domains, IPs, CIDRs, …, up to 1,000): Search is off, and the right "
              "side lists a curl command, a dnsdbq command and a DNSDB Scout link for each line.")
SUBDOMAINS_KEY = "dnsdb_search_subdomains"
LABELS_KEY = "dnsdb_search_labels"
BATCH_SHOW = {"Scout share link": "Scout link", "curl": "curl", "dnsdbq": "dnsdbq", "dnsdbflex": "dnsdbflex"}


def open_search(value, mode="auto"):
    """Opens the DNSDB page with `value` typed in (nothing is sent until Search)."""
    navigation.go(PAGE, **{VALUE_KEY: str(value), MODE_KEY: mode})


def _epoch(day, end=False):
    if not day:
        return None
    stamp = pd.Timestamp(day).tz_localize("UTC") + (pd.Timedelta(days=1) if end else pd.Timedelta(0))
    return int(stamp.timestamp())


def _defaults():
    st.session_state.setdefault(VALUE_KEY, "")
    if st.session_state.get(MODE_KEY) not in ("auto", *ds.SEARCHES):
        st.session_state[MODE_KEY] = "auto"
    if st.session_state.get(FIELD_KEY) not in ds.FLEX_FIELDS:
        st.session_state[FIELD_KEY] = "rrnames"
    if st.session_state.get(RRTYPE_KEY) not in ds.RRTYPES:
        st.session_state[RRTYPE_KEY] = "ANY"
    if st.session_state.get(LIMIT_KEY) not in DNSDB_LIMIT_OPTIONS:
        st.session_state[LIMIT_KEY] = DNSDB_DEFAULT_LIMIT
    st.session_state.setdefault(AGGR_KEY, True)
    st.session_state.setdefault(STRICT_KEY, False)
    st.session_state.setdefault(PRESELECT_KEY, SEED_DEFAULT_TARGETS)
    if st.session_state.get(SHOW_KEY) not in SHOW_AS:
        st.session_state[SHOW_KEY] = SHOW_AS[0]


def _clear():
    st.session_state[VALUE_KEY] = ""
    st.session_state[EXCLUDE_KEY] = ""
    st.session_state[BAILIWICK_KEY] = ""
    st.session_state[MODE_KEY] = "auto"
    st.session_state.pop(STATE_KEY, None)


def _auto_caption(values):
    """What Auto picks for the values typed, shown under *Search type* (a select box keeps its first option label)."""
    if not values:
        return "Auto: the search follows what you type."
    if len(values) == 1:
        return f"Auto: {ds.SEARCHES[ds.detect(values[0])][0]}."
    return "Auto per line: " + ", ".join(f"{label} ×{count}" for label, count in ds.mode_counts(values).items()) + "."


def _form():
    """
    The search as set on the left (no request): (search of the first value, pre-select, the values typed one per line,
    the searches of all of them).
    """
    text = st.text_area("Search for", key=VALUE_KEY, help=VALUE_HELP, height=90,
                        placeholder="example.com · *.example.com · 203.0.113.0/24 · ^login\\..*\n"
                                    "or several, one per line")
    values = ds.split_values(text)
    value = values[0] if values else ""
    modes = {ds.detect(v) for v in values} or {"rrset"}
    c1, c2 = st.columns(2)
    choice = c1.selectbox("Search type", ["auto", *ds.SEARCHES], key=MODE_KEY,
                          format_func=lambda m: "Auto" if m == "auto" else ds.SEARCHES[m][0],
                          help="\n\n".join(f"**{label}**: {what}." for label, what, _ in ds.SEARCHES.values()))
    if choice == "auto":
        c1.caption(_auto_caption(values))
    if choice != "auto":
        modes = {choice}
    mode = ds.detect(value) if choice == "auto" else choice
    flex = any(ds.SEARCHES[m][2] == "flex" for m in modes)
    c2.selectbox("Record type", ds.RRTYPES, key=RRTYPE_KEY, disabled=modes == {"rdata_ip"},
                 help="ANY: every type except DNSSEC (ANY-DNSSEC: only those). An IP search returns A and AAAA only. "
                      "Flexible search on record values covers SOA, CNAME, HINFO, MX, NS, NAPTR, PTR, RP, SRV, SPF and "
                      "TXT.")
    field, exclude, bailiwick = "rrnames", "", ""
    if flex:
        field = st.segmented_control("Search in", list(ds.FLEX_FIELDS), key=FIELD_KEY, required=True,
                                     format_func=ds.FLEX_FIELDS.get,
                                     help="Owner names: the names records are published under. Record values: what "
                                          "the records hold (a CNAME target, a name server, a TXT string, …).")
        exclude = st.text_input("Exclude", key=EXCLUDE_KEY,
                                placeholder="\\.(com|net)\\.$" if "regex" in modes else "*.com.",
                                help="Results matching this (a regex or glob, like the search) are left out. Names end "
                                     "with a dot in DNSDB (`example.com.`).")
    elif modes == {"rrset"}:
        bailiwick = st.text_input("Bailiwick", key=BAILIWICK_KEY, placeholder="example.com",
                                  help="Only records from this zone's servers (e.g. `com` for the delegation NS "
                                       "records seen at the TLD servers). Empty: every bailiwick.")
    c1, c2 = st.columns(2)
    limit = c1.selectbox("Records", DNSDB_LIMIT_OPTIONS, key=LIMIT_KEY, format_func=lambda n: f"{n:,}",
                         help="The most records (flexible search: names or values) DNSDB returns. One search is one "
                              "DNSDB query whatever the limit.")
    preselect = c2.number_input("Pre-select the most seen", min_value=0, max_value=SEED_MAX_TARGETS, step=5,
                                key=PRESELECT_KEY,
                                help="Domains and IPs ticked for analysis right after the search (in the most records "
                                     "first).")
    c1, c2 = st.columns(2)
    after = c1.date_input("Seen after (UTC)", value=None, key=AFTER_KEY, format="YYYY-MM-DD",
                          max_value=dt.date.today())
    before = c2.date_input("Seen before (UTC)", value=None, key=BEFORE_KEY, format="YYYY-MM-DD")
    c1, c2 = st.columns(2)
    strict = c1.checkbox("Strict Mode", key=STRICT_KEY, disabled=not (after or before),
                         help="Off: records seen at any time in the window (last seen after, first seen before). On: "
                              "records first and last seen inside it (first seen after, last seen before).")
    aggregated = True
    if any(ds.SEARCHES[m][2] == "lookup" for m in modes):
        aggregated = c2.checkbox("Aggregated", key=AGGR_KEY,
                                 help="On: one record per name, type and value with its first and last seen over all "
                                      "time. Off: one per time slice (`aggr=f`, dnsdbq `-g`): shows gaps and returns.")
    subdomains = False
    if len(values) > 1 and "rrset" in modes:
        subdomains = st.checkbox("Every name under each domain (`*.domain`)", key=SUBDOMAINS_KEY,
                                 help="Each plain domain line is looked up as `*.domain` (the domain and all its "
                                      "subdomains) instead of the name alone. Lines already with a wildcard stay.")
    search = ds.Search(mode=mode, value=value, rrtype=st.session_state[RRTYPE_KEY], bailiwick=bailiwick, field=field,
                       exclude=exclude, limit=int(limit), after=_epoch(after), before=_epoch(before, end=True),
                       strict=bool(strict), aggregated=bool(aggregated))
    searches = ds.expand(search, values, auto=choice == "auto", subdomains=subdomains) if len(values) > 1 else []
    return search, int(preselect), values, searches


def _search(search, preselect):
    result = fetch_dnsdb_search(ds.url(search))
    previous = st.session_state.get(STATE_KEY) or {}
    domains, ips = ds.targets(result.data, preselect, ds.clean_value(search.mode, search.value)
                              if search.mode in ("rrset", "rdata_name", "rdata_ip") else "")
    st.session_state[STATE_KEY] = {"search": search, "query": ds.url(search), "result": result,
                                   "records": ds.records_frame(result.data), "domains": domains, "ips": ips,
                                   "version": previous.get("version", 0) + 1}


def _label(search):
    return f"DNSDB {search.label}: {ds.clean_value(search.mode, search.value)}"


def search_status(state):
    """The search as a Data sources row of the run it leads to; `Request` lets Lookup Queries rebuild it."""
    result, search = state["result"], state["search"]
    row = {**result.status_row(), "Source": SEARCH_SOURCE, "Target": _label(search)[len("DNSDB "):]}
    if not result.error:
        row["Status"] = "Partial" if result.truncated else ("OK" if result.data else "No data")
        row["Detail"] = f"{len(result.data or []):,} records" + (f"; {row['Detail']}" if row["Detail"] else "")
    row["Request"] = search.to_dict()
    return row


def _analyze(targets, case_key, state):
    case = find_case(case_key, load_settings().get(PROFILES_SETTING))
    if case is not None:
        apply_use_case(case)
    st.session_state[ORIGIN_KEY] = search_status(state)
    start_hunt(targets, _label(state["search"]), hunt_parent("dnsdb"))


def _code(search, issues):
    st.markdown("**The same search outside the app**",
                help="Built from the form as it is (no request is made). curl and dnsdbq read your key from "
                     "$DNSDB_API_KEY (dnsdbq: also ~/.dnsdb-query.conf); no credential value is shown. The Scout link "
                     "opens DNSDB Scout with this search filled in, run there with your own Scout login.")
    st.markdown(ds.describe(search))
    if not search.value.strip():
        st.caption("Type a value (or several, one per line): the DNSDB request, curl, dnsdbq and a DNSDB Scout link "
                   "appear here.")
        return
    show = st.segmented_control("Show as", SHOW_AS, key=SHOW_KEY, required=True, label_visibility="collapsed")
    link = "" if issues else ds.scout_link(search)   # no link for a search DNSDB would refuse
    if show == "curl":
        st.code(ds.curl(search), language="bash", wrap_lines=True)
    elif show == "dnsdbq":
        st.code(ds.cli(search), language="bash", wrap_lines=True)
        if search.flex:
            st.caption("dnsdbq has no regex or glob search: dnsdbflex finds the names (`-F`, dnsdbq's batch format) "
                       "and dnsdbq looks up their records (`-f`), one dnsdbq query per name.")
    elif show == "dnsdbflex":
        command = ds.flex_cli(search)
        if command:
            st.code(command, language="bash", wrap_lines=True)
            st.caption("dnsdbflex returns the matching names (or values), not their records: add `-F | dnsdbq -f -j` "
                       "for the records." + ("" if search.flex else " The lookup is written as the same glob (DNSDB "
                                                                     "names end with a dot)."))
        else:
            st.caption("dnsdbflex searches names and name-like values by regex or glob: it has no form for an IP, a "
                       "raw value or this record type. Use curl or dnsdbq.")
    elif link:
        st.code(link, language="text", wrap_lines=True)
    else:
        st.caption("No Scout link: fix the search first (see the left), or DNSDB Scout has no form for it (raw "
                   "RRset), or the link would be longer than Scout accepts. curl and dnsdbq still show it.")
    if link:
        st.link_button("Open in DNSDB Scout", link, icon=":material/open_in_new:",
                       help="Opens scout.dnsdb.info with this search filled in; Scout runs it with your Scout login "
                            "(the query counts on that key).")


def _batch_code(searches, values):
    """Several values: a command and a Scout link per line, each with its own *Open in DNSDB Scout*."""
    frame = ds.batch_frame(searches)
    st.markdown("**The same searches outside the app**",
                help="One search per line, built from the form as it is (no request is made). curl and dnsdbq read "
                     "your key from $DNSDB_API_KEY; no credential value is shown. Each Scout link opens DNSDB Scout "
                     "with that search filled in, run there with your own Scout login (one query each).")
    bad = int((frame["Problem"] != "").sum())
    st.markdown(f"**{len(frame):,} searches**, one per line" +
                (f" (the first {ds.MAX_VALUES:,} of {len(values):,} lines)" if len(values) > ds.MAX_VALUES else "") +
                (f"; **{bad:,}** with a problem (see the table)" if bad else "") + ".")
    columns = ["Value", "Search", "Scout link"] + (["Problem"] if bad else [])
    table = frame[columns].assign(**{"Scout link": frame["Scout link"].replace("", None)})   # no link: an empty cell
    st.dataframe(
        table, hide_index=True, width="stretch", height=min(38 + 35 * len(frame), 420),
        column_config={"Scout link": st.column_config.LinkColumn("DNSDB Scout", display_text="Open in DNSDB Scout",
                                                                 help="Opens Scout with this line's search filled "
                                                                      "in; empty when Scout has no link for it"),
                       "Problem": st.column_config.Column("Problem", help="Why this line has no Scout link")})
    with st.expander(f"All commands and links ({len(frame):,} lines)", icon=":material/terminal:", expanded=True):
        show = st.segmented_control("Show as", SHOW_AS, key=SHOW_KEY, required=True, label_visibility="collapsed")
        lines = [line for line in frame[BATCH_SHOW[show]] if line]
        if len(lines) < len(frame):
            st.caption(f"{len(frame) - len(lines):,} of {len(frame):,} lines have no {show} form "
                       + ("(IPs and raw values: dnsdbflex searches names by regex or glob)." if show == "dnsdbflex"
                          else "(see the table)."))
        labels = st.toggle("Label each line", key=LABELS_KEY, value=True,
                           help="On: each entry under a `# value · search type` line, a blank line between entries. "
                                "Off: one bare entry per line, to paste into a script or another tool.")
        text = ds.listing(frame, BATCH_SHOW[show], labels) or "(no valid search)"
        with st.container(height=360 if len(lines) > (5 if labels else 10) else "content", border=False):
            st.code(text, language="text" if show == "Scout share link" else "bash",
                    wrap_lines=show == "Scout share link")
    st.download_button("Download the searches (CSV)", frame.to_csv(index=False), file_name="dnsdb_searches.csv",
                       mime="text/csv", icon=":material/download:",
                       help="Every line with its search type, Scout link, curl and dnsdbq command")


def render_dnsdb_page():
    st.header("DNSDB", help="Search DNSDB passive DNS directly: lookups by name, wildcard, IP, CIDR or range, and "
                            "Flexible Search by regex or glob. The query is shown before it is sent.")
    st.caption("**Step 1:** type a domain, `*.domain`, an IP, a CIDR, a regex or a glob; the DNSDB query, curl, dnsdbq "
               "and a DNSDB Scout link are on the right before anything is sent. Search runs it (one DNSDB query). "
               "**Step 2:** tick the domains and IPs the records name, pick a use case and Analyze.")
    _defaults()
    left, right = split()
    with left:
        search, preselect, values, searches = _form()
        batch = len(values) > 1
        issues = ds.problems(search)
        typed = bool(values)
        if batch:
            st.info(f"{len(values):,} values: **Search** runs one value at a time. The curl and dnsdbq commands and a "
                    "DNSDB Scout link for each line are on the right; to analyze them all, paste them on **Start**.",
                    icon=":material/format_list_bulleted:")
        elif typed:
            for issue in issues:
                st.warning(issue, icon=":material/edit_note:")
            for note in ds.notes(search):
                st.caption(f":material/tips_and_updates: {note}")
        with st.container(horizontal=True, vertical_alignment="center"):
            clicked = st.button("Search", type="primary", icon=":material/manage_search:", width="content",
                                disabled=batch,
                                help="One value at a time: keep one line to search here." if batch else
                                "One DNSDB query; the same search again within the cache lifetime costs none.")
            st.button("Clear", icon=":material/close:", type="tertiary", key="dnsdb_search_clear", width="content",
                      on_click=_clear, disabled=not typed and not st.session_state.get(STATE_KEY),
                      help="Empties the search and removes its results from this page.")
        if clicked:
            if not typed:
                st.warning("Type what to search for first.", icon=":material/edit_note:")
            elif issues:
                st.warning("Fix the search first (see above): nothing was sent.", icon=":material/edit_note:")
            else:
                with st.spinner("Searching DNSDB..."):
                    _search(search, preselect)
    state = st.session_state.get(STATE_KEY)
    with right:
        if batch:
            _batch_code(searches, values)
        else:
            _code(search, issues if typed else ["empty"])
        if state:
            last_search_card(state, ds.url(search), _facts(state), _label(state["search"]))
    if state:
        st.divider()
        _render_results(state)


def _facts(state):
    result = state["result"]
    facts = [f"{len(result.data or []):,} records" + (" (limit reached)" if result.truncated else ""),
             "from the cache" if result.cached_at else "1 DNSDB query"]
    return facts + (["error"] if result.error else [])


def _tick(table, how, count=0):
    state = st.session_state[STATE_KEY]
    frame = state[table].copy()
    frame["Analyze"] = False
    if how != "none" and not frame.empty:
        frame.loc[frame.index[:count or SEED_MAX_TARGETS], "Analyze"] = True
    state[table] = frame
    state["version"] += 1


def _editor(state, table, frame):
    with st.container(horizontal=True, vertical_alignment="center"):
        st.caption("Tick:", width="content")
        st.button(f"{SEED_DEFAULT_TARGETS} most seen", key=f"dnsdb_top_{table}", on_click=_tick,
                  args=(table, "top", SEED_DEFAULT_TARGETS), type="tertiary", icon=":material/done_all:")
        st.button(f"First {SEED_MAX_TARGETS}" if len(frame) > SEED_MAX_TARGETS else "All", key=f"dnsdb_all_{table}",
                  on_click=_tick, args=(table, "all"), type="tertiary", icon=":material/select_all:",
                  help=f"A run analyzes at most {SEED_MAX_TARGETS} targets")
        st.button("None", key=f"dnsdb_none_{table}", on_click=_tick, args=(table, "none"), type="tertiary",
                  icon=":material/deselect:")
    return st.data_editor(
        frame, key=f"dnsdb_editor::{table}::{state['version']}", hide_index=True, width="stretch",
        disabled=[c for c in frame.columns if c != "Analyze"],
        column_config={"Analyze": st.column_config.CheckboxColumn("Analyze", help="Include in the analysis run"),
                       "Via": st.column_config.Column("Via", help="Owner name: a name the records are published "
                                                                  "under; a record type: named in that record's value"),
                       "Records": st.column_config.NumberColumn("Records", help="Records naming it"),
                       "Names": st.column_config.NumberColumn("Names", help="Distinct names behind it"),
                       "Last Seen": st.column_config.DatetimeColumn("Last Seen", format="YYYY-MM-DD")})


def _render_results(state):
    result, records = state["result"], state["records"]
    st.subheader("Results", help="The search these results came from is under *Last search* above.")
    if result.error:
        st.error(f"DNSDB: {result.error}" + (f" ({len(result.data):,} records before it)" if result.data else ""))
        if not result.data:
            return
    c1, c2, c3, c4 = st.columns(4)
    c1.metric("Records", f"{len(result.data or []):,}" + ("+" if result.truncated else ""))
    c2.metric("Domains", f"{len(state['domains']):,}")
    c3.metric("IPs", f"{len(state['ips']):,}")
    c4.metric("Queries", "cached" if result.cached_at else "1")
    if result.truncated:
        st.info(f"DNSDB stopped at the limit ({result.note or 'result limit reached'}): more records match. Narrow "
                "the search (record type, time window, a tighter pattern) or raise *Records*.", icon=":material/info:")
    if not result.data:
        st.info(result.note or "DNSDB has no record for this search.")
        return
    tabs = st.tabs(["Records", "Domains", "IPs", "Breakdown", "Raw JSON"], key="dnsdb_search_tabs", on_change="rerun")
    with tabs[0]:
        st.caption(f"**{len(records):,} record(s)** as DNSDB returned them" +
                   (" (aggregated: one per name, type and value)." if state["search"].aggregated and
                    not state["search"].flex else "."))
        st.dataframe(records, hide_index=True, width="stretch",
                     column_config={"First Seen": st.column_config.DatetimeColumn("First Seen", format="YYYY-MM-DD"),
                                    "Last Seen": st.column_config.DatetimeColumn("Last Seen", format="YYYY-MM-DD")})
    with tabs[1]:
        st.caption(f"**{len(state['domains']):,} domain(s).** Registered domains of the owner names, and of the names in "
                   "CNAME, NS, MX, PTR, SRV and SOA values; the searched domain itself is left out.")
        domains = _editor(state, "domains", state["domains"])
    with tabs[2]:
        st.caption(f"**{len(state['ips']):,} IP(s).** Public addresses in A and AAAA records.")
        ips = _editor(state, "ips", state["ips"])
    with tabs[3]:
        _breakdown(result.data, records, state["domains"])
    with tabs[4]:
        st.download_button("Download the records (JSON)", json.dumps(result.data, indent=1, default=str),
                           file_name="dnsdb_results.json", mime="application/json", icon=":material/download:")
        st.json(result.data[:20], expanded=False)
        if len(result.data) > 20:
            st.caption(f"The first 20 of {len(result.data):,} records; the download has all of them.")
    render_analyze_selection("dnsdb", selected(domains, "Target"), selected(ips, "Target"), _analyze, state)


def _breakdown(data, records, domains):
    types = ds.type_counts(data)
    seen = records["Last Seen"] if "Last Seen" in records else pd.Series(dtype="datetime64[ns]")
    first = records["First Seen"] if "First Seen" in records else pd.Series(dtype="datetime64[ns]")
    tiles([("Record types", f"{len(types):,}", None),
           ("Owner names", f"{records['RRName'].nunique():,}" if "RRName" in records else "–", None),
           ("First seen", first.min().strftime("%Y-%m-%d") if first.notna().any() else "–", None),
           ("Last seen", seen.max().strftime("%Y-%m-%d") if seen.notna().any() else "–", None)])
    c1, c2 = st.columns(2)
    if not types.empty:
        fig = px.bar(types.head(15).sort_values().rename_axis("Type").reset_index(name="Records"), x="Records",
                     y="Type", orientation="h", color_discrete_sequence=[COLOR])
        fig.update_layout(margin=dict(t=30, l=10, r=10, b=10), title="Records per type", yaxis_title=None,
                          xaxis_title=None)
        with c1:
            chart(fig, key="dnsdb_types", height=260)
    if not domains.empty:
        top = domains.head(10).set_index("Target")["Records"]
        fig = px.bar(top.sort_values().rename_axis("Domain").reset_index(name="Records"), x="Records", y="Domain",
                     orientation="h", color_discrete_sequence=[COLOR])
        fig.update_layout(margin=dict(t=30, l=10, r=10, b=10), title="Top domains", yaxis_title=None,
                          xaxis_title=None)
        with c2:
            chart(fig, key="dnsdb_domains", height=260)
    if first.notna().any():
        months = first.dropna().dt.strftime("%Y-%m").value_counts().sort_index()
        fig = px.bar(months.rename_axis("Month").reset_index(name="Records"), x="Month", y="Records",
                     color_discrete_sequence=[COLOR])
        fig.update_layout(margin=dict(t=30, l=10, r=10, b=10), title="First seen per month", xaxis_title=None)
        chart(fig, key="dnsdb_first_seen", height=240)
