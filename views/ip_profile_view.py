"""
IP profile page (Overview): one IP address or CIDR range on one screen, like the Domain and Certificate profiles. The
IP and CIDR targets come first, then the domains' hosting IPs and the addresses the DNS resolution reached. Cards per
source (Iris hosting, BGP routing, VPNDB, names and domains on it, certificates, alerts), an action row, a range view
for CIDR targets, and on-demand lookups for the hosting IPs a run did not look up in full.
"""
import ipaddress

import pandas as pd
import streamlit as st

from config import PIVOT_STRONG_MAX, PIVOT_USEFUL_MAX, TARGET_IRIS_DOMAINS
from core import bgp
from core import ip_profile as ipp
from core.address_targets import names_on
from core.certsql import certificates_query
from core.helpers import is_cidr, is_ip_address
from core.irisql import similar_query
from integrations import bgpdb
from integrations.dnsdb import _lookup_urls
from integrations.http import StatusLog
from views import navigation
from views.common import metric, metric_slots
from views.query_editor import set_query

SELECTED_KEY = "ip_profile_address"
EVENTS_DONE_KEY = "ip_profile_events_done"   # addresses whose certificate events were looked up here
DATE = st.column_config.DatetimeColumn(format="YYYY-MM-DD")


def open_button(address, label="IP profile", key=None, container=None, **kwargs):
    """A button that opens the IP profile on `address` (an IP or a CIDR range)."""
    kwargs.setdefault("icon", ":material/lan:")
    kwargs.setdefault("type", "tertiary")
    navigation.jump_button("ip_profile", label, state={SELECTED_KEY: str(address)}, container=container,
                           button_key=key or f"ip_profile_open::{address}", **kwargs)


def open_address(address):
    navigation.go("ip_profile", **{SELECTED_KEY: str(address)})


def _label(table):
    rows = {r["Address"]: r for r in table.to_dict("records")}

    def label(address):
        row = rows.get(address)
        if row is None:
            return address
        extras = [row["Kind"]] + ([f"{row['Alerts']} alert(s)"] if row["Alerts"] else []) + \
            ([row["VPNDB"]] if row["VPNDB"] else []) + ([row["Routing"]] if row["Routing"] == "Unauthorized" else [])
        return f"{address} · {' · '.join(extras)}"
    return label


def render_ip_profile(ctx):
    ds, alerts = ctx.ds, ctx.view.active
    targets = list(ctx.collected.targets) if ctx.collected is not None else []
    st.header("IP profile", help="One IP address or CIDR range: its hosting, BGP routing, VPNDB verdict, the names "
                                 "and domains seen on it, the certificates naming it or served on it, and the alerts "
                                 "naming it. IP and CIDR targets first, then the domains' hosting IPs and the "
                                 "addresses the DNS resolution reached. Built from the loaded data; the lookups a "
                                 "hosting IP did not get can be made here, one click each.")
    table = ipp.candidates(ds, targets, alerts)
    options = list(table["Address"]) if not table.empty else []
    picked = st.session_state.get(SELECTED_KEY)
    if picked and picked not in options and (is_ip_address(picked) or is_cidr(picked)):
        options.insert(0, picked)   # opened from a page on an address the run has little on
    if not options:
        st.info("This run has no IP address to show: no IP or CIDR target, and no hosting IP was collected.")
        return
    if picked not in options:
        st.session_state[SELECTED_KEY] = options[0]
    c_pick, c_count = st.columns([3, 1], vertical_alignment="bottom")
    address = c_pick.selectbox("IP address or range", options, key=SELECTED_KEY, format_func=_label(table))
    with c_count.popover(f"All {len(table):,} addresses", icon=":material/list:", width="stretch"):
        st.dataframe(table, hide_index=True, width="stretch", height=320)
    naming = ipp.alerts_naming(alerts, address)
    _header(ds, address, naming, targets)
    _actions(ds, address)
    if is_cidr(address):
        _range(ctx, address, naming)
    else:
        _single(ctx, address, naming)


# ---- header and actions -----------------------------------------------------------------------------------------------

def _header(ds, address, naming, targets):
    kind = ipp.kind_of(address, targets)
    if is_cidr(address):
        network = ipaddress.ip_network(address, strict=False)
        kind += f" · IPv{network.version}, {network.num_addresses:,} addresses"
    else:
        kind += f" · IPv{ipaddress.ip_address(address).version}"
    badges = " ".join(f":{colour}-badge[{text}]" for text, colour in ipp.badges(ds, address, len(naming)))
    st.markdown(f"### {address}  \n{kind}  {badges}")
    sentence = ipp.why(ds, address, naming)
    if sentence:
        st.caption("**Why it matters:** " + sentence)
    domains = ipp.domains_using(ds, address)
    served, named = ipp.certificates_served(ds, address), ipp.certificates_naming(ds, address)
    route = ipp.routing(ds, address)
    metrics = [("Domains seen on it", f"{len(domains):,}", "From passive DNS, Domain History and Iris"),
               ("The run's domains", f"{int(domains['Analyzed'].sum()):,}", "Analyzed domains that used it"),
               ("Alerts naming it", f"{len(naming):,}", "Active alerts whose evidence names it"),
               ("Certificates", f"{len(set(served['SHA-256']) | set(named['SHA-256'])):,}",
                "Served on it (Certificate events) or naming it (SAN IP)"),
               ("Upstreams", f"{len(route['upstreams']):,}", "Networks seen in front of its origin (BGPDB)")]
    for col, (label, value, help_text) in zip(metric_slots(len(metrics)), metrics):
        metric(col, label, value, help=help_text)


def _curls(address):
    lines = []
    if bgpdb.load_bgpdb_host():
        block = address if is_cidr(address) else bgp.lookup_block(address)
        lines.append(f"# BGPDB: prefixes and origins\n{bgpdb.curl_command('ip', block)}")
    url = _lookup_urls(address)[0]
    lines.append("# DNSDB: names on it (reverse IP)\ncurl -s -H \"X-API-Key: $DNSDB_API_KEY\" "
                 f"-H 'Accept: application/x-ndjson' '{url}?limit=1000'")
    return "\n\n".join(lines)


def _actions(ds, address):
    from views.certsql_view import QUERY_KEY as CERTSQL_KEY  # the query pages import the profiles' helpers
    from views.irisql_view import QUERY_KEY as IRISQL_KEY
    from views.recent_view import open_sightings
    with st.container(horizontal=True, vertical_alignment="center"):
        if st.button("Where else seen", key="ipp_seen", icon=":material/visibility:", type="tertiary",
                     help="Runs → Indicator Sightings for this address (local files, no API query)"):
            open_sightings(address)
        if st.button("Domains on it in IrisQL", key="ipp_irisql", icon=":material/manage_search:", type="tertiary",
                     help="Opens IrisQL with the domains whose current IPs are this address (or in this range); "
                          "Search there runs it (one Iris Investigate query)"):
            set_query(IRISQL_KEY, similar_query(address))
            navigation.go("irisql")
        if st.button("Search in DNSDB", key="ipp_dnsdb", icon=":material/saved_search:", type="tertiary",
                     help="Opens the DNSDB page with this address (or range): names that resolved into it, with the "
                          "query, dnsdbq command and Scout link shown first; Search there runs it (one DNSDB query)"):
            from views.dnsdb_view import open_search
            open_search(address)
        if st.button("Certificates in CertsQL", key="ipp_certsql", icon=":material/badge:", type="tertiary",
                     help="Opens CertsQL with certificates naming this address (or an address in the range)"):
            set_query(CERTSQL_KEY, certificates_query(address))
            navigation.go("certsql")
        domains = [d for d in ipp.domains_using(ds, address)["Domain"] if not d.startswith("(")]
        on = getattr(ds, "target_domains", None)
        if on is not None and not on.empty:
            domains = list(dict.fromkeys(list(on.loc[on["Target"] == address].sort_values(
                "Risk Score", ascending=False, na_position="last")["Domain"]) + domains))
        domains = [d for d in domains if d not in set(ds.selected_domains)][:25]
        if domains:
            from views.hunt_actions import analyze_button
            analyze_button(domains, address, key=f"ipp_analyze::{address}", label=f"Analyze {len(domains)} domain(s)",
                           help="Analyzes the domains seen on it that are not in this run yet (the riskiest Iris "
                                f"domains first: {', '.join(domains[:3])}{', …' if len(domains) > 3 else ''}) as a "
                                "new run linked to this one.")
        with st.popover("Copy", icon=":material/content_copy:"):
            st.code(address, language="text")
            st.caption("The same lookups outside the app (keys from the environment):")
            st.code(_curls(address), language="bash")


# ---- one address ------------------------------------------------------------------------------------------------------

def _single(ctx, address, naming):
    ds = ctx.ds
    c_host, c_route = st.columns(2)
    with c_host.container(border=True):
        _hosting(ds, address)
    with c_route.container(border=True):
        _routing(ds, address)
    with st.container(border=True):
        _vpndb(ds, address)
    _names_and_domains(ctx, address)
    _certificates(ctx, address)
    _alerts(naming)


def _hosting(ds, address):
    st.markdown("**Hosting** (Iris Investigate)")
    intel = (getattr(ds, "ip_intel", None) or {}).get(address)
    on = getattr(ds, "target_domains", None)
    found = on[on["Target"] == address] if on is not None and not on.empty else pd.DataFrame()
    if not intel:
        if not found.empty:
            st.caption(f"None of the run's domains has it as a current IP in Iris, but Iris has **{len(found):,} "
                       "other domain(s)** on it now: see *Domains on it in Iris* below.")
        else:
            st.caption("None of the run's domains has it as a current IP in Iris (it is an IP target, a past or a "
                       "resolved address). Other domains in Iris may use it: *Find the domains on it in Iris* below "
                       "(one Iris Investigate query, the same as IrisQL `ip matches`).")
        return
    count = intel.get("count")
    strength = ("" if not count else "strong pivot" if count <= PIVOT_STRONG_MAX else "useful pivot"
                if count <= PIVOT_USEFUL_MAX else "shared hosting: a weak pivot")
    facts = {"ASN": intel.get("asn") or "", "ISP": intel.get("isp") or "", "Country": intel.get("country") or "",
             "Domains on it in Iris": f"{count:,} ({strength})" if count else "",
             "The run's domains on it now": ", ".join(sorted(intel.get("domains") or ()))}
    st.dataframe(pd.DataFrame([{"Field": k, "Value": str(v)} for k, v in facts.items() if v]), hide_index=True,
                 width="stretch")


def _routing(ds, address):
    from views.bgp_page import source_view
    with st.container(horizontal=True, vertical_alignment="center"):
        st.markdown("**BGP routing**", width="content")
        view, source = source_view(ds, "ipp_bgp_source")
        if view is ds and not getattr(ds, "alt_bgp_source", ""):
            st.caption(f"({source})", width="content")
    _routing_facts(view, address, source)
    _registration(ds, address)


def _registration(ds, address):
    """The address's registry network object and abuse contact (RIPEstat), when the run looked them up."""
    frame = getattr(ds, "bgp_registration", None)
    if frame is None or frame.empty or address not in set(frame["IP"].astype(str)):
        return
    row = frame[frame["IP"].astype(str) == address].iloc[0]
    st.markdown("**Registration** (RIPEstat)")
    registered = pd.to_datetime(row.get("Registered"), errors="coerce")
    facts = {"Range": row.get("Range"), "Net name": row.get("Net Name"), "Organisation": row.get("Organisation"),
             "Description": row.get("Description"), "Type": row.get("Type"), "Country": row.get("Country"),
             "RIR": row.get("RIR"), "Registered": f"{registered:%Y-%m-%d}" if pd.notna(registered) else "",
             "Abuse contact": row.get("Abuse Contact")}
    st.dataframe(pd.DataFrame([{"Field": k, "Value": str(v)} for k, v in facts.items() if v]), hide_index=True,
                 width="stretch")


def _routing_facts(ds, address, source="BGPDB"):
    route = ipp.routing(ds, address)
    main = route["main"]
    if main is None:
        resolved = route["resolved"]
        if not resolved.empty:
            st.dataframe(resolved.astype(str), hide_index=True, width="stretch")
            st.caption("From the DNS resolution's routing lookups.")
        else:
            st.caption("Not looked up (BGP routing off, a private address, or over the run's limit).")
        return
    status = main["Status"]
    colour = {"Valid": "green", "Unauthorized": "red"}.get(status, "gray")
    st.markdown(f"`{main['Prefix']}` announced by **{main['Origin']}** {main.get('AS Name') or ''} "
                f":{colour}-badge[{status}]")
    facts = {"RIR": f"{main.get('RIR') or ''} {main.get('RIR Country') or ''}".strip(),
             "Announced since": f"{main['First Seen']:%Y-%m-%d}" if pd.notna(main.get("First Seen")) else "",
             "Route collectors" if source == "BGPDB" else "RIS peers seeing it": str(main.get("Collectors") or ""),
             "Other origins seen": ", ".join(sorted(set(route["origins"]["Origin"]) - {main["Origin"]})),
             "Upstreams": ", ".join(route["upstreams"][:8])}
    st.dataframe(pd.DataFrame([{"Field": k, "Value": v} for k, v in facts.items() if v]), hide_index=True,
                 width="stretch")
    if not route["more_specifics"].empty:
        st.caption(f"{len(route['more_specifics'])} more-specific prefix(es) announced inside it")
        st.dataframe(route["more_specifics"][["Prefix", "Origin", "Status", "Collectors"]], hide_index=True,
                     width="stretch", height=150)
    navigation.link("bgp", label="BGP page", icon=":material/hub:")


def _vpndb(ds, address):
    from views.ip_card import render_ip_card
    st.markdown("**VPN, proxy and Tor** (VPNDB)")
    if ipaddress.ip_address(address).version == 6:
        st.caption("VPNDB does not collect IPv6 addresses.")
        return
    table = getattr(ds, "anonymizers", None)
    row = table[table["IP"].astype(str) == address].iloc[0].to_dict() \
        if table is not None and not table.empty and address in set(table["IP"].astype(str)) else {"IP": address}
    if len(row) == 1:
        st.caption("Not in this run's VPNDB check (over its budget, or the check was off). The *Full VPNDB answer* "
                   "tab fetches its verdict on demand.")
    render_ip_card(row, "ipp", ds)


def _names_and_domains(ctx, address):
    ds = ctx.ds
    c_names, c_iris = st.columns(2)
    with c_names:
        domains = ipp.domains_using(ds, address)
        st.markdown(f"**Domains seen on it** · {len(domains):,}",
                    help="Passive DNS and Domain History of the run (the analyzed domains' own records and, for an IP "
                         "target, every name DNSDB saw on it), and the run's domains Iris has on it now. Select an "
                         "analyzed domain for its profile.")
        if domains.empty:
            st.caption("No DNS record of the run points to it.")
        else:
            picked = st.dataframe(domains, hide_index=True, width="stretch", height=260, on_select="rerun",
                                  selection_mode="single-row", key=f"ipp_domains::{address}",
                                  column_config={"First Seen": DATE, "Last Seen": DATE})
            rows = picked.selection.rows if picked and picked.selection else []
            if rows and domains.iloc[rows[0]]["Analyzed"]:
                navigation.jump_button("profile", f"Open {domains.iloc[rows[0]]['Domain']} in Domain profile",
                                       {"profile_domain": domains.iloc[rows[0]]["Domain"]}, button_key="ipp_domain_go",
                                       icon=":material/domain:", type="tertiary")
    with c_iris:
        _iris_domains(ctx, address)


def _iris_domains(ctx, address):
    ds = ctx.ds
    on = getattr(ds, "target_domains", None)
    rows = on[on["Target"] == address] if on is not None and not on.empty else pd.DataFrame()
    st.markdown(f"**Domains on it in Iris** · {len(rows):,}",
                help="Iris Investigate's reverse lookup: domains whose current IPs are this address (or in the range), "
                     f"up to {TARGET_IRIS_DOMAINS}, riskiest first.")
    if not rows.empty:
        st.dataframe(rows.drop(columns=["Target"]), hide_index=True, width="stretch", height=260)
        return
    st.caption("Not looked up for this address: IP and CIDR targets get it in the run; a hosting IP on demand.")
    st.button(f"Find the domains on it in Iris (1 Iris Investigate query, up to {TARGET_IRIS_DOMAINS})",
              key=f"ipp_iris::{address}", on_click=_lookup_iris, args=(ctx, address), icon=":material/search:")


def _certificates(ctx, address):
    ds = ctx.ds
    served, named = ipp.certificates_served(ds, address), ipp.certificates_naming(ds, address)
    c_served, c_named = st.columns(2)
    with c_served:
        st.markdown(f"**Certificates served on it** · {served['SHA-256'].nunique():,}",
                    help="Certificate events: where the Certificate API saw each certificate served. Select one for "
                         "its Certificate profile.")
        if served.empty:
            st.caption("None in the run's certificate events.")
            if is_ip_address(address) and not _events_looked_up(ctx, address):
                st.button("Look up the certificate events on this IP (Certificate API, last 365 days)",
                          key=f"ipp_events::{address}", on_click=_lookup_events, args=(ctx, address),
                          icon=":material/badge:")
        else:
            _cert_table(served, f"ipp_served::{address}")
    with c_named:
        st.markdown(f"**Certificates naming it** · {len(named):,}", help="Certificates with this address among "
                                                                         "their SAN IPs (Certificate Search)")
        if named.empty:
            st.caption("No certificate of the run names it.")
        else:
            _cert_table(named, f"ipp_named::{address}")


def _cert_table(table, key):
    from views.cert_profile_view import open_button as open_cert
    picked = st.dataframe(table, hide_index=True, width="stretch", height=220, on_select="rerun",
                          selection_mode="single-row", key=key, column_config={"First Seen": DATE, "Last Seen": DATE})
    rows = picked.selection.rows if picked and picked.selection else []
    if rows:
        open_cert(table.iloc[rows[0]]["SHA-256"], key=f"{key}::open")


def _alerts(naming):
    st.markdown(f"**Alerts naming it** · {len(naming):,}")
    if naming.empty:
        st.caption("No active alert names this address.")
        return
    cols = [c for c in ("Domain", "Threat Type", "Severity", "Confidence", "Category", "Threat Logic") if c in naming]
    st.dataframe(naming[cols], hide_index=True, width="stretch",
                 column_config={"Threat Logic": st.column_config.TextColumn("Why", width="large")})
    navigation.link("alerts", label="Alerts with their evidence")


# ---- a range ----------------------------------------------------------------------------------------------------------

def _range(ctx, cidr, naming):
    ds = ctx.ds
    c_route, c_vpn = st.columns(2)
    with c_route.container(border=True):
        _routing(ds, cidr)
    with c_vpn.container(border=True):
        st.markdown("**VPN, proxy and Tor in the range** (VPNDB)")
        prefixes = getattr(ds, "prefixes", None)
        row = prefixes[prefixes["CIDR"] == cidr] if prefixes is not None and not prefixes.empty else pd.DataFrame()
        if row.empty:
            st.caption("Not looked up in VPNDB (the VPNDB check was off, or no key).")
        else:
            facts = [{"Field": k, "Value": str(v)} for k, v in row.iloc[0].items()
                     if k != "CIDR" and str(v) not in ("", "nan", "<NA>", "None")]
            st.dataframe(facts, hide_index=True, width="stretch", height=220)
    addresses = ipp.range_addresses(ds, cidr, ctx.view.active)
    st.markdown(f"**Addresses in the range with data** · {len(addresses):,}",
                help="Every address of the range that the run has something on: names in passive DNS, a VPNDB "
                     "verdict, alerts. Select one to open its own profile.")
    if addresses.empty:
        st.caption("No address of the range has data yet.")
    else:
        picked = st.dataframe(addresses, hide_index=True, width="stretch", height=260, on_select="rerun",
                              selection_mode="single-row", key=f"ipp_range::{cidr}")
        rows = picked.selection.rows if picked and picked.selection else []
        if rows:
            open_button(addresses.iloc[rows[0]]["Address"], label=f"Open {addresses.iloc[rows[0]]['Address']}",
                        key="ipp_range_open")
    c_names, c_iris = st.columns(2)
    with c_names:
        names = names_on(ds.pdns, cidr)
        st.markdown(f"**Names in passive DNS** · {names['Name'].nunique():,}")
        st.dataframe(names.drop_duplicates("Name").head(500), hide_index=True, width="stretch", height=260,
                     column_config={"First Seen": DATE, "Last Seen": DATE})
    with c_iris:
        _iris_domains(ctx, cidr)
    _certificates(ctx, cidr)
    _alerts(naming)


# ---- on-demand lookups -----------------------------------------------------------------------------------------------

def _events_looked_up(ctx, address):
    """Whether the run (an IP target) or this page already asked the Certificate API for the IP's events."""
    if address in st.session_state.get(EVENTS_DONE_KEY, set()):
        return True
    statuses = getattr(ctx.collected, "statuses", None) or []
    return any(s.get("Source") == "Cert Events (IP)" and str(s.get("Target")) == address for s in statuses)


def _finish(ctx, log, message):
    from views.sidebar import APP_RERUN_KEY, TOAST_KEY
    ctx.collected.statuses = list(ctx.collected.statuses) + log.rows
    st.session_state[TOAST_KEY] = message
    st.session_state[APP_RERUN_KEY] = True


def _lookup_iris(ctx, address):
    """Button callback: Iris's domains on one address, kept with the run (saved with it and its offline copy)."""
    from integrations.collector import TARGET_DOMAIN_COLUMNS, collect_target_domains
    log = StatusLog()
    found = collect_target_domains([address], log)
    current = ctx.collected.target_domains if ctx.collected.target_domains is not None else pd.DataFrame(
        columns=TARGET_DOMAIN_COLUMNS)
    merged = pd.concat([current[current["Target"] != address] if not current.empty else current, found],
                       ignore_index=True)
    ctx.collected.target_domains = ctx.ds.target_domains = merged
    error = next((r["Detail"] for r in log.rows if r.get("Status") == "Error"), "")
    _finish(ctx, log, f"Iris: {len(found):,} domain(s) on {address}." + (f" {error}" if error else ""))


def _lookup_events(ctx, address):
    """Button callback: the Certificate API's events on one IP, added to the run's certificate events."""
    from integrations.certificates import fetch_cert_events_ip
    from integrations.fetch_runner import _safe_call
    log = StatusLog()
    result = _safe_call(fetch_cert_events_ip, "Cert Events (IP)", address, address)
    log.record(result)
    rows = pd.DataFrame([{"Domain": address, "Hostname": ev.get("hostname", address), "RRName": ev.get("hostname", address),
                          "IP": address, "Cert_SHA256": ev.get("sha256", "N/A"), "Source": "Cert API (IP Events)",
                          "Timestamp": ev.get("event_timestamp") or ev.get("first_seen"),
                          "First Seen": ev.get("first_seen"), "Last Seen": ev.get("last_seen")}
                         for ev in (result.data or [])])
    st.session_state.setdefault(EVENTS_DONE_KEY, set()).add(address)   # no button again, even with no event
    for owner in (ctx.collected, ctx.ds):
        current = getattr(owner, "cert_hostnames", None)
        owner.cert_hostnames = pd.concat([current, rows], ignore_index=True) if current is not None else rows
    _finish(ctx, log, f"Certificate API: {len(result.data or []):,} event(s) on {address}."
            + (f" {result.error}" if result.error else ""))
