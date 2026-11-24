"""
Sidebar controls (Analyst options: selection and display options; view filters), the pending Analyze request and the settings kept in session state
that the Settings page edits (collection options, thresholds, cache lifetime): they persist while other pages show.
"""
import html
from dataclasses import dataclass

import pandas as pd
import pytz
import streamlit as st

from config import (
    BGPDB_ASN_MAX,
    BGPDB_MAX_IPS,
    BGPDB_ROUTE_MAX,
    CACHE_GROUP_DEFAULTS,
    CACHE_GROUPS,
    CACHE_LIFETIMES,
    DEFAULT_THRESHOLDS,
    DNSDB_DEFAULT_LIMIT,
    DNSDB_LIMIT_OPTIONS,
    DOMAIN_HISTORY_CAP_MAX,
    DOMAIN_HISTORY_MAX_CHANGES,
    DOMAIN_HISTORY_SAFETY_LIMIT,
    FETCH_CACHE_TTL_SECONDS,
    LOGO_CANDIDATES,
    SEED_DEFAULT_TARGETS,
    SEED_MAX_TARGETS,
    THRESHOLD_SPECS,
    VPNDB_ASN_MAX,
    VPNDB_DETAIL_MAX,
    VPNDB_MAX_IPS,
    VPNDB_NEIGHBOUR_MAX,
    VPNDB_REVERSE_MAX,
)
from core.helpers import md_escape
from core.hostnames import apex_of, candidate_hostnames
from core.offline import format_size, list_offline_datasets
from core.persistence import load_settings, save_setting
from core.use_cases import (
    COLLECTION_DEFAULTS,
    HISTORY_MODES,
    OPTION_LABELS,
    OVERRIDES_SETTING,
    PROFILES_SETTING,
    effective_settings,
    find_case,
    history_cap,
    history_period_days,
)
from core.window import CUSTOM_RANGE, DEFAULT_WINDOW, WINDOW_PRESETS
from integrations.cache import cache_usage, clear_all_caches, set_cache_ttl, set_group_ttl
from integrations.credentials import (
    BGPDB,
    CERT_API,
    DNSDB,
    DOMAINTOOLS,
    ENVIRONMENT,
    IN_USE,
    NOT_SET,
    SERVICES,
    SET_NOT_USED,
    SOURCES,
    VPNDB,
    CredentialFileError,
    clear_credential_cache,
    credential_overview,
    save_credentials,
    saved_sections,
)
from views.idn_display import UNICODE_KEY


@dataclass
class LookupSettings:
    raw_input: str
    dnsdb_limit: int
    include_ct: bool
    ct_max_hashes: int
    force_refresh: bool
    pivot_ips: bool
    pivot_max_ips: int
    txt_records: int
    caa_lookup: bool
    run: bool
    mode: str = "live"            # "live" queries the APIs; "offline" re-analyzes a saved dataset
    save_offline: bool = False    # live mode: also save the collected data as an offline dataset
    offline_id: str = None        # offline mode: dataset to load
    seed_preselect: int = SEED_DEFAULT_TARGETS   # derived targets pre-selected from certificate inputs
    cname_lookup: bool = False    # CNAME lookup where a capped main query holds no CNAME
    fresh: bool = False           # re-run from Cached details: query every source again (refreshes these targets' cache)
    vpndb_check: bool = False     # VPNDB verdict (VPN, residential proxy, Tor) of the hosting IPs
    vpndb_only: bool = False      # IP check use case: only VPNDB, for the IP targets
    vpndb_max_ips: int = VPNDB_MAX_IPS      # hosting IPs in the bulk request
    vpndb_details: int = VPNDB_DETAIL_MAX   # full verdicts and weekly histories
    vpndb_context: bool = True              # neighbouring /24s, hosting networks, leads on dedicated exits
    bgp_check: bool = False                 # BGPDB: BGP routing of the hosting IPs
    bgp_max_ips: int = BGPDB_MAX_IPS        # hosting IPs looked up in BGPDB
    bgp_context: bool = True                # BGPDB: prefixes announced around the run's prefixes
    history_days: int = 0                   # Domain History: only changes of the last N days (0: no period)
    history_max: int = DOMAIN_HISTORY_MAX_CHANGES   # Domain History: changes per domain at most (0: no cap)
    pdns_incremental: bool = False          # DNSDB: only records seen since the last offline copy of the targets

    def collection_summary(self):
        """Collection settings recorded in an offline dataset's manifest."""
        return {"pdns_provider": "DNSDB Scout", "dnsdb_limit": self.dnsdb_limit, "include_ct": self.include_ct,
                "ct_max_hashes": self.ct_max_hashes, "pivot_ips": self.pivot_ips, "pivot_max_ips": self.pivot_max_ips,
                "txt_records": self.txt_records, "caa_lookup": self.caa_lookup, "seed_preselect": self.seed_preselect,
                "cname_lookup": self.cname_lookup, "vpndb_check": self.vpndb_check, "vpndb_only": self.vpndb_only,
                "vpndb_max_ips": self.vpndb_max_ips, "vpndb_details": self.vpndb_details,
                "vpndb_context": self.vpndb_context, "bgp_check": self.bgp_check, "bgp_max_ips": self.bgp_max_ips,
                "bgp_context": self.bgp_context, "history_days": self.history_days,
                "history_max": self.history_max,
                "pdns_incremental": self.pdns_incremental}


ANALYST_KEY = "analyst_mode"
STICKY_KEYS = (*COLLECTION_DEFAULTS, *(spec.state_key for spec in THRESHOLD_SPECS), ANALYST_KEY, "analysis_window",
               "analysis_window_range", "display_timezone", "use_case", "profile_domain", UNICODE_KEY,
               "irisql_query", "irisql_max_results", "irisql_sort", "irisql_preselect",   # IrisQL search (irisql_view)
               "certsql_query", "certsql_max_results", "certsql_sort", "certsql_sort_order", "certsql_preselect", "certsql_fields",   # CertsQL (certsql_view)
               "irisql_analyze_scope", "certsql_analyze_scope",   # domains / IPs / both (analyze_selection)
               "hunt_map_details", "hunt_map_layout", "hunt_map_size", "hunt_map_open")   # Hunt map → Map options


def init_state():
    """Defaults for the settings, and keeps every settings key alive while its widget is on another page."""
    for key, default in COLLECTION_DEFAULTS.items():
        st.session_state.setdefault(key, default)
    for spec in THRESHOLD_SPECS:
        st.session_state.setdefault(spec.state_key, spec.default)
    st.session_state.setdefault(ANALYST_KEY, True)
    for key in STICKY_KEYS:   # Streamlit drops a widget's state when the widget is not drawn; re-assigning keeps it
        if key in st.session_state:
            st.session_state[key] = st.session_state[key]
    apply_cache_settings(load_settings())


CACHE_GROUP_SETTING = "cache_group_seconds"   # dt_settings.json: {group: seconds, or null to follow the cache lifetime}
FOLLOW = "Same as cache lifetime"


def group_lifetimes(settings):
    """{group: seconds or None} of the saved settings, the built-in defaults where nothing is saved."""
    saved = settings.get(CACHE_GROUP_SETTING)
    if not isinstance(saved, dict):
        return {group: CACHE_GROUP_DEFAULTS.get(group) for group in CACHE_GROUPS}
    return {group: saved.get(group) for group in CACHE_GROUPS}


def apply_cache_settings(settings):
    set_cache_ttl(settings.get("cache_seconds", FETCH_CACHE_TTL_SECONDS))
    for group, seconds in group_lifetimes(settings).items():
        set_group_ttl(group, seconds)


def lookup_settings(raw_input, run, save_offline=False):
    """LookupSettings of a live run from the collection options in session state."""
    opt = st.session_state
    return LookupSettings(raw_input, int(opt["opt_dnsdb_limit"]),
                          bool(opt["opt_ct"]), int(opt["opt_ct_max"]), bool(opt["opt_force_refresh"]),
                          bool(opt["opt_pivot"]), int(opt["opt_pivot_max"]),
                          int(opt["opt_txt_records"]) if opt["opt_txt"] else 0, bool(opt["opt_caa"]), run,
                          mode="live", save_offline=bool(save_offline), seed_preselect=int(opt["opt_seed_preselect"]),
                          cname_lookup=bool(opt["opt_cname"]), vpndb_check=bool(opt["opt_vpndb"]),
                          vpndb_only=bool(opt["opt_vpndb_only"]), vpndb_max_ips=int(opt["opt_vpndb_max_ips"]),
                          vpndb_details=int(opt["opt_vpndb_details"]), vpndb_context=bool(opt["opt_vpndb_context"]),
                          bgp_check=bool(opt["opt_bgpdb"]), bgp_max_ips=int(opt["opt_bgpdb_max_ips"]),
                          bgp_context=bool(opt["opt_bgpdb_context"]),
                          history_days=next_history_days(), history_max=next_history_cap(),
                          pdns_incremental=bool(opt["opt_pdns_incremental"]))


def next_history_days():
    """Days of Domain History the next Analyze fetches (0: all), from the period option and the analysis window."""
    opt = st.session_state
    custom = opt.get("analysis_window_range")
    start = custom[0] if isinstance(custom, (list, tuple)) and custom else None
    return history_period_days(opt.get("opt_history_mode", "all"), opt.get("opt_history_days"),
                               opt.get("analysis_window"), start)


def next_history_cap():
    """Domain History changes per domain the next Analyze fetches at most (0: no cap)."""
    opt = st.session_state
    return history_cap(opt.get("opt_history_mode", "all"), opt.get("opt_history_max"))


def history_option_text():
    """The Domain History period and cap of the next Analyze, e.g. "the last 30 days, up to 1,000 changes"."""
    days, cap = next_history_days(), next_history_cap()
    if not cap:
        return "every change (all time, no limit)"
    return (f"the last {days:,} days, " if days else "the newest changes, ") + f"up to {cap:,} per domain"


def options_summary():
    """One line naming the collection options of the next run."""
    opt = st.session_state
    if opt["opt_vpndb_only"]:
        return "VPNDB IP check only (IP targets)" + (" · force refresh" if opt["opt_force_refresh"] else "")
    parts = [f"DNSDB Scout {int(opt['opt_dnsdb_limit']):,}"]
    parts += [label for key, label in (("opt_txt", f"TXT {opt['opt_txt_records']}"), ("opt_caa", "CAA"),
                                       ("opt_cname", "CNAME")) if opt[key]]
    parts.append(f"CT {opt['opt_ct_max']}" if opt["opt_ct"] else "no CT")
    if opt["opt_vpndb"]:
        parts.append(f"VPNDB {int(opt['opt_vpndb_max_ips'])}/{int(opt['opt_vpndb_details'])}"
                     + ("" if opt["opt_vpndb_context"] else " (no neighbourhood)"))
    if opt["opt_bgpdb"]:
        parts.append(f"BGPDB {int(opt['opt_bgpdb_max_ips'])}" + ("" if opt["opt_bgpdb_context"] else " (no neighbours)"))
    if opt["opt_pivot"]:
        parts.append(f"IP pivots {opt['opt_pivot_max']}")
    if opt["opt_pdns_incremental"]:
        parts.append("incremental pDNS")
    days, cap = next_history_days(), next_history_cap()
    if days or cap != DOMAIN_HISTORY_MAX_CHANGES:
        parts.append("history " + " / ".join(filter(None, [f"{days} d" if days else "",
                                                           f"{cap:,}" if cap else "no limit"])))
    if opt["opt_force_refresh"]:
        parts.append("force refresh")
    return " · ".join(parts)


def apply_use_case(case):
    """Button callback: the use case's options (with the analyst's saved changes) and window go into session state."""
    st.session_state.update(effective_settings(case, load_settings().get(OVERRIDES_SETTING)))
    st.session_state["use_case"] = case.key


def use_case_status():
    """(selected use case or profile, whether the collection options were changed since it was applied), or (None, False)."""
    saved = load_settings()
    case = find_case(st.session_state.get("use_case"), saved.get(PROFILES_SETTING))
    if case is None:
        return None, False
    applied = effective_settings(case, saved.get(OVERRIDES_SETTING))
    return case, any(st.session_state.get(key) != value for key, value in applied.items())


def is_analyst():
    return bool(st.session_state.get(ANALYST_KEY, True))


LIVE_MODE = "Live lookups"
IRISQL_MODE = "IrisQL"
CERTSQL_MODE = "CertsQL"
QUERY_MODES = {IRISQL_MODE: "irisql", CERTSQL_MODE: "certsql"}   # data source -> its query page
HISTORY_TAB_KEY = "history_tab"            # Runs → Compare & trends' tab row
OFFLINE_SELECT_KEY = "offline_manage"       # the dataset picked on Data → Saved datasets
OFFLINE_LOAD_KEY = "offline_load"           # a dataset whose Load button was clicked: the next app run loads it
OFFLINE_JUMP_KEY = "_offline_jump"          # Data source just switched to Offline dataset: open Saved datasets
OFFLINE_ARRIVE_KEY = "_offline_arrive"      # ... and keep it selected there (a page switch drops the radio's change)
LIVE_JUMP_KEY = "_live_jump"               # Data source just switched to Live lookups: open Start
START_RUN_KEY = "_start_run"   # Analyze clicked on the Start page: the next app run analyzes TARGETS_KEY
LAST_PAGE_KEY = "last_page"   # the page of the previous app run (the IrisQL / CertsQL data source follows its page)
DATA_MODE_KEY = "data_mode"
TARGETS_KEY = "targets_input"   # the targets of the next / last Analyze (no widget)
APP_RERUN_KEY = "_rerun_app"
TOAST_KEY = "_pending_toast"   # message from a button callback, shown on the next full run
OFFLINE_MODE = "Offline dataset"


def render_logo():
    for logo_file in LOGO_CANDIDATES:
        if logo_file.exists():
            st.sidebar.image(str(logo_file), width="stretch")
            return


def offline_load_settings():
    """LookupSettings that load the dataset *Load offline dataset* asked for (Saved datasets page), else None."""
    dataset_id = st.session_state.pop(OFFLINE_LOAD_KEY, None)
    manifest = next((m for m in list_offline_datasets() if m["id"] == dataset_id), None) if dataset_id else None
    if manifest is None:
        return None
    return LookupSettings("", DNSDB_DEFAULT_LIMIT, False, 0, False, False, 0, 0, False, True, mode="offline",
                          offline_id=dataset_id)


def request_offline_load(dataset_id):
    """Callback of *Load offline dataset* on Saved datasets: the next app run loads `dataset_id` (no API calls)."""
    st.session_state[OFFLINE_LOAD_KEY] = dataset_id


def render_unicode_toggle(container=None):
    (container or st.sidebar).toggle(
        "Show international domains in Unicode", key=UNICODE_KEY,
        help="Shows punycode names (xn--bcher-kva.de) as Unicode (bücher.de) in every table, text and chart. Display "
             "only: lookups always use the ASCII form the APIs store, and exports, downloads and the copyable queries "
             "keep it too.",
    )


SAVE_OFFLINE_KEY = "save_offline"   # Start page: also save the next run's data as an offline dataset


def render_analyst_options(settings_page=None, show_window=True):
    """
    Sidebar *Analyst options*: what the next Analyze collects (use case, collection options, API credentials), then
    the display options (Analyst mode, Unicode names, analysis window, timezone). Returns (WindowChoice, timezone).
    `show_window` False: a results page draws the window in its toolbar instead (the same setting).
    """
    st.sidebar.header("Analyst options")
    st.sidebar.markdown("##### Selection")
    case, changed = use_case_status()
    st.sidebar.caption((f"**{case.title}**" + (" (changed)" if changed else "") + " · " if case is not None else "")
                       + f"{options_summary()}")
    if settings_page is not None:
        st.sidebar.page_link(settings_page, label="Change collection options", icon=":material/tune:")
    render_credential_chip(settings_page)
    st.sidebar.markdown("##### Config options")
    st.sidebar.toggle("Analyst mode", key=ANALYST_KEY,
                      help="On: every page, including Hunt and Evidence (hunt map, pivots, hostname inventory, raw "
                           "records, lookup queries). Off: a simpler set of pages for a quick review.")
    render_unicode_toggle()
    if show_window:
        render_analysis_window(st.sidebar)
    window_choice = window_choice_from_state()
    st.session_state.setdefault("display_timezone", "UTC")
    timezone = st.sidebar.selectbox("Display timezone", pytz.common_timezones, key="display_timezone",
                                    help="Shifts timelines and tempo charts to this timezone. Detection always runs "
                                         "on UTC.")
    return window_choice, timezone


def pending_lookup():
    """
    The run asked for this app run: a dataset loaded on Saved datasets, or the targets of an Analyze button (Start
    page, IrisQL, CertsQL, hunt leads), which put them in session state (TARGETS_KEY). There is no sidebar target box.
    """
    offline = offline_load_settings()
    if offline is not None:
        return offline
    run = st.session_state.pop(START_RUN_KEY, False)
    save_offline = st.session_state.pop(SAVE_OFFLINE_KEY + "_run", False) if run else False
    return lookup_settings(st.session_state.get(TARGETS_KEY, ""), run, save_offline)


def render_collection_options(prefix=""):
    """
    Settings page: every collection option (session state, so it holds for the next Analyze). With a `prefix` the same
    widgets edit a use case's saved options (keys `prefix + option`) instead.
    """
    st.markdown("**Passive DNS (DNSDB Scout)**")
    c1, c2 = st.columns(2)
    c1.selectbox(OPTION_LABELS["opt_dnsdb_limit"], DNSDB_LIMIT_OPTIONS, key=prefix + "opt_dnsdb_limit", format_func=lambda v: f"{v:,}",
                 help="Maximum passive DNS records fetched per queried name, from the DNSDB v2 REST API with your DNSDB "
                      "key (see API credentials). Very large limits slow down charts and tables.")
    c1, c2 = st.columns(2)
    c1.checkbox(OPTION_LABELS["opt_txt"], key=prefix + "opt_txt",
                help="Runs an extra TXT-only passive DNS query per domain (name/TXT and *.name/TXT) "
                     "and merges the latest records. Large result limits are often filled "
                     "by A/NS/CNAME records before any TXT record appears, leaving TXT fingerprinting and SPF/tunneling "
                     "detections empty.")
    c2.number_input(OPTION_LABELS["opt_txt_records"], min_value=1, max_value=500, step=1, key=prefix + "opt_txt_records",
                    disabled=not st.session_state[prefix + "opt_txt"])
    c1.checkbox(OPTION_LABELS["opt_caa"], key=prefix + "opt_caa",
                help="Queries the CAA record of each domain name directly (name/CAA). "
                     "Without it, a CAA record can fall outside a truncated pDNS result and the domain looks "
                     "unprotected.")
    c2.checkbox(OPTION_LABELS["opt_cname"], key=prefix + "opt_cname",
                help="Queries CNAME records of each domain and its subdomains (*.name/CNAME and "
                     "name/CNAME), up to 5,000 records, where the main lookup stopped at its "
                     "limit (it then holds only some of the CNAMEs). DNSDB returns them aggregated, one record per "
                     "hostname and target. Needed for CNAME chains and the CNAME detections on busy domains.")
    c1.checkbox(OPTION_LABELS["opt_pivot"], key=prefix + "opt_pivot",
                help="DNSDB reverse lookups on each domain's current non-CDN IPs (from Iris Investigate and passive DNS) to "
                     "find other domains that used them over time. One extra DNSDB query per IP.")
    c2.number_input(OPTION_LABELS["opt_pivot_max"], min_value=1, max_value=200, step=1, key=prefix + "opt_pivot_max",
                    disabled=not st.session_state[prefix + "opt_pivot"])
    st.checkbox(OPTION_LABELS["opt_pdns_incremental"], key=prefix + "opt_pdns_incremental",
                help="Only the records seen since the last offline copy of the same targets. For target lists you analyze again and again (Monitor changes). When an offline copy of the same "
                     "targets exists (same DNSDB limit), DNSDB returns only the records seen since a day "
                     "before that copy, and the copy's older records are added. Each target is still one DNSDB query, "
                     "but the result limit holds new records instead of old ones, and the lookup is faster. Without an "
                     "offline copy the lookup is complete, as usual. Save an offline copy of each run (sidebar) so the "
                     "next one builds on it. DNSDB Scout only.")
    st.markdown("**Domain History**", help="Separate from the analysis window (sidebar, or the results toolbar), which only filters "
                "what the pages show. These options decide which changes Domain History fetches.")
    mode = st.session_state[prefix + "opt_history_mode"]
    c1, c2, c3 = st.columns([2, 1, 1])
    c1.selectbox(OPTION_LABELS["opt_history_mode"], list(HISTORY_MODES), key=prefix + "opt_history_mode",
                 format_func=HISTORY_MODES.get,
                 help="Which changes Domain History fetches for each domain. It returns the newest changes first, "
                      "100 per query.\n\n"
                      "- **Latest changes, up to Max changes** (default): the newest changes, up to *Max changes*. "
                      "Short histories come in full; a domain with a longer history stops there, and the app tells "
                      "you which domains have more.\n"
                      "- **Analysis window, up to Max changes**: only the changes inside the analysis window picked in "
                      "the sidebar when you click Analyze (*All time*: no period), still up to *Max changes*.\n"
                      "- **Custom number of days, up to Max changes**: the changes of the last N days, more or less than "
                      "the window.\n"
                      f"- **All time, no limit**: every change of every domain (stops at {DOMAIN_HISTORY_SAFETY_LIMIT:,} "
                      "as a safeguard). Long histories take many queries and longer to collect and process.\n\n"
                      "A period or a low *Max changes* costs fewer queries, but detections that compare with older history "
                      "(dormancy, parking) see only what was fetched.")
    c2.number_input(OPTION_LABELS["opt_history_days"], min_value=1, max_value=3650, step=30, key=prefix + "opt_history_days",
                    disabled=mode != "days", help="With *Custom number of days*: the changes of the last N days.")
    c3.number_input(OPTION_LABELS["opt_history_max"], min_value=100, max_value=DOMAIN_HISTORY_CAP_MAX, step=500,
                    key=prefix + "opt_history_max", disabled=mode == "unlimited",
                    help=f"Most changes fetched per domain (default {DOMAIN_HISTORY_MAX_CHANGES:,}; 100 per query). "
                         "A domain that reaches it has more changes, and the app says so.")
    cap = int(st.session_state[prefix + "opt_history_max"] or DOMAIN_HISTORY_MAX_CHANGES)
    if mode == "unlimited":
        st.caption(":orange[:material/warning: No limit: domains with long histories (thousands of changes) take many "
                   "Domain History queries, and collecting and processing them takes longer.]")
    elif cap > DOMAIN_HISTORY_MAX_CHANGES:
        st.caption(f":orange[:material/warning: Max changes above {DOMAIN_HISTORY_MAX_CHANGES:,} means up to "
                   f"{-(-cap // 100):,} queries per domain with a long history, and slower collection and "
                   "processing.]")
    if not prefix:
        st.caption(f"Next Analyze: {history_option_text()}.")
    st.markdown("**VPNDB**")
    st.checkbox(OPTION_LABELS["opt_vpndb"], key=prefix + "opt_vpndb",
                help="On in every use case. Sends the run's public IPv4 hosting addresses (IP targets, current Iris IPs, "
                     "passive DNS; no CDN addresses) to VPNDB in one bulk request, then fetches the full verdict and "
                     "weekly history of the ones it attributes to a VPN, proxy or Tor, within the budget below (each "
                     "use case sets its own). Each IP counts as one VPNDB query. Needs a VPNDB key (API credentials); without one the check is skipped.")
    off = not st.session_state[prefix + "opt_vpndb"] and not st.session_state[prefix + "opt_vpndb_only"]
    c1, c2 = st.columns(2)
    c1.number_input(OPTION_LABELS["opt_vpndb_max_ips"], min_value=1, max_value=VPNDB_MAX_IPS * 4, step=50,
                    key=prefix + "opt_vpndb_max_ips", disabled=off or st.session_state[prefix + "opt_vpndb_only"],
                    help="Public IPv4 hosting addresses sent in the bulk request (IP targets first, then each domain's "
                         "current Iris IPs and passive DNS addresses, most recent first). Each IP is one VPNDB query.")
    c2.number_input(OPTION_LABELS["opt_vpndb_details"], min_value=0, max_value=500, step=10, key=prefix + "opt_vpndb_details",
                    disabled=off,
                    help="Exits (or, with *Only the VPNDB IP check*, IPv4 targets) given the full verdict (sharing, IOC "
                         "value, Tor role, evidence) and the weekly history that tells whether the IP was an exit while "
                         "the domain used it. Two VPNDB queries each.")
    st.checkbox(OPTION_LABELS["opt_vpndb_context"], key=prefix + "opt_vpndb_context", disabled=off or st.session_state[prefix + "opt_vpndb_only"],
                help=f"Neighbouring /24s, hosting networks and other domains on dedicated exits: up to {VPNDB_NEIGHBOUR_MAX} /24 ranges and {VPNDB_ASN_MAX} hosting networks in VPNDB (one "
                     f"query each) and up to {VPNDB_REVERSE_MAX} DNSDB reverse lookups on dedicated exits. Feeds "
                     "*Hosted Among Anonymizer Exits* and the VPNDB page's Neighbourhood and Leads tabs.")
    st.markdown("**BGPDB**")
    st.checkbox(OPTION_LABELS["opt_bgpdb"], key=prefix + "opt_bgpdb",
                help="On in every use case; only queried with a BGPDB host (Settings → API credentials: an internal "
                     "DomainTools service, reachable on its network or VPN). Looks up each public hosting IP (IP "
                     "targets, current Iris IPs, passive DNS; IPv4 and IPv6, no CDN addresses): the announced prefix, "
                     "the origin network, RPKI / IRR validity and the RIR allocation; then the AS paths of the "
                     f"prefixes (up to {BGPDB_ROUTE_MAX}) and the origin and upstream networks (up to {BGPDB_ASN_MAX}). "
                     "Feeds the BGP page and the BGP routing alerts.")
    bgp_off = not st.session_state[prefix + "opt_bgpdb"] or st.session_state[prefix + "opt_vpndb_only"]
    b1, b2 = st.columns(2)
    b1.number_input(OPTION_LABELS["opt_bgpdb_max_ips"], min_value=1, max_value=BGPDB_MAX_IPS * 5, step=50,
                    key=prefix + "opt_bgpdb_max_ips", disabled=bgp_off,
                    help="Public hosting addresses looked up (IP targets first, then each domain's current Iris IPs "
                         "and passive DNS addresses, most recent first). One BGPDB query each.")
    b2.checkbox(OPTION_LABELS["opt_bgpdb_context"], key=prefix + "opt_bgpdb_context", disabled=bgp_off,
                help="The prefixes announced in the /20 (IPv6: /40) around the run's prefixes, and by whom: neighbours "
                     "of the same origin are leads. One query per range, up to 10 ranges.")
    st.checkbox(OPTION_LABELS["opt_vpndb_only"], key=prefix + "opt_vpndb_only",
                help="No other source: for runs on IP addresses and CIDR ranges only. Looks up the IP targets (IPv4 and IPv6) and CIDR "
                     "ranges in VPNDB and nothing else: no Iris, passive DNS, Domain History or certificates. Domain "
                     "targets are skipped (Data sources says so). Off in every use case except *Check IP addresses*; "
                     "turn it on in a profile only if that profile is meant for IP lists.")
    st.markdown("**Certificate API**")
    c1, c2 = st.columns(2)
    c1.checkbox(OPTION_LABELS["opt_ct"], key=prefix + "opt_ct",
                help="Two extra API calls per Cert API certificate. Disable for faster runs on large targets.")
    c2.number_input(OPTION_LABELS["opt_ct_max"], min_value=1, max_value=5000, step=5, key=prefix + "opt_ct_max",
                    disabled=not st.session_state[prefix + "opt_ct"],
                    help="The newest certificates are looked up first, taking turns between domains so one busy domain "
                         "does not use the whole budget. Each certificate costs two calls, so large values make runs slow.")
    c1.number_input(OPTION_LABELS["opt_seed_preselect"], min_value=1, max_value=SEED_MAX_TARGETS, step=5,
                    key=prefix + "opt_seed_preselect",
                    help="Domains / IPs found through certificate inputs are pre-selected up to this many (most "
                         "certificates first). You can change the selection before the run.")
    st.caption("Iris Investigate has no options: current hosting, registration, risk score, website and trackers are "
               "fetched for every domain (batched requests). To bypass the lookup cache: *Clear cache* under Settings → "
               "Storage & cache, or *Re-run with fresh lookups* on the Data sources page for the current targets.")


CHIP_DISMISSED_SETTING = "credential_notice_dismissed"   # dt_settings.json: the notice closed for this state


def _chip_state(missing, warnings):
    """What the notice is about: it comes back when a service or a warning changes."""
    return "|".join(sorted(missing)) + "||" + "|".join(sorted(warnings))


def _dismiss_chip(state):
    save_setting(CHIP_DISMISSED_SETTING, state)


def render_credential_chip(settings_page=None):
    """
    Sidebar: one line on API credentials (the matrix is on the Settings page). A warning while a service has no key or
    a warning; it can be closed, and stays closed until the services without a key (or the warnings) change.
    """
    overview = credential_overview()
    services, warnings = overview["services"], _credential_warnings(overview)
    found = sum(row["Found"] for row in services)
    text = f"API credentials: {found}/{len(services)} services ready" + (f", {len(warnings)} warning(s)" if warnings else "")
    missing = [SERVICE_SHORT_NAMES.get(row["Service"], row["Service"]) for row in services if not row["Found"]]
    if missing:
        text += f". No key, not queried: {', '.join(missing)}"
    state = _chip_state(missing, warnings)
    if (found < len(services) or warnings) and load_settings().get(CHIP_DISMISSED_SETTING) != state:
        with st.sidebar.container(horizontal=True, vertical_alignment="top", gap="small", wrap=False):
            st.warning(text, icon=":material/key:", width="stretch")
            st.button("", key="credential_chip_close", icon=":material/close:", type="tertiary", width="content",
                      on_click=_dismiss_chip, args=(state,),
                      help="Close this notice. It comes back when a service without a key or a warning changes; "
                           "Settings → API credentials always shows the state.")
        if settings_page is not None and found < len(services):
            st.sidebar.page_link(settings_page, label="Enter API keys (Settings → API credentials)",
                                 icon=":material/edit:")
    else:
        st.sidebar.caption(f":material/key: {text}")


STATUS_ICONS = {IN_USE: "🟢", SET_NOT_USED: "🟡", NOT_SET: "⚪"}
STATUS_LEGEND = "🟢 in use · 🟡 set, but a source checked earlier wins · ⚪ not set"
SOURCE_HEADERS = {"Environment": "Env", "credentials.toml": "TOML", "Files": "Files"}   # short headers fit the sidebar


SERVICE_SHORT_NAMES = {"DNSDB Scout": "DNSDB", "Certificate API": "Cert API"}
_CELL = "padding:3px 4px;border:none;"


def _credential_matrix_html(matrix):
    """Compact HTML table: Streamlit's markdown tables are too wide for the default sidebar."""
    head = "".join(f'<th style="{_CELL}text-align:center;" title="{html.escape(s)}">{SOURCE_HEADERS[s]}</th>' for s in SOURCES)
    rows = []
    for row in matrix:
        cells = "".join(f'<td style="{_CELL}text-align:center;" title="{html.escape(s)}: {row[s]}">{STATUS_ICONS[row[s]]}</td>'
                        for s in SOURCES)
        name = html.escape(row["Service"])
        rows.append(f'<tr><td style="{_CELL}" title="{name}">{SERVICE_SHORT_NAMES.get(row["Service"], name)}</td>{cells}</tr>')
    return (f'<table style="width:100%;border-collapse:collapse;font-size:0.85rem;margin-bottom:0.25rem;">'
            f'<tr><th style="{_CELL}text-align:left;">Service</th>{head}</tr>{"".join(rows)}</table>')


def _credential_warnings(overview):
    toml = overview["toml"]
    warnings = [w for row in overview["services"] for w in row["Warnings"]] + toml["warnings"]
    return list(dict.fromkeys(([toml["error"]] if toml["error"] else []) + warnings))


def render_credential_status():
    """Settings page: service x source matrix (environment, credentials.toml, files); every option in a dialog."""
    overview = credential_overview()
    services, warnings = overview["services"], _credential_warnings(overview)
    found = sum(row["Found"] for row in services)
    issues = f", {len(warnings)} warning(s)" if warnings else ""
    attention = found < len(services) or bool(warnings)
    with st.container(border=True):
        st.markdown(f"{':material/warning:' if attention else ':material/key:'} "
                    f"**API credentials ({found}/{len(services)} services ready{issues})**")
        st.markdown(_credential_matrix_html(overview["matrix"]), unsafe_allow_html=True)
        st.caption(f"{STATUS_LEGEND}  \nChecked in this order: Env (environment variables), TOML (credentials.toml), Files.")
        for row in services:
            if not row["Found"]:
                st.caption(f":red[{row['Service']}: no credentials found.]")
        for warning in warnings:
            st.caption(f":orange[{md_escape(warning)}]")
        col_details, col_reload = st.columns(2)
        if col_details.button("All options", key="credential_details", width="stretch",
                              help="Every variable, credentials.toml entry, and file, and which ones queries use."):
            _credential_details_dialog()
        if col_reload.button("Reload", key="reload_credentials", width="stretch",
                             help="Re-reads credentials.toml and the files without restarting the app. "
                                  "Changed environment variables need an app restart."):
            clear_credential_cache()
            st.rerun()
    _render_credential_form(overview, missing=found < len(services))


KEY_FIELDS = {   # service -> [(credentials.toml key, label, password field)]
    DOMAINTOOLS: [("username", "DomainTools API username", False), ("api_key", "DomainTools API key", True)],
    DNSDB: [("api_key", "DNSDB API key", True)],
    CERT_API: [("api_key", "Certificate API key (optional)", True)],
    VPNDB: [("api_key", "VPNDB API key", True)],
    BGPDB: [("host", "BGPDB host (FQDN)", False), ("api_key", "BGPDB API key (optional)", True)],
}
KEY_HELP = {
    CERT_API: "Only if the Certificate API needs its own key; otherwise it uses the DomainTools API key.",
    VPNDB: "A key created on vpndb.io under Account → API keys (starts with vpndb_). For an on-premise installation, "
           "also set [vpndb] url in credentials.toml or $VPNDB_URL.",
    BGPDB: "The internal BGPDB host, e.g. bgpdb-dt.dev.fsi.io (reachable on the DomainTools network or VPN). A bare "
           "name gets .dev.fsi.io, as in the bgpdbq tool. The key is only needed if the host asks for one. Read from "
           "~/.bgpdbq.conf too, when the bgpdbq tool is set up.",
}


def _save_entered_keys(prefix="cred"):
    """
    Form callback: saves the filled fields (widget keys `prefix::service::key`) to credentials.toml; empty fields keep
    what is saved. Returns the services saved (empty when nothing was).
    """
    entered = {service: {key: (st.session_state.get(f"{prefix}::{service}::{key}") or "").strip() for key, _, _ in fields}
               for service, fields in KEY_FIELDS.items()}
    for service, fields in KEY_FIELDS.items():   # never keep keys in the session longer than this callback
        for key, _, _ in fields:
            st.session_state[f"{prefix}::{service}::{key}"] = ""
    updates = {service: {k: v for k, v in values.items() if v} for service, values in entered.items()}
    updates = {service: values for service, values in updates.items() if values}
    if not updates:
        st.session_state[TOAST_KEY] = "Nothing to save: every field was empty."
        return []
    domaintools = updates.get(DOMAINTOOLS, {})
    if len(domaintools) == 1 and DOMAINTOOLS not in saved_sections():
        st.session_state[TOAST_KEY] = "Enter both the DomainTools username and API key; nothing was saved."
        return []
    try:
        path = save_credentials(updates)
    except (CredentialFileError, OSError) as exc:
        st.session_state[TOAST_KEY] = f"Not saved: {exc}"
        return []
    resolved = {row["Service"]: row for row in credential_overview()["services"]}
    overridden = [service for service in updates if resolved[service]["Kind"] == ENVIRONMENT]
    st.session_state[TOAST_KEY] = (f"Saved {', '.join(updates)} to {path}."
                                   + (f" {', '.join(overridden)} still uses environment variables, which win."
                                      if overridden else ""))
    return list(updates)


def _remove_saved_keys(service):
    try:
        path = save_credentials({}, remove=(service,))
    except (CredentialFileError, OSError) as exc:
        st.session_state[TOAST_KEY] = f"Not removed: {exc}"
        return
    st.session_state[TOAST_KEY] = f"Removed the {service} keys from {path}."


def _render_credential_form(overview, missing):
    """Enter keys in the app: saved to credentials.toml, the second source checked, so the order stays the same."""
    toml, saved = overview["toml"], saved_sections()
    with st.expander("Enter API keys", expanded=missing, icon=":material/edit:"):
        st.caption(f"Saved to `{toml['path']}`, outside the project folder, readable only by your user (`chmod 600`). "
                   "Keys are never shown again and are not kept in the browser or in dt_settings.json. Environment "
                   "variables still win over this file, and the `~/.dt*` files are used only when it has no key. "
                   "Leave a field empty to keep what is saved. Saving rewrites the file without its comments.")
        if toml["error"]:
            st.warning("credentials.toml cannot be read, so nothing can be saved to it: " + toml["error"])
            return
        with st.form("credential_form", border=False, enter_to_submit=False):
            for service, fields in KEY_FIELDS.items():
                st.markdown(f"**{service}** · {SERVICES[service]}"
                            + (" · *saved in credentials.toml*" if service in saved else ""))
                columns = st.columns(len(fields)) if len(fields) > 1 else [st]
                for column, (key, label, secret) in zip(columns, fields):
                    column.text_input(label, key=f"cred::{service}::{key}", type="password" if secret else "default",
                                      autocomplete="off",
                                      placeholder="saved; leave empty to keep" if service in saved else "",
                                      help=KEY_HELP.get(service))
            st.form_submit_button("Save to credentials.toml", type="primary", icon=":material/save:",
                                  on_click=_save_entered_keys)
        if saved:
            st.caption("Remove keys saved in credentials.toml:")
            for column, service in zip(st.columns(len(KEY_FIELDS)), saved):
                column.button(f"Remove {service}", key=f"cred_remove::{service}", icon=":material/delete:",
                              on_click=_remove_saved_keys, args=(service,), width="stretch")


def _status_text(option):
    if option["Used for"]:
        return f"{STATUS_ICONS[IN_USE]} In use: {', '.join(option['Used for'])}"
    return f"{STATUS_ICONS[SET_NOT_USED]} Set, not used" if option["Configured"] else f"{STATUS_ICONS[NOT_SET]} Not set"


@st.dialog("API credentials", width="large")
def _credential_details_dialog():
    overview = credential_overview()
    st.markdown("Each credential comes from the **first** source that has it: **Environment**, then **credentials.toml**, "
                "then **Files**. The Certificate API uses the DomainTools API key unless it has its own key. "
                "Values are never shown.")
    rows = []
    for source in SOURCES:
        for option in overview["options"][source]:
            notes = [n for n in (option["Note"], option["Detail"]) if n] + option["Warnings"]
            rows.append({"Source": source, "Option": option["Option"], "Status": _status_text(option),
                         "For": ", ".join(option["For"]), "Notes": " · ".join(notes)})
    st.dataframe(pd.DataFrame(rows), hide_index=True, width="stretch", height=35 * (len(rows) + 1) + 3,
                 column_config={"Notes": st.column_config.TextColumn("Notes", width="large")})
    toml = overview["toml"]
    state = "could not be read" if toml["error"] else "found" if toml["exists"] else "not created"
    st.caption(f"credentials.toml: `{toml['path']}` ({state})" + (", set by `$DT_CREDENTIALS_FILE`" if toml["overridden"] else "")
               + ". Environment variables are read when the app starts.")
    for warning in _credential_warnings(overview):
        st.warning(warning)


@dataclass
class WindowChoice:
    preset: str
    custom_range: tuple = None


def render_apex_notice(conversions):
    """Lists subdomain inputs that were analyzed as their apex domain."""
    if not conversions:
        return
    lines = "  \n".join(f"`{original}` → `{apex}`" for original, apex in conversions)
    st.sidebar.info(f"Subdomains are analyzed at the apex domain (lookups still cover its subdomains):  \n{lines}")


def render_idn_notice(conversions):
    """Lists Unicode domain inputs that were looked up in their punycode (xn--) form."""
    if not conversions:
        return
    lines = "  \n".join(f"`{original}` → `{ascii_name}`" for original, ascii_name in conversions)
    st.sidebar.info("International domains are looked up in their ASCII (punycode) form, as DNS, certificates and the "
                    f"DomainTools APIs store them:  \n{lines}")


WINDOW_HELP = ("Restricts alerts, IOCs, DIF / risk scores, exports, and charts to records active in this window "
               "(pDNS last seen, Domain History changes, certificates valid, events observed). Dormancy and "
               "domain-hopping context is still computed from full history. Choose 'All time' to review older "
               "activity. Changing it needs no new lookups.")


def window_choice_from_state():
    """The analysis window picked (sidebar before a run, the results toolbar after): defaults to the last 30 days."""
    st.session_state.setdefault("analysis_window", DEFAULT_WINDOW)
    preset = st.session_state["analysis_window"]
    picked = st.session_state.get("analysis_window_range")
    custom = (picked[0], picked[1]) if preset == CUSTOM_RANGE and isinstance(picked, (list, tuple)) \
        and len(picked) == 2 else None
    return WindowChoice(preset, custom)


def render_analysis_window(container, width="stretch"):
    """The analysis window selector in `container` (the sidebar, or the results toolbar)."""
    st.session_state.setdefault("analysis_window", DEFAULT_WINDOW)
    preset = container.selectbox("Show activity from", list(WINDOW_PRESETS), key="analysis_window", help=WINDOW_HELP,
                                 width=width)
    if preset == CUSTOM_RANGE:
        today = pd.Timestamp.now().date()
        st.session_state.setdefault("analysis_window_range", (today - pd.Timedelta(days=30), today))
        picked = container.date_input("Date range", key="analysis_window_range", width=width)
        if not (isinstance(picked, (list, tuple)) and len(picked) == 2):
            container.caption("Select both a start and an end date.")


def reset_thresholds():
    for spec in THRESHOLD_SPECS:
        st.session_state[spec.state_key] = spec.default


def current_thresholds():
    """{engine_key: value} of the detection thresholds (Settings page sliders, kept in session state)."""
    return {**DEFAULT_THRESHOLDS, **{spec.key: st.session_state.get(spec.state_key, spec.default) for spec in THRESHOLD_SPECS}}


def render_threshold_controls():
    """Settings page: one slider per ThresholdSpec, grouped by the data each applies to."""
    st.caption("Fine-tune threat engine aggressiveness. Changing one re-runs the engine on the data already collected, "
               "with no new API calls.")
    sections = list(dict.fromkeys(spec.section for spec in THRESHOLD_SPECS))
    for column, section in zip(st.columns(2) * ((len(sections) + 1) // 2), sections):
        with column.container(border=True):
            st.markdown(f"**{section}**")
            for spec in THRESHOLD_SPECS:
                if spec.section == section:
                    st.slider(spec.label, min_value=spec.min_value, max_value=spec.max_value, step=spec.step,
                              key=spec.state_key, help=spec.help)
    st.button("Reset defaults", on_click=reset_thresholds, icon=":material/restart_alt:")


def _hostname_options(collected):
    """
    (hostname, apex) for the hostnames the run's data mentions, computed once per dataset (certificate rows are scanned
    one by one).
    """
    marker = (id(collected), st.session_state.get("run_created"))
    cached = st.session_state.get("_hostname_options")
    if cached and cached[0] == marker:
        return cached[1]
    ssl = pd.concat([f for f in (collected.ssl, collected.ssl_active) if f is not None and not f.empty], ignore_index=True) \
        if not (collected.ssl.empty and collected.ssl_active.empty) else pd.DataFrame()
    domains = collected.domain_targets or collected.targets
    focus_hosts = [h for hosts in (getattr(collected, "host_focus", None) or {}).values() for h in hosts]
    options = [(h, apex_of(h)) for h in candidate_hostnames(collected.pdns, ssl, collected.cert_hostnames, domains,
                                                          focus_hosts)]
    st.session_state["_hostname_options"] = (marker, options)
    return options


def focus_key():
    return f"host_focus::{st.session_state.get('run_created')}"


HUNT_KEY = "hunt_request"   # {"id": parent run id, "via": what led here}: the next app run analyzes TARGETS_KEY


RUN_OPTION_KEYS = tuple(k for k in COLLECTION_DEFAULTS if k != "opt_force_refresh")   # what Run again restores


def run_options():
    """The use case, analysis window and collection options of the run being analyzed (saved with its snapshot)."""
    state = st.session_state
    options = {key: state[key] for key in RUN_OPTION_KEYS if key in state}
    options["use_case"] = state.get("use_case")
    options["analysis_window"] = state.get("analysis_window", DEFAULT_WINDOW)
    picked = state.get("analysis_window_range")
    if options["analysis_window"] == CUSTOM_RANGE and isinstance(picked, (list, tuple)) and len(picked) == 2:
        options["analysis_window_range"] = [str(day) for day in picked]
    return options


def run_again(lines, options, via="Run again"):
    """
    Button callback: puts a saved run's use case, window and collection options back (`options`, see run_options;
    a run saved without them keeps the current ones) and analyzes `lines` right away as a new run.
    """
    options = options or {}
    st.session_state.update({key: options[key] for key in RUN_OPTION_KEYS if key in options})
    if "use_case" in options:
        st.session_state["use_case"] = options["use_case"]
    if options.get("analysis_window") in WINDOW_PRESETS:
        st.session_state["analysis_window"] = options["analysis_window"]
        dates = options.get("analysis_window_range")
        if options["analysis_window"] == CUSTOM_RANGE and dates and len(dates) == 2:
            st.session_state["analysis_window_range"] = tuple(pd.Timestamp(day).date() for day in dates)
    start_hunt(lines, via)


def start_hunt(lines, via, parent_id=None, direct=False):
    """
    Button callback: makes `lines` the targets and analyzes them right away as a new run, linked to
    run `parent_id` through `via` (hunt tree). `direct`: certificate targets skip the review screens (suggested hunt).
    """
    st.session_state[TARGETS_KEY] = "\n".join(dict.fromkeys(line for line in lines if line))
    st.session_state[DATA_MODE_KEY] = LIVE_MODE
    st.session_state[HUNT_KEY] = {"id": parent_id, "via": via, "direct": direct}
    st.session_state[APP_RERUN_KEY] = True


def focus_on_hostnames(hostnames):
    """Button callback: adds hostnames to the hostname focus (results toolbar) (the calling view reruns the whole app)."""
    key = focus_key()
    st.session_state[key] = list(dict.fromkeys(list(st.session_state.get(key) or []) + list(hostnames)))
    st.session_state[APP_RERUN_KEY] = True
    st.session_state[TOAST_KEY] = (f"Focused the views on {len(st.session_state[key]):,} hostname(s); clear "
                                   "*Hostnames* in the results toolbar to see everything again.")


def show_pending_toast():
    """Shows the message a button callback left: a callback must not draw elements during a fragment rerun."""
    message = st.session_state.pop(TOAST_KEY, None)
    if message:
        st.toast(message)


def render_cache_settings():
    """Cache lifetime of successful lookups (saved in dt_settings.json), applied to every cached fetch."""
    seconds = load_settings().get("cache_seconds", FETCH_CACHE_TTL_SECONDS)
    labels = list(CACHE_LIFETIMES)
    current = next((label for label, value in CACHE_LIFETIMES.items() if value == seconds), "1 day")
    label = st.selectbox(
        "Cache lifetime", labels, index=labels.index(current), key="cache_lifetime",
        help="How long a successful lookup is reused: the same domain, name, record type and limit looked up again "
             "(in this or a later run, also after an app restart) costs no API query. Covers passive DNS and its TXT / "
             "CAA / CNAME lookups, CNAME chases and reverse lookups, IP pivots, certificates, Domain History, "
             "Iris Investigate (per batch of domains, with risk scores) and VPNDB. Each source can keep its results "
             "for its own lifetime (below). Kept in dt_cache/ (local, git-ignored). The Data sources page "
             "marks each reused lookup *From cache*. Off: always query.")
    save_setting("cache_seconds", CACHE_LIFETIMES[label])
    set_cache_ttl(CACHE_LIFETIMES[label])
    _render_group_lifetimes(CACHE_LIFETIMES[label] <= 0)
    count, size = cache_usage()
    if st.button("Clear cache", key="clear_cache", icon=":material/delete_sweep:", disabled=not count,
                 help="Deletes every cached lookup now (dt_cache/ and memory), without running anything. The next "
                      "lookups and chases query the APIs again."):
        st.toast(f"Deleted {clear_all_caches():,} cached lookup(s).")
        count, size = cache_usage()
    st.caption(f"{count:,} cached lookup(s), {format_size(size)}." if count else "The cache is empty.")


def _render_group_lifetimes(off):
    """Each source group's own lifetime: results that change rarely can be kept longer, ones that change often less."""
    lifetimes = group_lifetimes(load_settings())
    names = {seconds: label for label, seconds in CACHE_LIFETIMES.items() if seconds}
    options = [None, *names]
    st.markdown("**Per source**", help="How long each source's results are reused. VPNDB verdicts and BGPDB routing "
                "change often (6 hours by default); the others follow the cache lifetime above. Domain History "
                "changes rarely: 7 days there saves Domain History quota. With the cache off, every source is off.")
    changed, columns = {}, st.columns(2)
    for index, (group, label) in enumerate(CACHE_GROUPS.items()):
        current = lifetimes[group] if lifetimes[group] in options else None
        choice = columns[index % 2].selectbox(label, options, index=options.index(current), key=f"cache_group::{group}",
                                              disabled=off, format_func=lambda s: FOLLOW if s is None else names[s])
        changed[group] = choice
        set_group_ttl(group, choice)
    if changed != lifetimes:
        save_setting(CACHE_GROUP_SETTING, changed)


def rerun_app_if_requested():
    """Called inside a fragment after its buttons: a callback that changed sidebar state needs a full app rerun."""
    if st.session_state.pop(APP_RERUN_KEY, False):
        st.rerun()


EMPTY_TARGETS_KEY = "start_targets_empty"   # Analyze clicked with an empty Targets box: the Start page says so


def start_analyze(source_key):
    """
    Start page *Analyze* callback: its target box becomes the targets, and the next app run analyzes them. The button
    is always enabled (a text area only sends its text when it loses focus, and the click does that), so an empty box
    is caught here instead.
    """
    if not str(st.session_state.get(source_key) or "").strip():
        st.session_state[EMPTY_TARGETS_KEY] = True
        return
    st.session_state[TARGETS_KEY] = st.session_state.get(source_key, "")
    st.session_state[SAVE_OFFLINE_KEY + "_run"] = bool(st.session_state.get(SAVE_OFFLINE_KEY))
    st.session_state[DATA_MODE_KEY] = LIVE_MODE
    st.session_state[START_RUN_KEY] = True
