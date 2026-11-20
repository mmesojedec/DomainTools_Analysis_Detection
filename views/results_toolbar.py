"""
Results toolbar: one row under the status line of every results page, shown once a run or dataset is loaded. It
fine-tunes what the pages show from the data already collected, with no new lookups: the analysis window, the
domains, the hosting network (BGPDB origin, VPNDB verdict), a hostname focus, the record types, the alert severities and confidences, and the most used detection
thresholds. Each change re-runs the detection rules on the loaded data and updates every page.

Every filter lives in session state, so the analysis is built once per app run, before the page draws, and keeps the
choices while a page without the toolbar is open.
"""
import dataclasses
from dataclasses import dataclass, field

import pandas as pd
import streamlit as st

from config import THRESHOLD_SPECS
from core import bgp
from core.hostnames import focus_from_hostnames
from core.intel_data import CONFIDENCE_ORDER, SEVERITY_ORDER
from core.use_cases import history_period_days
from core.window import CUSTOM_RANGE
from views import navigation
from views.idn_display import display_name
from views.sidebar import _hostname_options, focus_key, is_analyst, render_analysis_window, run_again

SEVERITY_KEY, CONFIDENCE_KEY = "flt_severity", "flt_confidence"
# the thresholds analysts change most, in the toolbar's Detection popover; every one is on Settings
COMMON_THRESHOLDS = ("risk_score", "high_risk_score", "nrd_days", "flux_ips", "entropy")
SPECS = {spec.key: spec for spec in THRESHOLD_SPECS}


@dataclass
class ViewFilters:
    domains: list = field(default_factory=list)       # the domains (and IP / CIDR targets) the pages show
    dh_types: list = field(default_factory=list)      # Domain History record types kept
    pdns_types: list = field(default_factory=list)    # passive DNS record types kept
    host_focus: dict = field(default_factory=dict)    # {apex: [hostnames]}; empty: every hostname
    severities: list = field(default_factory=lambda: list(SEVERITY_ORDER))
    confidences: list = field(default_factory=lambda: list(CONFIDENCE_ORDER))


def _marker():
    return st.session_state.get("run_created") or "run"


def domains_key():
    return f"view_domains::{_marker()}"


def dh_key():
    return f"view_dh_types::{_marker()}"


def pdns_key():
    return f"view_pdns_types::{_marker()}"


def asn_key():
    return f"view_asns::{_marker()}"


def vpndb_key():
    return f"view_vpndb::{_marker()}"


def _split(value):
    return {d.strip() for d in str(value).split(",") if d.strip()}


def network_options(collected):
    """
    ({ASN: label}, {ASN: domains}, {VPNDB verdict: domains}) of the loaded run: the usual BGP origin network of each
    domain's hosting IPs (BGPDB) and the VPNDB verdict of each (VPN, Tor, Not anonymous, ...). Empty without that data.
    """
    labels, by_asn, by_verdict = {}, {}, {}
    origins = getattr(collected, "bgp_origins", None)
    if origins is not None and not origins.empty:
        for _, row in bgp.main_origins(origins).iterrows():
            labels.setdefault(row["Origin"], f"{row['Origin']} {row['AS Name']}".strip())
            by_asn.setdefault(row["Origin"], set()).update(_split(row["Domains"]))
    checked = getattr(collected, "anonymizers", None)
    if checked is not None and not checked.empty and "Category" in checked:
        for _, row in checked.iterrows():
            if row["Category"]:
                by_verdict.setdefault(str(row["Category"]), set()).update(_split(row["Domains"]))
    return labels, by_asn, by_verdict


def network_domains(collected, asns, verdicts):
    """
    The domains whose hosting matches the Network filter: any picked origin network AND any picked VPNDB verdict
    (a group left empty does not filter). None when nothing is picked.
    """
    if not asns and not verdicts:
        return None
    _, by_asn, by_verdict = network_options(collected)
    keep = None
    for picked, index in ((asns, by_asn), (verdicts, by_verdict)):
        if picked:
            found = set().union(*(index.get(value, set()) for value in picked))
            keep = found if keep is None else keep & found
    return keep


def filter_options(collected):
    """(domains and IP / CIDR targets, Domain History record types, passive DNS record types) of the loaded run."""
    found = []
    for frame in (collected.dh, collected.pdns, collected.ssl):
        if not frame.empty:
            found.extend(frame["Domain"].dropna().unique())
    checked = getattr(collected, "anonymizers", None)
    if checked is not None and not checked.empty:   # IP targets checked in VPNDB (IP check use case)
        found.extend(ip for ip in checked["IP"] if ip in collected.targets)
    ranges = getattr(collected, "prefixes", None)
    if ranges is not None and not ranges.empty:   # CIDR targets (VPNDB)
        found.extend(ranges["CIDR"])
    present = set(found)
    domains = list(dict.fromkeys(d for d in collected.targets if d in present)) + sorted(present - set(collected.targets))
    dh = sorted(collected.dh["Field"].dropna().unique()) if not collected.dh.empty else []
    pdns = sorted(collected.pdns["Field"].dropna().unique()) if not collected.pdns.empty else []
    return domains, dh, pdns


def _keep(key, allowed, default):
    """The value of filter `key`, limited to `allowed`; re-assigned so it survives pages that do not draw it."""
    state = st.session_state
    value = state.get(key, default)
    allowed = set(allowed)
    state[key] = [v for v in (value or []) if v in allowed]
    return state[key]


def _focus_options(collected, domains):
    selected = set(domains)
    return [h for h, apex in _hostname_options(collected) if apex in selected]


def filter_state(collected):
    """
    The filters picked for the loaded run (all domains, record types, hostnames, severities and confidences until
    narrowed). Read before the page draws: the toolbar's widgets write the same session state.
    """
    all_domains, all_dh, all_pdns = filter_options(collected)
    domains = _keep(domains_key(), all_domains, []) or all_domains
    labels, _, by_verdict = network_options(collected)
    matching = network_domains(collected, _keep(asn_key(), labels, []), _keep(vpndb_key(), by_verdict, []))
    if matching is not None and any(d in matching for d in domains):   # no match: the filter is not applied
        domains = [d for d in domains if d in matching]
    dh = _keep(dh_key(), all_dh, []) or all_dh
    pdns = _keep(pdns_key(), all_pdns, []) or all_pdns
    if not is_analyst():   # the simple mode keeps every record type
        dh, pdns = all_dh, all_pdns
    hostnames = _focus_options(collected, domains)
    initial = [h for hosts in (getattr(collected, "host_focus", None) or {}).values() for h in hosts]
    focus = _keep(focus_key(), hostnames, initial) if hostnames else []
    severities = _keep(SEVERITY_KEY, SEVERITY_ORDER, list(SEVERITY_ORDER))
    confidences = _keep(CONFIDENCE_KEY, CONFIDENCE_ORDER, list(CONFIDENCE_ORDER))
    return ViewFilters(domains, dh, pdns, focus_from_hostnames(focus), severities, confidences)


def filter_alerts(view, filters):
    """The alert view with only the picked severities and confidences (risk scores still count every alert)."""
    active = view.active
    if active.empty or (len(filters.severities) == len(SEVERITY_ORDER)
                        and len(filters.confidences) == len(CONFIDENCE_ORDER)):
        return view
    keep = active["Severity"].isin(filters.severities) & active["Confidence"].isin(filters.confidences)
    changes = {"active": active[keep]}
    for name in ("new_mask", "first_detected_mask"):
        mask = getattr(view, name, None)
        if isinstance(mask, pd.Series):
            changes[name] = mask[keep.reindex(mask.index, fill_value=False)]
    return dataclasses.replace(view, **changes)


def _changed_thresholds():
    return [spec for spec in THRESHOLD_SPECS if st.session_state.get(spec.state_key, spec.default) != spec.default]


def _reset_filters(collected):
    state = st.session_state
    for key in (domains_key(), dh_key(), pdns_key(), focus_key(), asn_key(), vpndb_key()):
        state[key] = []
    state[SEVERITY_KEY], state[CONFIDENCE_KEY] = list(SEVERITY_ORDER), list(CONFIDENCE_ORDER)
    for spec in THRESHOLD_SPECS:
        state[spec.state_key] = spec.default


def _reset_thresholds():
    for spec in THRESHOLD_SPECS:
        st.session_state[spec.state_key] = spec.default


def _count(picked, total, noun):
    return f"{noun} · all" if not picked or len(picked) == total else f"{noun} · {len(picked)} of {total}"


def render_results_toolbar(collected, filters):
    """The toolbar row: every control changes the pages at once, from the loaded data (no API query)."""
    all_domains, all_dh, all_pdns = filter_options(collected)
    state = st.session_state
    with st.container(horizontal=True, wrap=True, vertical_alignment="bottom", gap="small", key="results_toolbar"):
        render_analysis_window(st, width=190)
        with st.popover(_count(state[domains_key()], len(all_domains), "Domains"), icon=":material/language:",
                        help="Only these domains (and IP or CIDR targets) on every page"):
            st.multiselect("Domains", all_domains, key=domains_key(), format_func=display_name,
                           placeholder=f"All {len(all_domains)} domains")
        hostnames = _focus_options(collected, filters.domains)
        if hostnames:
            focus = state.get(focus_key()) or []
            with st.popover(f"Hostnames · {len(focus)}" if focus else "Hostnames · all", icon=":material/dns:",
                            help="Focus on chosen hostnames"):
                st.multiselect(
                    "Focus on hostnames", hostnames, key=focus_key(), placeholder="All hostnames",
                    help="Leave empty to analyze every hostname. Choosing hostnames keeps only their passive DNS "
                         "records (and names under them), the certificates covering them and their certificate "
                         "events, for their domains only. Domain History and Iris Investigate (with risk scores) "
                         "stay domain-wide. See Hostname Inventory for every hostname.")
        if is_analyst() and (all_dh or all_pdns):
            picked = len(state[dh_key()] or all_dh) + len(state[pdns_key()] or all_pdns)
            label = "Record types · all" if picked == len(all_dh) + len(all_pdns) else \
                f"Record types · {picked} of {len(all_dh) + len(all_pdns)}"
            with st.popover(label, icon=":material/filter_list:",
                            help="Leave record types out of the analysis: alerts, risk, timelines and records"):
                st.caption("The detection rules, risk scores, charts and Evidence records use only the types kept.")
                if all_pdns:
                    st.multiselect("Passive DNS record types", all_pdns, key=pdns_key(), placeholder="Every type")
                if all_dh:
                    st.multiselect("Domain History record types", all_dh, key=dh_key(), placeholder="Every type")
        labels, _, by_verdict = network_options(collected)
        if labels or by_verdict:
            picked = len(state.get(asn_key()) or []) + len(state.get(vpndb_key()) or [])
            with st.popover(f"Network · {picked} picked" if picked else "Network · all", icon=":material/hub:",
                            help="Only the domains hosted on chosen networks (BGPDB origin) or with a chosen VPNDB "
                                 "verdict, on every page"):
                if labels:
                    st.multiselect("Origin network (BGPDB)", sorted(labels), key=asn_key(), format_func=labels.get,
                                   placeholder="Every network",
                                   help="The network that normally announces the domain's hosting IPs. A domain on "
                                        "several networks is kept when any of them is picked")
                if by_verdict:
                    st.multiselect("VPNDB verdict", sorted(by_verdict), key=vpndb_key(), placeholder="Every verdict",
                                   help="A domain is kept when any of its checked IPs has a picked verdict (VPN, "
                                        "Tor, Residential proxy, Not anonymous, Not observed, ...)")
                matching = network_domains(collected, state.get(asn_key()), state.get(vpndb_key()))
                if matching is not None:
                    shown = [d for d in (state[domains_key()] or all_domains) if d in matching]
                    if shown:
                        st.caption(f"{len(shown)} domain(s) match: {', '.join(shown[:8])}"
                                   + (" …" if len(shown) > 8 else ""))
                    else:
                        st.warning("No selected domain matches both: the Network filter is not applied.")
                st.caption("Both picked: a domain must match one network and one verdict.")
        narrowed = len(filters.severities) < len(SEVERITY_ORDER) or len(filters.confidences) < len(CONFIDENCE_ORDER)
        with st.popover("Alerts · filtered" if narrowed else "Alerts · all", icon=":material/warning:",
                        help="Alerts shown on Summary, Alerts, Domain profile and exports"):
            st.multiselect("Severity", SEVERITY_ORDER, key=SEVERITY_KEY, placeholder="No severity picked")
            st.multiselect("Confidence", CONFIDENCE_ORDER, key=CONFIDENCE_KEY, placeholder="No confidence picked")
            st.caption("Risk scores still count every alert.")
        changed = _changed_thresholds()
        with st.popover(f"Detection · {len(changed)} changed" if changed else "Detection · defaults",
                        icon=":material/tune:", help="The most used detection thresholds"):
            for key in COMMON_THRESHOLDS:
                spec = SPECS[key]
                st.slider(spec.label, min_value=spec.min_value, max_value=spec.max_value, step=spec.step,
                          key=spec.state_key, help=spec.help)
            with st.container(horizontal=True):
                st.button("Reset to defaults", key="toolbar_reset_thresholds", on_click=_reset_thresholds,
                          icon=":material/restart_alt:", type="tertiary", disabled=not changed)
                navigation.link("settings", label="Every threshold")
        is_filtered = (state[domains_key()] or state[dh_key()] or state[pdns_key()] or state.get(focus_key())
                       or state.get(asn_key()) or state.get(vpndb_key())
                       or narrowed or changed)
        if is_filtered:
            st.button("Reset filters", key="toolbar_reset", on_click=_reset_filters, args=(collected,),
                      icon=":material/filter_alt_off:", type="tertiary",
                      help="Every domain, hostname, network, record type, severity and confidence, and the default "
                           "thresholds")


def render_window_coverage(collected, window, run_options, created):
    """
    A note when the window starts before the Domain History this run fetched (a period of N days): widening the
    window needs the older changes, so it offers to run the targets again with this window.
    """
    options = run_options or {}
    mode = options.get("opt_history_mode")
    picked = options.get("analysis_window_range")
    days = history_period_days(mode, options.get("opt_history_days"), options.get("analysis_window"),
                               picked[0] if isinstance(picked, (list, tuple)) and picked else None,
                               today=pd.Timestamp(created).date() if created else None)
    created = pd.to_datetime(created, errors="coerce", utc=True)
    if not days or pd.isna(created):
        return
    fetched_from = created.tz_localize(None) - pd.Timedelta(days=days)
    if window.start is not None and window.start >= fetched_from - pd.Timedelta(days=1):
        return
    state = st.session_state
    new_options = {**options, "analysis_window": state.get("analysis_window")}
    if state.get("analysis_window") == CUSTOM_RANGE and state.get("analysis_window_range"):
        new_options["analysis_window_range"] = [str(day) for day in state["analysis_window_range"]]
    new_options["opt_history_mode"] = "window"   # the new run fetches Domain History for the window picked
    with st.container(horizontal=True, vertical_alignment="center"):
        st.caption(f":orange[:material/history:] This run fetched Domain History for the last {days:,} days only "
                   f"(from {fetched_from:%Y-%m-%d}); older changes are not in it. The other sources cover the window.")
        st.button("Run again with this window", key="toolbar_rerun_window", on_click=run_again,
                  args=(list(collected.targets), new_options), icon=":material/replay:", type="tertiary",
                  help="A new live run of the same targets with this window (it uses API queries)")
