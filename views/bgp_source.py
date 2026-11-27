"""
The BGP routing source of every run (BGPDB, RIPEstat or both) and RIPEstat's registration lookup: saved settings,
shown in the BGP routing part of the collection options.
"""
import streamlit as st

from config import BGP_SOURCE_SETTING, BGP_SOURCES, RIPESTAT_MAX_IPS, RIPESTAT_REGISTRATION_SETTING
from core.persistence import load_settings, save_setting


def _save_bgp_source():
    save_setting(BGP_SOURCE_SETTING, st.session_state["settings_bgp_source"])


def _save_ripestat_registration():
    save_setting(RIPESTAT_REGISTRATION_SETTING, bool(st.session_state["settings_ripestat_registration"]))


def render_bgp_source(disabled=False):
    """Where BGP routing comes from (BGPDB, RIPEstat or both) and whether RIPEstat adds each IP's registration."""
    from integrations.ripestat_stage import routing_plan
    saved = load_settings()
    st.session_state.setdefault("settings_bgp_source", saved.get(BGP_SOURCE_SETTING)
                                if saved.get(BGP_SOURCE_SETTING) in BGP_SOURCES else "both")
    st.session_state.setdefault("settings_ripestat_registration", bool(saved.get(RIPESTAT_REGISTRATION_SETTING, True)))
    st.radio("BGP routing source", list(BGP_SOURCES), format_func=BGP_SOURCES.get, key="settings_bgp_source",
             on_change=_save_bgp_source, disabled=disabled,
             help="Saved for every run, whatever the use case or profile. BGPDB: an internal DomainTools service "
                  "(its host under Settings → API credentials; DomainTools network or VPN), about the last 30 days. "
                  "RIPEstat: RIPE NCC's public data service, BGP routing seen by the RIPE RIS route collectors (years "
                  f"of history) and registry data from all five RIRs; no key, up to {RIPESTAT_MAX_IPS} IPs per run, "
                  "and the addresses and networks looked up are sent to RIPE NCC.")
    use_bgpdb, ripe = routing_plan()
    st.caption("Next run: " + {
        (True, "always"): "BGP routing from **BGPDB and RIPEstat** (the BGP page switches between them; the alerts "
                          "use BGPDB, or RIPEstat when BGPDB does not answer).",
        (True, "fallback"): "BGP routing from **BGPDB**; from **RIPEstat** if BGPDB does not answer.",
        (True, "never"): "BGP routing from **BGPDB**.",
        (False, "always"): "BGP routing from **RIPEstat**" + (" (no BGPDB host set)." if st.session_state[
            "settings_bgp_source"] != "ripestat" else "."),
        (False, "never"): "no BGP routing (BGPDB only, and no BGPDB host is set).",
    }.get((use_bgpdb, ripe), ""))
    st.checkbox("Registration and abuse contact of each hosting IP (RIPEstat)", key="settings_ripestat_registration",
                on_change=_save_ripestat_registration, disabled=disabled,
                help="The registry's network object of each IP (net name, organisation, type, country, registration "
                     "date) and where to report abuse, also when routing comes from BGPDB. Shown on the BGP page "
                     "(Registration) and the IP profile. Saved for every run.")
