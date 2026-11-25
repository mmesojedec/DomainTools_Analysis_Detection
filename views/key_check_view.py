"""
"Check API keys": asks each service whether the saved credentials work (integrations.key_check) and shows one line per
service. Used by the welcome dialog after the keys are saved and by Settings → API credentials. A key that does not
work is a notice (toast and a red line), never a block.
"""
import pandas as pd
import streamlit as st

from integrations.credentials import DNSDB
from integrations.key_check import FAILED, OK, SKIPPED, WARNING, check_keys, summary
from views.api_usage_view import DNSDB_QUOTA_KEY

RESULTS_KEY = "key_checks"   # session: (list of KeyCheck, checked at)
ICONS = {OK: ":green[:material/check_circle:]", WARNING: ":orange[:material/warning:]",
         FAILED: ":red[:material/cancel:]", SKIPPED: ":gray[:material/radio_button_unchecked:]"}
WHAT_IS_ASKED = ("DomainTools: one Account Information query (counts against *Account information*, not Iris). "
                 "DNSDB: the key's rate limit (free). VPNDB: the Tor overview (not metered). BGPDB: one `asn` "
                 "lookup (no quota; DomainTools network or VPN). The Certificate API is not asked: it uses the "
                 "DomainTools key, and each of its requests counts against its quota.")


def run_key_checks(notify=True):
    """Checks every service now (no cache), keeps the results for this session and notifies the outcome."""
    with st.spinner("Checking the API keys..."):
        checks = check_keys()
    st.session_state[RESULTS_KEY] = (checks, pd.Timestamp.now(tz="UTC"))
    dnsdb = next((c.result for c in checks if c.service == DNSDB and c.result is not None), None)
    if dnsdb is not None and dnsdb.ok:   # the quota banners and the Account page read it
        st.session_state[DNSDB_QUOTA_KEY] = (dnsdb, pd.Timestamp.now(tz="UTC"))
    if notify:
        failed = any(c.status == FAILED for c in checks)
        st.toast(summary(checks), icon=":material/error:" if failed else ":material/check_circle:")
    return checks


def last_checks():
    """(checks, checked at) of the last check this session, or (None, None)."""
    return st.session_state.get(RESULTS_KEY) or (None, None)


def render_key_checks(checks, checked_at=None):
    """One line per service: icon, service, what came back; notes (quota, expiry, missing products) under it."""
    for check in checks:
        st.markdown(f"{ICONS[check.status]} **{check.service}**: {check.text}")
        for note in check.notes:
            st.caption(f":material/subdirectory_arrow_right: {note}")
    st.caption((f"Checked {checked_at:%Y-%m-%d %H:%M} UTC. " if checked_at is not None else "") + WHAT_IS_ASKED)


def render_check_section():
    """Settings → API credentials: Check API keys and the last result."""
    st.markdown("**Check API keys**", help=WHAT_IS_ASKED)
    if st.button("Check API keys", key="settings_check_keys", icon=":material/network_check:",
                 help="Asks each service whether the saved key works, with its cheapest request."):
        run_key_checks()
    checks, at = last_checks()
    if checks:
        render_key_checks(checks, at)
    else:
        st.caption("Not checked in this session yet.")
