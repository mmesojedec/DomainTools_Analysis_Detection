"""
Account page: the DomainTools account behind the configured API credentials, and each product's limits, usage this
month and today, and expiry (Account Information API). Fetched once per session and on Refresh.
"""
import json

import pandas as pd
import streamlit as st

from core.account import (
    APP_PRODUCTS,
    account_parts,
    endpoints,
    missing_app_products,
    nearest_expiry,
    products_frame,
)
from integrations.account import account_information
from integrations.credentials import load_dnsdb_key, load_vpndb_key
from integrations.dnsdb import fetch_dnsdb_rate_limit
from integrations.vpndb import VPNDB_RATE_LIMIT, last_quota
from views.api_usage_view import DNSDB_QUOTA_KEY
from views.quota_banner import HELP as QUOTA_HELP
from views.quota_banner import render_quota_banners

REFRESH_KEY = "account_refresh_requested"
FILTER_KEY = "account_filter"
FILTERS = ("all", "used")
FILTER_LABELS = {"all": "All products", "used": "Used this month"}


def _load():
    """The shared account answer (at most one query an hour; Refresh asks again)."""
    with st.spinner("Fetching account information..."):
        result, at = account_information(refresh=st.session_state.pop(REFRESH_KEY, False))
    return result, pd.Timestamp(at, unit="s", tz="UTC")


def _epoch_text(value):
    """DNSDB epoch seconds as a UTC time; its words ("n/a", "unlimited") as they are."""
    if isinstance(value, (int, float)):
        return pd.Timestamp(value, unit="s", tz="UTC").strftime("%Y-%m-%d %H:%M UTC")
    return str(value) if value not in (None, "") else "—"


def _render_other_quotas():
    """DNSDB (asked on demand: the check costs no query) and VPNDB (from its last answer this session)."""
    st.subheader("Other services", help="DNSDB and VPNDB are separate subscriptions with their own quotas.")
    c1, c2 = st.columns(2)
    with c1:
        st.markdown("**DNSDB**")
        if not load_dnsdb_key():
            st.caption("No DNSDB key (Settings → API credentials).")
        else:
            if st.button("Check DNSDB quota", key="dnsdb_quota_check", icon=":material/speed:",
                         help="Asks DNSDB for this key's quota. The check does not count against it."):
                st.session_state[DNSDB_QUOTA_KEY] = (fetch_dnsdb_rate_limit(), pd.Timestamp.now(tz="UTC"))
            checked = st.session_state.get(DNSDB_QUOTA_KEY)
            if checked:
                result, at = checked
                if not result.ok:
                    st.error(f"Could not check the DNSDB quota: {result.error}", icon=":material/error:")
                else:
                    rate = result.data or {}
                    st.dataframe(pd.DataFrame([
                        {"Item": "Limit", "Value": str(rate.get("limit", "—"))},
                        {"Item": "Remaining", "Value": str(rate.get("remaining", "—"))},
                        {"Item": "Resets", "Value": _epoch_text(rate.get("reset"))},
                        {"Item": "Key expires", "Value": _epoch_text(rate.get("expires"))},
                        {"Item": "Most results per query", "Value": str(rate.get("results_max", "—"))},
                    ]), hide_index=True, width="stretch")
                    st.caption(f"Checked {at:%Y-%m-%d %H:%M UTC}.")
    with c2:
        st.markdown("**VPNDB**")
        quota = last_quota()
        if not load_vpndb_key():
            st.caption("No VPNDB key (Settings → API credentials).")
        elif not quota:
            st.caption("Only VPNDB demo accounts have a quota; VPNDB reports it with each answer, so it shows here "
                       "after the next VPNDB lookup that reaches the API (lookups answered from the lookup cache do "
                       f"not). The only limit of a customer account is {VPNDB_RATE_LIMIT}.")
        elif quota.get("no_quota"):
            st.success("No quota: this is a customer account (only demo accounts have one).",
                       icon=":material/all_inclusive:")
            st.caption(f"The only limit is {VPNDB_RATE_LIMIT}; beyond it VPNDB answers HTTP 429 and asks to wait "
                       f"60 s. As of the last VPNDB answer, "
                       f"{pd.Timestamp(quota['at'], unit='s', tz='UTC'):%Y-%m-%d %H:%M UTC}.")
        else:
            labels = {"remaining": "Remaining", "remaining_day": "Remaining today", "remaining_lists": "Lists left",
                      "notice": "Notice"}
            st.dataframe(pd.DataFrame([{"Item": labels.get(k, k), "Value": str(v)} for k, v in quota.items()
                                       if k != "at"]), hide_index=True, width="stretch")
            st.caption(f"As of the last VPNDB answer, {pd.Timestamp(quota['at'], unit='s', tz='UTC'):%Y-%m-%d %H:%M UTC}.")


COLUMN_CONFIG = {
    "Used by this app": st.column_config.CheckboxColumn("App", help="Lookups of this app count against it"),
    "Used for": st.column_config.TextColumn(help="What in this app queries it"),
    "Today": st.column_config.NumberColumn(format="localized", help="Queries today"),
    "This month": st.column_config.NumberColumn(format="localized", help="Queries this month"),
    "Monthly limit": st.column_config.NumberColumn(format="localized", help="Empty: no monthly limit (hour or minute limits only)"),
    "Left this month": st.column_config.NumberColumn("Left", format="localized", help="Monthly limit minus this month's queries"),
    "Used %": st.column_config.ProgressColumn("Used", min_value=0, max_value=100, format="%.1f%%",
                                              help="Share of the monthly limit used"),
    "Per hour": st.column_config.NumberColumn(format="localized", help="Rate limit per hour; empty when none"),
    "Per minute": st.column_config.NumberColumn(format="localized", help="Rate limit per minute; empty when none"),
    "Expires": st.column_config.TextColumn(help="Empty: no expiration date"),
    "ID": st.column_config.TextColumn(help="Product ID in the API response"),
}


def _render_app_products(frame):
    app = frame[frame["Used by this app"]].copy()
    if app.empty:
        return
    st.subheader("Products this app uses", help="The products the app's lookups count against. Lookups served from "
                                                 "the lookup cache cost no query.")
    app["Used for"] = app["ID"].map(APP_PRODUCTS)
    st.dataframe(app[["Product", "Left this month", "Used %", "This month", "Monthly limit", "Today", "Per minute",
                      "Used for"]], hide_index=True, width="stretch", column_config=COLUMN_CONFIG)


def render_account_page():
    st.header("Account", help="The DomainTools account of the configured API credentials (Settings → API "
                              "credentials) and its products' limits and usage, from the Account Information API. "
                              "Usage is counted by DomainTools for all clients of this account, not only this app.")
    result, fetched = _load()
    with st.container(horizontal=True, vertical_alignment="center"):
        st.caption(f"Fetched {fetched:%Y-%m-%d %H:%M:%S %Z}. Kept for an hour and shared with Analyze "
                   "and the Data sources page; each refresh is one Account Information query.")
        if st.button("Refresh", icon=":material/refresh:", key="account_refresh"):
            st.session_state[REFRESH_KEY] = True
            st.rerun()
    if not result.ok:
        st.error(f"Could not fetch the account information: {result.error}", icon=":material/error:")
        _render_other_quotas()
        return

    account, products = account_parts(result.data)
    frame = products_frame(products)
    active = account.get("active")
    status = "active" if active else ("inactive" if active is False else "status unknown")
    expiry = nearest_expiry(products)
    st.markdown(f"**{account.get('api_username') or '—'}** · {status} · {len(products):,} products"
                + (f" · earliest expiry {expiry}" if expiry else "")
                + (f" · label: {account['label']}" if account.get("label") else ""))
    if active is False:
        st.error("The account is not active: lookups will fail.", icon=":material/block:")
    render_quota_banners(link=False)
    st.caption(f":material/info: {QUOTA_HELP}")

    _render_app_products(frame)
    missing = missing_app_products(products)
    if missing:
        st.warning("**Not in this account**, so these lookups will fail or be skipped:\n"
                   + "\n".join(f"- **{feature}**: {effect}" for feature, effect in missing)
                   + "\n\nTurn the matching collection options off on *Settings → Collection options*, or ask "
                     "your DomainTools account team about adding the product.", icon=":material/info:")
    near = frame[(frame["Used %"].fillna(0) >= 80) & ~frame["Used by this app"]]   # the app's own: banners above
    if not near.empty:
        st.warning("Other products of the account over 80% of the monthly limit: " + ", ".join(
            f"{row['Product']} ({row['Used %']:g}%)" for row in near.to_dict("records")),
            icon=":material/warning:")

    st.subheader("All products")
    if st.session_state.get(FILTER_KEY) not in FILTERS:
        st.session_state[FILTER_KEY] = "all"
    choice = st.segmented_control("Show", FILTERS, key=FILTER_KEY, required=True, format_func=FILTER_LABELS.get)
    shown = frame[frame["This month"].fillna(0) > 0] if choice == "used" else frame
    st.dataframe(shown, hide_index=True, width="stretch", column_config=COLUMN_CONFIG)
    st.caption(f"{len(shown):,} of {len(frame):,} products.")

    _render_other_quotas()

    feeds = endpoints(products)
    if feeds:
        with st.expander("Endpoints of file downloads"):
            for pid, paths in feeds.items():
                st.markdown(f"**{pid}**")
                st.code("\n".join(paths), language=None)
    with st.expander("Raw response"):
        st.code(json.dumps({"response": result.data}, indent=2), language="json")
