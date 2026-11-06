"""
Account page: the DomainTools account behind the configured API credentials, and each product's limits, usage this
month and today, and expiry (Account Information API). Fetched once per session and on Refresh.
"""
import json
from datetime import datetime

import streamlit as st

from core.account import (
    APP_PRODUCTS,
    account_parts,
    endpoints,
    missing_app_products,
    nearest_expiry,
    products_frame,
)
from integrations.account import fetch_account_information

ACCOUNT_KEY = "account_information"   # session: (FetchResult, fetched at)
FILTER_KEY = "account_filter"
FILTERS = ("all", "used")
FILTER_LABELS = {"all": "All products", "used": "Used this month"}


def _load():
    if ACCOUNT_KEY not in st.session_state:
        with st.spinner("Fetching account information..."):
            st.session_state[ACCOUNT_KEY] = (fetch_account_information(), datetime.now().astimezone())
    return st.session_state[ACCOUNT_KEY]


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
        st.caption(f"Fetched {fetched:%Y-%m-%d %H:%M:%S %Z}. Each refresh is one Account Information query.")
        if st.button("Refresh", icon=":material/refresh:", key="account_refresh"):
            st.session_state.pop(ACCOUNT_KEY, None)
            st.rerun()
    if not result.ok:
        st.error(f"Could not fetch the account information: {result.error}", icon=":material/error:")
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

    _render_app_products(frame)
    missing = missing_app_products(products)
    if missing:
        st.warning("**Not in this account**, so these lookups will fail or be skipped:\n"
                   + "\n".join(f"- **{feature}**: {effect}" for feature, effect in missing)
                   + "\n\nTurn the matching collection options off on *Settings → Collection options*, or ask "
                     "your DomainTools account team about adding the product.", icon=":material/info:")
    near = frame[frame["Used %"].fillna(0) >= 80]
    if not near.empty:
        st.warning("Over 80% of the monthly limit used: " + ", ".join(
            f"{row['Product']} ({row['Used %']:g}%)" for row in near.to_dict("records")),
            icon=":material/warning:")

    st.subheader("All products")
    if st.session_state.get(FILTER_KEY) not in FILTERS:
        st.session_state[FILTER_KEY] = "all"
    choice = st.segmented_control("Show", FILTERS, key=FILTER_KEY, required=True, format_func=FILTER_LABELS.get)
    shown = frame[frame["This month"].fillna(0) > 0] if choice == "used" else frame
    st.dataframe(shown, hide_index=True, width="stretch", column_config=COLUMN_CONFIG)
    st.caption(f"{len(shown):,} of {len(frame):,} products.")

    feeds = endpoints(products)
    if feeds:
        with st.expander("Endpoints of file downloads"):
            for pid, paths in feeds.items():
                st.markdown(f"**{pid}**")
                st.code("\n".join(paths), language=None)
    with st.expander("Raw response"):
        st.code(json.dumps({"response": result.data}, indent=2), language="json")
