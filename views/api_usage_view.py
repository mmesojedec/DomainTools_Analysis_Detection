"""
API usage helpers: what each service has left (known without a query) and the products a run skips because the
account does not have them.
"""
import pandas as pd
import streamlit as st

from core.account import STAGE_NAMES, STAGE_PRODUCTS, unavailable_stages
from core.api_usage import DNSDB, VPNDB
from integrations.vpndb import last_quota

DNSDB_QUOTA_KEY = "dnsdb_quota"   # session: (FetchResult of the DNSDB rate limit, fetched at)


def service_quotas():
    """{service: what is left} known without a query: DNSDB from its last rate-limit check, VPNDB from its last answer."""
    quotas = {}
    dnsdb = st.session_state.get(DNSDB_QUOTA_KEY)
    if dnsdb and dnsdb[0].ok:
        left = (dnsdb[0].data or {}).get("remaining")
        if isinstance(left, int):
            quotas[DNSDB] = left
    vpndb = last_quota()
    for key in ("remaining_day", "remaining"):
        try:
            quotas[VPNDB] = int(vpndb[key])
            break
        except (KeyError, TypeError, ValueError):
            continue
    return quotas


def missing_stage_lines(products):
    return [f"**{STAGE_NAMES[stage]}** ({' or '.join(STAGE_PRODUCTS[stage])})" for stage in sorted(unavailable_stages(products))]


def skipped_products_note(products):
    """A line for the Analyze status when stages are skipped because the account lacks their product, else ''."""
    missing = missing_stage_lines(products)
    return ("Skipped, not in this DomainTools account: " + ", ".join(missing)) if missing else ""


def quota_age(at):
    return pd.Timestamp(at, unit="s", tz="UTC").strftime("%Y-%m-%d %H:%M UTC") if at else ""

