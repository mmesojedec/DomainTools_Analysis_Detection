"""
Quota and expiry banners: red when a product this app uses has used up its monthly quota or expired, yellow from
QUOTA_WARN_PERCENT used or EXPIRY_WARN_DAYS before it expires. Built from what the app already knows (the Account
Information answer kept for an hour, the last DNSDB quota check, VPNDB's last answer): no query is made for them.
"""
import streamlit as st

from config import EXPIRY_WARN_DAYS, QUOTA_WARN_PERCENT
from core.account import account_alerts, dnsdb_alerts
from integrations.account import known_products
from integrations.vpndb import last_quota
from views import navigation
from views.api_usage_view import DNSDB_QUOTA_KEY

HELP = (f"Red: a product this app uses has used up its monthly quota or expired, so its lookups fail. Yellow: "
        f"{QUOTA_WARN_PERCENT}% or more of its quota used, or it expires within {EXPIRY_WARN_DAYS} days. From the last "
        "Account Information answer (refreshed at most hourly, also by each Analyze), the last *Check DNSDB quota* "
        "and VPNDB's last answer; no query is made for these banners.")
TITLES = {"error": "Quota used up or subscription expired", "warning": "Quota or subscription running low"}


def quota_alerts():
    """Every banner line known now: DomainTools products, the DNSDB key, a VPNDB demo account's quota notice."""
    alerts = account_alerts(known_products())
    checked = st.session_state.get(DNSDB_QUOTA_KEY)
    if checked and checked[0].ok:
        alerts += dnsdb_alerts(checked[0].data)
    notice = last_quota().get("notice")
    if notice:
        alerts.append({"level": "warning", "product": "VPNDB", "text": f"VPNDB (demo account): {notice}"})
    return alerts


def render_quota_banners(link=True):
    """One red banner for what is used up or expired, one yellow for what is close; nothing when all is well."""
    alerts = quota_alerts()
    for level, show, icon in (("error", st.error, ":material/block:"), ("warning", st.warning, ":material/warning:")):
        lines = [alert["text"] for alert in alerts if alert["level"] == level]
        if lines:
            show(f"**{TITLES[level]}**  \n" + "  \n".join(f"- {line}" for line in lines), icon=icon)
    if alerts and link:
        navigation.link("account", label="Quota details on the Account page", icon=":material/account_circle:")
