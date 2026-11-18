"""
Registration and DNS lifecycle rules: re-registered (drop-caught) domains, throwaway registrant mail, name server
churn and a registrar transfer followed by new name servers. They read the Iris Investigate profile and the Domain
History / passive DNS events the run already has (no extra lookups).
"""
import pandas as pd

from core.helpers import registrable_domain
from core.intel_data import DISPOSABLE_EMAIL_DOMAINS
from core.network_intel import is_large_dns_provider, is_parking_ns, record_types
from core.threat_detection.context import evidence_record, fmt_ts

REREGISTERED_GAP_DAYS = 365      # Iris saw the name this long before its current registration: an earlier owner
CERT_BEFORE_CREATE_DAYS = 30     # a certificate this much older than the registration belongs to an earlier owner
NS_CHURN_WINDOW = pd.Timedelta(days=30)
NS_CHURN_PROVIDERS = 3           # distinct name server providers within the window
TRANSFER_NS_DAYS = 14            # new name servers this soon after a registrar change
NS_FIELDS = {"NS", "NAME_SERVER"}


def rule_reregistered(ctx):
    """The domain existed before its current registration: drop-caught or re-registered after it lapsed."""
    created = ctx.profile.get("create_date")
    if ctx.is_ip or created is None or pd.isna(created):
        return
    reasons, evidence = [], []
    first_seen = ctx.profile.get("first_seen")
    if first_seen is not None and pd.notna(first_seen) and (created - first_seen).days > REREGISTERED_GAP_DAYS:
        reasons.append(f"Iris first saw it {fmt_ts(first_seen, '%Y-%m-%d')}, {(created - first_seen).days:,} days "
                       f"before the current registration ({fmt_ts(created, '%Y-%m-%d')})")
        evidence.append(evidence_record(first_seen, "First Seen (Iris)", ctx.domain))
    if not ctx.ssl.empty and "Not Before Date" in ctx.ssl.columns:
        issued = pd.to_datetime(ctx.ssl["Not Before Date"], errors="coerce").dropna()
        older = issued[issued < created - pd.Timedelta(days=CERT_BEFORE_CREATE_DAYS)]
        if not older.empty:
            reasons.append(f"{len(older)} certificate(s) issued before the registration, the oldest "
                           f"{fmt_ts(older.min(), '%Y-%m-%d')}: an earlier owner's")
            evidence.append(evidence_record(older.min(), "Certificate before registration", ctx.domain))
    if reasons:
        ctx.add(
            "Re-Registered Domain", "Medium", "T1583.001 (Acquire Infrastructure: Domains)",
            "The domain had an earlier life before its current registration: " + "; ".join(reasons) + ". Lapsed "
            "domains are bought for their history and reputation.",
            f"Created: {fmt_ts(created, '%Y-%m-%d')}\nRegistrar: {ctx.profile.get('registrar') or 'N/A'}",
            flag="reregistered", evidence=evidence,
        )


def rule_disposable_registrant(ctx):
    """The registration's email domains include a throwaway mail service."""
    throwaway = sorted({d for d in ctx.profile.get("email_domains", []) if d in DISPOSABLE_EMAIL_DOMAINS})
    if throwaway:
        ctx.add(
            "Disposable Registrant Email", "Medium", "T1585.002 (Establish Accounts: Email Accounts)",
            f"The registration uses a throwaway mail service ({', '.join(throwaway)}): nobody can be reached there "
            "for abuse reports.",
            f"Email domains: {', '.join(ctx.profile.get('email_domains', []))}",
            flag="disposable_email",
        )


def _ns_rows(ctx):
    ev = ctx.events
    if ev.empty:
        return ev
    rows = ev[record_types(ev).isin(NS_FIELDS)].copy()
    rows["Provider"] = rows["Value"].astype(str).map(_providers)
    return rows.explode("Provider").dropna(subset=["Provider"]).sort_values("Date", kind="stable")


def _providers(value):
    hosts = [h.strip().lower().rstrip(".") for h in str(value).replace(",", "\n").split("\n") if h.strip()]
    providers = sorted({registrable_domain(h) or h for h in hosts if h and h not in ("-", "none")})
    return providers or None


def rule_ns_churn(ctx):
    """Several different name server providers within 30 days: the domain keeps moving its DNS."""
    rows = _ns_rows(ctx)
    if rows.empty:
        return
    dates, providers = rows["Date"].tolist(), rows["Provider"].tolist()
    parking = {p: is_parking_ns(p) for p in set(providers)}
    counts, end = {}, 0   # non-parking providers of rows [i, end): the rows within 30 days of row i (dates sorted)
    for i, start in enumerate(dates):
        while end < len(dates) and dates[end] <= start + NS_CHURN_WINDOW:
            if not parking[providers[end]]:
                counts[providers[end]] = counts.get(providers[end], 0) + 1
            end += 1
        if i and not parking[providers[i - 1]]:
            counts[providers[i - 1]] -= 1
            if not counts[providers[i - 1]]:
                del counts[providers[i - 1]]
        window = set(counts)
        if len(window) >= NS_CHURN_PROVIDERS:
            ctx.add(
                "Name Server Churn", "Medium", "T1584.002 (Compromise Infrastructure: DNS Server)",
                f"{len(window)} name server providers within 30 days from {fmt_ts(start, '%Y-%m-%d')}: domains used "
                "for abuse move DNS to stay ahead of takedowns.",
                f"Providers: {', '.join(sorted(window))}",
                flag="ns_churn",
                evidence=[evidence_record(d, "NS", p) for d, p in zip(dates[i:], providers[i:])
                          if d <= start + NS_CHURN_WINDOW][:25],
            )
            return


def rule_transfer_then_ns(ctx):
    """A registrar change followed within two weeks by new, non-mainstream name servers: hijack or drop-catch."""
    ev = ctx.events
    if ev.empty:
        return
    fields = record_types(ev)
    transfers = ev[fields.str.contains("REGISTRAR", na=False)]
    if transfers.empty:
        return
    ns = _ns_rows(ctx)
    for _, change in transfers.iterrows():
        after = ns[(ns["Date"] > change["Date"]) & (ns["Date"] <= change["Date"] + pd.Timedelta(days=TRANSFER_NS_DAYS))]
        after = after[~after["Provider"].map(lambda p: is_large_dns_provider(p) or is_parking_ns(p))]
        if not after.empty:
            first = after.iloc[0]
            ctx.add(
                "Registrar Transfer then New Name Servers", "Medium-High", "T1584.001 (Compromise Infrastructure: Domains)",
                f"Registrar changed {fmt_ts(change['Date'], '%Y-%m-%d')} and the name servers moved to "
                f"{first['Provider']} {(first['Date'] - change['Date']).days} day(s) later: typical of a hijacked or "
                "drop-caught domain being put to new use.",
                f"Registrar change: {str(change.get('Value'))[:120]}\nNew name servers: {first['Provider']} "
                f"({fmt_ts(first['Date'], '%Y-%m-%d')})",
                flag="transfer_ns",
                evidence=[evidence_record(change["Date"], "Registrar", str(change.get("Value"))[:120]),
                          evidence_record(first["Date"], "NS", first["Provider"])],
            )
            return


LIFECYCLE_RULES = (rule_reregistered, rule_disposable_registrant, rule_ns_churn, rule_transfer_then_ns)
