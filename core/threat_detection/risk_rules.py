"""
DomainTools risk score rules: what the score's components say together. Proximity (how close the domain is to known
bad infrastructure: shared IPs, name servers, registrant) high while the domain's own threat profile (Malware,
Phishing, Spam) is low means a harmless-looking domain next to bad infrastructure. On an established domain whose
infrastructure changed recently, that is how a hijacked domain looks. They read the risk components and the events the
run already has (no extra lookups).
"""
import ipaddress
import re

import pandas as pd

from core.helpers import registrable_domain
from core.network_intel import cdn_for_ip, record_types
from core.threat_detection.context import evidence_record, fmt_ts, host_keys

THREAT_PROFILE = ("Malware", "Phishing", "Spam")
SHARED_IP_DOMAINS = 1000   # an IP Iris counts this many domains on is shared hosting: bad neighbours are common there
MAX_CHANGES = 15
# record type -> the kind of infrastructure it names
CHANGE_KINDS = {"A": "IP", "AAAA": "IP", "IP": "IP", "NS": "Name servers", "NAME_SERVER": "Name servers",
                "REGISTRAR": "Registrar", "REGISTRANT_NAME": "Registrant", "REGISTRANT_ORG": "Registrant"}
_SPLIT = re.compile(r"[\s,;|]+")


def risk_pattern(components, min_proximity, max_threat):
    """(proximity, {Malware, Phishing, Spam: score}) when Proximity is at least `min_proximity` and every threat
    profile score is known and at most `max_threat`; None otherwise. `components` as integrations.risk names them."""
    proximity = (components or {}).get("Proximity", {}).get("Score")
    threat = {name: (components or {}).get(name, {}).get("Score") for name in THREAT_PROFILE}
    if proximity is None or proximity < min_proximity:
        return None
    if any(score is None or score > max_threat for score in threat.values()):
        return None   # an unknown threat profile is not a low one
    return proximity, threat


def _age(ctx):
    """(days, since): the domain's age from its Iris create date, else its first event; (None, None) unknown."""
    since = ctx.profile.get("create_date")
    if since is None or pd.isna(since):
        since = ctx.events["Date"].min() if not ctx.events.empty else None
    if since is None or pd.isna(since):
        return None, None
    return (ctx.now - pd.Timestamp(since)).days, pd.Timestamp(since)


def _network(ip):
    try:
        address = ipaddress.ip_address(ip)
    except ValueError:
        return None
    return str(ipaddress.ip_network(f"{address}/{24 if address.version == 4 else 48}", strict=False))


def _units(kind, value, ip_intel):
    """What one record names, as comparable units: an IP's network (/24, /48; CDN addresses none), a name server's
    provider (registrable domain), a registrar or registrant as text."""
    parts = [p.strip().lower().rstrip(".") for p in _SPLIT.split(str(value)) if p.strip()] if kind in (
        "IP", "Name servers") else [str(value).strip().lower()]
    if kind == "IP":
        return {(n, p) for p in parts if (n := _network(p)) and not cdn_for_ip(p, ip_intel)}
    if kind == "Name servers":
        return {(registrable_domain(p) or p, p) for p in parts if "." in p and _network(p) is None}
    text = parts[0] if parts else ""
    return {(text, text)} if text and text not in ("-", "none", "nan", "redacted for privacy") else set()


def _blank(value):
    return value is None or (not isinstance(value, (list, dict)) and pd.isna(value)) or not str(value).strip() \
        or str(value).strip().lower() in ("none", "nan")


def recent_changes(ctx, days):
    """
    [(date, kind, value)] infrastructure the domain moved to in the last `days` days: an IP network (not a CDN) or
    name server provider it had not used before, a new registrar or registrant. Only records of the domain itself and
    www count, not other subdomains. A Domain History record compares its Before and After (its first capture, with
    no Before, is not a change); a passive DNS record compares with the earlier records of the same kind in the data.
    """
    ev = ctx.events
    if ev.empty:
        return []
    kinds = record_types(ev).map(CHANGE_KINDS)
    hosts = host_keys(ev, ctx.domain)
    rows = ev.assign(_kind=kinds)[kinds.notna() & hosts.isin({ctx.domain, f"www.{ctx.domain}"})]
    if rows.empty:
        return []
    rows = rows.sort_values("Date", kind="stable")
    cutoff = ctx.now - pd.Timedelta(days=days)
    seen, changes = {}, []
    for _, row in rows.iterrows():
        kind = row["_kind"]
        units = _units(kind, row.get("Value"), ctx.ip_intel)
        known = seen.setdefault(kind, set())
        history = "Change Event" in row.index and not _blank(row.get("Change Event"))
        if row["Date"] >= cutoff and units:
            if history:   # Domain History: a change from its Before value
                before = set() if _blank(row.get("Before")) else {u for u, _ in _units(kind, row["Before"], ctx.ip_intel)}
                new = [label for unit, label in sorted(units) if unit not in before] if before else []
            else:         # passive DNS: a value of a kind seen before, but not this one
                new = [label for unit, label in sorted(units) if unit not in known] if known else []
            if new:
                changes.append((row["Date"], kind, ", ".join(new[:4])))
        known.update(unit for unit, _ in units)
    return changes[:MAX_CHANGES]


def _shared_hosting(ctx):
    """The domain's current IPs when every one is shared by SHARED_IP_DOMAINS or more domains (Iris), else []."""
    ips = [ip for ip in ctx.profile.get("ips", []) if ip.get("ip")]
    if ips and all((ip.get("count") or 0) >= SHARED_IP_DOMAINS for ip in ips):
        return [f"{ip['ip']} ({ip['count']:,} domains)" for ip in ips]
    return []


def rule_risk_neighbourhood(ctx):
    """Proximity high, threat profile low: Possible Domain Hijack on an established domain that recently moved its
    infrastructure, Benign-Looking Domain in Malicious Neighborhood otherwise."""
    if ctx.is_ip:
        return
    t = ctx.thresholds
    found = risk_pattern(ctx.risk_components, t["proximity_min"], t["threat_profile_max"])
    if not found:
        return
    proximity, threat = found
    scores = f"Proximity {proximity:g}; " + ", ".join(f"{name} {score:g}" for name, score in threat.items())
    tags = ctx.risk_components.get("Proximity", {}).get("Evidence") or ""
    age, since = _age(ctx)
    old = age is not None and age >= t["hijack_age_days"]
    changes = recent_changes(ctx, t["hijack_change_days"]) if old else []
    shared = _shared_hosting(ctx)
    created = f"{fmt_ts(since, '%Y-%m-%d')} ({age:,} days ago)" if since is not None else "unknown"
    iocs = [f"Risk scores: {scores}", f"Proximity evidence: {tags or 'none listed'}", f"Created: {created}"]
    iocs += [f"Shared IPs: {', '.join(shared)}"] if shared else []
    evidence = [evidence_record(None, "Proximity score", f"{proximity:g}" + (f" ({tags})" if tags else ""))]
    evidence += [evidence_record(None, f"{name} score", f"{score:g}") for name, score in threat.items()]
    if changes:
        iocs += [f"[{fmt_ts(date)}] {kind} ➔ {value}" for date, kind, value in changes]
        evidence += [evidence_record(date, kind, value, artifact=value.split(", ")[0]) for date, kind, value in changes]
        kinds = sorted({kind for _, kind, _ in changes})
        ctx.add(
            "Possible Domain Hijack", "High", "T1584.001 (Compromise Infrastructure: Domains)",
            f"An established domain (created {created}) whose own threat profile is low ({scores}) moved its "
            f"{', '.join(k.lower() for k in kinds)} in the last {t['hijack_change_days']:g} days and now sits next to "
            "known bad infrastructure: how a hijacked or compromised domain looks. Check whether the owner made "
            "the change." + (" Its IPs are shared hosting, which also explains a high Proximity." if shared else ""),
            "\n".join(iocs), flag="hijack", confidence="Low" if shared else "Medium", evidence=evidence,
        )
        return
    if not old:
        why = (f"It is {age:,} days old, so more likely set up this way than hijacked." if age is not None
               else "Its age is unknown.")
    else:
        why = (f"No move of its IPs, name servers, registrar or registrant was seen in the last "
               f"{t['hijack_change_days']:g} days, so nothing shows a hijack.")
    ctx.add(
        "Benign-Looking Domain in Malicious Neighborhood", "Medium", "T1583.001 (Acquire Infrastructure: Domains)",
        f"Its own threat profile is low but it sits next to known bad infrastructure ({scores}). {why} "
        + ("Its IPs are shared hosting, where bad neighbours are common." if shared else
           "Shared hosting, a new actor domain with a harmless name, or a compromise are the usual reasons."),
        "\n".join(iocs), flag="risk_neighbourhood", confidence="Low" if shared else "Medium", evidence=evidence,
    )


RISK_RULES = (rule_risk_neighbourhood,)
