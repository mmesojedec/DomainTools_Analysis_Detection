"""
Use cases on the Start page: what an analyst wants to do, the collection options and analysis window that suit it, and
the pages to work through afterwards. Applying one only changes settings in session state; Analyze then runs it.

Every use case is a full set of collection options: the global defaults (COLLECTION_DEFAULTS) with the use case's own
changes on top. The analyst can change a built-in use case's options on the Settings page (saved until reset) and save
custom profiles of their own; both are kept in dt_settings.json.
"""
import re
from dataclasses import dataclass, field

import pandas as pd

from config import (
    CAA_SUPPLEMENT_FETCH_LIMIT,
    CERT_CTL_LIMIT,
    CERT_EVENTS_MAX_RECORDS,
    CERT_SEARCH_MAX_RECORDS,
    CIDR_ADDRESSES_PER_RANGE,
    CIDR_MAX_RANGES,
    CNAME_SUPPLEMENT_FETCH_LIMIT,
    CT_LOOKUP_DEFAULT_MAX_HASHES,
    DNSDB_DEFAULT_LIMIT,
    DOMAIN_HISTORY_MAX_CHANGES,
    DOMAIN_HISTORY_SAFETY_LIMIT,
    IP_CHECK_MAX_IPS,
    IRIS_INVESTIGATE_BATCH_SIZE,
    MONITOR_HISTORY_DAYS,
    PIVOT_DEFAULT_MAX_IPS,
    PIVOT_IP_RECORD_LIMIT,
    SEED_DEFAULT_TARGETS,
    TXT_SUPPLEMENT_DEFAULT_RECORDS,
    TXT_SUPPLEMENT_FETCH_LIMIT,
    VPNDB_ASN_MAX,
    VPNDB_DETAIL_MAX,
    VPNDB_MAX_IPS,
    VPNDB_NEIGHBOUR_MAX,
    VPNDB_REVERSE_MAX,
)
from core.window import CUSTOM_RANGE, DEFAULT_WINDOW, WINDOW_PRESETS

# Collection options (session state key -> global default), edited on Settings → Collection options
COLLECTION_DEFAULTS = {
    "opt_dnsdb_limit": DNSDB_DEFAULT_LIMIT,
    "opt_txt": True,
    "opt_txt_records": TXT_SUPPLEMENT_DEFAULT_RECORDS,
    "opt_caa": True,
    "opt_cname": True,
    "opt_pivot": False,
    "opt_pivot_max": PIVOT_DEFAULT_MAX_IPS,
    "opt_pdns_incremental": False,          # DNSDB: only records seen since the last offline copy of the targets
    "opt_history_mode": "all",              # Domain History period: HISTORY_MODES
    "opt_history_days": 365,                # Domain History: changes of the last N days (mode "days")
    "opt_history_max": DOMAIN_HISTORY_MAX_CHANGES,   # Domain History: cap of changes per domain (not in mode "unlimited")
    "opt_vpndb": True,
    "opt_vpndb_max_ips": VPNDB_MAX_IPS,     # hosting IPs in the bulk request (one VPNDB query each)
    "opt_vpndb_details": VPNDB_DETAIL_MAX,  # full verdicts and weekly histories of the exits (one query each)
    "opt_vpndb_context": True,              # neighbouring /24s, hosting networks, other domains on dedicated exits
    "opt_vpndb_only": False,
    "opt_ct": True,
    "opt_ct_max": CT_LOOKUP_DEFAULT_MAX_HASHES,
    "opt_seed_preselect": SEED_DEFAULT_TARGETS,
    "opt_force_refresh": False,
}
WINDOW_KEY = "analysis_window"
OPTION_LABELS = {
    "opt_dnsdb_limit": "DNSDB result limit per domain",
    "opt_txt": "TXT lookup", "opt_txt_records": "Latest TXT records per domain",
    "opt_caa": "CAA lookup", "opt_cname": "CNAME lookup",
    "opt_pivot": "Pivot on hosting IPs", "opt_pivot_max": "Max IPs to pivot on",
    "opt_pdns_incremental": "Incremental passive DNS", "opt_history_mode": "Domain History period",
    "opt_history_days": "Domain History period (days)", "opt_history_max": "Domain History changes per domain",
    "opt_vpndb": "VPN / proxy / Tor check (VPNDB)", "opt_vpndb_only": "Only the VPNDB IP check",
    "opt_vpndb_max_ips": "VPNDB: hosting IPs per run", "opt_vpndb_details": "VPNDB: full verdicts per run",
    "opt_vpndb_context": "VPNDB: neighbourhood and leads",
    "opt_ct": "CT log & co-occurrence telemetry", "opt_ct_max": "Max certificates for CT lookups",
    "opt_seed_preselect": "Certificate inputs: pre-selected targets", "opt_force_refresh": "Force refresh",
    WINDOW_KEY: "Analysis window",
}
# what a use case or profile sets: every collection option except the one-off Force refresh, and the analysis window
PROFILE_KEYS = (*(key for key in COLLECTION_DEFAULTS if key != "opt_force_refresh"), WINDOW_KEY)
GLOBAL_DEFAULTS = {**{key: COLLECTION_DEFAULTS[key] for key in PROFILE_KEYS if key != WINDOW_KEY},
                   WINDOW_KEY: DEFAULT_WINDOW}
PROFILE_WINDOWS = [name for name in WINDOW_PRESETS if name != CUSTOM_RANGE]
CUSTOM_PREFIX = "custom:"
# dt_settings.json keys
OVERRIDES_SETTING = "use_case_overrides"   # {use case key: {option: value}} changed on Settings → Use cases
PROFILES_SETTING = "custom_profiles"       # [{"name", "description", "settings"}]


@dataclass(frozen=True)
class UseCase:
    key: str
    title: str
    icon: str
    summary: str
    settings: dict = field(default_factory=dict)   # changes to the global defaults (option key -> value)
    steps: tuple = ()                              # (page key, what to do there)
    custom: bool = False                           # a profile the analyst saved


# VPNDB in every use case, with a budget that suits it (each hosting IP, full verdict and lookup is one VPNDB query)
VPNDB_FULL = {"opt_vpndb": True, "opt_vpndb_max_ips": VPNDB_MAX_IPS, "opt_vpndb_details": VPNDB_DETAIL_MAX,
              "opt_vpndb_context": True}    # infrastructure, C2, reporting: everything
VPNDB_QUICK = {"opt_vpndb": True, "opt_vpndb_max_ips": 100, "opt_vpndb_details": 20,
               "opt_vpndb_context": True}   # triage: one or a few domains, but the full picture
VPNDB_LIGHT = {"opt_vpndb": True, "opt_vpndb_max_ips": 200, "opt_vpndb_details": 20,
               "opt_vpndb_context": False}  # takeover, phishing, monitoring: the verdicts, no neighbourhood


USE_CASES = (
    UseCase("triage", "Triage a suspicious domain", ":material/policy:",
            "Is this domain malicious or risky? Risk score, the alerts that matter, and the domain's full profile.",
            {"opt_pivot": False, **VPNDB_QUICK, WINDOW_KEY: "Last 30 days"},
            (("summary", "Read the summary and what to check next"),
             ("profile", "Open the riskiest domain's profile"),
             ("alerts", "Review its alerts and the evidence behind them"))),
    UseCase("infrastructure", "Map related infrastructure", ":material/hub:",
            "Who else runs on the same hosting? Shared IPs, name servers, certificates and CNAME targets across domains.",
            {"opt_caa": False, "opt_pivot": True, **VPNDB_FULL, WINDOW_KEY: "All time"},
            (("dns", "Compare hosting, name servers and shared infrastructure (DIF)"),
             ("pivots", "Rank the pivots that tie domains together"),
             ("cname", "Chase CNAMEs, check cross-domain links and reverse CNAME"),
             ("certs", "Look for shared certificates"))),
    UseCase("c2", "Hunt C2 infrastructure", ":material/radar:",
            "Command-and-control servers and the infrastructure behind them: self-signed and default certificates, "
            "rare shared values, and domains hopping across the same IPs.",
            {"opt_pivot": True, "opt_ct": True, **VPNDB_FULL, WINDOW_KEY: "Last 90 days"},
            (("certs", "Check the Self-Signed tab for C2 defaults and certificates served live"),
             ("pivots", "Rank the pivots: certificate hashes, IPs and name servers few domains share"),
             ("dns", "Look for domain hopping on shared IPs and watchlisted hosting"),
             ("alerts", "Mark each alert Malicious or Benign"))),
    UseCase("takeover", "Subdomain takeover check", ":material/link_off:",
            "Which subdomains still point to deleted cloud resources or unverified services?",
            {"opt_txt": False, "opt_caa": False, "opt_pivot": False, **VPNDB_LIGHT, "opt_vpndb_max_ips": 100,
             "opt_vpndb_details": 10, WINDOW_KEY: "All time"},
            (("cname", "Chase the CNAMEs, then filter Dead end and Takeover-prone"),
             ("hostnames", "Check the hostnames that never resolved"),
             ("alerts", "Review Dangling CNAME alerts"))),
    UseCase("phishing", "Phishing & lookalikes", ":material/phishing:",
            "Brand lookalikes, suspicious subdomains and freshly issued certificates. Add your brands on Settings → "
            "Brand watchlist.",
            {"opt_ct_max": 100, "opt_pivot": False, **VPNDB_LIGHT, WINDOW_KEY: "Last 30 days"},
            (("certs", "Review new certificates and their names"),
             ("triage", "Sort subdomains by phishing signals"),
             ("alerts", "Check lookalike and email alerts"))),
    UseCase("monitor", "Monitor changes", ":material/monitoring:",
            "What changed since the last run? New alerts, new infrastructure, resolved findings. Save an offline copy "
            "of each run: the next one then looks up only new passive DNS records.",
            {**VPNDB_LIGHT, "opt_pdns_incremental": True, "opt_history_mode": "days",
             "opt_history_days": MONITOR_HISTORY_DAYS,
             WINDOW_KEY: "Last 30 days"},
            (("summary", "See new and resolved alerts since the last run"),
             ("history", "Compare runs over time"),
             ("alerts", "Review what is new"))),
    UseCase("ipcheck", "Check IP addresses (VPN, proxy, Tor)", ":material/vpn_lock:",
            "Who is behind an IPv4 or IPv6 address or a CIDR range: VPN, residential proxy, Tor or hosting, with "
            "provider, confidence and evidence. Only VPNDB is queried: enter IP addresses or ranges as targets.",
            {"opt_vpndb_only": True, "opt_vpndb": True, "opt_vpndb_details": IP_CHECK_MAX_IPS, WINDOW_KEY: "All time"},
            (("summary", "Read each IP's verdict, provider and evidence"),
             ("export", "Download the verdicts (Data Export → VPN / proxy / Tor)"))),
    UseCase("export", "Report & export evidence", ":material/description:",
            "Hand findings over: alert evidence, tables and the queries to reproduce every lookup.",
            {**VPNDB_FULL, WINDOW_KEY: "Last 30 days"},
            (("alerts", "Pick the alerts to report"),
             ("export", "Download the tables and evidence"),
             ("queries", "Copy the queries that reproduce each lookup"))),
)
BY_KEY = {case.key: case for case in USE_CASES}


def clean_settings(settings):
    """Only the options a profile may set, with values of the default's type (stale or hand-edited entries dropped)."""
    clean = {}
    for key, value in (settings or {}).items():
        if key not in PROFILE_KEYS:
            continue
        default = GLOBAL_DEFAULTS[key]
        if key == WINDOW_KEY:
            if value in PROFILE_WINDOWS:
                clean[key] = value
        elif isinstance(default, bool):
            clean[key] = bool(value)
        elif isinstance(default, int):
            try:
                clean[key] = int(value)
            except (TypeError, ValueError):
                continue
        elif isinstance(value, type(default)):
            clean[key] = value
    return clean


def builtin_settings(case):
    """A use case's options before the analyst changed anything: the global defaults plus its own changes."""
    return {**GLOBAL_DEFAULTS, **case.settings}


def effective_settings(case, overrides=None):
    """The options a use case applies now: its built-in options plus what the analyst saved on Settings → Use cases."""
    if case.custom:
        return {**GLOBAL_DEFAULTS, **clean_settings(case.settings)}
    return {**builtin_settings(case), **clean_settings((overrides or {}).get(case.key))}


def is_customized(case, overrides=None):
    return not case.custom and effective_settings(case, overrides) != builtin_settings(case)


def profile_key(name):
    return CUSTOM_PREFIX + (re.sub(r"[^a-z0-9]+", "-", str(name).strip().lower()).strip("-") or "profile")


def custom_cases(profiles):
    """UseCase entries of the analyst's saved profiles ([{"name", "description", "settings"}])."""
    cases, seen = [], set()
    for profile in profiles or []:
        name = str(profile.get("name", "")).strip()
        key = profile_key(name)
        if not name or key in seen:
            continue
        seen.add(key)
        cases.append(UseCase(key, name, ":material/tune:", str(profile.get("description", "")).strip(),
                             clean_settings(profile.get("settings")), custom=True))
    return cases


def all_cases(profiles=None):
    return [*USE_CASES, *custom_cases(profiles)]


def find_case(key, profiles=None):
    return next((case for case in all_cases(profiles) if case.key == key), None)


def upsert_profile(profiles, name, description, settings):
    """Profiles with `name` added or replaced (same key); returns the new list."""
    key = profile_key(name)
    kept = [p for p in profiles or [] if profile_key(p.get("name", "")) != key]
    return [*kept, {"name": str(name).strip(), "description": str(description or "").strip(),
                    "settings": clean_settings(settings)}]


def remove_profile(profiles, key):
    return [p for p in profiles or [] if profile_key(p.get("name", "")) != key]


HISTORY_MODES = {"all": "Latest changes, up to Max changes (default)",
                 "window": "Analysis window, up to Max changes",
                 "days": "Custom number of days, up to Max changes",
                 "unlimited": "All time, no limit"}


def history_period_days(mode, days, window=None, window_start=None, today=None):
    """
    Days of Domain History changes a run fetches (0: no period, the newest changes): `days` in mode "days"; in mode
    "window" the analysis window's (`window` a preset name; a custom range uses `window_start`, its first day), none
    for *All time*.
    """
    if mode == "days":
        return max(0, int(days or 0))
    if mode != "window":
        return 0
    if WINDOW_PRESETS.get(window):
        return int(WINDOW_PRESETS[window])
    if window == CUSTOM_RANGE and window_start is not None:
        today = pd.Timestamp.now(tz="UTC").date() if today is None else pd.Timestamp(today).date()
        return max(1, (today - pd.Timestamp(window_start).date()).days + 1)
    return 0


def history_cap(mode, cap):
    """Changes fetched per domain at most: `cap` (the default when unset), 0 for "All time, no limit"."""
    if mode == "unlimited":
        return 0
    return max(1, int(cap or DOMAIN_HISTORY_MAX_CHANGES))


def history_limit_text(settings):
    """The Domain History limit of `settings` for the query plan: the period and the cap of changes per domain."""
    mode = settings.get("opt_history_mode", "all")
    if mode == "unlimited":
        return f"All time, no limit (stops at {DOMAIN_HISTORY_SAFETY_LIMIT:,}); slower for long histories"
    cap = history_cap(mode, settings.get("opt_history_max"))
    if mode == "window":
        window = settings.get(WINDOW_KEY)
        days = WINDOW_PRESETS.get(window)
        span = f"{days:,} days" if days else ("all time" if window and window != CUSTOM_RANGE else "")
        return f"Analysis window ({span}), up to {cap:,} changes" if span else f"Analysis window, up to {cap:,} changes"
    if mode == "days" and int(settings.get("opt_history_days") or 0) > 0:
        return f"{int(settings['opt_history_days']):,} days, up to {cap:,} changes"
    return f"{cap:,} changes"


def query_plan(settings):
    """
    What a run with these options looks up for each target domain, and the limit of each lookup:
    [{"Key", "Source", "Lookup", "Limit", "Always"}] (Key: the row's name in integrations.progress; Always: made by
    every run, whatever the options). IP and certificate
    targets use the same sources where they apply.
    """
    s = {**GLOBAL_DEFAULTS, **(settings or {})}
    if s["opt_vpndb_only"]:
        return [{"Key": "vpndb", "Source": "VPNDB", "Lookup": "VPN, residential proxy and Tor verdict of each IP target "
                 "(IPv4 and IPv6) and CIDR range; no other source, domain targets are skipped",
                 "Limit": f"one bulk request, full verdict of up to {int(s['opt_vpndb_details'])} IPs; per CIDR range one "
                          f"prefix query and up to {CIDR_ADDRESSES_PER_RANGE} addresses ({CIDR_MAX_RANGES} ranges)",
                 "Always": True}]
    rows = [
        {"Key": "iris", "Source": "Iris Investigate", "Lookup": "Registration, current hosting, risk score, website and trackers",
         "Limit": f"batches of {IRIS_INVESTIGATE_BATCH_SIZE} domains"},
        {"Key": "history", "Source": "Domain History", "Lookup": "Registration, DNS and certificate changes",
         "Limit": history_limit_text(s)},
        {"Key": "certs", "Source": "Certificate API", "Lookup": "Certificates naming the domain, and certificate events",
         "Limit": f"{CERT_SEARCH_MAX_RECORDS:,} certificates, {CERT_EVENTS_MAX_RECORDS:,} events"},
    ]
    for row in rows:
        row["Always"] = True
    rows.append({"Key": "pdns", "Source": "DNSDB Scout", "Lookup": "Passive DNS of the domain and every subdomain (all types)"
                 + ("; incremental: only records seen since the last offline copy of these targets"
                    if s["opt_pdns_incremental"] else ""),
                 "Limit": f"{int(s['opt_dnsdb_limit']):,} records"})
    capped = " (only when the main lookup hit its limit)"
    if s["opt_txt"]:
        rows.append({"Key": "TXT", "Source": "DNSDB Scout", "Lookup": "TXT records" + capped,
                     "Limit": f"{TXT_SUPPLEMENT_FETCH_LIMIT:,} fetched, latest {int(s['opt_txt_records'])} kept"})
    if s["opt_caa"]:
        rows.append({"Key": "CAA", "Source": "DNSDB Scout", "Lookup": "CAA record of the domain" + capped,
                     "Limit": f"{CAA_SUPPLEMENT_FETCH_LIMIT:,} records"})
    if s["opt_cname"]:
        rows.append({"Key": "CNAME", "Source": "DNSDB Scout", "Lookup": "CNAME records of the domain and subdomains" + capped,
                     "Limit": f"{CNAME_SUPPLEMENT_FETCH_LIMIT:,} records"})
    if s["opt_pivot"]:
        rows.append({"Key": "pivot", "Source": "DNSDB Scout", "Lookup": "Other domains on the current hosting IPs (one lookup per IP)",
                     "Limit": f"{int(s['opt_pivot_max'])} IPs per run, {PIVOT_IP_RECORD_LIMIT:,} records each"})
    if s["opt_vpndb"]:
        context = bool(s["opt_vpndb_context"])
        rows.append({"Key": "vpndb", "Source": "VPNDB", "Lookup": "VPN, residential proxy and Tor verdict of the IPs the "
                     "domains use, and of CIDR targets (only with a VPNDB key); weekly history of each exit"
                     + ("; the /24 around the other hosting addresses, the Iris hosting networks, and the other domains "
                        "on dedicated exits (DNSDB)" if context else ""),
                     "Limit": f"{int(s['opt_vpndb_max_ips'])} IPs per run in one bulk request, full verdict and "
                              f"history of up to {int(s['opt_vpndb_details'])} anonymizer IPs"
                              + (f", {VPNDB_NEIGHBOUR_MAX} ranges, {VPNDB_ASN_MAX} networks, {VPNDB_REVERSE_MAX} DNSDB "
                                 "lookups" if context else "")})
    if s["opt_ct"]:
        rows.append({"Key": "ct", "Source": "Certificate API", "Lookup": "CT log entries and co-occurrence of the newest certificates",
                     "Limit": f"{int(s['opt_ct_max'])} certificates per run, 2 calls each ({CERT_CTL_LIMIT:,} entries)"})
    for row in rows:
        row.setdefault("Always", False)
    return rows


def compare_plan(settings, default):
    """
    query_plan of `settings`, each row with the "Default" limit of the same lookup in `default`'s plan ("off" when
    `default` does not make it). Lookups `default` makes and `settings` does not follow, with the limit "off".
    """
    base = {(row["Source"], row["Lookup"]): (row["Key"], row["Limit"]) for row in query_plan(default)}
    rows = [{**row, "Default": base.pop((row["Source"], row["Lookup"]), (None, "off"))[1]} for row in query_plan(settings)]
    return rows + [{"Key": key, "Source": source, "Lookup": lookup, "Limit": "off", "Always": False, "Default": limit}
                   for (source, lookup), (key, limit) in base.items()]


def plan_lines(settings, default=None):
    """query_plan as short markdown lines; with `default`, a lookup that differs from it notes the default limit."""
    rows = compare_plan(settings, default) if default is not None else query_plan(settings)
    return [f"**{row['Source']}**: {row['Lookup']} — {row['Limit']}"
            + (f" *(default: {row['Default']})*" if row.get("Default", row["Limit"]) != row["Limit"] else "")
            for row in rows]


def changed_options(settings, reference):
    """Option keys whose value in `settings` differs from `reference`."""
    return [key for key in PROFILE_KEYS if settings.get(key) != reference.get(key)]
