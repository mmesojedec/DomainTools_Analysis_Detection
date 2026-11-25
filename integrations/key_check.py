"""
Checks that the saved API credentials work, with the cheapest request each service has (never the lookup cache):
- DomainTools API (Iris Investigate, Domain History, Account, and the Certificate API on the same key): one Account
  Information query (it counts against the account-information product, not Iris). It also says which products the
  account has, and the quota and expiry of the ones this app uses.
- DNSDB: the key's rate limit (/dnsdb/v2/rate_limit), which does not count against the quota.
- VPNDB: the Tor overview (/tor): needs the key, not metered.
- BGPDB: one `asn` lookup (BGPDB has no quota); only reachable on the DomainTools network or VPN.
A failed check is a notice, never a block: the app still starts and a service that fails is simply not useful.
"""
from concurrent.futures import ThreadPoolExecutor
from dataclasses import dataclass, field

from core.account import account_alerts, account_parts, dnsdb_alerts, missing_app_products, product_name
from integrations import bgpdb, vpndb
from integrations.account import account_information
from integrations.credentials import (
    BGPDB,
    CERT_API,
    DNSDB,
    DOMAINTOOLS,
    VPNDB,
    load_bgpdb_host,
    load_cert_api_key,
    load_dnsdb_key,
    load_dtapi_credentials,
    load_vpndb_key,
)
from integrations.dnsdb import fetch_dnsdb_rate_limit

OK, WARNING, FAILED, SKIPPED = "ok", "warning", "failed", "skipped"
BGPDB_TEST_ASN = "AS13335"   # any well-known network: the answer only has to come back
CHECKED = (DOMAINTOOLS, DNSDB, CERT_API, VPNDB, BGPDB)


@dataclass
class KeyCheck:
    service: str
    status: str            # OK, WARNING (works, with a notice), FAILED, SKIPPED (no key)
    text: str              # one sentence: what was asked and what came back
    notes: list = field(default_factory=list)   # quota, expiry and missing-product lines
    request: str = ""      # what was sent, for the details
    result: object = None  # the FetchResult (the DNSDB one feeds the quota banner)

    @property
    def works(self):
        return self.status in (OK, WARNING)


def _failed(service, request, error, result=None):
    return KeyCheck(service, FAILED, f"Not working: {error}", request=request, result=result)


def check_domaintools():
    request = "Account Information (GET /v1/account)"
    if not load_dtapi_credentials():
        return KeyCheck(DOMAINTOOLS, SKIPPED, "No username and API key: Iris Investigate, Domain History, IrisQL "
                                              "and the Account page are not queried.", request=request)
    result, _ = account_information(refresh=True)
    if not result.ok:
        return _failed(DOMAINTOOLS, request, result.error, result)
    _, products = account_parts(result.data)
    missing = missing_app_products(products)
    alerts = account_alerts(products)
    notes = [f"No {feature} on the account: {effect} are skipped." for feature, effect in missing]
    notes += [f"{alert['text']}." for alert in alerts]
    used = sorted({product_name(p.get("id")) for p in products})
    status = WARNING if missing or any(a["level"] == "error" for a in alerts) else OK
    return KeyCheck(DOMAINTOOLS, status, f"Works: the account has {len(products)} product(s)"
                    + (f" ({', '.join(used[:6])}{', …' if len(used) > 6 else ''})" if used else "") + ".",
                    notes, request, result)


def check_dnsdb():
    request = "Rate limit (GET /dnsdb/v2/rate_limit, not counted against the quota)"
    if not load_dnsdb_key():
        return KeyCheck(DNSDB, SKIPPED, "No key: passive DNS, CNAME chasing and IP pivots are not queried.",
                        request=request)
    result = fetch_dnsdb_rate_limit()
    if not result.ok:
        return _failed(DNSDB, request, result.error, result)
    rate = result.data or {}
    left, limit = rate.get("remaining"), rate.get("limit")
    quota = (f"{left:,} of {limit:,} queries left" if isinstance(left, int) and isinstance(limit, int)
             else f"quota: {limit}" if limit not in (None, "") else "")
    alerts = dnsdb_alerts(rate)
    return KeyCheck(DNSDB, WARNING if any(a["level"] == "error" for a in alerts) else OK,
                    "Works" + (f": {quota}" if quota else "") + ".", [f"{a['text']}." for a in alerts], request, result)


def check_cert_api():
    if not load_cert_api_key():
        return KeyCheck(CERT_API, SKIPPED, "No key of its own: uses the DomainTools API key (the DomainTools check "
                                           "covers it).")
    if load_dtapi_credentials() and load_cert_api_key() == load_dtapi_credentials()[1]:
        return KeyCheck(CERT_API, SKIPPED, "Same key as the DomainTools API: the DomainTools check covers it.")
    return KeyCheck(CERT_API, SKIPPED, "Has its own key: not tested, since every Certificate API request counts "
                                       "against its quota. A CertsQL search shows whether it works.")


def check_vpndb():
    request = "Tor overview (GET /tor, not metered)"
    if not load_vpndb_key():
        return KeyCheck(VPNDB, SKIPPED, "No key: the VPN, residential proxy and Tor check is not made.",
                        request=request)
    result = vpndb._get("tor", "/tor")   # not the cached tor_overview(): the key itself has to be asked
    if not result.ok:
        return _failed(VPNDB, request, result.error, result)
    notice = vpndb.last_quota().get("notice")
    return KeyCheck(VPNDB, OK, "Works: the Tor overview came back.", [f"Demo account: {notice}."] if notice else [],
                    request, result)


def check_bgpdb():
    request = f"asn/{BGPDB_TEST_ASN}"
    if not load_bgpdb_host():
        return KeyCheck(BGPDB, SKIPPED, "No host (internal DomainTools service, optional): BGP routing is not "
                                        "looked up.", request=request)
    result = bgpdb._query("asn", BGPDB_TEST_ASN)   # not the cached lookup_asn(): the host itself has to answer
    if not result.ok:
        if result.extras.get(bgpdb.UNREACHABLE):
            return _failed(BGPDB, request, f"the host did not answer ({result.error}). BGPDB is only reachable on "
                                           "the DomainTools network or VPN.", result)
        return _failed(BGPDB, request, result.error, result)
    return KeyCheck(BGPDB, OK, f"Works: {request} answered with {result.record_count} record(s).", request=request,
                    result=result)


CHECKS = {DOMAINTOOLS: check_domaintools, DNSDB: check_dnsdb, CERT_API: check_cert_api, VPNDB: check_vpndb,
          BGPDB: check_bgpdb}


def check_keys(services=CHECKED):
    """KeyCheck per service, in `services` order; the services are asked at the same time."""
    with ThreadPoolExecutor(max_workers=len(services) or 1) as pool:
        return list(pool.map(lambda service: CHECKS[service](), services))


def summary(checks):
    """One line for a notification: what works, what failed, what has no key."""
    failed = [c.service for c in checks if c.status == FAILED]
    warned = [c.service for c in checks if c.status == WARNING]
    working = [c.service for c in checks if c.works]
    if failed:
        return f"Not working: {', '.join(failed)}." + (f" Working: {', '.join(working)}." if working else "")
    if warned:
        return f"All keys work; check the notes for {', '.join(warned)}."
    return f"All keys work ({', '.join(working)})." if working else "No API keys to check yet."
