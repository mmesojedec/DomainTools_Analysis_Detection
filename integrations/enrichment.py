"""DomainTools Iris Investigate (SDK) enrichment, web tracker extraction, and active SSL parsing."""
import pandas as pd

from config import IRIS_INVESTIGATE_BATCH_SIZE, IRISQL_DEFAULT_RESULTS, IRISQL_PAGE_SIZE, PIVOT_RESULT_LIMIT
from core.helpers import refang_domain
from integrations.cache import cached_fetch
from integrations.credentials import DTAPI_MISSING, get_dt_api
from integrations.http import FetchResult, describe_exception, sdk_call

SOURCE = "Iris Investigate"

TRACKER_FIELDS = (
    ("ga4", "Google Analytics 4 (GA4)"),
    ("gtm_codes", "Google Tag Manager (GTM)"),
    ("google_analytics", "Google Universal Analytics"),
    ("adsense", "Google AdSense"),
    ("yandex_codes", "Yandex Metrica"),
    ("baidu_codes", "Baidu Analytics"),
    ("hotjar_codes", "Hotjar"),
    ("matomo_codes", "Matomo Analytics"),
    ("fb_codes", "Facebook Pixel"),
    ("statcounter_project_codes", "StatCounter Project"),
    ("statcounter_security_codes", "StatCounter Security"),
)


def unwrap_value(value, default=None):
    """Iris fields are often {"value": x, "count": n}; returns x (or the value itself)."""
    if isinstance(value, dict):
        return value.get("value", default)
    return default if value is None else value


@cached_fetch(group="iris")
def fetch_iris_batch(domains):
    """Runs one Iris Investigate call for up to 100 domains. `domains` is a tuple; data maps domain -> result."""
    label = ", ".join(domains[:3]) + (f" (+{len(domains) - 3} more)" if len(domains) > 3 else "")
    api = get_dt_api()
    if api is None:
        return FetchResult(SOURCE, label, data={}, error=DTAPI_MISSING)
    try:
        response = sdk_call(lambda: api.iris_investigate(domains=list(domains)).response())
    except Exception as exc:
        return FetchResult(SOURCE, label, data={}, error=describe_exception(exc))

    wanted = set(domains)
    found = {}
    for item in (response or {}).get("results", []) or []:
        dom = str(item.get("domain", "")).lower()
        if dom in wanted:
            found[dom] = item
    missing = sorted(wanted - set(found))
    return FetchResult(SOURCE, label, data=found, record_count=len(found),
                       note=f"Not found in Iris: {', '.join(missing)}" if missing else None)


@cached_fetch(group="iris")
def fetch_iris_pivot(param, value, limit=PIVOT_RESULT_LIMIT):
    """
    One Iris Investigate search on a pivot value (e.g. param="email"): data is the list of matching domain records
    (first page, up to `limit`), extras["total"] the number of matching domains in Iris.
    """
    label = f"{param}={value}"
    api = get_dt_api()
    if api is None:
        return FetchResult(SOURCE, label, data=[], error=DTAPI_MISSING)
    try:
        response = sdk_call(lambda: api.iris_investigate(**{param: value}, page_size=limit).response())
    except Exception as exc:
        return FetchResult(SOURCE, label, data=[], error=describe_exception(exc))
    results = list((response or {}).get("results", []) or [])
    total = (response or {}).get("total_count") or len(results)
    return FetchResult(SOURCE, label, data=results, record_count=len(results), truncated=total > len(results),
                       extras={"total": total})


@cached_fetch(group="iris")
def fetch_irisql(query, max_results=IRISQL_DEFAULT_RESULTS, sort_by="", page_size=IRISQL_PAGE_SIZE):
    """
    One IrisQL search (Iris Investigate, the query as the raw POST body): data is the list of matching domain records,
    requested page by page (`position`) until `max_results`; extras: "total" (matching domains in Iris), "pages",
    "message". An error keeps the records of the pages fetched before it.
    """
    label = "IrisQL: " + next((line.strip() for line in query.splitlines()[1:] if line.strip()), query.strip())[:80]
    api = get_dt_api()
    if api is None:
        return FetchResult(SOURCE, label, data=[], error=DTAPI_MISSING)
    results, total, pages, position, message = [], 0, 0, None, None
    while len(results) < max_results:
        params = {"page_size": min(page_size, max_results - len(results))}
        if sort_by:
            params["sort_by"] = sort_by
        if position:
            params["position"] = position
        try:
            response = sdk_call(lambda params=params: api.iris_investigate(irisql=query, **params).response()) or {}
        except Exception as exc:
            return FetchResult(SOURCE, label, data=results, record_count=len(results), error=describe_exception(exc),
                               extras={"total": total, "pages": pages})
        pages += 1
        results.extend(response.get("results", []) or [])
        total = response.get("total_count") or total or len(results)
        message = response.get("message") or message
        position = response.get("position")
        if not response.get("has_more_results") or not position or not response.get("results"):
            break
    return FetchResult(SOURCE, label, data=results, record_count=len(results), truncated=total > len(results),
                       extras={"total": total, "pages": pages, "message": message})


def iris_batches(target_domains):
    clean = list(dict.fromkeys(refang_domain(d) for d in target_domains if d))
    return [tuple(clean[i:i + IRIS_INVESTIGATE_BATCH_SIZE]) for i in range(0, len(clean), IRIS_INVESTIGATE_BATCH_SIZE)]


def _to_naive_ts(value):
    parsed = pd.to_datetime(value, errors="coerce", utc=True)
    return parsed.tz_localize(None) if pd.notna(parsed) else pd.NaT


def extract_iris_profile(result_obj):
    """
    Normalizes the Iris Investigate fields used by intel rules and the domain profile: create/expiration/first-seen
    dates, registrar, IPs with ASN/ISP/country, name servers, redirects, popularity rank, website response, current
    MX hosts, SPF record and the email domains of the registration.
    """
    obj = result_obj if isinstance(result_obj, dict) else {}
    ips = []
    for entry in obj.get("ip", []) or []:
        if not isinstance(entry, dict):
            continue
        address = str(unwrap_value(entry.get("address")) or "").strip()
        if not address:
            continue
        asns = [unwrap_value(a) for a in entry.get("asn", []) or [] if unwrap_value(a) not in (None, "")]
        try:
            asn = int(asns[0]) if asns else None
        except (TypeError, ValueError):
            asn = None
        count = entry.get("address", {}).get("count") if isinstance(entry.get("address"), dict) else None
        ips.append({
            "ip": address,
            "count": count,   # domains on the IP in Iris
            "asn": asn,
            "isp": str(unwrap_value(entry.get("isp")) or "").strip(),
            "country": str(unwrap_value(entry.get("country_code")) or "").strip().upper(),
        })
    name_servers = []
    for entry in obj.get("name_server", []) or []:
        host = unwrap_value(entry.get("host")) if isinstance(entry, dict) else entry
        if host and str(host).strip():
            name_servers.append(str(host).strip().lower().rstrip("."))
    return {
        "create_date": _to_naive_ts(unwrap_value(obj.get("create_date"))),
        "expiration_date": _to_naive_ts(unwrap_value(obj.get("expiration_date"))),
        "first_seen": _to_naive_ts(unwrap_value(obj.get("first_seen"))),
        "registrar": str(unwrap_value(obj.get("registrar")) or "").strip(),
        "ips": ips,
        "name_servers": name_servers,
        "redirect": str(unwrap_value(obj.get("redirect")) or "").strip(),
        "redirect_domain": str(unwrap_value(obj.get("redirect_domain")) or "").strip().lower(),
        "server_type": str(unwrap_value(obj.get("server_type")) or "").strip(),
        "popularity_rank": _positive_int(unwrap_value(obj.get("popularity_rank"))),
        "active": obj.get("active") if isinstance(obj.get("active"), bool) else None,
        "website_response": _positive_int(unwrap_value(obj.get("website_response"))),
        "mx_hosts": _mx_hosts(obj.get("mx")),
        "spf": str(unwrap_value(obj.get("spf_info")) or "").strip(),
        "email_domains": [str(unwrap_value(e)).strip().lower() for e in obj.get("email_domain", []) or []
                          if str(unwrap_value(e) or "").strip()],
    }


def _positive_int(value):
    """An Iris number (popularity rank, HTTP response) as an int; None when missing or 0 (Iris: not ranked)."""
    try:
        number = int(float(value))
    except (TypeError, ValueError):
        return None
    return number if number > 0 else None


def _mx_hosts(entries):
    hosts = []
    for entry in entries or []:
        host = unwrap_value(entry.get("host")) if isinstance(entry, dict) else entry
        if host and str(host).strip():
            hosts.append(str(host).strip().lower().rstrip("."))
    return list(dict.fromkeys(hosts))


def extract_web_trackers(result_obj):
    """Extracts GA4, GTM, Yandex, Baidu, Hotjar, Matomo, Pixel, and StatCounter tracking IDs."""
    trackers = []
    if not isinstance(result_obj, dict):
        return trackers

    def add(platform, value):
        code = str(value).strip() if value is not None else ""
        if code:
            trackers.append({"Platform": platform, "Code": code})

    for field_name, platform in TRACKER_FIELDS:
        field_val = result_obj.get(field_name)
        if isinstance(field_val, list):
            for item in field_val:
                add(platform, unwrap_value(item) if isinstance(item, dict) else item)
        elif isinstance(field_val, (dict, str)):
            add(platform, unwrap_value(field_val))
    return trackers


def extract_ssl_data_from_enrichment(enrichment_map):
    """Parses active ssl_info certificates returned by Iris Investigate."""
    ssl_records = []
    now_utc = pd.Timestamp.now(tz="UTC").tz_localize(None)
    for domain_name, obj in (enrichment_map or {}).items():
        ssl_info = obj.get("ssl_info", []) if isinstance(obj, dict) else []
        if not isinstance(ssl_info, list):
            continue
        for cert in ssl_info:
            if not isinstance(cert, dict):
                continue
            cn = unwrap_value(cert.get("common_name"), "")
            issuer = unwrap_value(cert.get("issuer_common_name"), "")
            cn_clean, issuer_clean = str(cn).strip().lower(), str(issuer).strip().lower()
            alt_names = []
            for alt in cert.get("alt_names", []) or []:
                value = unwrap_value(alt) if isinstance(alt, dict) else alt
                if value and str(value).strip():
                    alt_names.append(str(value).strip())
            ssl_records.append({
                "Domain": domain_name,
                "Timestamp": now_utc.strftime("%Y-%m-%d %H:%M:%S"),
                "Hash": str(unwrap_value(cert.get("hash"), "")),
                "Common Name": str(cn),
                "Issuer": str(issuer),
                "Alt Names List": alt_names,
                "Not Before": str(unwrap_value(cert.get("not_before"), "")),
                "Not After": str(unwrap_value(cert.get("not_after"), "")),
                "Duration": unwrap_value(cert.get("duration")),
                "Is Self Signed": bool(cn_clean) and cn_clean == issuer_clean,
                "Source": SOURCE + " API",
            })

    df = pd.DataFrame(ssl_records)
    if not df.empty:
        df["Date"] = now_utc  # observation time; churn analysis uses Not Before Date instead
        df["Not Before Date"] = pd.to_datetime(df["Not Before"], format="%Y%m%d", errors="coerce")
        df["Not After Date"] = pd.to_datetime(df["Not After"], format="%Y%m%d", errors="coerce")
    return df
