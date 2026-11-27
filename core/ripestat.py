"""
RIPEstat answers in the shape of BGPDB records, so core.bgp turns them into the same tables (origins, networks, AS
paths, more-specific prefixes) and computes the same findings; plus the registration of each address (registry
network object and abuse contact), which BGPDB does not give.

Differences from BGPDB, said where the tables are shown:
- First Seen goes back as far as RIS does (years), not about 30 days: a prefix's age is its real age.
- `Updates` of an origin is the number of periods RIS saw the announcement (routing-history timelines); `Collectors`
  the RIS full-feed peers that saw it last.
- AS paths are RIS's current view (looking-glass): First Seen is the oldest path change among the peers, Last Seen
  the time of the answer.
- More-specific prefixes carry no dates and no registry check.
"""
import ipaddress

import pandas as pd

RIR_NAMES = {"RIPE NCC": "RIPE", "RIPE": "RIPE", "ARIN": "ARIN", "APNIC": "APNIC", "LACNIC": "LACNIC",
             "AFRINIC": "AFRINIC"}
REGISTRATION_COLUMNS = ["IP", "Domains", "Range", "Net Name", "Organisation", "Description", "Type", "Country", "RIR",
                        "Registered", "Abuse Contact"]
ACTIVE_DAYS = 90   # an origin of an address counts when RIS saw it announce the prefix within this many days


def _ts(value):
    stamp = pd.to_datetime(value, errors="coerce", utc=True)
    return stamp.tz_localize(None) if pd.notna(stamp) else pd.NaT


def _number(value):
    return str(value or "").strip().upper().removeprefix("AS")


# ---- routing -----------------------------------------------------------------------------------------------------------

def history_records(data, active_days=ACTIVE_DAYS):
    """
    BGPDB-shaped `ip` records from a routing-history answer: one per (prefix, origin) RIS saw within `active_days` of
    the answer's end, first and last seen over the whole history.
    """
    data = data if isinstance(data, dict) else {}
    end = _ts(data.get("query_endtime"))
    if pd.isna(end):
        end = pd.Timestamp.now(tz="UTC").tz_localize(None)
    records = []
    for origin in data.get("by_origin") or []:
        for prefix in origin.get("prefixes") or []:
            timelines = [t for t in prefix.get("timelines") or [] if isinstance(t, dict)]
            if not timelines:
                continue
            ordered = sorted(timelines, key=lambda t: str(t.get("endtime") or ""))
            first = min(str(t.get("starttime") or "") for t in timelines)
            last = str(ordered[-1].get("endtime") or "")
            if pd.isna(_ts(last)) or _ts(last) < end - pd.Timedelta(days=active_days):
                continue
            records.append({"prefix": prefix.get("prefix", ""), "origin": f"AS{_number(origin.get('origin'))}",
                            "first": first, "last": last, "count": len(timelines),
                            "collectors": int(round(float(ordered[-1].get("full_peers_seeing") or 0)))})
    return records


def add_validity(record, status=None, rpki=None):
    """
    The record with BGPDB's validity flags: RPKI from an rpki-validation answer (valid; invalid_asn / invalid: another
    origin is authorized; invalid_length: the prefix is longer than the ROA allows), IRR from a routing-status answer
    (a route object for this origin: valid; route objects only for other origins: invalid origin).
    """
    record = dict(record)
    state = str((rpki or {}).get("status") or "").lower()
    if state == "valid":
        record["rpki_valid"] = True
    elif state in ("invalid_asn", "invalid"):
        record["rpki_invalid_origin"] = True
    elif state == "invalid_length":
        record["rpki_invalid"] = True
    objects = {_number(o.get("origin")): o.get("route_objects") or [] for o in (status or {}).get("origins") or []
               if isinstance(o, dict)}
    if objects.get(_number(record.get("origin"))):
        record["irr_valid"] = True
    elif any(objects.values()):
        record["irr_invalid_origin"] = True
    return record


def rir_text(rir=None, country=None):
    """BGPDB's RIR line ("RIPE 2003-11-20 NL") from a rir and a rir-stats-country answer, or ""."""
    entries = (rir or {}).get("rirs") or []
    if not entries:
        return ""
    name = RIR_NAMES.get(str(entries[0].get("rir") or "").upper(), str(entries[0].get("rir") or "").split()[0].upper())
    day = str(entries[0].get("first_time") or "")[:10]
    places = [r.get("location") for r in (country or {}).get("located_resources") or [] if r.get("location")]
    return " ".join(part for part in (name, day, places[0] if places else "") if part) if day else ""


def whois_rir_text(whois=None, country=None):
    """
    BGPDB's RIR line ("ARIN 2010-07-14 US") from a whois answer (the RIR holding the resource, the registration date
    of its first object) and a rir-stats-country answer (the country), or "".
    """
    authorities = (whois or {}).get("authorities") or []
    if not authorities:
        return ""
    name = RIR_NAMES.get(str(authorities[0]).upper(), str(authorities[0]).upper())
    day = ""
    records = [_fields(r) for r in (whois or {}).get("records") or []]
    networks = sorted((r for r in records if any(key in r for key in _NETWORK_KEYS)), key=_size)
    for fields in networks + [r for r in records if r not in networks]:   # the most specific network first
        stamp = _ts(_first(fields, "RegDate", "created"))
        if pd.notna(stamp) and stamp.year > 1970:   # RIPE writes 1970-01-01 for objects older than its dates
            day = f"{stamp:%Y-%m-%d}"
            break
    places = [r.get("location") for r in (country or {}).get("located_resources") or [] if r.get("location")]
    return " ".join(part for part in (name, day, places[0] if places else "") if part) if day else ""


def asn_record(asn, overview=None, neighbours=None, whois=None, country=None):
    """A BGPDB-shaped `asn` record: name (as-overview), RIR line (whois), upstream (left) and downstream (right)
    counts (asn-neighbours)."""
    counts = (neighbours or {}).get("neighbour_counts") or {}
    holder = str((overview or {}).get("holder") or "")
    line = whois_rir_text(whois, country)
    return {"asn": f"AS{_number(asn)}", "asname": [holder] if holder else [], "rir_asn": [line] if line else [],
            "hop_upstream": counts.get("left"), "hop_downstream": counts.get("right") or 0}


def _path(text):
    hops = []
    for hop in str(text or "").split():
        hop = hop.strip("{}")
        if hop.isdigit() and (not hops or hops[-1] != f"AS{hop}"):
            hops.append(f"AS{hop}")
    return hops


def route_records(prefix, data):
    """
    BGPDB-shaped `route?hops=2` records from a looking-glass answer: the paths cut to their last two hops (upstream
    and origin), one record per (prefix, upstream, origin) with the route collectors and peers that see it.
    """
    groups = {}
    when = str((data or {}).get("latest_time") or (data or {}).get("query_time") or "")
    for rrc in (data or {}).get("rrcs") or []:
        for peer in rrc.get("peers") or []:
            hops = _path(peer.get("as_path"))
            if not hops:
                continue
            key = (peer.get("prefix") or prefix, tuple(hops[-2:]))
            group = groups.setdefault(key, {"route": key[0], "path": list(key[1]), "collectors": set(), "peers": 0,
                                            "first": None, "last": when})
            group["collectors"].add(rrc.get("rrc"))
            group["peers"] += 1
            changed = str(peer.get("last_updated") or "")
            if changed and (group["first"] is None or changed < group["first"]):
                group["first"] = changed
            group["last"] = max(group["last"] or "", str(peer.get("latest_time") or ""))
    return [{**group, "collectors": len(group["collectors"]), "count": group["peers"]} for group in groups.values()]


def more_specific_records(data):
    """BGPDB-shaped `prefix` records from a routing-status answer's more-specific prefixes (no dates)."""
    records = []
    for entry in (data or {}).get("more_specifics") or []:
        if isinstance(entry, dict):
            records.append({"prefix": entry.get("prefix", ""), "origin": f"AS{_number(entry.get('origin'))}"
                            if entry.get("origin") else ""})
        elif entry:
            records.append({"prefix": str(entry), "origin": ""})
    return records


# ---- registration ------------------------------------------------------------------------------------------------------

_NETWORK_KEYS = ("inetnum", "inet6num", "NetRange")


def _fields(record):
    out = {}
    for entry in record or []:
        if isinstance(entry, dict) and entry.get("key"):
            out.setdefault(entry["key"], []).append(str(entry.get("value") or "").strip())
    return out


def _first(fields, *keys):
    for key in keys:
        for value in fields.get(key) or []:
            if value:
                return value
    return ""


def _size(fields):
    """Addresses in a network object (to pick the most specific), or infinity when it cannot be read."""
    text = _first(fields, "CIDR", "inetnum", "inet6num", "NetRange").split(",")[0].strip()
    try:
        if "/" in text:
            return ipaddress.ip_network(text, strict=False).num_addresses
        low, _, high = text.partition("-")
        return int(ipaddress.ip_address(high.strip())) - int(ipaddress.ip_address(low.strip())) + 1
    except ValueError:
        return float("inf")


def registration_row(ip, domains, whois=None, abuse=None):
    """
    A REGISTRATION_COLUMNS row from a whois and an abuse-contact-finder answer: the most specific network object of
    the address in its RIR's database (net name, organisation, description, type, country, registration date) and
    the abuse contacts. Personal details in the answer (people, phones, addresses) are not taken.
    """
    records = [_fields(r) for r in (whois or {}).get("records") or []]
    networks = [r for r in records if any(key in r for key in _NETWORK_KEYS)]
    network = min(networks, key=_size) if networks else {}
    org_record = next((r for r in records if "OrgName" in r or "org-name" in r), {})
    authorities = (whois or {}).get("authorities") or []
    rir = RIR_NAMES.get(str(authorities[0]).upper(), str(authorities[0]).upper()) if authorities else ""
    return {"IP": ip, "Domains": ", ".join(sorted(domains)),
            "Range": _first(network, "CIDR", "inetnum", "inet6num", "NetRange"),
            "Net Name": _first(network, "netname", "NetName"),
            "Organisation": _first(network, "Organization", "org-name") or _first(org_record, "OrgName", "org-name")
            or _first(network, "org"),
            "Description": _first(network, "descr"),
            "Type": _first(network, "status", "NetType"),
            "Country": _first(network, "country", "Country") or _first(org_record, "Country", "country"),
            "RIR": rir,
            "Registered": _ts(_first(network, "created", "RegDate")),
            "Abuse Contact": ", ".join((abuse or {}).get("abuse_contacts") or [])}


def registration_frame(rows):
    return pd.DataFrame(rows, columns=REGISTRATION_COLUMNS)
