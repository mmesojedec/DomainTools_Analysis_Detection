"""IP profile: the addresses of a run and what each source has on one of them, from the loaded data (no request)."""
from types import SimpleNamespace

import pandas as pd

from core import ip_profile as ipp

SEEN = pd.Timestamp("2026-11-01")


def dataset():
    events = pd.DataFrame({
        "Domain": ["evil.com", "evil.com", "104.21.59.0/24", "93.184.215.14"],
        "RRName": ["evil.com.", "www.evil.com.", "x.other.net.", "y.third.org."],
        "Field": ["A", "A", "A", "A"], "Value": ["93.184.215.14", "93.184.215.14", "104.21.59.7", "93.184.215.14"],
        "Date": [SEEN] * 4, "Last Seen": [SEEN] * 4})
    return SimpleNamespace(
        events_all_utc=events, pdns=events, selected_domains=["evil.com", "104.21.59.0/24", "93.184.215.14"],
        ip_intel={"93.184.215.14": {"asn": 15133, "isp": "Edgecast", "country": "US", "count": 120,
                                    "domains": {"evil.com"}}},
        bgp_origins=pd.DataFrame({"IP": ["93.184.215.14"], "Domains": ["evil.com"], "Prefix": ["93.184.215.0/24"],
                                  "Origin": ["AS15133"], "AS Name": ["EDGECAST"], "Status": ["Unauthorized"],
                                  "Updates": [9], "Collectors": [40], "First Seen": [SEEN], "RIR": ["RIPE"],
                                  "RIR Country": ["EU"]}),
        bgp_routes=pd.DataFrame({"Prefix": ["93.184.215.0/24"] * 2, "Upstream": ["AS174", "AS3356"],
                                 "Collectors": [30, 50], "Updates": [5, 5]}),
        bgp_neighbours=pd.DataFrame(), bgp_asns=pd.DataFrame(), resolution_routing=pd.DataFrame(),
        anonymizers=pd.DataFrame({"IP": ["93.184.215.14"], "Category": ["VPN"], "Provider": ["nordvpn"],
                                  "Tor": [None]}),
        prefixes=pd.DataFrame(), range_ips=pd.DataFrame(), target_domains=pd.DataFrame(),
        ssl=pd.DataFrame({"Domain": ["evil.com"], "Hash": ["aa"], "Common Name": ["evil.com"], "Issuer": ["R3"],
                          "SAN IPv4": ["93.184.215.14"], "SAN DNS": ["evil.com"], "JA4X": [""],
                          "Not Before": [""], "Not After": [""]}),
        cert_hostnames=pd.DataFrame({"Domain": ["evil.com"], "Hostname": ["evil.com"], "IP": ["93.184.215.14"],
                                     "Cert_SHA256": ["aa"], "Source": ["Cert API (Hostname Events)"],
                                     "First Seen": ["2026-10-01"], "Last Seen": ["2026-11-01"]}))


ALERTS = pd.DataFrame({"Domain": ["evil.com"], "Threat Type": ["Unauthorized BGP Origin"], "Severity": ["High"],
                       "Threat Logic": ["AS15133 announces 93.184.215.0/24 (IP 93.184.215.14) without authorization"]})


def test_candidates_put_targets_first_then_the_most_interesting():
    table = ipp.candidates(dataset(), ["evil.com", "104.21.59.0/24", "93.184.215.14"], ALERTS)
    assert list(table["Address"])[:2] == ["93.184.215.14", "104.21.59.0/24"]
    row = table.iloc[0]
    assert (row["Kind"], row["Alerts"], row["Routing"], row["VPNDB"]) == ("IP target", 1, "Unauthorized",
                                                                          "VPN · nordvpn")
    assert "104.21.59.7" not in set(table["Address"])   # a range's addresses are on its range view, not the picker


def test_one_address_from_every_source():
    ds = dataset()
    domains = ipp.domains_using(ds, "93.184.215.14")
    assert list(domains["Domain"]) == ["evil.com", "third.org"] and bool(domains.iloc[0]["Analyzed"])
    assert list(ipp.certificates_served(ds, "93.184.215.14")["Common Name"]) == ["evil.com"]
    assert list(ipp.certificates_naming(ds, "93.184.215.14")["SHA-256"]) == ["aa"]
    route = ipp.routing(ds, "93.184.215.14")
    assert route["main"]["Origin"] == "AS15133" and route["upstreams"] == ["AS3356", "AS174"]
    labels = [text for text, _ in ipp.badges(ds, "93.184.215.14", 1)]
    assert labels == ["Routing: Unauthorized", "VPNDB: VPN · nordvpn", "1 alert(s)"]
    sentence = ipp.why(ds, "93.184.215.14", ipp.alerts_naming(ALERTS, "93.184.215.14"))
    assert "named by 1 alert(s)" in sentence and "without RPKI / IRR authorization" in sentence


def test_a_range_lists_its_addresses_with_data():
    ds = dataset()
    table = ipp.range_addresses(ds, "104.21.59.0/24", ALERTS)
    assert list(table["Address"]) == ["104.21.59.7"] and table.iloc[0]["Names"] == 1
    assert list(ipp.domains_using(ds, "104.21.59.0/24")["Domain"]) == ["other.net"]


def test_a_lone_target_opens_its_profile():
    from app import landing
    one = SimpleNamespace(targets=["104.21.59.7/24"], domain_targets=[])
    assert landing(one) == ("ip_profile", {"ip_profile_address": "104.21.59.0/24"})
    assert landing(SimpleNamespace(targets=["evil.com"], domain_targets=["evil.com"])) == \
        ("profile", {"profile_domain": "evil.com"})
    assert landing(SimpleNamespace(targets=["a.com", "b.com"], domain_targets=["a.com", "b.com"])) == ("summary", {})
    cert = SimpleNamespace(items=["sha256:aa"], hits=[{"sha256": "aa"}])
    assert landing(one, cert) == ("cert_profile", {"cert_profile_hash": "aa"})
