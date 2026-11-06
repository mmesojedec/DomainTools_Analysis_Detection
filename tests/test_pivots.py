from core.pivots import build_pivot_ranking, iris_curl, iris_search_params, iter_pivots, pivot_domains_frame, signal_of


def val(value, count):
    return {"value": value, "count": count}


RECORD_A = {
    "ip": [{"address": val("203.0.113.5", 40), "asn": [val(64500, 900000)]}],
    "name_server": [{"host": val("NS1.Bad-DNS.example.", 12), "domain": val("bad-dns.example", 12),
                     "ip": [val("198.51.100.7", 12)]}],
    "registrant_contact": {"email": [val("Actor@Mail.example", 75)], "phone": val("15550100", 0)},
    "soa_email": [val("dns@cloudflare.com", 117803495)],
    "ssl_info": [{"hash": val("ABCDEF0123456789ABCDEF0123456789ABCDEF01", 3), "subject": val("CN=bad.example", 3),
                  "common_name": val("bad.example", 3), "organization": val("", 0)}],
    "ga4": [val("G-ABC123", 5000)],
    "google_analytics": val("", 0),
    "redirect_domain": val("Landing.example", 1),
}
RECORD_B = {
    "ip": [{"address": val("203.0.113.5", 40)}],
    "registrant_contact": {"email": [val("actor@mail.example", 77)]},
}


def test_signal_levels():
    assert [signal_of(n) for n in (0, None, 1, 2, 500, 501, 10_000, 10_001)] == [
        "Count unknown", "Count unknown", "This domain only", "Strong", "Strong", "Useful", "Useful", "Weak"]


def test_iter_pivots_reads_every_pivotable_field():
    found = {(kind, param, value): target for kind, param, value, _, target in iter_pivots(RECORD_A)}
    assert found[("IP address", "ip", "203.0.113.5")] == "203.0.113.5"
    assert ("Name server", "nameserver_host", "ns1.bad-dns.example") in found
    assert found[("Name server IP", "nameserver_ip", "198.51.100.7")] == "198.51.100.7"
    assert ("Contact email", "email", "actor@mail.example") in found
    assert ("SOA email", "email", "dns@cloudflare.com") in found
    sha1 = "abcdef0123456789abcdef0123456789abcdef01"
    assert found[("SSL certificate (SHA-1)", "ssl_hash", sha1)] == f"sha1:{sha1}"
    assert found[("SSL subject", "ssl_subject", "CN=bad.example")] == "cn:bad.example"
    assert ("Google Analytics 4 (GA4)", "google_analytics_4", "G-ABC123") in found
    assert found[("Redirect domain", "redirect_domain", "landing.example")] == "landing.example"
    assert not any(kind == "Google Universal Analytics" for kind, _, _ in found)   # empty values are skipped


def test_ranking_orders_by_signal_then_shared_then_count():
    ranking = build_pivot_ranking({"a.example": RECORD_A, "b.example": RECORD_B})
    assert list(ranking["Value"][:3]) == ["203.0.113.5", "actor@mail.example",   # shared by both, fewest Iris first
                                          "abcdef0123456789abcdef0123456789abcdef01"]
    email = ranking.iloc[1]
    assert (email["Run Domains"], email["Shared With"], email["Iris Domains"]) == (2, "a.example, b.example", 77)
    strong = ranking[ranking["Signal"] == "Strong"]
    assert list(strong["Run Domains"]) == sorted(strong["Run Domains"], reverse=True)
    assert ranking.set_index("Value").loc["dns@cloudflare.com", "Signal"] == "Weak"
    assert ranking.set_index("Value").loc["15550100", "Signal"] == "Count unknown"
    assert ranking["Signal"].iloc[-1] == "Count unknown"


def test_empty_enrichment_gives_an_empty_ranking():
    assert build_pivot_ranking({}).empty and build_pivot_ranking(None).empty


def test_iris_search_helpers():
    assert iris_search_params("email=actor@mail.example") == {"email": "actor@mail.example"}
    assert iris_curl("ssl_subject=CN=bad.example") == (
        'curl -s "https://api.domaintools.com/v1/iris-investigate/?ssl_subject=CN%3Dbad.example'
        '&api_username=$DT_API_USERNAME&api_key=$DT_API_KEY"')


def test_pivot_domains_frame_sorts_by_risk():
    frame = pivot_domains_frame([
        {"domain": "LOW.example", "domain_risk": {"risk_score": 10}, "create_date": val("2026-01-01", 1),
         "ip": [{"address": val("203.0.113.5", 40)}], "active": True},
        {"domain": "high.example", "domain_risk": {"risk_score": 95}, "registrar": val("Example Registrar", 9)},
        "not a record",
    ])
    assert list(frame["Domain"]) == ["high.example", "low.example"]
    assert frame.iloc[1]["IPs"] == "203.0.113.5" and frame.iloc[0]["Registrar"] == "Example Registrar"
