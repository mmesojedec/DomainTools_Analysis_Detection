import json

import pytest

from integrations import vpndb

# operationId of every operation in the VPNDB OpenAPI specification (1.0.0)
SPEC_OPERATIONS = {
    "getIp", "getPrefix", "getPrefixAddresses", "getIpHistory", "getPrefixTimeline", "getAsn", "getService",
    "getServiceNetworks", "search", "bulkLookup", "listServices", "getTor", "listTorRelays", "getMeta", "getOpenApi",
    "getSuggest", "getOrg", "getCountries", "getCountry", "getOrgNetworks", "getAsnNetworks", "getSources",
}


class Response:
    def __init__(self, status=200, body=None, headers=None, text=None):
        self.status_code, self.headers = status, headers or {}
        self._body = body
        self.text = text if text is not None else json.dumps(body)

    def json(self):
        if self._body is None:
            raise ValueError("no JSON")
        return self._body


class Session:
    """Answers each call with the next queued response and records what was asked."""
    def __init__(self, *responses):
        self.responses, self.calls = list(responses), []

    def _answer(self, method, url, **kwargs):
        self.calls.append((method, url, kwargs))
        return self.responses.pop(0)

    def get(self, url, **kwargs):
        return self._answer("GET", url, **kwargs)

    def post(self, url, **kwargs):
        return self._answer("POST", url, **kwargs)


@pytest.fixture
def session(monkeypatch):
    monkeypatch.setattr(vpndb, "load_vpndb_key", lambda: "vpndb_test")
    monkeypatch.setattr(vpndb, "vpndb_base_url", lambda: "https://vpndb.test/api/v1")
    fake = Session()
    monkeypatch.setattr(vpndb, "_session", lambda: fake)
    return fake


def test_every_operation_of_the_specification_has_a_function():
    assert set(vpndb.OPERATIONS) == SPEC_OPERATIONS and all(map(callable, vpndb.OPERATIONS.values()))


def test_verdict_sends_the_key_and_keeps_the_quota(session):
    session.responses.append(Response(body={"ip": "45.248.77.91", "anonymous": True, "confidence": 3,
                                            "datasetVersion": "2026-10-30"},
                                      headers={"X-Quota-Remaining": "299990", "X-Quota-Notice": "80 % used"}))
    result = vpndb.lookup_ip("45.248.77.91")
    method, url, kwargs = session.calls[0]
    assert (method, url) == ("GET", "https://vpndb.test/api/v1/ip/45.248.77.91")
    assert kwargs["headers"]["Authorization"] == "Bearer vpndb_test"
    assert result.ok and result.data["anonymous"] and result.status_row()["Status"] == "OK"
    assert result.extras["quota"] == {"remaining": "299990", "notice": "80 % used"}
    assert vpndb.lookup_ip("45.248.77.91").note.startswith("From cache") and len(session.calls) == 1


def test_a_miss_is_data_not_an_error(session):
    session.responses.append(Response(404, {"observed": False, "reason": "not_collected"}))
    result = vpndb.lookup_ip("2001:db8::1")
    assert result.ok and result.data["observed"] is False and "IPv6" in result.note
    assert result.status_row()["Status"] == "No data"
    assert session.calls[0][1].endswith("/ip/2001%3Adb8%3A%3A1")


def test_errors_carry_the_api_note_and_429_is_not_waited_for(session):
    session.responses += [Response(429, {"error": "quota_exceeded", "note": "Write to sales."},
                                   {"Retry-After": "3600"}),
                          Response(401, {"error": "unauthenticated", "note": "Send an API key."})]
    limited = vpndb.lookup_asn("AS9009")
    assert limited.error == "Demo quota exhausted, retry after 3600 s: Write to sales."
    assert session.calls[0][1].endswith("/asn/9009")
    assert vpndb.lookup_prefix("45.248.77.0/24").error.endswith("check the API key: Send an API key.")
    assert session.calls[1][1].endswith("/prefix/45.248.77.0%2F24")


def test_no_key_no_call_except_for_the_open_endpoints(session, monkeypatch):
    monkeypatch.setattr(vpndb, "load_vpndb_key", lambda: None)
    assert "VPNDB key not found" in vpndb.lookup_service("MULLVAD_VPN").error and not session.calls
    session.responses += [Response(body={"datasetVersion": "v1"}), Response(text="openapi: 3.1.0\n")]
    assert vpndb.meta().data == {"datasetVersion": "v1"}
    assert vpndb.openapi_spec().data == "openapi: 3.1.0\n"
    assert all("Authorization" not in call[2]["headers"] for call in session.calls)


def test_pages_are_followed_and_merged(session):
    session.responses += [
        Response(body={"tag": "NORD", "networks": [{"network": "1.0.0.0/24"}], "nextCursor": "c1"}),
        Response(body={"tag": "NORD", "networks": [{"network": "2.0.0.0/24"}], "nextCursor": "c2"}),
    ]
    result = vpndb.service_networks("NORD", current=True, max_pages=2)
    assert [n["network"] for n in result.data["networks"]] == ["1.0.0.0/24", "2.0.0.0/24"]
    assert result.truncated and result.data["nextCursor"] == "c2" and result.record_count == 2
    assert session.calls[0][2]["params"] == {"min_confidence": 1, "current": "true", "size": 200}
    assert session.calls[1][2]["params"]["cursor"] == "c1"

    session.responses += [Response(body={"network": "94.250.0.0/16", "addresses": [{"ip": "94.250.0.1"}]})]
    last = vpndb.prefix_addresses("94.250.0.0/16", date_from="2026-10-01", pool="residential")
    assert not last.truncated and "nextCursor" not in last.data
    assert session.calls[2][2]["params"] == {"size": 50, "pool": "residential", "from": "2026-10-01"}


def test_bulk_is_split_at_the_limit_and_merged(session, monkeypatch):
    monkeypatch.setattr(vpndb, "BULK_LIMIT", 2)
    session.responses += [
        Response(body={"total": 2, "anonymous": 1, "results": [{"ip": "1.1.1.1"}, {"ip": "2.2.2.2"}],
                       "byProvider": {"nordvpn": 1}, "byAsn": {"136557": 1}, "unknown": 1}),
        Response(body={"total": 1, "anonymous": 1, "results": [{"ip": "3.3.3.3"}],
                       "byProvider": {"mullvad": 1, "nordvpn": 2}, "byAsn": {"136557": 1}, "unknown": 0}),
    ]
    result = vpndb.bulk_lookup(("1.1.1.1", "2.2.2.2", "1.1.1.1", "3.3.3.3"))
    assert [call[2]["json"]["ips"] for call in session.calls] == [["1.1.1.1", "2.2.2.2"], ["3.3.3.3"]]
    assert session.calls[0][0] == "POST" and result.record_count == 3
    assert (result.data["total"], result.data["anonymous"], result.data["unknown"]) == (3, 2, 1)
    assert result.data["byProvider"] == {"nordvpn": 3, "mullvad": 1} and result.data["byAsn"] == {"136557": 2}


def test_tor_relays_as_csv_keep_their_cursor(session):
    session.responses.append(Response(text="address,port\n1.2.3.4,9001\n", headers={"X-Next-Cursor": "n1"}))
    result = vpndb.tor_relays(role="exit", fmt="csv")
    assert result.data.startswith("address,port") and result.extras["next_cursor"] == "n1" and result.truncated
    assert session.calls[0][2]["headers"]["Accept"] == "text/csv"
    assert session.calls[0][2]["params"] == {"role": "exit", "size": 200, "format": "csv"}
