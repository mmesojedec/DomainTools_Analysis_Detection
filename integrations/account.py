"""DomainTools Account Information (SDK): the account's products, limits and usage. Not cached: usage changes."""
from integrations.credentials import DTAPI_MISSING, get_dt_api
from integrations.http import FetchResult, describe_exception

SOURCE = "Account Information"


def fetch_account_information():
    """One /v1/account query (it counts against the account-information product). data = the API `response` object."""
    api = get_dt_api()
    if api is None:
        return FetchResult(SOURCE, "account", error=DTAPI_MISSING)
    try:
        payload = api.account_information().data()
    except Exception as exc:
        return FetchResult(SOURCE, "account", error=describe_exception(exc))
    response = (payload or {}).get("response", payload or {}) or {}
    return FetchResult(SOURCE, "account", data=response, record_count=len(response.get("products") or []))
