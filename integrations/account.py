"""
DomainTools Account Information (SDK): the account's products, limits and usage. Not in the lookup cache (usage
changes); `account_information()` keeps the last answer for an hour in memory, shared by the Account page, the cost
estimate and the product check of each Analyze, so they cost at most one query an hour.
"""
import threading
import time

from core.account import account_parts
from integrations.credentials import DTAPI_MISSING, get_dt_api, load_dtapi_credentials
from integrations.http import FetchResult, describe_exception, metered, sdk_call

SOURCE = "Account Information"
MEMO_SECONDS = 3600
_memo = {"result": None, "at": None}   # the last successful answer and when (epoch seconds) it was fetched
_lock = threading.Lock()


@metered
def fetch_account_information():
    """One /v1/account query (it counts against the account-information product). data = the API `response` object."""
    api = get_dt_api()
    if api is None:
        return FetchResult(SOURCE, "account", error=DTAPI_MISSING)
    try:
        payload = sdk_call(lambda: api.account_information().data())
    except Exception as exc:
        return FetchResult(SOURCE, "account", error=describe_exception(exc))
    response = (payload or {}).get("response", payload or {}) or {}
    return FetchResult(SOURCE, "account", data=response, record_count=len(response.get("products") or []))


def account_information(refresh=False):
    """(FetchResult, fetched at epoch seconds): the last answer when under an hour old, else a new query."""
    with _lock:
        if not refresh and _memo["result"] is not None and time.time() - _memo["at"] < MEMO_SECONDS:
            return _memo["result"], _memo["at"]
    result, now = fetch_account_information(), time.time()
    if result.ok:
        with _lock:
            _memo.update(result=result, at=now)
    return result, now


def known_products():
    """The account's products from the last answer (no query), or None when there is none yet."""
    with _lock:
        result = _memo["result"]
    return account_parts(result.data)[1] if result is not None else None


def account_products(fetch=True):
    """The account's products: the last answer, else (with `fetch` and DomainTools credentials) a new query; None
    when unknown (no credentials, or the query failed)."""
    products = known_products()
    if products is None and fetch and load_dtapi_credentials():
        result, _ = account_information()
        products = account_parts(result.data)[1] if result.ok else None
    return products


def forget_account():
    with _lock:
        _memo.update(result=None, at=None)
