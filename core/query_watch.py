"""
Watched IrisQL queries: a hunt query saved with the domains it returned, so checking it again shows only the domains
that are new since the last check (an actor's new registrations, a lookalike wave). Kept in dt_settings.json; a
check is an ordinary IrisQL search (its queries are counted as usual).
"""
from datetime import datetime, timezone

from core.persistence import load_settings, save_setting

WATCH_SETTING = "query_watches"
MAX_SEEN = 20_000   # domains remembered per watch


def _now():
    return datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


def list_watches():
    watches = load_settings().get(WATCH_SETTING)
    return watches if isinstance(watches, list) else []


def _save(watches):
    save_setting(WATCH_SETTING, watches)


def add_watch(name, query, max_results, sort_by, domains):
    """Saves (or replaces) watch `name` with the domains the query returned now as already seen."""
    watches = [w for w in list_watches() if w.get("name") != name]
    watches.append({"name": name, "query": query, "max_results": int(max_results), "sort_by": sort_by or "",
                    "seen": sorted(set(domains))[:MAX_SEEN], "created": _now(), "checked": _now()})
    _save(watches)


def remove_watch(name):
    _save([w for w in list_watches() if w.get("name") != name])


def check_watch(name, domains):
    """
    Records a check of watch `name` that returned `domains`: (new domains, time of the previous check). The new ones
    join the seen list, so the next check reports only what appears after this one.
    """
    watches = list_watches()
    for watch in watches:
        if watch.get("name") == name:
            seen = set(watch.get("seen") or [])
            new = sorted(set(domains) - seen)
            previous = watch.get("checked")
            watch["seen"] = sorted(seen | set(domains))[:MAX_SEEN]
            watch["checked"] = _now()
            _save(watches)
            return new, previous
    return sorted(set(domains)), None
