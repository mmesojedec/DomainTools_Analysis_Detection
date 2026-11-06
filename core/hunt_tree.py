"""
Hunt tree: which run a run was started from, and through which pivot. A run started from a lead, a certificate or
a watched list records {"id": parent run id, "via": what led to it} in its snapshot; following those links rebuilds
the path from the first seed to any run, and the whole tree of a hunt.
"""


def _targets(snapshot, limit=3):
    targets = snapshot.get("seeds") or snapshot.get("targets") or []
    return ", ".join(targets[:limit]) + (f" +{len(targets) - limit}" if len(targets) > limit else "")


def _parent_id(snapshot):
    return (snapshot.get("parent") or {}).get("id")


def hunt_trail(runs, run_id):
    """Snapshots from the hunt's first run to `run_id`, following parent links (`runs`: [(key, snapshot)])."""
    by_id = {snapshot["id"]: snapshot for _, snapshot in runs}
    trail, seen = [], set()
    current = by_id.get(run_id)
    while current is not None and current["id"] not in seen:
        seen.add(current["id"])
        trail.append(current)
        current = by_id.get(_parent_id(current))
    return list(reversed(trail))


def hunt_tree(runs):
    """
    Rows (depth-first, oldest branch first) of every hunt with two or more runs: {Depth, Run, Parent, Key, Created,
    Targets, Via, Alerts, Target List}. Runs that neither started from nor led to another run are left out.
    """
    by_id = {snapshot["id"]: (key, snapshot) for key, snapshot in runs}
    children = {}
    for _, snapshot in runs:
        parent = _parent_id(snapshot)
        if parent in by_id:
            children.setdefault(parent, []).append(snapshot["id"])
    roots = [snapshot["id"] for _, snapshot in runs if _parent_id(snapshot) not in by_id and snapshot["id"] in children]
    rows = []

    def walk(run_id, depth, seen):
        if run_id in seen:
            return
        seen.add(run_id)
        key, snapshot = by_id[run_id]
        rows.append({"Depth": depth, "Run": run_id, "Parent": _parent_id(snapshot) if depth else None, "Key": key,
                     "Created": snapshot.get("created"),
                     "Targets": _targets(snapshot), "Via": (snapshot.get("parent") or {}).get("via", ""),
                     "Alerts": len(snapshot.get("alerts") or []), "Target List": snapshot.get("targets") or []})
        for child in sorted(children.get(run_id, []), key=lambda c: str(by_id[c][1].get("created"))):
            walk(child, depth + 1, seen)

    for root in sorted(roots, key=lambda r: str(by_id[r][1].get("created"))):
        walk(root, 0, set())
    return rows


def trail_text(trail):
    """'a.com → (via IP 1.2.3.4) b.com, c.com' for a hunt trail."""
    parts = []
    for i, snapshot in enumerate(trail):
        via = (snapshot.get("parent") or {}).get("via")
        parts.append((f"*via {via}* → " if i and via else "→ " if i else "") + f"**{_targets(snapshot)}**")
    return " ".join(parts)
