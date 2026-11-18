"""
Hunt tree: which run a run was started from, and through which pivot. A run started from a lead, a certificate or
a watched list records {"id": parent run id, "via": what led to it} in its snapshot; following those links rebuilds
the path from the first seed to any run, and the whole tree of a hunt.
"""
from core.persistence import SAME_TARGETS


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


def trail_steps(trail):
    """
    The hunt trail with runs that only repeat the previous step's targets (Run again, the same list again) folded into
    it: [(snapshot, runs)], `runs` counting the step and its repeats.
    """
    steps = []
    for snapshot in trail:
        via = (snapshot.get("parent") or {}).get("via")
        if steps and via in RERUN_VIAS and _target_set(snapshot) == _target_set(steps[-1][0]):
            steps[-1] = (steps[-1][0], steps[-1][1] + 1)
        else:
            steps.append((snapshot, 1))
    return steps


def trail_text(trail):
    """'a.com (3 runs) → via IP 1.2.3.4 → b.com, c.com' for a hunt trail; repeated runs of a step are counted, not listed."""
    parts = []
    for i, (snapshot, runs) in enumerate(trail_steps(trail)):
        via = (snapshot.get("parent") or {}).get("via")
        parts.append((f"*via {via}* → " if i and via else "→ " if i else "") + f"**{_targets(snapshot)}**"
                     + (f" ({runs} runs)" if runs > 1 else ""))
    return " ".join(parts)


def hunt_root(runs, run_id):
    """The id of the first run of the hunt `run_id` belongs to (itself when it was not started from another run)."""
    trail = hunt_trail(runs, run_id)
    return trail[0]["id"] if trail else None


def hunt_members(runs, root_id):
    """[(key, snapshot, depth)] of the hunt that starts at `root_id`: the run, then each run started from it, depth-first."""
    by_id = {snapshot["id"]: (key, snapshot) for key, snapshot in runs}
    children = {}
    for _, snapshot in runs:
        children.setdefault(_parent_id(snapshot), []).append(snapshot["id"])
    members, seen = [], set()

    def walk(run_id, depth):
        if run_id in seen or run_id not in by_id:
            return
        seen.add(run_id)
        key, snapshot = by_id[run_id]
        members.append((key, snapshot, depth))
        for child in sorted(children.get(run_id, []), key=lambda c: str(by_id[c][1].get("created"))):
            walk(child, depth + 1)

    walk(root_id, 0)
    return members


RERUN_VIAS = ("Run again", SAME_TARGETS)   # a run of its parent's targets again (not a pivot that found them)


def _target_set(snapshot):
    return tuple(sorted(set(snapshot.get("targets") or []) | set(snapshot.get("seeds") or [])))


def collapse_repeats(members):
    """
    Folds the runs that only repeat their parent's targets (Run again, the same list analyzed again: RERUN_VIAS) into the first
    of them, for drawing: (members, repeats, alias). The kept box carries the newest repeat's results under the first
    run's id and place; runs started from any repeat hang from it. `repeats`: {kept id: [its runs, oldest first]}
    for boxes of two or more runs; `alias`: {run id: kept id}.
    """
    kept, alias, repeats, depths, out = {}, {}, {}, {}, []
    for key, snapshot, depth in members:
        parent = alias.get(_parent_id(snapshot))
        via = str((snapshot.get("parent") or {}).get("via") or "")
        if parent is not None and depth and via in RERUN_VIAS and _target_set(snapshot) == _target_set(kept[parent][1]):
            alias[snapshot["id"]] = parent
            repeats.setdefault(parent, [kept[parent][2]]).append(snapshot)
            first = kept[parent][2]
            kept[parent] = (key, {**snapshot, "id": parent, "parent": first.get("parent"),
                                  "created": snapshot.get("created")}, first)
            continue
        if parent is not None:
            snapshot = {**snapshot, "parent": {**snapshot["parent"], "id": parent}}
            depth = depths[parent] + 1
        alias[snapshot["id"]] = snapshot["id"]
        depths[snapshot["id"]] = depth
        kept[snapshot["id"]] = (key, snapshot, snapshot)
        out.append(snapshot["id"])
    if not repeats:
        return list(members), {}, {m[1]["id"]: m[1]["id"] for m in members}
    return [(kept[i][0], kept[i][1], depths[i]) for i in out], repeats, alias
