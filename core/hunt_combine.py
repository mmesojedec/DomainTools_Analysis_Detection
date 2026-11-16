"""
Combined hunts (Hunt map → Combined hunts): what separate hunts share, so an analyst can see where they meet and join
them. Two hunts are related when their runs recorded the same linkable value (certificate, IP, name server, tracker,
email; not CDNs, large DNS providers, role or privacy mailboxes) or analyzed the same domain. No API calls.
"""
from collections import Counter

from core.hunt_result import domain_values, hunt_result
from core.hunt_tree import hunt_members

CROSS_EDGES = 3    # strongest links drawn between two hunts on the combined map
DOMAIN = "Domain"  # the kind of a link made by a domain both runs analyzed

_VALUES = {}       # run id -> its linkable values (a saved run's artifacts don't change)


def run_values(snapshot):
    """{(kind, value)} a run recorded (linkable values only), plus ("Domain", d) for each domain it analyzed."""
    run_id = snapshot.get("id")
    if run_id not in _VALUES:
        values = set().union(*domain_values(snapshot).values()) if snapshot.get("artifacts") else set()
        _VALUES[run_id] = values | {(DOMAIN, str(d).lower()) for d in snapshot.get("targets") or []}
    return _VALUES[run_id]


def hunt_values(members):
    return set().union(*(run_values(snapshot) for _, snapshot, _ in members)) if members else set()


def hunt_roots(runs):
    """Every hunt's first run id, newest hunt first: runs not started from another saved run (single runs too)."""
    ids = {snapshot["id"] for _, snapshot in runs}
    roots = [snapshot for _, snapshot in runs if (snapshot.get("parent") or {}).get("id") not in ids]
    return [snapshot["id"] for snapshot in sorted(roots, key=lambda s: str(s.get("created")), reverse=True)]


def related_hunts(runs, root_id, roots=None, limit=None):
    """[(other root id, Counter of shared kinds)] of the hunts sharing values with hunt `root_id`, most shared first."""
    mine = hunt_values(hunt_members(runs, root_id))
    related = []
    for other in roots if roots is not None else hunt_roots(runs):
        if other == root_id:
            continue
        shared = mine & hunt_values(hunt_members(runs, other))
        if shared:
            related.append((other, Counter(kind for kind, _ in shared)))
    related.sort(key=lambda pair: (-sum(pair[1].values()), pair[0]))
    return related[:limit] if limit else related


def cross_links(hunts, per_pair=CROSS_EDGES):
    """
    [{"source", "target", "shared": Counter, "values": [(kind, value)]}]: between runs of different hunts (`hunts`:
    {root id: members}), the strongest `per_pair` links for each pair of hunts.
    """
    roots = list(hunts)
    links = []
    for i, first in enumerate(roots):
        for second in roots[i + 1:]:
            pairs = []
            for _, a, _ in hunts[first]:
                for _, b, _ in hunts[second]:
                    shared = run_values(a) & run_values(b)
                    if shared:
                        pairs.append({"source": a["id"], "target": b["id"], "shared": Counter(k for k, _ in shared),
                                      "values": sorted(shared)})
            pairs.sort(key=lambda link: -len(link["values"]))
            links.extend(pairs[:per_pair])
    return links


def best_anchor(members, snapshot):
    """The run of a hunt (`members`) sharing the most with `snapshot`: where a joined hunt attaches (else the newest)."""
    values = run_values(snapshot)
    return max((s for _, s, _ in members), key=lambda s: (len(run_values(s) & values), str(s.get("created"))))["id"]


def combined_result(hunts):
    """hunt_result over several hunts, their starting points together as one start."""
    snapshots = [snapshot for members in hunts.values() for _, snapshot, _ in members]
    roots = [members[0][1] for members in hunts.values()]
    start = {"id": "combined", "targets": sorted({t for root in roots for t in root.get("targets") or []}),
             "artifacts": {domain: kinds for root in roots for domain, kinds in (root.get("artifacts") or {}).items()}}
    return hunt_result(snapshots, start)
