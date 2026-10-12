"""Derived numbers: everything the report states is computed here, never typed by hand."""
from collections import Counter
from . import model as m

BY_ID = {c["id"]: c for c in m.CONTROLS}
VAULT_BY_KEY = {k: {"key": k, "title": t, "question": q, "tech": tech} for k, t, q, tech in m.VAULT}


def risk(threat):
    return threat["likelihood"] * threat["impact"]


def edge_count(control_id):
    return sum(control_id in e["controls"] for p in m.PATHS for e in p["edges"])


def non_network_share():
    total = len(m.CONTROLS)
    net = sum(c["vault"] == "wall" for c in m.CONTROLS)
    return (total - net) / total, net, total


def status_counts(controls=None):
    return Counter(c["status"] for c in (controls or m.CONTROLS))


def vault_mix():
    """Per vault element: total controls and how many are fully in place."""
    rows = []
    for key, title, question, tech in m.VAULT:
        cs = [c for c in m.CONTROLS if c["vault"] == key]
        rows.append({"key": key, "title": title, "tech": tech, "total": len(cs),
                     "in_place": sum(c["status"] == "in_place" for c in cs)})
    return rows


def weakest_elements(n=2):
    rows = [r for r in vault_mix() if r["total"]]
    return sorted(rows, key=lambda r: (r["in_place"] / r["total"], -r["total"]))[:n]


def priority_table():
    """Controls not yet fully in place, ranked.

    score = sum of risk scores of the threats the control mitigates
          + 2 x the number of attack-path edges it helps break.
    A gap counts fully; a partial control counts half (the work left is smaller).
    """
    rows = []
    for c in m.CONTROLS:
        if c["status"] == "in_place":
            continue
        threats = [t for t in m.THREATS if c["id"] in t["controls"]]
        edges = edge_count(c["id"])
        raw = sum(risk(t) for t in threats) + 2 * edges
        score = raw if c["status"] == "gap" else raw / 2
        rows.append({"control": c, "threats": [t["id"] for t in threats], "edges": edges, "score": score})
    return sorted(rows, key=lambda r: (-r["score"], r["control"]["id"]))
