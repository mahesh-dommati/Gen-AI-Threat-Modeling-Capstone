"""Rule checks for the capstone. `python run.py` fails if any check fails."""
from . import model as m
from . import analysis as a


def run(executive_summary_text=None):
    checks = []

    def check(name, ok, detail=""):
        checks.append((name, bool(ok), detail))

    ids = set(a.BY_ID)

    # --- the 7 required sections have content
    sections = {
        "1 Architecture and trust boundaries": m.BOUNDARIES,
        "2 Critical assets": m.ASSETS,
        "3 Threat register": m.THREATS,
        "4 Three multi-step attack paths": m.PATHS,
        "5 Control map": m.CONTROLS,
        "6 Remediation priorities": a.priority_table(),
    }
    empty = [k for k, v in sections.items() if not v]
    check("Sections 1-6 all have content", not empty, ", ".join(empty) or "ok")
    check("Exactly three attack paths", len(m.PATHS) == 3, f"{len(m.PATHS)} paths")
    if executive_summary_text is not None:
        words = len(executive_summary_text.split())
        check("Executive summary fits one page (<= 400 words)", 0 < words <= 400, f"{words} words")

    # --- threat register
    seen = {t["stride"] for t in m.THREATS}
    missing = [s for s in m.STRIDE if s not in seen]
    check("All six STRIDE categories appear in the threat register", not missing, ", ".join(missing) or "complete")

    # --- referential integrity
    bad = set()
    for t in m.THREATS:
        bad |= {c for c in t["controls"] if c not in ids}
    for p in m.PATHS:
        for e in p["edges"]:
            bad |= {c for c in e["controls"] if c not in ids}
    for b in m.BOUNDARIES:
        bad |= {c for c in b["controls"] if c not in ids}
    check("Every referenced control id exists", not bad, ", ".join(sorted(bad)) or "ok")

    # --- attack paths: a control on every edge, and not preventive-only
    unbroken = [f'{p["id"]}: {e["from"]} -> {e["to"]}' for p in m.PATHS for e in p["edges"] if not e["controls"]]
    n_edges = sum(len(p["edges"]) for p in m.PATHS)
    check("Every attack-path edge has a breaking control", not unbroken, f"{n_edges} edges" if not unbroken else "; ".join(unbroken))
    prevent_only = []
    for p in m.PATHS:
        phases = {a.BY_ID[c]["phase"] for e in p["edges"] for c in e["controls"]}
        if not (phases & {"detect", "respond", "recover"}) or "prevent" not in phases:
            prevent_only.append(p["id"])
    check("Every path mixes prevent with detect/respond/recover", not prevent_only, ", ".join(prevent_only) or "ok")

    # --- threats: not preventive-only
    threat_prevent_only = [t["id"] for t in m.THREATS
                           if {a.BY_ID[c]["phase"] for c in t["controls"]} <= {"prevent"}]
    check("No threat is covered by preventive controls alone", not threat_prevent_only, ", ".join(threat_prevent_only) or "ok")

    # --- the vault rule
    share, net, total = a.non_network_share()
    check("At least 50% of controls are non-network", share >= 0.5, f"{total - net}/{total} = {share:.0%}")
    check("Network controls exist (the wall is present, just not alone)", net > 0, f"{net} wall controls")
    phases_missing = [p for p in m.PHASES if not any(c["phase"] == p for c in m.CONTROLS)]
    check("Prevent, detect, respond and recover are all populated", not phases_missing, ", ".join(phases_missing) or "complete")
    empty_vault = [r["title"] for r in a.vault_mix() if r["total"] == 0]
    check("Every element of the vault has at least one control", not empty_vault, ", ".join(empty_vault) or "complete")

    # --- evidence-based controls
    weak = [c["id"] for c in m.CONTROLS if not c["assumption"].strip() or not c["evidence"].strip()]
    check("Every control states its assumption and its evidence", not weak, ", ".join(weak) or "ok")
    return checks


def all_passed(checks):
    return all(ok for _, ok, _ in checks)
