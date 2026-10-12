"""Builds docs/CAPSTONE_REPORT.md and docs/EXECUTIVE_SUMMARY.md from the model."""
from . import model as m
from . import analysis as a

STATUS_LABEL = {"in_place": "In place", "partial": "Partial", "gap": "Gap"}
QUOTE = ("A bank vault is an asset-protection system. The wall is only one control; identity checks, "
         "dual authorization, cameras, alarms, logs and incident response matter too.")


def table(headers, rows):
    out = ["| " + " | ".join(headers) + " |", "|" + "|".join("---" for _ in headers) + "|"]
    out += ["| " + " | ".join(str(c) for c in r) + " |" for r in rows]
    return "\n".join(out)


def cname(cid):
    return f"`{cid}` {a.BY_ID[cid]['name']}"


def vtitle(key):
    return a.VAULT_BY_KEY[key]["title"]


# ------------------------------------------------------------------ section builders
def diagram():
    return """```mermaid
flowchart LR
  U([User]) -- TB1 --> GW[Web/API gateway and WAF]
  GW -- TB2 --> IDP[Identity provider<br/>SSO and OIDC]
  IDP -- TB3 --> WL[Workload on Azure / AWS / GCP<br/>orchestrator]
  WL -- TB4 --> LLM[LLM service]
  WL -- TB5 --> RAG[(RAG and vector store)]
  CI[CI/CD and GitHub] -- TB6 --> WL
  GW -. TB7 .-> MON[Monitoring and immutable logs]
  WL -. TB7 .-> MON
  RAG -. TB7 .-> MON
  CI -. TB7 .-> MON
```"""


def sec_vault():
    rows = []
    for r in a.vault_mix():
        v = a.VAULT_BY_KEY[r["key"]]
        rows.append([f"**{v['title']}**", v["question"], v["tech"], f"{r['total']} ({r['in_place']} in place)"])
    share, net, total = a.non_network_share()
    head = (f"> {QUOTE}\n\nThis review applies that idea to the GenAI pipeline. Each of the {total} controls sits on one "
            f"element of the vault. Only the wall is network security: **{net} of {total} controls**, so "
            f"**{share:.0%} of the design is non-network**, against the required minimum of 50%.\n\n")
    return head + table(["Vault element", "The question it answers", "Technical layer", "Controls"], rows)


def sec_architecture():
    rows = [[b["id"], f"{b['from']} → {b['to']}", b["note"], ", ".join(f"`{c}`" for c in b["controls"])]
            for b in m.BOUNDARIES]
    return ("Flow: User → Web/API → Identity → Azure/AWS/GCP workload → LLM service → RAG/data layer → CI/CD → monitoring.\n\n"
            + diagram() + "\n\n" + table(["ID", "Boundary", "What crosses it", "Main controls"], rows))


def sec_assets():
    rows = [[x["id"], x["name"], x["location"], x["impact"], x["vault_equiv"]] for x in m.ASSETS]
    return table(["ID", "Asset", "Where it lives", "Impact if lost", "In the vault analogy"], rows)


def sec_threats():
    rows = []
    for t in sorted(m.THREATS, key=lambda t: -a.risk(t)):
        rows.append([t["id"], t["stride"], t["title"], t["asset"], t["boundary"],
                     t["likelihood"], t["impact"], a.risk(t), ", ".join(t["controls"])])
    return ("Likelihood and impact are scored 1-5; risk = likelihood × impact (inherent, before the proposed controls). "
            "Sorted by risk.\n\n"
            + table(["ID", "STRIDE", "Threat", "Asset", "Boundary", "L", "I", "Risk", "Controls"], rows))


def sec_paths():
    out = []
    for p in m.PATHS:
        out.append(f"### Path {p['id']}: {p['name']} — \"{p['heist']}\"\n")
        out.append("**Chain:** " + " → ".join(p["steps"]) + "\n")
        rows = [[f"{i}", f"{e['from']} → {e['to']}", "<br>".join(cname(c) for c in e["controls"])]
                for i, e in enumerate(p["edges"], 1)]
        out.append(table(["Edge", "Attacker step", "Controls that break it"], rows) + "\n")
        out.append(f"**In plain words:** {p['plain']}\n")
        out.append(f"**Residual risk:** {p['residual']}\n")
    return "\n".join(out)


def sec_controls():
    out = ["Status is an assumed baseline for this fictional environment. For each control: the assumption it "
           "makes, and the evidence that would prove it works.\n"]
    for phase in m.PHASES:
        cs = [c for c in m.CONTROLS if c["phase"] == phase]
        out.append(f"### {phase.capitalize()} ({len(cs)})\n")
        rows = [[c["id"], c["name"], vtitle(c["vault"]), STATUS_LABEL[c["status"]], c["assumption"], c["evidence"]] for c in cs]
        out.append(table(["ID", "Control", "Vault element", "Status", "Assumption", "Evidence it works"], rows) + "\n")
    s = a.status_counts()
    out.append(f"**Overall:** {s['in_place']} in place, {s['partial']} partial, {s['gap']} gaps. {m.RESIDUAL_GLOBAL}")
    return "\n".join(out)


def sec_priorities(n=5):
    rows = []
    for i, r in enumerate(a.priority_table()[:n], 1):
        c = r["control"]
        rows.append([i, cname(c["id"]), vtitle(c["vault"]), STATUS_LABEL[c["status"]],
                     ", ".join(r["threats"]) or "-", r["edges"], f"{r['score']:g}"])
    return ("Ranked by: sum of the risk scores of the threats a control mitigates, plus 2 per attack-path edge it breaks; "
            "partial controls count half because less work remains.\n\n"
            + table(["Rank", "Control", "Vault element", "Status", "Threats mitigated", "Path edges broken", "Score"], rows))


def executive_summary():
    share, net, total = a.non_network_share()
    s = a.status_counts()
    top = a.priority_table()[:3]
    weak = " and ".join(r["title"].lower() for r in a.weakest_elements(2))
    asks = "\n".join(f"{i}. **{r['control']['name']}**." for i, r in enumerate(top, 1))
    return f"""A bank vault is not secured by its wall. It is secured by identity checks, dual authorization, cameras, alarms, logs and a plan for when something goes wrong. We reviewed our multi-cloud GenAI service the same way.

**What we protect.** The vault keys (secrets and API keys), staff badges (workload identities), the deposit boxes (customer data behind the AI) and the blueprints (source code and build pipelines).

**What we found.** Three realistic break-ins. In the first, our build system is compromised and borrows a powerful cloud key. In the second, a carefully worded question talks the AI into running something it should not. In the third, the key to our AI provider is stolen and used to run up costs. None of them needs to beat the wall; each walks around it.

**Where we stand.** The design has {total} controls across ten vault layers. The wall is only {net} of them, so {share:.0%} of our protection does not depend on the network. Today {s['in_place']} are fully in place, {s['partial']} are partial and {s['gap']} are gaps. The weakest layers are {weak}. Every step of all three break-ins has at least one control that stops it, and each break-in is covered by both prevention and detection or response.

**What we ask for.** Fund and complete, in this order:
{asks}

**What remains.** Even then, a trusted insider with real approval rights, or a new way of tricking the AI, could still cause harm. The aim is to make such events hard, visible and recoverable rather than impossible. We will re-score the risks once these are done."""


def sec_exec():
    return executive_summary()


# ------------------------------------------------------------------ assembly
def build():
    es = executive_summary()
    report = f"""# Multi-Cloud GenAI Threat Model: Security Architecture Review

*Fictional environment. User → Web/API → Identity → Azure/AWS/GCP workload → LLM service → RAG/data layer → CI/CD → monitoring.*
*Generated by `python run.py` from `capstone/model.py`; do not edit by hand.*

## The vault analogy

{sec_vault()}

## 1. Architecture and trust boundaries

{sec_architecture()}

## 2. Critical assets

{sec_assets()}

## 3. Threat register

{sec_threats()}

## 4. Three multi-step attack paths

{sec_paths()}

## 5. Prevent / detect / respond / recover control map

{sec_controls()}

## 6. Top remediation priorities

{sec_priorities()}

## 7. Executive summary

{es}
"""
    exec_doc = "# Executive Summary: GenAI Platform Security Review\n\n" + es + "\n"
    return {"docs/CAPSTONE_REPORT.md": report, "docs/EXECUTIVE_SUMMARY.md": exec_doc}, es
