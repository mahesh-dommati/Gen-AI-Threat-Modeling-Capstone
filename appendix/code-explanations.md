# Appendix: explanations for Day 1–9 exercises

These are the building blocks. The capstone (Day 10) lives in `capstone/` and reuses their ideas:
risk scoring (Day 1) drives the threat register and priorities, permission review (Day 3) became control C08,
STRIDE (Day 7) shapes the threat register, attack paths (Day 8) became the three edge-by-edge paths, and the
prevent/detect/respond/recover gap analysis (Day 9) became the control map and status tracking.

## ex01 – Asset risk scoring
`assets` is a list of dicts, each with `likelihood` and `impact` on a 1–5 scale.
Risk score = likelihood × impact (max 25). Then the list is sorted descending so the
riskiest asset (`secrets`, 5×5 = 25) comes first.
- Notebook gotcha: `sorted(...)` was the last line, so Jupyter only *displayed* the result;
  the original `assets` list stayed unsorted. The repo version returns a new sorted list.

## ex02 – Controls matrix
A list of dicts, one per trust relationship (Developer→GitHub, App→LLM API). Each answers:
who owns it, what we assume can be compromised, how identity is verified, how privilege is
limited, what log proves it, and which part the cloud provider vs. you secures
(shared responsibility). `pandas.DataFrame` renders it as a table.

## ex03 – Permission review
`any("*" in p for p in perms)` flags `*` and `admin:*`. `build-runner` and `ops-admin` are
flagged; narrower alternatives (`repo:clone`, `registry:push`, ...) implement least privilege.
Note: the alternatives are sample values; real ones come from what the job actually calls.

## ex04 – Data classification and flow
Four classes (Public → Restricted) get progressively stronger encryption in transit/at rest,
tighter access and richer logging. The ASCII diagram shows
User → App → RAG → Vector store → App → LLM → User, with TLS/mTLS on each hop.

## ex05 – Abuse cases
Five abuse cases in "Given [capability], when [action], then [outcome]" form: prompt
injection, DoS/cost exhaustion, backdoored model, insecure output parser (RCE), model inversion.

## ex06 – Workload checklist
Eight items: image provenance, vulnerabilities, runtime privilege, secrets, patching,
workload identity, network exposure, telemetry. `done` starts as `False` so it works as an audit form.

## ex07 – STRIDE
Spoofing, Tampering, Repudiation, Information disclosure, Denial of service, Elevation of
privilege, each tied to a concrete threat in the architecture.

## ex08 – Attack path
Five edges from exposed component to business impact. Each edge has one control that breaks it,
which is the point of attack-path thinking: you only need to cut one edge to stop the chain.

## ex09 – Control gap analysis
Classifies controls into Prevent / Detect / Respond / Recover. The original only checked whether
each category had at least one control, so it printed "Active" for categories whose controls were
marked "Gaps Identified (Incomplete)". The repo version also counts implemented controls.
