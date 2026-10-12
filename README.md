# Multi-Cloud GenAI Threat Model (Capstone)

A security architecture review of a fictional environment:

`User → Web/API → Identity → Azure/AWS/GCP workload → LLM service → RAG/data layer → CI/CD → monitoring`

## The idea: think like a bank vault

> A bank vault is an asset-protection system. The wall is only one control; identity checks, dual authorization, cameras, alarms, logs and incident response matter too.

Every control in this model is placed on one element of the vault. Only the wall is network security,
so the capstone rule "at least half of the controls come from non-network layers" is satisfied by design (85%)
and checked by code.

| Vault element | Technical layer |
|---|---|
| The wall | Network |
| Identity checks | Identity and secrets |
| Dual authorization | Least privilege, approvals, break-glass |
| Locked deposit boxes | Encryption, signed RAG sources, per-user retrieval |
| The teller window | Input/output guardrails, schema validation, rate limits |
| Reinforced interior | Container and runner hardening |
| Cameras | Telemetry |
| Alarms | Anomaly detection and alerting |
| The logbook | Immutable audit logs |
| Incident response | Revocation, isolation, rebuild, recovery |

## Deliverables (the 7 required sections)

| Section | Where |
|---|---|
| Full report: sections 1-7 | [`docs/CAPSTONE_REPORT.md`](docs/CAPSTONE_REPORT.md) |
| 7. One-page executive summary | [`docs/EXECUTIVE_SUMMARY.md`](docs/EXECUTIVE_SUMMARY.md) |

The report covers: 1 architecture and trust boundaries (with a diagram), 2 critical assets, 3 threat register
(all six STRIDE categories, risk-scored), 4 three multi-step attack paths with a control on every edge,
5 prevent/detect/respond/recover control map (each control lists its assumption and the evidence that proves it works),
6 top remediation priorities (computed), 7 executive summary.

## How it works

```
capstone/model.py      the single source of truth: controls, threats, paths, assets
capstone/analysis.py   derived numbers (risk, non-network share, priorities)
capstone/validate.py   13 rule checks (STRIDE complete, every edge broken, >=50% non-network, ...)
capstone/report.py     renders the Markdown documents
run.py                 regenerate docs/ and validate
appendix/              Day 1-9 exercises that led here
```

```bash
python run.py            # regenerate docs/ and run all checks (standard library only)
python run.py --check    # CI mode: fail if a check fails or docs/ are stale
```

To change the design, edit `capstone/model.py` (for example a control's `status`) and run `python run.py`.
The priorities and executive summary update automatically; nothing in the report is typed by hand.

## Put it on GitHub

```bash
git init -b main
git add .
git commit -m "GenAI threat model capstone"
git remote add origin https://github.com/<your-username>/multi-cloud-genai-threat-model.git
git push -u origin main
```

The included GitHub Action runs `python run.py --check` on every push.

All content is fictional sample data. Never commit real keys, tokens or customer data.
