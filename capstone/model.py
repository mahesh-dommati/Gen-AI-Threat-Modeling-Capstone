"""The capstone data: one source of truth for the whole threat model.

Analogy (the design principle of this repo):
    A bank vault is an asset-protection system. The wall is only one control;
    identity checks, dual authorization, cameras, alarms, logs and incident
    response matter too.

Every control is placed on one element of the vault. Only ONE element (the wall)
is network security, so the "at least half non-network" rule falls out of the design.

NOTE: this is a fictional environment. Control `status` values are an ASSUMED
baseline for the exercise; edit them to re-run the prioritisation.
"""

# ---------------------------------------------------------------- vault elements
VAULT = [
    # key, title, question the element answers, technical layer
    ("wall", "The wall", "Can the crowd get close? Necessary, never sufficient.", "Network"),
    ("identity", "Identity checks", "Who are you, really? Prove it every time.", "Identity & secrets"),
    ("dual_auth", "Dual authorization", "Can one person or one key open the vault alone? Never.", "Authorization & change control"),
    ("boxes", "Locked deposit boxes", "Inside the vault, does each box still have its own lock?", "Data protection"),
    ("teller", "The teller window", "Is everything passed through the window inspected?", "Application guardrails"),
    ("interior", "Reinforced interior", "If someone gets in, how little can they do?", "Host & runtime"),
    ("cameras", "Cameras", "Can we see what is happening everywhere?", "Telemetry"),
    ("alarms", "Alarms", "Does someone get told when behaviour looks wrong?", "Detection"),
    ("logs", "The logbook", "Is there a tamper-proof record of who did what?", "Audit evidence"),
    ("response", "Incident response", "Lockdown, guards, and a plan to reopen safely.", "Respond & recover"),
]

PHASES = ["prevent", "detect", "respond", "recover"]
STRIDE = ["Spoofing", "Tampering", "Repudiation", "Information Disclosure",
          "Denial of Service", "Elevation of Privilege"]


def C(cid, name, vault, phase, status, assumption, evidence):
    return {"id": cid, "name": name, "vault": vault, "phase": phase, "status": status,
            "assumption": assumption, "evidence": evidence}


# status: in_place | partial | gap
CONTROLS = [
    # --- the wall (network) ---
    C("C01", "WAF and API gateway request filtering", "wall", "prevent", "in_place",
      "Common attack patterns are recognisable at the edge.",
      "Blocked-request logs; scheduled test payloads are rejected."),
    C("C02", "Private endpoints for vector DB, secrets manager and LLM gateway", "wall", "prevent", "partial",
      "Data-tier services never need a public address.",
      "Cloud config scan shows no public IPs; external port scan finds nothing."),
    C("C03", "Egress allow-list to approved LLM endpoints, plus provider-side IP restriction on API keys", "wall", "prevent", "gap",
      "Workloads only ever talk to a short, known list of destinations.",
      "A pod calling an unapproved host is denied and logged; a stolen key fails from other IPs."),
    C("C04", "mTLS between orchestrator and data tier", "wall", "prevent", "partial",
      "Both ends of an internal call can present a valid certificate.",
      "Plain connections to the data tier are refused in a test."),
    # --- identity checks ---
    C("C05", "Hardware-MFA SSO with device posture for developers and admins", "identity", "prevent", "in_place",
      "Passwords and IP addresses alone are not proof of identity.",
      "IdP policy export; sign-in logs show no password-only logins."),
    C("C06", "Short-lived OIDC workload identity for runners and pods; no static keys", "identity", "prevent", "gap",
      "Anything long-lived will eventually be stolen.",
      "Credential inventory finds zero static cloud keys; tokens expire within an hour."),
    C("C07", "Secrets pulled from a vault at runtime; none in env vars or images", "identity", "prevent", "partial",
      "A dumped environment must not contain anything valuable.",
      "Secret scanning of code, images and live env finds nothing."),
    # --- dual authorization ---
    C("C08", "Least-privilege scoped roles; wildcard permissions blocked by policy-as-code in CI", "dual_auth", "prevent", "partial",
      "Every role can be described by the few actions its job really needs.",
      "CI fails on any role containing a wildcard; access review shows no admin-style roles on workloads."),
    C("C09", "Two-person approval for production, IAM and system-prompt changes", "dual_auth", "prevent", "partial",
      "No single insider or compromised account should be able to change production alone.",
      "Protected branch and environment settings; no change merged without a second approver."),
    C("C10", "Break-glass admin access: time-boxed, approved and alerted", "dual_auth", "prevent", "gap",
      "Emergencies happen, so standing admin rights are not needed.",
      "No standing admin accounts; every break-glass use has a ticket and an alert."),
    # --- locked deposit boxes ---
    C("C11", "Encryption at rest with customer-managed keys and separate key administrators", "boxes", "prevent", "in_place",
      "Whoever can read the storage should not automatically hold the key.",
      "KMS key policy review; storage admins cannot decrypt."),
    C("C12", "Signed, provenance-checked ingestion bundles for RAG sources", "boxes", "prevent", "gap",
      "Retrieved documents are only as trustworthy as their source.",
      "Unsigned or altered bundles are rejected at ingestion in a test."),
    C("C13", "Per-user retrieval authorization (document-level access checks at query time)", "boxes", "prevent", "partial",
      "The model must never see more than the asking user may see.",
      "A test user cannot retrieve another team's documents, even by prompt."),
    # --- teller window ---
    C("C14", "Independent input and output guardrails (separate validator)", "teller", "prevent", "gap",
      "The main model can be talked out of its instructions; a second check cannot be talked out of the same way.",
      "Red-team prompt suite; measured bypass rate tracked over time."),
    C("C15", "Deterministic schema validation; LLM output is never executed raw", "teller", "prevent", "gap",
      "Model output is untrusted input to every downstream system.",
      "Code review and tests show no path from model text to a shell, SQL or eval."),
    C("C16", "Per-client rate limits and per-key spend caps", "teller", "prevent", "partial",
      "One caller should not be able to consume everyone's capacity or budget.",
      "Load test hits the limit and is throttled; billing alert at the cap."),
    # --- reinforced interior ---
    C("C17", "Non-root containers, read-only root filesystem, dropped capabilities", "interior", "prevent", "gap",
      "Some application bug will eventually be exploitable.",
      "Admission policy rejects any pod that runs as root or writes to its root filesystem."),
    C("C18", "Ephemeral isolated build runners; signed and scanned images only", "interior", "prevent", "partial",
      "A build environment is a target, so it should hold nothing and live briefly.",
      "Runners are destroyed after each job; unsigned images fail admission."),
    # --- cameras ---
    C("C19", "Central structured telemetry from app, IAM, gateway, CI/CD and LLM calls", "cameras", "detect", "partial",
      "You cannot investigate what you never recorded.",
      "Every tier has a log source in the SIEM; gaps are reported weekly."),
    # --- alarms ---
    C("C20", "Anomaly alerts: LLM credential use, egress volume (DLP), privileged role use outside pipelines", "alarms", "detect", "partial",
      "Attackers behave differently from normal users and pipelines.",
      "Simulated stolen-key use and bulk export each raise an alert within minutes."),
    C("C21", "Alerts on admin, system-prompt and break-glass changes", "alarms", "detect", "gap",
      "Sensitive changes are rare enough to alert on every one.",
      "A test change to a system prompt produces an alert naming the actor."),
    # --- logbook ---
    C("C22", "Immutable audit logs in a separate account, tied to named identities", "logs", "detect", "in_place",
      "Whoever is compromised must not be able to erase their own tracks.",
      "WORM retention setting; log-account permissions exclude workload roles."),
    # --- incident response ---
    C("C23", "Automated token and API-key revocation playbook", "response", "respond", "partial",
      "Speed matters more than perfection once a credential leaks.",
      "Game-day: a leaked key is revoked in minutes, with no manual hunting."),
    C("C24", "Automated isolation of compromised container instances", "response", "respond", "gap",
      "A suspect workload should be cut off first and examined second.",
      "Test alert quarantines a pod and keeps forensic state."),
    C("C25", "Rebuild and redeploy from immutable IaC and signed artifacts", "response", "recover", "partial",
      "A rebuilt environment is more trustworthy than a cleaned one.",
      "Quarterly rebuild from scratch succeeds within the target time."),
    C("C26", "Point-in-time database recovery from isolated backups", "response", "recover", "in_place",
      "Backups survive the same compromise as the primary only if they share credentials.",
      "Restore test completed; backup account has separate credentials."),
    C("C27", "Key rotation runbook, rehearsed every quarter", "response", "recover", "gap",
      "After an incident, every secret that might have been seen is replaced.",
      "Last rehearsal date and duration recorded; zero manual-only steps."),
]

# ---------------------------------------------------------------- architecture
BOUNDARIES = [
    {"id": "TB1", "from": "User", "to": "Web/API gateway", "note": "Public internet to application gateway (TLS termination)", "controls": ["C01", "C16"]},
    {"id": "TB2", "from": "Web/API", "to": "Identity provider", "note": "SAML/OIDC token exchange", "controls": ["C05"]},
    {"id": "TB3", "from": "Identity", "to": "Azure/AWS/GCP workload", "note": "Role assignment at the compute runtime", "controls": ["C06", "C08"]},
    {"id": "TB4", "from": "Workload", "to": "LLM service", "note": "Egress to an external managed API", "controls": ["C03", "C07"]},
    {"id": "TB5", "from": "Workload", "to": "RAG / data layer", "note": "Private database authorization", "controls": ["C02", "C04", "C13"]},
    {"id": "TB6", "from": "CI/CD", "to": "Cloud infrastructure", "note": "Privileged deployment runner", "controls": ["C09", "C18", "C06"]},
    {"id": "TB7", "from": "All tiers", "to": "Monitoring", "note": "Log pipeline into immutable storage and alerting", "controls": ["C19", "C22"]},
]

ASSETS = [
    {"id": "A1", "name": "Secrets and API keys", "location": "External secret vault / enveloped KMS",
     "impact": "Critical: total platform compromise", "vault_equiv": "The vault combination and keys"},
    {"id": "A2", "name": "Workload OIDC identity tokens", "location": "Workload pod identity / IAM roles",
     "impact": "High: access to downstream resources", "vault_equiv": "Staff badges"},
    {"id": "A3", "name": "Customer data in vector database", "location": "Vector data store (NoSQL index)",
     "impact": "High: compliance penalties, data leak", "vault_equiv": "Contents of the deposit boxes"},
    {"id": "A4", "name": "Source code and CI/CD pipelines", "location": "GitHub Enterprise / build runners",
     "impact": "High: supply-chain compromise", "vault_equiv": "Vault blueprints and the construction crew"},
]

# ---------------------------------------------------------------- threats
def T(tid, stride, title, asset, boundary, likelihood, impact, controls):
    return {"id": tid, "stride": stride, "title": title, "asset": asset, "boundary": boundary,
            "likelihood": likelihood, "impact": impact, "controls": controls}


THREATS = [
    T("T1", "Spoofing", "Stolen workload token used to impersonate the backend to the LLM or data tier", "A2", "TB3", 3, 4, ["C06", "C04", "C20"]),
    T("T2", "Tampering", "Poisoned documents enter the RAG store through an insecure ingestion flow", "A3", "TB5", 3, 4, ["C12", "C09", "C22"]),
    T("T3", "Repudiation", "An admin edits system prompts or LLM settings and no attributable log exists", "A4", "TB7", 3, 3, ["C22", "C21", "C09"]),
    T("T4", "Information Disclosure", "Prompt injection makes the model reveal other customers' data", "A3", "TB5", 4, 5, ["C14", "C13", "C20"]),
    T("T5", "Denial of Service", "Token-flooding requests exhaust API limits and cloud budget", "A1", "TB1", 4, 3, ["C16", "C01", "C20"]),
    T("T6", "Elevation of Privilege", "Wildcard IAM on a CI/CD service account is abused to gain cloud admin", "A4", "TB6", 3, 5, ["C08", "C06", "C09", "C21"]),
    T("T7", "Information Disclosure", "LLM API key read from environment variables after an app compromise", "A1", "TB4", 4, 4, ["C07", "C03", "C20", "C23"]),
    T("T8", "Tampering", "A compromised build pipeline ships a malicious image", "A4", "TB6", 3, 5, ["C18", "C09", "C25"]),
    T("T9", "Elevation of Privilege", "Model output is executed by a vulnerable parser, giving code execution", "A2", "TB3", 3, 5, ["C15", "C17", "C24"]),
]

# ---------------------------------------------------------------- attack paths
def PATH(pid, name, heist, steps, edge_controls, residual, plain):
    assert len(edge_controls) == len(steps) - 1, f"{pid}: need one control list per edge"
    edges = [{"from": steps[i], "to": steps[i + 1], "controls": edge_controls[i]} for i in range(len(steps) - 1)]
    return {"id": pid, "name": name, "heist": heist, "steps": steps, "edges": edges,
            "residual": residual, "plain": plain}


PATHS = [
    PATH("A", "Supply chain to cloud compromise", "The inside job",
         ["CI/CD runner compromised", "Cloud credential obtained", "Admin-level cloud access",
          "Production DB config modified", "Customer data exfiltrated"],
         [["C18", "C06"], ["C08", "C20"], ["C09", "C10", "C21"], ["C11", "C20", "C23"]],
         "A malicious change that two approvers both miss, or a determined insider with legitimate access.",
         "Someone tampers with the construction crew's tools, borrows a master key, and walks out with the boxes. "
         "We make the key short-lived, make one key unable to do everything, and require a second signature."),
    PATH("B", "Prompt injection to code execution", "The smooth talker",
         ["Public API endpoint", "Malicious prompt accepted", "Guardrails ignored by the LLM",
          "Output parser executes generated script", "Code execution on the container"],
         [["C01", "C16"], ["C14", "C20"], ["C15"], ["C17", "C24"]],
         "New injection techniques will bypass any single guardrail; the schema check (C15) must stay deterministic.",
         "A customer talks the teller into handing something over the counter. "
         "We inspect what goes through the window and never let anything said at the window open a door."),
    PATH("C", "LLM API key theft", "The pickpocket",
         ["Application vulnerability exploited", "Environment variables dumped", "Third-party LLM API key stolen",
          "Key used from attacker infrastructure", "Corporate quota and budget depleted"],
         [["C17"], ["C07"], ["C03", "C20"], ["C16", "C23"]],
         "A key that is stolen and used quickly from an allowed network location before an alert fires.",
         "A thief lifts a badge from a coat pocket. We stop leaving badges in coat pockets, make badges work only "
         "from known doors, and cap how much any badge can spend."),
]

# ---------------------------------------------------------------- narrative bits
RESIDUAL_GLOBAL = (
    "Detection and response controls are the least mature part of the design, and the plan assumes "
    "they will be tested rather than merely configured. Novel LLM attack techniques will outpace any fixed rule set."
)
