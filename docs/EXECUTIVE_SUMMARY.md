# Executive Summary: GenAI Platform Security Review

A bank vault is not secured by its wall. It is secured by identity checks, dual authorization, cameras, alarms, logs and a plan for when something goes wrong. We reviewed our multi-cloud GenAI service the same way.

**What we protect.** The vault keys (secrets and API keys), staff badges (workload identities), the deposit boxes (customer data behind the AI) and the blueprints (source code and build pipelines).

**What we found.** Three realistic break-ins. In the first, our build system is compromised and borrows a powerful cloud key. In the second, a carefully worded question talks the AI into running something it should not. In the third, the key to our AI provider is stolen and used to run up costs. None of them needs to beat the wall; each walks around it.

**Where we stand.** The design has 27 controls across ten vault layers. The wall is only 4 of them, so 85% of our protection does not depend on the network. Today 5 are fully in place, 12 are partial and 10 are gaps. The weakest layers are dual authorization and the teller window. Every step of all three break-ins has at least one control that stops it, and each break-in is covered by both prevention and detection or response.

**What we ask for.** Fund and complete, in this order:
1. **Anomaly alerts: LLM credential use, egress volume (DLP), privileged role use outside pipelines**.
2. **Short-lived OIDC workload identity for runners and pods; no static keys**.
3. **Two-person approval for production, IAM and system-prompt changes**.

**What remains.** Even then, a trusted insider with real approval rights, or a new way of tricking the AI, could still cause harm. The aim is to make such events hard, visible and recoverable rather than impossible. We will re-score the risks once these are done.
