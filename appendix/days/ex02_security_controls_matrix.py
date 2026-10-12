"""Day 2 - Per-component control matrix: owner, trust assumption, verification,
least privilege, logging evidence, shared responsibility."""
import pandas as pd

CONTROLS = [
    {
        "component": "Developer → GitHub",
        "owner": "Security Ops & Engineering Leads",
        "trust_assumption": "Assume developer workstations can be compromised; do not trust IP alone.",
        "verification_mechanism": "Developer SSO with Hardware MFA + device posture compliance.",
        "least_privilege_control": "Repository-specific read/write roles (no admin access by default).",
        "logging_evidence": "GitHub Enterprise audit logs, Okta authentication logs.",
        "shared_responsibility": "Provider (GitHub): platform security. Customer: access management, branch protection, credential auditing.",
    },
    {
        "component": "App → LLM API",
        "owner": "DevOps & Backend Platform Team",
        "trust_assumption": "Assume the app runtime is susceptible to threats; no long-lived static API keys.",
        "verification_mechanism": "OIDC / Workload Identity Federation with short-lived tokens.",
        "least_privilege_control": "Scoped IAM role: specific model invocation only, no admin actions.",
        "logging_evidence": "Cloud IAM access logs, API gateway invocation logs.",
        "shared_responsibility": "Provider: IAM control plane and infrastructure. Customer: tight role scoping, usage auditing.",
    },
]


def main():
    pd.set_option("display.max_colwidth", None)
    print(pd.DataFrame(CONTROLS).T.to_string())


if __name__ == "__main__":
    main()
