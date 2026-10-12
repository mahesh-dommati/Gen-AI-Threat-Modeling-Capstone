"""Day 8 - Attack path: exposed component -> initial access -> credential gain ->
privilege expansion -> target asset -> impact, with a control on each edge."""
import pandas as pd

PATH = [
    ("1. Exposed component -> Initial access",
     "Public App Orchestrator endpoint compromised via injection / input-validation flaw.",
     "WAF rules + strict runtime input schema validation."),
    ("2. Initial access -> Credential gain",
     "Attacker code in the container dumps environment variables / local tokens.",
     "Externalized secrets (Vault/Secret Manager) + read-only root filesystem."),
    ("3. Credential gain -> Privilege expansion",
     "Stolen keys used to enumerate cloud resources and find over-permissive admin roles.",
     "Short-lived, environment-bound OIDC workload identities; no static keys."),
    ("4. Privilege expansion -> Target asset",
     "Elevated privileges give read/write access to the Vector Database.",
     "Least-privilege IAM (no wildcards) + database segmentation."),
    ("5. Target asset -> Impact",
     "Bulk exfiltration of confidential customer data; compliance and reputation damage.",
     "DLP filters, egress anomaly detection, automatic query rate limiting."),
]


def main():
    pd.set_option("display.max_colwidth", None)
    df = pd.DataFrame(PATH, columns=["Edge", "Attacker action", "Breaking control"])
    print(df.to_string(index=False))


if __name__ == "__main__":
    main()
