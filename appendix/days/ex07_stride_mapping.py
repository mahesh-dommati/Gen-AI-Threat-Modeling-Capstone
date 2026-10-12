"""Day 7 - One concrete threat per STRIDE category for the GenAI architecture."""
import pandas as pd

STRIDE = {
    "Spoofing": "Stolen OIDC/identity token used to impersonate the App orchestrator and query the Vector Data Store directly.",
    "Tampering": "Compromised ingestion pipeline injects poisoned context documents into the Vector Data Store.",
    "Repudiation": "Admin changes system prompts or LLM platform settings with no audit log recording the action.",
    "Information Disclosure": "Prompt injection bypasses orchestrator filters and leaks customer support transcripts.",
    "Denial of Service": "Flood of long, expensive generation requests exhausts API quota and rate limits.",
    "Elevation of Privilege": "Over-broad wildcard IAM on CI/CD service account is abused to gain global admin.",
}


def main():
    pd.set_option("display.max_colwidth", None)
    df = pd.DataFrame(list(STRIDE.items()), columns=["STRIDE", "Threat"])
    print(df.to_string(index=False))


if __name__ == "__main__":
    main()
