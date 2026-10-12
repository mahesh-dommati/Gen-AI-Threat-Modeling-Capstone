"""Day 4 - Data classification (encryption/access/logging) + RAG data-flow diagram."""
import pandas as pd

CLASSIFICATION = [
    {"item": "public product FAQ", "classification": "Public",
     "encryption_transit": "TLS 1.3", "encryption_rest": "Optional (standard AES-256)",
     "access_control": "Anonymous read", "logging_expectation": "CDN & web access logs (anonymized)"},
    {"item": "employee handbook", "classification": "Internal",
     "encryption_transit": "TLS 1.3 with enterprise SSO", "encryption_rest": "AES-256 with KMS",
     "access_control": "Authenticated employees", "logging_expectation": "IdP authentication & resource access logs"},
    {"item": "customer support transcript", "classification": "Confidential",
     "encryption_transit": "TLS 1.3 with PFS", "encryption_rest": "Customer-managed keys (CMK)",
     "access_control": "Role-based (support reps only)", "logging_expectation": "Detailed data access & export auditing"},
    {"item": "API secret", "classification": "Restricted",
     "encryption_transit": "mTLS only", "encryption_rest": "Envelope encryption / secret manager",
     "access_control": "Machine workload identities only", "logging_expectation": "Real-time access alerts & tamper logs"},
]

DATA_FLOW = """
[ User ]
   | 1. Prompt (TLS 1.3)
   v
[ App (Gateway / Orchestrator) ] --2. retrieval query--> [ RAG Engine ]
   ^                                                        | 3. vector search (mTLS)
   |                                                        v
   |                                                [ Vector Data Store ]
   |                                                        |
   +------------ 4. relevant chunks returned ---------------+
   |
   | 5. prompt + context (mTLS)
   v
[ LLM API (external / managed) ]
   |
   +-- 6. response --> App --> User  (validate output before returning)
"""


def main():
    pd.set_option("display.max_colwidth", None)
    print(pd.DataFrame(CLASSIFICATION).to_string(index=False))
    print("\n" + "=" * 30 + " DATA FLOW " + "=" * 30)
    print(DATA_FLOW)


if __name__ == "__main__":
    main()
