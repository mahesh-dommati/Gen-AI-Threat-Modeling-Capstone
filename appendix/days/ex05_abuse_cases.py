"""Day 5 - GenAI API abuse cases: Given [capability], when [action], then [outcome]."""

ABUSE_CASES = [
    ("an attacker capable of submitting arbitrary prompts",
     "they inject system-override instructions (prompt injection)",
     "the model ignores its guardrails and outputs restricted or harmful content"),
    ("an attacker with network access to the LLM API",
     "they send high-frequency automated requests (resource exhaustion)",
     "legitimate users are denied service and API costs inflate"),
    ("an attacker able to submit prompts containing crafted trigger words",
     "they query a backdoored model",
     "pre-planted malicious behavior fires (e.g., leaking confidential keys)"),
    ("an attacker who can supply highly structured input",
     "they exploit a vulnerable parser that handles model output",
     "arbitrary code executes on the application server (RCE)"),
    ("an attacker with read access to generated responses",
     "they run extensive model-inversion / extraction queries",
     "private training data or RAG context chunks are reconstructed"),
]


def main():
    for i, (given, when, then) in enumerate(ABUSE_CASES, 1):
        print(f"{i}. Given {given}, when {when}, then {then}.")


if __name__ == "__main__":
    main()
