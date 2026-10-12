"""Day 9 - Classify controls (Prevent/Detect/Respond/Recover) and find gaps.

Improvement over the notebook: gaps are judged on BOTH coverage (is the category
populated?) and maturity (is each control actually Implemented?).
"""
import pandas as pd

PORTFOLIO = [
    {"Control": "Hardware MFA & SSO", "Category": "Prevent", "Status": "Implemented"},
    {"Control": "Least-Privilege Role Policies", "Category": "Prevent", "Status": "Implemented"},
    {"Control": "Structured Audit Logging", "Category": "Detect", "Status": "Implemented"},
    {"Control": "Real-Time Anomaly Alerting", "Category": "Detect", "Status": "Incomplete"},
    {"Control": "Token Revocation Playbook", "Category": "Respond", "Status": "Incomplete"},
    {"Control": "Automated Safe Redeployment", "Category": "Recover", "Status": "Incomplete"},
]
CATEGORIES = ["Prevent", "Detect", "Respond", "Recover"]


def analyze(portfolio):
    df = pd.DataFrame(portfolio)
    rows = []
    for cat in CATEGORIES:
        sub = df[df["Category"] == cat]
        total = len(sub)
        done = int((sub["Status"] == "Implemented").sum())
        if total == 0:
            verdict = "GAP: no controls"
        elif done == 0:
            verdict = "GAP: nothing implemented yet"
        elif done < total:
            verdict = "PARTIAL"
        else:
            verdict = "OK"
        rows.append({"Category": cat, "Mapped": total, "Implemented": done, "Verdict": verdict})
    return pd.DataFrame(rows)


def main():
    print(pd.DataFrame(PORTFOLIO).to_string(index=False))
    print("\n=== Coverage & maturity ===")
    print(analyze(PORTFOLIO).to_string(index=False))
    print("\nA system with only preventive controls is fragile: when prevention fails "
          "(e.g., token theft), detection, response and recovery limit the damage.")


if __name__ == "__main__":
    main()
