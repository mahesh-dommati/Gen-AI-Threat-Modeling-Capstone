"""Day 1 - Asset risk scoring: risk = likelihood x impact (1-5 scale each)."""

ASSETS = [
    {"asset": "LLM API endpoint", "likelihood": 3, "impact": 4},
    {"asset": "Identity token", "likelihood": 4, "impact": 5},
    {"asset": "Vector database", "likelihood": 3, "impact": 5},
    {"asset": "CI/CD pipeline", "likelihood": 3, "impact": 5},
    {"asset": "source code", "likelihood": 4, "impact": 5},
    {"asset": "secrets", "likelihood": 5, "impact": 5},
    {"asset": "customer data", "likelihood": 4, "impact": 5},
    {"asset": "cloud infrastructure", "likelihood": 3, "impact": 5},
]


def score(assets):
    """Return a NEW sorted list (highest risk first) without mutating the input."""
    scored = [{**a, "risk_score": a["likelihood"] * a["impact"]} for a in assets]
    return sorted(scored, key=lambda x: x["risk_score"], reverse=True)


def main():
    print("=== Asset Risk Ranking ===")
    for a in score(ASSETS):
        print(f'{a["asset"]:22} L={a["likelihood"]} I={a["impact"]}  risk={a["risk_score"]}')


if __name__ == "__main__":
    main()
