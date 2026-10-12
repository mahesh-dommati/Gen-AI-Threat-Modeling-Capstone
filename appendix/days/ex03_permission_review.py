"""Day 3 - Permission review: flag wildcard/admin privileges, propose narrower ones."""

PERMISSIONS = {
    "genai-app": ["model:invoke", "storage:read"],
    "build-runner": ["*"],        # full access to every action
    "analyst": ["logs:read"],
    "ops-admin": ["admin:*"],     # unbounded admin
}

PROPOSED = {
    "build-runner": ["repo:clone", "registry:push", "cache:write"],
    "ops-admin": ["user:provision", "billing:read", "monitoring:write"],
}


def is_risky(perms):
    return any("*" in p for p in perms)


def main():
    print("=== Permission Review ===")
    for principal, perms in PERMISSIONS.items():
        status = "REVIEW REQUIRED (wildcard)" if is_risky(perms) else "Bounded"
        print(f"{principal:12} | {status:27} | {perms}")
        if is_risky(perms) and principal in PROPOSED:
            print(f"{'':12} | -> narrower: {PROPOSED[principal]}")


if __name__ == "__main__":
    main()
