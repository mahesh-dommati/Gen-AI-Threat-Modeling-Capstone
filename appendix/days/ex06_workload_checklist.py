"""Day 6 - Container/workload security checklist (status flags start False)."""
import pandas as pd

CHECKLIST = {
    "Image provenance": "Base images are signed and come only from trusted, verified registries.",
    "Known vulnerabilities reviewed": "Scan images in CI/CD; block deployment on critical CVEs.",
    "Runs as least privilege": "Non-root user, read-only root filesystem, dropped capabilities.",
    "Secrets externalized": "No secrets in code or images; use an external vault.",
    "Patching strategy": "Automated rebuilds continuously apply OS/runtime patches to base images.",
    "Workload identity scoped": "Short-lived, environment-bound tokens (OIDC) instead of static keys.",
    "Network exposure minimized": "Strict ingress/egress policies and segmentation; TLS in transit.",
    "Telemetry enabled": "Structured audit logs, API rate metrics and traces to spot anomalies.",
}


def build_table():
    return pd.DataFrame(
        [{"control": k, "done": False, "description": v} for k, v in CHECKLIST.items()]
    )


def main():
    pd.set_option("display.max_colwidth", None)
    print(build_table().to_string(index=False))


if __name__ == "__main__":
    main()
