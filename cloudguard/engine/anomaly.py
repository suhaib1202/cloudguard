import boto3
from cloudguard.engine.finding import Finding, Severity, Status


def detect_anomalies():
    findings = []
    iam = boto3.client("iam")

    try:
        users = iam.list_users()["Users"]

        for u in users:
            if not u.get("PasswordLastUsed"):
                findings.append(Finding(
                    check_id="AWS-IAM-ANOM-001",
                    severity=Severity.MEDIUM,
                    provider="AWS",
                    service="IAM",
                    title="Unused IAM user",
                    status=Status.FAIL,
                    resource_id=u["UserName"],
                    resource_name=u["UserName"],
                    region="global",
                    description="User never used",
                    remediation="Remove unused users"
                ))

    except Exception:
        pass

    return findings