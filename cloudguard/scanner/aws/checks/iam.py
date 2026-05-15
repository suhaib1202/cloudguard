def check_root_keys(iam):
    findings = []

    try:
        summary = iam.get_account_summary()["SummaryMap"]

        if summary.get("AccountAccessKeysPresent", 0) > 0:
            findings.append({
                "check_id": "AWS-IAM-001",
                "service": "IAM",
                "resource": "root-account",
                "issue": "Root account has access keys",
                "severity": "CRITICAL"
            })

    except Exception:
        pass

    return findings