def apply_ai_risk(findings):
    """
    Enhance risk scoring using simple AI-like logic
    """

    # Count types of findings
    has_public_s3 = any("S3" in f.service and "Public" in f.title for f in findings)
    has_admin_user = any("AdministratorAccess" in f.title for f in findings)

    for f in findings:

        # 🔥 Rule 1: Combination risk (very important)
        if has_public_s3 and has_admin_user:
            f.risk_score += 10
            f.ai_flag = "🔥 Combined Risk: Public Data + Admin Access"

        # 🔥 Rule 2: Critical stacking
        if f.severity.name == "CRITICAL":
            f.risk_score += 5

        # 🔥 Rule 3: Sensitive service boost
        if f.service == "IAM":
            f.risk_score += 5

        # Cap score
        if f.risk_score > 100:
            f.risk_score = 100

    return findings