def check_s3_public_buckets(s3):
    findings = []

    buckets = s3.list_buckets()["Buckets"]

    for bucket in buckets:
        name = bucket["Name"]

        try:
            acl = s3.get_bucket_acl(Bucket=name)

            for grant in acl["Grants"]:
                grantee = grant.get("Grantee", {})

                if "URI" in grantee and "AllUsers" in grantee["URI"]:
                    findings.append({
                        "check_id": "AWS-S3-001",
                        "service": "S3",
                        "resource": name,
                        "issue": "Public S3 bucket",
                        "severity": "CRITICAL"
                    })

        except Exception:
            pass

    return findings