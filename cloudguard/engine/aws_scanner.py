import boto3
from cloudguard.engine.finding import Finding, Severity, Status
from cloudguard.engine.advanced_scanner import scan_ec2, scan_rds, scan_lambda
from cloudguard.engine.anomaly import detect_anomalies


def scan_s3():
    findings = []

    s3 = boto3.client("s3")

    buckets = s3.list_buckets()["Buckets"]

    for bucket in buckets:
        bucket_name = bucket["Name"]

        # ✅ CHECK ACL (old method)
        try:
            acl = s3.get_bucket_acl(Bucket=bucket_name)

            for grant in acl["Grants"]:
                grantee = grant.get("Grantee", {})

                if grantee.get("URI") == "http://acs.amazonaws.com/groups/global/AllUsers":
                    findings.append(
                        Finding(
                            check_id="AWS-S3-REAL-001",
                            severity=Severity.CRITICAL,
                            provider="AWS",
                            service="S3",
                            title="Public S3 bucket (ACL)",
                            status=Status.FAIL,
                            resource_id=bucket_name,
                            resource_name=bucket_name,
                            region="global",
                            description="Bucket is public via ACL",
                            remediation="Remove public ACL access"
                        )
                    )
        except Exception:
            pass

        # ✅ CHECK BUCKET POLICY (modern method)
        try:
            policy = s3.get_bucket_policy(Bucket=bucket_name)
            policy_str = policy["Policy"]

            if '"Principal":"*"' in policy_str or '"Principal": "*"' in policy_str:
                findings.append(
                    Finding(
                        check_id="AWS-S3-REAL-002",
                        severity=Severity.CRITICAL,
                        provider="AWS",
                        service="S3",
                        title="Public S3 bucket (Policy)",
                        status=Status.FAIL,
                        resource_id=bucket_name,
                        resource_name=bucket_name,
                        region="global",
                        description="Bucket is public via policy",
                        remediation="Restrict bucket policy"
                    )
                )
        except Exception:
            pass

    return findings


def scan_security_groups():
    findings = []

    ec2 = boto3.client("ec2")

    response = ec2.describe_security_groups()

    for sg in response["SecurityGroups"]:
        for perm in sg["IpPermissions"]:
            for ip_range in perm.get("IpRanges", []):
                if ip_range.get("CidrIp") == "0.0.0.0/0":

                    findings.append(
                        Finding(
                            check_id="AWS-EC2-REAL-001",
                            severity=Severity.HIGH,
                            provider="AWS",
                            service="EC2",
                            title="Security Group open to world",
                            status=Status.FAIL,
                            resource_id=sg["GroupId"],
                            resource_name=sg["GroupName"],
                            region="unknown",
                            description="Port open to 0.0.0.0/0",
                            remediation="Restrict inbound rules"
                        )
                    )

    return findings


def run_aws_scan():
    findings = []

    print("🔍 Running AWS real scan...\n")

    # ✅ Existing scans (your current logic)
    findings.extend(scan_s3())
    findings.extend(scan_security_groups())
    findings.extend(scan_iam())

    # 🔥 ADD THIS PART HERE 👇
    findings.extend(scan_ec2())
    findings.extend(scan_rds())
    findings.extend(scan_lambda())

    # 🧠 Anomaly detection
    findings.extend(detect_anomalies())

    return findings


def scan_iam():
    findings = []

    iam = boto3.client("iam")

    # ✅ 1. Check root account access keys
    try:
        summary = iam.get_account_summary()["SummaryMap"]

        if summary.get("AccountAccessKeysPresent", 0) > 0:
            findings.append(
                Finding(
                    check_id="AWS-IAM-001",
                    severity=Severity.CRITICAL,
                    provider="AWS",
                    service="IAM",
                    title="Root account has active access keys",
                    status=Status.FAIL,
                    resource_id="root",
                    resource_name="root-account",
                    region="global",
                    description="Root account should not have access keys",
                    remediation="Delete root access keys immediately"
                )
            )
    except Exception:
        pass

    # ✅ 2. Check admin policies attached to users
    try:
        users = iam.list_users()["Users"]

        for user in users:
            username = user["UserName"]

            attached_policies = iam.list_attached_user_policies(UserName=username)

            for policy in attached_policies["AttachedPolicies"]:
                if policy["PolicyName"] == "AdministratorAccess":
                    findings.append(
                        Finding(
                            check_id="AWS-IAM-002",
                            severity=Severity.CRITICAL,
                            provider="AWS",
                            service="IAM",
                            title="User has AdministratorAccess",
                            status=Status.FAIL,
                            resource_id=username,
                            resource_name=username,
                            region="global",
                            description="User has full admin privileges",
                            remediation="Apply least privilege principle"
                        )
                    )
    except Exception:
        pass

    # ✅ 3. Check inline wildcard policies
    try:
        users = iam.list_users()["Users"]

        for user in users:
            username = user["UserName"]

            inline_policies = iam.list_user_policies(UserName=username)

            for policy_name in inline_policies["PolicyNames"]:
                policy = iam.get_user_policy(
                    UserName=username,
                    PolicyName=policy_name
                )

                policy_doc = str(policy["PolicyDocument"])

                if '"Action": "*"' in policy_doc or '"Action":"*"' in policy_doc:
                    findings.append(
                        Finding(
                            check_id="AWS-IAM-003",
                            severity=Severity.HIGH,
                            provider="AWS",
                            service="IAM",
                            title="User has wildcard (*) permissions",
                            status=Status.FAIL,
                            resource_id=username,
                            resource_name=username,
                            region="global",
                            description="User policy allows all actions",
                            remediation="Restrict policy permissions"
                        )
                    )
    except Exception:
        pass

    return findings