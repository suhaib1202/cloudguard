import boto3
from cloudguard.engine.finding import Finding, Severity, Status


def scan_ec2():
    findings = []
    ec2 = boto3.client("ec2")

    try:
        groups = ec2.describe_security_groups()["SecurityGroups"]

        for g in groups:
            for perm in g.get("IpPermissions", []):
                for ip in perm.get("IpRanges", []):
                    if ip.get("CidrIp") == "0.0.0.0/0":
                        findings.append(Finding(
                            check_id="AWS-EC2-OPEN-001",
                            severity=Severity.HIGH,
                            provider="AWS",
                            service="EC2",
                            title="Security group open to world",
                            status=Status.FAIL,
                            resource_id=g["GroupId"],
                            resource_name=g["GroupName"],
                            region="unknown",
                            description="Port open to 0.0.0.0/0",
                            remediation="Restrict access"
                        ))
    except Exception:
        pass

    return findings


def scan_rds():
    findings = []
    rds = boto3.client("rds")

    try:
        dbs = rds.describe_db_instances()["DBInstances"]

        for db in dbs:
            if db.get("PubliclyAccessible"):
                findings.append(Finding(
                    check_id="AWS-RDS-001",
                    severity=Severity.HIGH,
                    provider="AWS",
                    service="RDS",
                    title="RDS publicly accessible",
                    status=Status.FAIL,
                    resource_id=db["DBInstanceIdentifier"],
                    resource_name=db["DBInstanceIdentifier"],
                    region="unknown",
                    description="Database exposed to internet",
                    remediation="Disable public access"
                ))
    except Exception:
        pass

    return findings


def scan_lambda():
    findings = []
    lam = boto3.client("lambda")

    try:
        funcs = lam.list_functions()["Functions"]

        for f in funcs:
            if f.get("Environment"):
                findings.append(Finding(
                    check_id="AWS-LAMBDA-001",
                    severity=Severity.MEDIUM,
                    provider="AWS",
                    service="Lambda",
                    title="Lambda has environment variables",
                    status=Status.FAIL,
                    resource_id=f["FunctionName"],
                    resource_name=f["FunctionName"],
                    region="unknown",
                    description="May expose secrets",
                    remediation="Encrypt env variables"
                ))
    except Exception:
        pass

    return findings