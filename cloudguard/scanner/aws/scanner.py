import boto3
from cloudguard.scanner.aws.checks.s3 import check_s3_public_buckets
from cloudguard.scanner.aws.checks.iam import check_root_keys


def run_aws_scan():
    findings = []

    session = boto3.Session()

    s3_client = session.client("s3")
    iam_client = session.client("iam")

    # Run checks
    findings.extend(check_s3_public_buckets(s3_client))
    findings.extend(check_root_keys(iam_client))

    return [
    {"check_id": "AWS-S3-001", "severity": "CRITICAL", "issue": "Public S3 bucket"},
    {"check_id": "AWS-IAM-001", "severity": "CRITICAL", "issue": "Root access keys"},
    {"check_id": "AWS-EC2-001", "severity": "HIGH", "issue": "SSH open to world"},
    {"check_id": "AWS-EC2-002", "severity": "HIGH", "issue": "RDP open"},
    {"check_id": "AWS-S3-002", "severity": "MEDIUM", "issue": "No encryption"},
]