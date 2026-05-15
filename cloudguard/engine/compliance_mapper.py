from cloudguard.engine.finding import Finding


CIS_MAPPING = {
    "AWS-S3-001": ["CIS AWS 1.1"],
    "AWS-S3-002": ["CIS AWS 1.2"],
    "AWS-EC2-001": ["CIS AWS 2.1"],
    "AWS-EC2-002": ["CIS AWS 2.2"],
    "AWS-IAM-001": ["CIS AWS 1.4"],
}


NIST_MAPPING = {
    "AWS-S3-001": ["NIST AC-3"],
    "AWS-S3-002": ["NIST SC-28"],
    "AWS-EC2-001": ["NIST AC-4"],
    "AWS-EC2-002": ["NIST AC-17"],
    "AWS-IAM-001": ["NIST IA-5"],
}


def get_controls(check_id):
    return (
        CIS_MAPPING.get(check_id, []),
        NIST_MAPPING.get(check_id, []),
    )


def enrich_findings(findings):
    for f in findings:
        cis, nist = get_controls(f.check_id)
        f.cis_controls = cis
        f.nist_controls = nist