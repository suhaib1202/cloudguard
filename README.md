\# CloudGuard — Multi-Cloud Security Auditor



Scans AWS, Azure, and GCP against CIS Benchmarks v3 and NIST SP 800-53 Rev 5.

Detects misconfigurations, scores risk 0-100, generates remediation playbooks.



!\[CloudGuard Report](screenshot(1).png)(screenshot(2).png)



\## Real Findings on a Live AWS Account

| Finding | Severity | Risk |

|---|---|---|

| Public S3 bucket (Policy) | CRITICAL | 95 |

| User has AdministratorAccess | CRITICAL | 100 |

| Unused IAM user | MEDIUM | 35 |



\## Checks Implemented

\- AWS-IAM: Root keys, MFA, password policy, overprivileged roles

\- AWS-S3: Public access, ACLs, versioning, encryption, logging

\- AWS-EC2: SSH/RDP open to internet, VPC flow logs, EBS encryption

\- AWS-CloudTrail: Multi-region, log validation, CloudWatch integration

\- Azure: Storage HTTPS, blob public access, RBAC, NSGs

\- GCP: Cloud Storage IAM, uniform access, compute external IPs



\## Quick Start

```bash

git clone https://github.com/suhaib1202/cloudguard.git

cd cloudguard

python -m venv venv \&\& venv\\Scripts\\activate

pip install -e .

cp .env.example .env

cloudguard quickcheck

cloudguard scan

```



\## Tech Stack

Python · boto3 · azure-sdk · google-cloud · Jinja2 · Click · Rich

