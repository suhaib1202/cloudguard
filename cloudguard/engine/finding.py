from enum import Enum
from dataclasses import dataclass, field
from typing import List
import uuid


class Provider(str, Enum):
    AWS = "AWS"
    AZURE = "AZURE"
    GCP = "GCP"


class Severity(str, Enum):
    CRITICAL = "CRITICAL"
    HIGH = "HIGH"
    MEDIUM = "MEDIUM"
    LOW = "LOW"


class Status(str, Enum):
    PASS = "PASS"
    FAIL = "FAIL"


@dataclass
class Finding:
    check_id: str
    title: str
    provider: Provider
    service: str
    severity: Severity
    status: Status
    resource_id: str
    resource_name: str
    region: str
    description: str
    remediation: str

    finding_id: str = field(default_factory=lambda: str(uuid.uuid4()))
    risk_score: int = 0
    cis_controls: List[str] = field(default_factory=list)
    nist_controls: List[str] = field(default_factory=list)

    @property
    def is_failed(self) -> bool:
        return self.status == Status.FAIL

    def to_dict(self):
        return {
            "finding_id": self.finding_id,
            "check_id": self.check_id,
            "title": self.title,
            "provider": self.provider,
            "service": self.service,
            "severity": self.severity,
            "status": self.status,
            "resource_id": self.resource_id,
            "resource_name": self.resource_name,
            "region": self.region,
            "description": self.description,
            "remediation": self.remediation,
            "risk_score": self.risk_score,
            "cis_controls": self.cis_controls,
            "nist_controls": self.nist_controls,
        }