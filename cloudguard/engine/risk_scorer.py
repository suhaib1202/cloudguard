from typing import List
from cloudguard.engine.finding import Finding, Severity, Status


SEVERITY_WEIGHTS = {
    Severity.CRITICAL: 40,
    Severity.HIGH: 30,
    Severity.MEDIUM: 20,
    Severity.LOW: 10,
}


class RiskScorer:

    def score(self, finding: Finding) -> int:
        base = SEVERITY_WEIGHTS.get(finding.severity, 0)

        title = finding.title.lower()

        # Strong boost for dangerous exposure
        if "public" in title or "open" in title or "exposed" in title:
            base += 40

        return min(base, 100)

    def score_all(self, findings: List[Finding]) -> List[Finding]:
        for f in findings:
            f.risk_score = self.score(f)
        return findings


class RiskScorer:

    def score_all(self, findings):
        for f in findings:
            if f.severity.name == "CRITICAL":
                f.risk_score = 80
            elif f.severity.name == "HIGH":
                f.risk_score = 70
            elif f.severity.name == "MEDIUM":
                f.risk_score = 20
            else:
                f.risk_score = 10


def compute_account_risk(findings):
    critical = sum(1 for f in findings if f.severity.name == "CRITICAL")
    high = sum(1 for f in findings if f.severity.name == "HIGH")
    medium = sum(1 for f in findings if f.severity.name == "MEDIUM")

    total = len(findings)

    overall_score = min(100, critical * 40 + high * 30 + medium * 20)

    return {
        "critical": critical,
        "high": high,
        "medium": medium,
        "total": total,
        "overall_score": overall_score
    }