"""Unit tests for the CloudGuard engine."""
import pytest
from cloudguard.engine.finding import Finding, Provider, Severity, Status
from cloudguard.engine.risk_scorer import RiskScorer, compute_account_risk
from cloudguard.engine.compliance_mapper import get_controls, enrich_findings


def _make_finding(severity=Severity.HIGH, status=Status.FAIL, check_id="AWS-S3-001"):
    return Finding(
        check_id      = check_id,
        title         = "Test finding",
        provider      = Provider.AWS,
        service       = "S3",
        severity      = severity,
        status        = status,
        resource_id   = "arn:aws:s3:::my-bucket",
        resource_name = "my-bucket",
        region        = "us-east-1",
        description   = "A test finding.",
        remediation   = "Fix it.",
    )


class TestFinding:
    def test_is_failed(self):
        f = _make_finding(status=Status.FAIL)
        assert f.is_failed is True

    def test_is_not_failed(self):
        f = _make_finding(status=Status.PASS)
        assert f.is_failed is False

    def test_to_dict_has_all_keys(self):
        d = _make_finding().to_dict()
        for key in ["check_id", "severity", "provider", "risk_score", "remediation"]:
            assert key in d

    def test_unique_finding_ids(self):
        f1 = _make_finding()
        f2 = _make_finding()
        assert f1.finding_id != f2.finding_id


class TestRiskScorer:
    def test_critical_public_bucket_scores_high(self):
        f = _make_finding(severity=Severity.CRITICAL)
        f.title = "S3 bucket publicly open"
        score = RiskScorer().score(f)
        assert score > 70

    def test_low_finding_scores_low(self):
        f = _make_finding(severity=Severity.LOW)
        score = RiskScorer().score(f)
        assert score < 30

    def test_score_clamped_to_100(self):
        f = _make_finding(severity=Severity.CRITICAL)
        f.title = "public exposed unrestricted open AllUsers"
        f.service = "S3"
        score = RiskScorer().score(f)
        assert score <= 100

    def test_score_all_returns_same_list(self):
        findings = [_make_finding() for _ in range(5)]
        result = RiskScorer().score_all(findings)
        assert result is findings
        assert all(f.risk_score > 0 for f in result)


class TestComplianceMapper:
    def test_known_check_returns_controls(self):
        cis, nist = get_controls("AWS-S3-001")
        assert len(cis) > 0
        assert len(nist) > 0
        assert any("CIS AWS" in c for c in cis)

    def test_unknown_check_returns_empty(self):
        cis, nist = get_controls("UNKNOWN-999")
        assert cis == []
        assert nist == []

    def test_enrich_findings_in_place(self):
        f = _make_finding(check_id="AWS-IAM-001")
        enrich_findings([f])
        assert len(f.cis_controls) > 0
        assert len(f.nist_controls) > 0


class TestAccountRisk:
    def test_no_failures_zero_score(self):
        findings = [_make_finding(status=Status.PASS)]
        summary = compute_account_risk(findings)
        assert summary["overall_score"] == 0.0
        assert summary["critical_count"] == 0

    def test_all_critical_high_score(self):
        findings = [_make_finding(severity=Severity.CRITICAL, status=Status.FAIL) for _ in range(5)]
        RiskScorer().score_all(findings)
        summary = compute_account_risk(findings)
        assert summary["critical_count"] == 5
        assert summary["overall_score"] > 0