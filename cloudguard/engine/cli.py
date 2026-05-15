import click

from cloudguard.engine.finding import Finding, Severity, Status
from cloudguard.engine.risk_scorer import RiskScorer, compute_account_risk
from cloudguard.engine.compliance_mapper import enrich_findings
from cloudguard.engine.reporter.report_generator import generate_html_report
from cloudguard.engine.aws_scanner import run_aws_scan
from cloudguard.engine.ai_risk import apply_ai_risk


@click.group()
def cli():
    """CloudGuard CLI"""
    pass


@cli.command()
def quickcheck():
    """Check if CLI is working"""
    click.echo("✅ CloudGuard CLI is working!")
    click.echo("AWS ✓ Authenticated (simulated)")


@cli.command()
@click.option("--no-azure", is_flag=True, help="Skip Azure scan")
@click.option("--no-gcp", is_flag=True, help="Skip GCP scan")
@click.option("--company", default="Demo Corp", help="Company name")
def scan(no_azure, no_gcp, company):
    """Run cloud security scan"""

    click.echo("🔍 Running AWS real scan...\n")

    findings = run_aws_scan()

    if not findings:
        click.echo("✅ No issues found in AWS (or no resources accessible)\n")
        return

    scorer = RiskScorer()
    scorer.score_all(findings)
    findings = apply_ai_risk(findings)

    enrich_findings(findings)

    summary = compute_account_risk(findings)

    click.echo(
        f"AWS - {summary['critical']} critical  "
        f"{summary['high']} high  "
        f"{summary['medium']} medium  "
        f"({summary['total']} total)\n"
    )

    click.echo(f"Risk Score: {summary['overall_score']}/100\n")

    click.echo("Check ID   | Severity | Provider | Title                | Risk")
    click.echo("-" * 75)

    for f in findings:
        ai_note = getattr(f, "ai_flag", "")
        click.echo(
            f"{f.check_id:<15} | {f.severity.name:<8} | {f.provider:<8} | "
            f"{f.title:<25} | {f.risk_score} {ai_note}"
        )

    report_path = generate_html_report(findings, summary, company)

    click.echo("\n✅ Report generated")
    click.echo(f"HTML Report: {report_path}")


if __name__ == "__main__":
    cli()