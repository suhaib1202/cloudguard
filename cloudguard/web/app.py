from flask import Flask, render_template
from cloudguard.engine.aws_scanner import run_aws_scan
from cloudguard.engine.risk_scorer import RiskScorer, compute_account_risk
from cloudguard.engine.ai_risk import apply_ai_risk

app = Flask(__name__)

@app.route("/")
def dashboard():
    findings = run_aws_scan()

    scorer = RiskScorer()
    scorer.score_all(findings)

    findings = apply_ai_risk(findings)

    summary = compute_account_risk(findings)

    return render_template("dashboard.html", findings=findings, summary=summary)


if __name__ == "__main__":
    app.run(debug=True)