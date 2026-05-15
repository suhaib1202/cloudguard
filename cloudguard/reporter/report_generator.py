from datetime import datetime
import os

def generate_html_report(company, findings, summary):
    os.makedirs("reports", exist_ok=True)

    filename = f"reports/cloudguard_report_{datetime.now().strftime('%Y-%m-%d_%H-%M-%S')}.html"

    rows = ""
    for f in findings:
        rows += f"""
        <tr>
            <td>{f.check_id}</td>
            <td>{f.severity}</td>
            <td>{f.provider}</td>
            <td>{f.title}</td>
            <td>{f.risk_score}</td>
        </tr>
        """

    html = f"""
    <html>
    <head>
        <title>CloudGuard Report</title>
        <style>
            body {{ font-family: Arial; background:#0f172a; color:white; }}
            h1 {{ color:#38bdf8; }}
            table {{ width:100%; border-collapse: collapse; }}
            th, td {{ border:1px solid #334155; padding:10px; }}
            th {{ background:#1e293b; }}
            tr:nth-child(even) {{ background:#1e293b; }}
        </style>
    </head>
    <body>
        <h1>☁ CloudGuard Security Report</h1>
        <h2>Company: {company}</h2>
        <h3>Risk Score: {summary['overall_score']}/100</h3>

        <table>
            <tr>
                <th>Check ID</th>
                <th>Severity</th>
                <th>Provider</th>
                <th>Title</th>
                <th>Risk</th>
            </tr>
            {rows}
        </table>
    </body>
    </html>
    """

    with open(filename, "w") as f:
        f.write(html)

    print(f"HTML Report: ./{filename}")