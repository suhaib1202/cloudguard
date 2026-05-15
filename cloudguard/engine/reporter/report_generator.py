from datetime import datetime


def generate_html_report(findings, summary, company):

    timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
    file_path = f"cloudguard_report_{timestamp}.html"

    critical = summary.get("critical", 0)
    high = summary.get("high", 0)
    medium = summary.get("medium", 0)
    total = summary.get("total", 0)
    score = summary.get("overall_score", 0)

    rows = ""
    for f in findings:
        rows += f"""
        <tr data-severity="{f.severity}">
            <td>{f.check_id}</td>
            <td><span class="badge {f.severity}">{f.severity}</span></td>
            <td>{f.service}</td>
            <td>{f.title}</td>
            <td>{f.risk_score}</td>
        </tr>
        """

    html = f"""
<!DOCTYPE html>
<html>
<head>
<meta charset="UTF-8">
<title>CloudGuard Report</title>

<script src="https://cdn.jsdelivr.net/npm/chart.js"></script>
<script src="https://cdnjs.cloudflare.com/ajax/libs/html2pdf.js/0.10.1/html2pdf.bundle.min.js"></script>

<style>

/* GLOBAL */
body {{
    font-family: Arial;
    background: #121212;
    color: #e0e0e0;
    margin: 0;
}}

/* CONTAINER */
.container {{
    width: 750px;   /* PERFECT FOR PDF */
    margin: auto;
    padding: 20px;
}}

/* CARDS */
.card {{
    background: #1e1e1e;
    padding: 20px;
    margin-bottom: 20px;
    border-radius: 10px;
    page-break-inside: avoid;
}}

/* HEADINGS */
h1, h2 {{
    color: white;
}}

/* TABLE */
table {{
    width: 100%;
    border-collapse: collapse;
}}

th, td {{
    padding: 10px;
    border-bottom: 1px solid #444;
}}

th {{
    background: #333;
}}

/* BADGES */
.badge {{
    padding: 5px 10px;
    border-radius: 5px;
    color: white;
}}

.CRITICAL {{ background: red; }}
.HIGH {{ background: orange; }}
.MEDIUM {{ background: goldenrod; }}

/* BUTTONS */
.btn {{
    background: #007bff;
    padding: 10px;
    color: white;
    border: none;
    border-radius: 5px;
    cursor: pointer;
}}

/* FILTER BUTTONS */
.filters button {{
    margin-right: 10px;
    padding: 8px 12px;
    border-radius: 5px;
    border: none;
    cursor: pointer;
    color: white;
}}

.btn-danger {{ background: red; }}
.btn-warning {{ background: orange; }}
.btn-medium {{ background: goldenrod; }}

/* CHART */
canvas {{
    max-width: 280px;
    display: block;
    margin: auto;
}}

/* PDF MODE */
@media print {{
    body {{
        background: white;
        color: black;
    }}

    .card {{
        background: white;
        color: black;
    }}

    #chart-section {{
        display: none;   /* ❗ REMOVE CHART FROM PDF */
    }}
}}

</style>
</head>

<body>

<div class="container" id="report-content">

<h1>CloudGuard Dashboard</h1>

<div class="card">
<h2>Company: {company}</h2>
<p><strong>Risk Score:</strong> {score}/100</p>
<p><strong>Critical:</strong> {critical} | <strong>High:</strong> {high} | <strong>Medium:</strong> {medium} | <strong>Total:</strong> {total}</p>
</div>

<div class="card" id="chart-section">
<h2>Severity Chart</h2>
<canvas id="severityChart"></canvas>
</div>

<div class="card">
<h2>Filters</h2>
<div class="filters">
<button class="btn" onclick="filterTable('ALL')">All</button>
<button class="btn-danger" onclick="filterTable('CRITICAL')">Critical</button>
<button class="btn-warning" onclick="filterTable('HIGH')">High</button>
<button class="btn-medium" onclick="filterTable('MEDIUM')">Medium</button>
</div>
</div>

<div class="card">
<h2>Findings</h2>

<table id="findingsTable">
<tr>
<th>ID</th>
<th>Severity</th>
<th>Service</th>
<th>Title</th>
<th>Risk</th>
</tr>

{rows}

</table>
</div>

<div class="card">
<button class="btn" onclick="downloadPDF()">Export PDF</button>
</div>

</div>

<script>

/* CHART */
new Chart(document.getElementById('severityChart'), {{
    type: 'pie',
    data: {{
        labels: ['Critical', 'High', 'Medium'],
        datasets: [{{
            data: [{critical}, {high}, {medium}],
            backgroundColor: ['red', 'orange', 'yellow']
        }}]
    }}
}});


/* FILTER */
function filterTable(severity) {{
    const rows = document.querySelectorAll("#findingsTable tr");

    rows.forEach((row, i) => {{
        if (i === 0) return;

        if (severity === "ALL") {{
            row.style.display = "";
        }} else {{
            const s = row.getAttribute("data-severity");
            row.style.display = s === severity ? "" : "none";
        }}
    }});
}}


/* CLEAN PDF EXPORT */
function downloadPDF() {{

    const element = document.getElementById("report-content");

    const opt = {{
        margin: 0.5,
        filename: 'cloudguard_report.pdf',

        html2canvas: {{
            scale: 2
        }},

        jsPDF: {{
            unit: 'in',
            format: 'a4',
            orientation: 'portrait'
        }}
    }};

    html2pdf().set(opt).from(element).save();
}}

</script>

</body>
</html>
"""

    with open(file_path, "w", encoding="utf-8") as f:
        f.write(html)

    return file_path