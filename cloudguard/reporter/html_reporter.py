from __future__ import annotations
import json, os
from datetime import datetime, timezone
from pathlib import Path
from jinja2 import Environment, BaseLoader
from cloudguard.engine.finding import Finding, Provider, Severity, Status
from cloudguard.engine.risk_scorer import compute_account_risk

TEMPLATE = r"""<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<title>CloudGuard — {{ scan_meta.company }}</title>
<style>
:root{--bg:#0a0c10;--bg-card:#111520;--bg-card2:#161b27;--border:#1e2535;--text:#c8d0e0;--text-dim:#6b7a99;--text-bright:#e8edf5;--accent:#4f9cf9;--critical:#ff2d55;--high:#ff6b35;--medium:#ffd60a;--low:#30d158;--pass:#30d158;--fail:#ff2d55;--warn:#ffd60a;}
*{box-sizing:border-box;margin:0;padding:0;}
body{background:var(--bg);color:var(--text);font-family:'Segoe UI',sans-serif;font-size:14px;line-height:1.6;}
.header{background:linear-gradient(135deg,#0d1117,#111829,#0d1117);border-bottom:1px solid var(--border);padding:40px 60px;}
.header-top{display:flex;justify-content:space-between;align-items:flex-start;margin-bottom:24px;}
.logo{display:flex;align-items:center;gap:14px;}
.logo-icon{width:48px;height:48px;background:linear-gradient(135deg,#4f9cf9,#7b5ea7);border-radius:12px;display:flex;align-items:center;justify-content:center;font-size:22px;}
.logo-text{font-size:22px;font-weight:700;color:var(--text-bright);}
.logo-sub{font-size:11px;color:var(--text-dim);margin-top:2px;}
.header-right{text-align:right;font-size:12px;color:var(--text-dim);}
.header-right .co{font-size:18px;font-weight:600;color:var(--text-bright);margin-top:4px;}
.header-title{font-size:30px;font-weight:700;color:var(--text-bright);}
.header-sub{font-size:14px;color:var(--text-dim);margin-top:6px;}
.risk-banner{background:var(--bg-card);border:1px solid var(--border);border-radius:16px;padding:32px 48px;margin:32px 60px;display:grid;grid-template-columns:auto 1fr 1fr 1fr 1fr 1fr;gap:32px;align-items:center;}
.score-wrap{text-align:center;}
.score-lbl{font-size:11px;text-transform:uppercase;letter-spacing:1px;color:var(--text-dim);}
.score-num{font-size:64px;font-weight:700;line-height:1;margin-top:4px;}
.score-num.c{color:var(--critical)}.score-num.h{color:var(--high)}.score-num.m{color:var(--medium)}.score-num.l{color:var(--low)}
.stat{text-align:center;border-left:1px solid var(--border);padding-left:32px;}
.stat-n{font-size:36px;font-weight:700;}
.stat-n.c{color:var(--critical)}.stat-n.h{color:var(--high)}.stat-n.m{color:var(--medium)}.stat-n.l{color:var(--low)}.stat-n.p{color:var(--pass)}
.stat-l{font-size:11px;text-transform:uppercase;letter-spacing:1px;color:var(--text-dim);margin-top:4px;}
.content{padding:0 60px 60px;}
.sec-title{font-size:11px;text-transform:uppercase;letter-spacing:2px;color:var(--text-dim);margin:40px 0 16px;display:flex;align-items:center;gap:12px;}
.sec-title::after{content:'';flex:1;height:1px;background:var(--border);}
.pgrid{display:grid;grid-template-columns:repeat(3,1fr);gap:16px;margin-bottom:8px;}
.pcard{background:var(--bg-card);border:1px solid var(--border);border-radius:12px;padding:20px 24px;}
.pname{font-size:13px;font-weight:600;color:var(--text-bright);margin-bottom:12px;display:flex;align-items:center;gap:8px;}
.dot{width:8px;height:8px;border-radius:50%;}
.aws-dot{background:#ff9900}.azure-dot{background:#0078d4}.gcp-dot{background:#4285f4}
.pstats{display:flex;gap:16px;}
.ps{text-align:center;}
.ps-n{font-size:22px;font-weight:700;}
.ps-l{font-size:10px;color:var(--text-dim);text-transform:uppercase;}
.badge{display:inline-block;padding:2px 8px;border-radius:4px;font-size:10px;font-weight:600;text-transform:uppercase;letter-spacing:0.5px;white-space:nowrap;}
.bCRITICAL{background:rgba(255,45,85,0.15);color:var(--critical);border:1px solid rgba(255,45,85,0.3);}
.bHIGH{background:rgba(255,107,53,0.15);color:var(--high);border:1px solid rgba(255,107,53,0.3);}
.bMEDIUM{background:rgba(255,214,10,0.12);color:var(--medium);border:1px solid rgba(255,214,10,0.3);}
.bLOW{background:rgba(48,209,88,0.1);color:var(--low);border:1px solid rgba(48,209,88,0.2);}
.bFAIL{background:rgba(255,45,85,0.12);color:var(--fail);border:1px solid rgba(255,45,85,0.25);}
.bPASS{background:rgba(48,209,88,0.1);color:var(--pass);border:1px solid rgba(48,209,88,0.2);}
.bWARN{background:rgba(255,214,10,0.1);color:var(--warn);border:1px solid rgba(255,214,10,0.25);}
.cid{font-family:monospace;font-size:11px;color:var(--accent);white-space:nowrap;}
.rbar{display:flex;align-items:center;gap:8px;}
.rtrack{width:60px;height:4px;background:var(--border);border-radius:2px;overflow:hidden;}
.rfill{height:100%;border-radius:2px;}
.rnum{font-family:monospace;font-size:11px;color:var(--text-dim);}
.fcard{background:var(--bg-card);border:1px solid var(--border);border-radius:12px;margin-bottom:12px;overflow:hidden;}
.fhdr{padding:16px 20px;display:flex;align-items:flex-start;gap:14px;cursor:pointer;}
.fhdr:hover{background:rgba(255,255,255,0.01);}
.fchev{margin-left:auto;color:var(--text-dim);font-size:12px;transition:transform 0.2s;flex-shrink:0;margin-top:2px;}
.fcard.open .fchev{transform:rotate(90deg);}
.fbody{display:none;padding:16px 20px 20px;border-top:1px solid var(--border);}
.fcard.open .fbody{display:block;}
.ftitle{font-size:14px;font-weight:500;color:var(--text-bright);line-height:1.4;}
.fmeta{display:flex;align-items:center;gap:8px;margin-top:6px;flex-wrap:wrap;}
.dgrid{display:grid;grid-template-columns:1fr 1fr;gap:16px;margin-top:16px;}
.dlbl{font-size:10px;text-transform:uppercase;letter-spacing:1px;color:var(--text-dim);margin-bottom:8px;}
.dtxt{font-size:13px;color:var(--text);line-height:1.6;}
.dcode{background:var(--bg);border:1px solid var(--border);border-radius:6px;padding:12px;font-family:monospace;font-size:12px;color:var(--accent);white-space:pre-wrap;word-break:break-all;line-height:1.5;}
.ctags{display:flex;flex-wrap:wrap;gap:6px;margin-top:8px;}
.ctag{font-family:monospace;font-size:10px;background:rgba(79,156,249,0.08);border:1px solid rgba(79,156,249,0.2);color:var(--accent);padding:2px 8px;border-radius:4px;}
.fbar{display:flex;gap:8px;margin-bottom:16px;flex-wrap:wrap;align-items:center;}
.fbtn{padding:6px 14px;border-radius:6px;border:1px solid var(--border);background:var(--bg-card);color:var(--text-dim);font-size:12px;cursor:pointer;transition:all 0.15s;}
.fbtn:hover,.fbtn.active{border-color:var(--accent);color:var(--accent);background:rgba(79,156,249,0.08);}
.srch{flex:1;min-width:200px;padding:7px 14px;border-radius:6px;border:1px solid var(--border);background:var(--bg-card);color:var(--text);font-size:13px;outline:none;}
.srch:focus{border-color:var(--accent);}
.ptable{background:var(--bg-card);border:1px solid var(--border);border-radius:12px;overflow:hidden;}
.ptable table{width:100%;border-collapse:collapse;font-size:13px;}
.ptable th{background:var(--bg-card2);padding:12px 16px;text-align:left;font-size:10px;text-transform:uppercase;letter-spacing:1px;color:var(--text-dim);font-weight:500;border-bottom:1px solid var(--border);}
.ptable td{padding:12px 16px;border-bottom:1px solid var(--border);}
.ptable tr:last-child td{border-bottom:none;}
.ptable tr:hover td{background:rgba(255,255,255,0.02);}
.footer{border-top:1px solid var(--border);padding:20px 60px;display:flex;justify-content:space-between;color:var(--text-dim);font-size:12px;font-family:monospace;}
</style>
</head>
<body>
<div class="header">
  <div class="header-top">
    <div class="logo">
      <div class="logo-icon">&#127697;</div>
      <div><div class="logo-text">CloudGuard</div><div class="logo-sub">Multi-Cloud Security Auditor v1.0</div></div>
    </div>
    <div class="header-right">
      <div>{{ scan_meta.timestamp }}</div>
      <div class="co">{{ scan_meta.company }}</div>
    </div>
  </div>
  <div class="header-title">Security Assessment Report</div>
  <div class="header-sub">CIS Benchmarks &amp; NIST SP 800-53 Rev 5 &nbsp;&middot;&nbsp; Providers: {{ scan_meta.providers|join(', ') }} &nbsp;&middot;&nbsp; {{ summary.total_checks }} checks</div>
</div>

<div class="risk-banner">
  <div class="score-wrap">
    <div class="score-lbl">Overall Risk Score</div>
    <div class="score-num {% if summary.overall_score >= 70 %}c{% elif summary.overall_score >= 40 %}h{% elif summary.overall_score >= 20 %}m{% else %}l{% endif %}">{{ summary.overall_score|int }}</div>
    <div class="score-lbl" style="margin-top:4px">/ 100</div>
  </div>
  <div class="stat"><div class="stat-n c">{{ summary.critical_count }}</div><div class="stat-l">Critical</div></div>
  <div class="stat"><div class="stat-n h">{{ summary.high_count }}</div><div class="stat-l">High</div></div>
  <div class="stat"><div class="stat-n m">{{ summary.medium_count }}</div><div class="stat-l">Medium</div></div>
  <div class="stat"><div class="stat-n l">{{ summary.low_count }}</div><div class="stat-l">Low</div></div>
  <div class="stat"><div class="stat-n p">{{ summary.pass_count }}</div><div class="stat-l">Passed</div></div>
</div>

<div class="content">
  <div class="sec-title">Provider Breakdown</div>
  <div class="pgrid">
    {% for provider, stats in provider_summary.items() %}
    <div class="pcard">
      <div class="pname"><div class="dot {{ provider|lower }}-dot"></div>{{ provider }}</div>
      <div class="pstats">
        <div class="ps"><div class="ps-n" style="color:var(--critical)">{{ stats.critical }}</div><div class="ps-l">Critical</div></div>
        <div class="ps"><div class="ps-n" style="color:var(--high)">{{ stats.high }}</div><div class="ps-l">High</div></div>
        <div class="ps"><div class="ps-n" style="color:var(--medium)">{{ stats.medium }}</div><div class="ps-l">Medium</div></div>
        <div class="ps"><div class="ps-n" style="color:var(--pass)">{{ stats.passed }}</div><div class="ps-l">Passed</div></div>
      </div>
    </div>
    {% endfor %}
  </div>

  <div class="sec-title">Failed Findings ({{ failed_findings|length }})</div>
  <div class="fbar">
    <button class="fbtn active" onclick="filterSev('ALL',this)">All</button>
    <button class="fbtn" onclick="filterSev('CRITICAL',this)">Critical</button>
    <button class="fbtn" onclick="filterSev('HIGH',this)">High</button>
    <button class="fbtn" onclick="filterSev('MEDIUM',this)">Medium</button>
    <button class="fbtn" onclick="filterSev('LOW',this)">Low</button>
    <input class="srch" type="text" placeholder="Search findings..." oninput="doSearch(this.value)">
  </div>

  <div id="fc">
    {% for f in failed_findings %}
    <div class="fcard" data-sev="{{ f.severity }}" data-txt="{{ f.title|lower }} {{ f.check_id|lower }}">
      <div class="fhdr" onclick="this.closest('.fcard').classList.toggle('open')">
        <div>
          <div class="ftitle">{{ f.title }}</div>
          <div class="fmeta">
            <span class="badge b{{ f.severity }}">{{ f.severity }}</span>
            <span class="badge b{{ f.status }}">{{ f.status }}</span>
            <span class="cid">{{ f.check_id }}</span>
            <span style="color:var(--text-dim);font-size:12px">{{ f.provider }} &middot; {{ f.service }} &middot; {{ f.region }}</span>
          </div>
        </div>
        <div style="margin-left:auto;display:flex;align-items:center;gap:16px;flex-shrink:0">
          <div class="rbar">
            <div class="rtrack"><div class="rfill" style="width:{{ f.risk_score }}%;background:{% if f.risk_score >= 70 %}var(--critical){% elif f.risk_score >= 40 %}var(--high){% elif f.risk_score >= 20 %}var(--medium){% else %}var(--low){% endif %}"></div></div>
            <div class="rnum">{{ f.risk_score }}</div>
          </div>
          <div class="fchev">&#9658;</div>
        </div>
      </div>
      <div class="fbody">
        <div class="dgrid">
          <div><div class="dlbl">Description</div><div class="dtxt">{{ f.description }}</div></div>
          <div><div class="dlbl">Remediation</div><div class="dcode">{{ f.remediation }}</div></div>
        </div>
        <div style="margin-top:16px;display:grid;grid-template-columns:1fr 1fr 1fr;gap:16px">
          <div><div class="dlbl">Resource</div><div style="font-family:monospace;font-size:11px;color:var(--text-dim);word-break:break-all">{{ f.resource_id }}</div></div>
          {% if f.cis_controls %}<div><div class="dlbl">CIS Controls</div><div class="ctags">{% for c in f.cis_controls %}<span class="ctag">{{ c }}</span>{% endfor %}</div></div>{% endif %}
          {% if f.nist_controls %}<div><div class="dlbl">NIST 800-53</div><div class="ctags">{% for c in f.nist_controls %}<span class="ctag">{{ c }}</span>{% endfor %}</div></div>{% endif %}
        </div>
        {% if f.evidence %}
        <div style="margin-top:16px"><div class="dlbl">Evidence</div><div class="dcode">{{ f.evidence | tojson(indent=2) }}</div></div>
        {% endif %}
      </div>
    </div>
    {% endfor %}
  </div>

  {% if passed_findings %}
  <div class="sec-title" style="margin-top:40px">Passed Checks ({{ passed_findings|length }})</div>
  <div class="ptable">
    <table>
      <thead><tr><th>Check ID</th><th>Title</th><th>Provider</th><th>Service</th><th>Resource</th><th>Severity</th></tr></thead>
      <tbody>
        {% for f in passed_findings %}
        <tr>
          <td><span class="cid">{{ f.check_id }}</span></td>
          <td style="color:var(--text-bright)">{{ f.title }}</td>
          <td style="font-size:12px;color:var(--text-dim)">{{ f.provider }}</td>
          <td style="font-size:12px;color:var(--text-dim)">{{ f.service }}</td>
          <td style="font-family:monospace;font-size:11px;color:var(--text-dim)">{{ f.resource_name }}</td>
          <td><span class="badge b{{ f.severity }}">{{ f.severity }}</span></td>
        </tr>
        {% endfor %}
      </tbody>
    </table>
  </div>
  {% endif %}
</div>

<div class="footer">
  <div>CloudGuard v1.0 &nbsp;&middot;&nbsp; {{ scan_meta.timestamp }}</div>
  <div>{{ summary.total_checks }} checks &nbsp;&middot;&nbsp; {{ failed_findings|length }} failed &nbsp;&middot;&nbsp; {{ passed_findings|length }} passed</div>
</div>

<script>
let curSev='ALL',curSrch='';
function apply(){
  document.querySelectorAll('#fc .fcard').forEach(el=>{
    const sevOk=curSev==='ALL'||el.dataset.sev===curSev;
    const srchOk=!curSrch||el.dataset.txt.includes(curSrch);
    el.style.display=(sevOk&&srchOk)?'block':'none';
  });
}
function filterSev(s,btn){
  curSev=s;
  document.querySelectorAll('.fbtn').forEach(b=>b.classList.remove('active'));
  btn.classList.add('active');
  apply();
}
function doSearch(v){curSrch=v.toLowerCase();apply();}
document.querySelectorAll('[data-sev="CRITICAL"]').forEach(el=>el.classList.add('open'));
</script>
</body>
</html>"""


class HTMLReporter:
    def __init__(self, findings, output_dir="./reports", company="Demo Corp"):
        self.findings = findings
        self.output_dir = Path(output_dir)
        self.company = company
        self.output_dir.mkdir(parents=True, exist_ok=True)

    def render(self):
        timestamp = datetime.now(timezone.utc)
        ts_str = timestamp.strftime("%Y%m%d_%H%M%S")
        html_path = self.output_dir / f"cloudguard_report_{ts_str}.html"
        json_path = self.output_dir / f"cloudguard_report_{ts_str}.json"

        summary = compute_account_risk(self.findings)
        failed_findings = sorted(
            [f for f in self.findings if f.status == Status.FAIL],
            key=lambda f: (-f.risk_score, -f.severity.score),
        )
        passed_findings = [f for f in self.findings if f.status == Status.PASS]
        provider_summary = self._build_provider_summary(self.findings)
        providers_scanned = list({f.provider.value for f in self.findings})

        env = Environment(loader=BaseLoader())
        env.filters["tojson"] = lambda v, **kw: json.dumps(v, default=str, **kw)
        template = env.from_string(TEMPLATE)

        html = template.render(
            scan_meta={
                "company": self.company,
                "timestamp": timestamp.strftime("%Y-%m-%d %H:%M UTC"),
                "providers": providers_scanned,
            },
            summary=summary,
            failed_findings=failed_findings,
            passed_findings=passed_findings,
            provider_summary=provider_summary,
        )

        html_path.write_text(html, encoding="utf-8")

        report_data = {
            "meta": {"generated_at": timestamp.isoformat(), "company": self.company},
            "summary": summary,
            "findings": [f.to_dict() for f in self.findings],
        }
        json_path.write_text(json.dumps(report_data, indent=2, default=str), encoding="utf-8")

        return html_path, json_path

    @staticmethod
    def _build_provider_summary(findings):
        summary = {}
        for provider in Provider:
            pf = [f for f in findings if f.provider == provider]
            if not pf:
                continue
            failed = [f for f in pf if f.status == Status.FAIL]
            summary[provider.value] = {
                "critical": sum(1 for f in failed if f.severity == Severity.CRITICAL),
                "high": sum(1 for f in failed if f.severity == Severity.HIGH),
                "medium": sum(1 for f in failed if f.severity == Severity.MEDIUM),
                "low": sum(1 for f in failed if f.severity == Severity.LOW),
                "passed": sum(1 for f in pf if f.status == Status.PASS),
                "total": len(pf),
            }
        return summary