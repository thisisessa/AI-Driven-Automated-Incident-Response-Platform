from jinja2 import Environment, FileSystemLoader
import os

def generate_html_report(case_id, target_ip, hash_val, volatility, scan_results):
    # Load the HTML template
    env = Environment(loader=FileSystemLoader('/app/templates'))
    template = env.get_template('forensic_report.html')
    
    # Render the HTML with actual data
    html_out = template.render(
        case_id=case_id,
        target_ip=target_ip,
        hash_val=hash_val,
        volatility=volatility,
        yara=scan_results.get("yara", []),
        clamav=scan_results.get("clamav", {})
    )
    
    # Save the report to the evidence vault
    report_path = f"/app/evidence_vault/reports/report_{case_id}.html"
    os.makedirs(os.path.dirname(report_path), exist_ok=True)
    
    with open(report_path, "w", encoding="utf-8") as f:
        f.write(html_out)
        
    return report_path
