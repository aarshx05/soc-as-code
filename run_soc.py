import os
import sys
import argparse
import subprocess
import json
import requests
from datetime import datetime

from reportlab.lib.pagesizes import A4
from reportlab.platypus import SimpleDocTemplate, Paragraph, Spacer
from reportlab.lib.styles import getSampleStyleSheet

# ===============================
# OpenRouter API Key
# ===============================
# If you insist on hardcoding, do it here (NOT recommended):
OPENROUTER_API_KEY = ""


def generate_output_filenames(base_dir="output"):
    os.makedirs(base_dir, exist_ok=True)
    ts = datetime.now().strftime("%Y%m%d_%H%M%S")
    alerts_file = os.path.join(base_dir, f"alerts_{ts}.json")
    metrics_file = os.path.join(base_dir, f"metrics_{ts}.json")
    report_file = os.path.join(base_dir, f"executive_report_{ts}.pdf")
    return alerts_file, metrics_file, report_file


def load_json_safe(path, default):
    try:
        with open(path, "r", encoding="utf-8") as f:
            return json.load(f)
    except Exception as e:
        print(f"[WARN] Failed to load {path}: {e}")
        return default


def build_structured_context(alerts_data, metrics_data, logs_path, sigma_path, yara_path):
    """
    Turn raw alerts/metrics JSON into a clean, structured context string
    that we feed into the AI model.
    """

    # test.py writes:
    #   alerts_file: {"alerts": [ ... ]}
    #   metrics_file: {"metrics": { ... }}
    alerts = alerts_data.get("alerts", []) if isinstance(alerts_data, dict) else []
    metrics = metrics_data.get("metrics", {}) if isinstance(metrics_data, dict) else {}

    total_logs = metrics.get("total_logs", 0)
    alerts_per_severity = metrics.get("alerts_per_severity", {})
    alerts_per_rule = metrics.get("alerts_per_rule", {})
    alerts_per_host = metrics.get("alerts_per_host", {})
    logs_per_host = metrics.get("logs_per_host", {})

    total_alerts = len(alerts)

    # Top 5 rules by alert count
    top_rules = sorted(
        alerts_per_rule.items(),
        key=lambda x: x[1],
        reverse=True
    )[:5]

    # Sample a few alerts to give model concrete examples
    sample_alerts = alerts[:5]

    context = []
    context.append("=== TECHNICAL CONTEXT ===")
    context.append(f"Logs source path: {logs_path}")
    context.append(f"Sigma rules path: {sigma_path}")
    context.append(f"YARA rules path: {yara_path or 'None'}")
    context.append("")

    context.append("=== HIGH LEVEL METRICS ===")
    context.append(f"Total logs processed: {total_logs}")
    context.append(f"Total alerts generated: {total_alerts}")
    context.append(f"Alerts per severity: {json.dumps(alerts_per_severity, indent=2)}")
    context.append(f"Alerts per rule: {json.dumps(alerts_per_rule, indent=2)}")
    context.append(f"Alerts per host: {json.dumps(alerts_per_host, indent=2)}")
    context.append(f"Logs per host: {json.dumps(logs_per_host, indent=2)}")
    context.append("")

    context.append("=== TOP RULES BY ALERT COUNT ===")
    for rule_id, count in top_rules:
        context.append(f"- {rule_id}: {count} alerts")
    context.append("")

    context.append("=== SAMPLE ALERTS (TRUNCATED) ===")
    for a in sample_alerts:
        # Don't dump entire raw log; just key fields
        rule_id = a.get("rule_id")
        rule_title = a.get("rule_title")
        severity = a.get("severity")
        host = a.get("host")
        ts = a.get("timestamp")
        context.append(
            f"- Rule={rule_id}, Title={rule_title}, Sev={severity}, Host={host}, Time={ts}"
        )
    context.append("")

    return "\n".join(context)


def generate_ai_summary(structured_context):
    """
    Send structured metrics + sample alerts to OpenRouter to generate
    an executive-ready SOC report.
    """

    if not OPENROUTER_API_KEY:
        return (
            "No OPENROUTER_API_KEY configured. Set it as an environment variable "
            "or hardcode it in run_soc.py."
        )

    user_prompt = f"""
You are a senior SOC analyst. Based on the following structured metrics and sample alerts:

{structured_context}

Write a professional **executive report** with these sections:

1. Overview  
   - What was tested (logs, Sigma/YARA rules)  
   - High-level goal of this simulation (validating SOC detections, rule robustness, etc.)

2. Key Metrics  
   - Total logs, total alerts  
   - Breakdown by severity, rule, and host  
   - Any patterns or concentrations worth noting

3. Detection Quality  
   - Where coverage looks strong (what types of activity are reliably caught)  
   - Where coverage is weak or missing (stealthy attacks, lateral movement, etc.)  
   - Comment on likely false positives or noisy rules based on counts

4. Risk & Impact  
   - What these results imply for the organization’s risk exposure  
   - Potential attacker behaviours that might slip past current rules

5. Recommendations  
   - Concrete, actionable tuning steps (e.g., reduce noise on specific high-volume rules)  
   - New detection ideas for gaps (lateral movement, privilege escalation, data exfiltration)  
   - Process/operational improvements (use of this simulator in CI/CD, validation pipelines, etc.)

Make it:
- Clear, concise, and non-technical enough for management  
- Still specific enough to be useful for the SOC team  
- Use headings and bullet points. Avoid raw JSON.
"""

    try:
        response = requests.post(
            url="https://openrouter.ai/api/v1/chat/completions",
            headers={
                "Authorization": f"Bearer {OPENROUTER_API_KEY}",
                "Content-Type": "application/json",
                "HTTP-Referer": "http://localhost",
                "X-Title": "SOC Executive Report Generator",
            },
            json={
                "model": "mistralai/mistral-7b-instruct:free",
                "messages": [
                    {
                        "role": "system",
                        "content": (
                            "You are an experienced SOC analyst writing executive-ready reports. "
                            "Use clear structure, headings, and bullet points."
                        ),
                    },
                    {"role": "user", "content": user_prompt},
                ],
            },
            timeout=60,
        )

        if response.status_code == 200:
            return response.json()["choices"][0]["message"]["content"]
        else:
            return f"AI request failed: {response.status_code} {response.text}"

    except Exception as e:
        return f"Error contacting AI: {e}"


def create_pdf_report(text, filename):
    """
    Render a slightly nicer PDF:
    - Title style for first heading
    - Heading styles for markdown-like '#', '##'
    - Normal style for body
    """
    doc = SimpleDocTemplate(filename, pagesize=A4)
    styles = getSampleStyleSheet()
    story = []

    first_title_used = False

    for raw_line in text.split("\n"):
        line = raw_line.strip()
        if not line:
            story.append(Spacer(1, 8))
            continue

        # Simple markdown-ish heading detection
        if line.startswith("## "):
            heading = line[3:].strip()
            story.append(Paragraph(heading, styles["Heading2"]))
            story.append(Spacer(1, 6))
        elif line.startswith("# "):
            heading = line[2:].strip()
            style = styles["Title"] if not first_title_used else styles["Heading1"]
            story.append(Paragraph(heading, style))
            story.append(Spacer(1, 10))
            first_title_used = True
        else:
            story.append(Paragraph(line, styles["Normal"]))
            story.append(Spacer(1, 4))

    doc.build(story)


def run_soc_simulator(logs, sigma, yara=None, output_dir="output", extra_args=None):
    alerts_file, metrics_file, report_file = generate_output_filenames(output_dir)

    cmd = [
        sys.executable,
        "test.py",
        "--logs",
        logs,
        "--sigma",
        sigma,
        "--out",
        alerts_file,
        "--metrics",
        metrics_file,
    ]
    if yara:
        cmd.extend(["--yara", yara])
    if extra_args:
        cmd.extend(extra_args)

    print(f"\n[+] Running SOC Simulator...")
    print(f"    Logs : {logs}")
    print(f"    Sigma: {sigma}")
    print(f"    YARA : {yara}")
    print(f"    Out alerts : {alerts_file}")
    print(f"    Out metrics: {metrics_file}\n")

    try:
        subprocess.run(cmd, check=True)
        print("\n--- Run Completed ---")
        print(f"Alerts saved to : {alerts_file}")
        print(f"Metrics saved to: {metrics_file}")

        # Load outputs
        alerts_data = load_json_safe(alerts_file, default={"alerts": []})
        metrics_data = load_json_safe(metrics_file, default={"metrics": {}})

        # Build structured context for the AI
        structured_context = build_structured_context(
            alerts_data, metrics_data, logs_path=logs, sigma_path=sigma, yara_path=yara
        )

        # Generate AI-based executive summary
        print("\n[+] Generating AI executive summary...")
        summary_text = generate_ai_summary(structured_context)

        # Save as PDF
        create_pdf_report(summary_text, report_file)
        print(f"[+] Executive report saved to: {report_file}")

    except subprocess.CalledProcessError as e:
        print(f"[ERROR] Simulator failed with exit code {e.returncode}")


def main():
    parser = argparse.ArgumentParser(
        description="SOC Simulator + AI Executive Reports (No-Embedding Version)"
    )
    parser.add_argument("--logs", required=True, help="Path to log file or directory")
    parser.add_argument("--sigma", required=True, help="Path to Sigma rules YAML")
    parser.add_argument("--yara", help="Path to YARA rules file (optional)")
    parser.add_argument(
        "--output-dir",
        default="output",
        help="Directory to save alerts, metrics, and reports",
    )
    parser.add_argument(
        "--extra", nargs=argparse.REMAINDER, help="Extra args passed to test.py"
    )
    args = parser.parse_args()

    run_soc_simulator(
        logs=args.logs,
        sigma=args.sigma,
        yara=args.yara,
        output_dir=args.output_dir,
        extra_args=args.extra,
    )


if __name__ == "__main__":
    main()
