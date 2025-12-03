import os
import sys
import json
import subprocess
from datetime import datetime

from flask import (
    Flask,
    render_template,
    request,
    redirect,
    url_for,
    send_from_directory,
    flash,
)

BASE_DIR = os.path.dirname(os.path.abspath(__file__))
DATASET_DIR = os.path.join(BASE_DIR, "dataset")
INDATA_DIR = os.path.join(BASE_DIR, "indata")
OUTPUT_DIR = os.path.join(BASE_DIR, "output")

os.makedirs(OUTPUT_DIR, exist_ok=True)

app = Flask(__name__)
app.secret_key = "change-this-secret"


# ----------------- helpers -----------------
def list_datasets():
    if not os.path.isdir(DATASET_DIR):
        return []
    out = []
    for f in os.listdir(DATASET_DIR):
        full = os.path.join(DATASET_DIR, f)
        if os.path.isfile(full) and f.lower().endswith((".json", ".jsonl", ".log")):
            out.append({"name": f, "rel": os.path.join("dataset", f)})
    return sorted(out, key=lambda x: x["name"].lower())


def list_sigma_rules():
    if not os.path.isdir(INDATA_DIR):
        return []
    out = []
    for f in os.listdir(INDATA_DIR):
        full = os.path.join(INDATA_DIR, f)
        if os.path.isfile(full) and f.lower().endswith((".yml", ".yaml", "")):
            # allow your existing files without extension like "sigma_test_rules_extensive"
            out.append({"name": f, "rel": os.path.join("indata", f)})
    return sorted(out, key=lambda x: x["name"].lower())


def list_yara_rules():
    if not os.path.isdir(INDATA_DIR):
        return []
    out = []
    for f in os.listdir(INDATA_DIR):
        full = os.path.join(INDATA_DIR, f)
        if os.path.isfile(full) and f.lower().endswith((".yar", ".yara")):
            out.append({"name": f, "rel": os.path.join("indata", f)})
    return sorted(out, key=lambda x: x["name"].lower())


def latest_output(prefix, suffix):
    """Return filename (not full path) of newest file in OUTPUT_DIR matching pattern."""
    candidates = []
    for f in os.listdir(OUTPUT_DIR):
        if f.startswith(prefix) and f.endswith(suffix):
            full = os.path.join(OUTPUT_DIR, f)
            candidates.append((f, os.path.getmtime(full)))
    if not candidates:
        return None
    candidates.sort(key=lambda x: x[1], reverse=True)
    return candidates[0][0]


def load_json_safe(path, default):
    try:
        with open(path, "r", encoding="utf-8") as fh:
            return json.load(fh)
    except Exception as e:
        print(f"[WARN] Failed to load {path}: {e}")
        return default


def summarize_metrics(metrics_data):
    """Turn metrics JSON into something easy to show in the UI."""
    if isinstance(metrics_data, dict) and "metrics" in metrics_data:
        metrics = metrics_data["metrics"]
    else:
        metrics = metrics_data if isinstance(metrics_data, dict) else {}

    total_logs = metrics.get("total_logs", 0)
    alerts_per_severity = metrics.get("alerts_per_severity", {})
    alerts_per_rule = metrics.get("alerts_per_rule", {})
    alerts_per_host = metrics.get("alerts_per_host", {})
    logs_per_host = metrics.get("logs_per_host", {})

    total_alerts = 0
    if isinstance(alerts_per_rule, dict):
        total_alerts = sum(alerts_per_rule.values())

    return {
        "total_logs": total_logs,
        "total_alerts": total_alerts,
        "alerts_per_severity": alerts_per_severity or {},
        "alerts_per_rule": alerts_per_rule or {},
        "alerts_per_host": alerts_per_host or {},
        "logs_per_host": logs_per_host or {},
    }


# ----------------- routes -----------------
@app.route("/", methods=["GET", "POST"])
def index():
    datasets = list_datasets()
    sigma_rules = list_sigma_rules()
    yara_rules = list_yara_rules()

    if request.method == "POST":
        dataset_rel = request.form.get("dataset")
        sigma_rel = request.form.get("sigma")
        yara_rel = request.form.get("yara")

        if not dataset_rel:
            flash("Please select a dataset.", "danger")
            return redirect(url_for("index"))
        if not sigma_rel:
            flash("Please select a Sigma rules file.", "danger")
            return redirect(url_for("index"))

        logs_path = os.path.join(BASE_DIR, dataset_rel)
        sigma_path = os.path.join(BASE_DIR, sigma_rel)
        yara_path = None
        if yara_rel and yara_rel != "none":
            yara_path = os.path.join(BASE_DIR, yara_rel)

        cmd = [
            sys.executable,
            os.path.join(BASE_DIR, "run_soc.py"),
            "--logs",
            logs_path,
            "--sigma",
            sigma_path,
            "--output-dir",
            OUTPUT_DIR,
        ]
        if yara_path:
            cmd.extend(["--yara", yara_path])

        try:
            print("[+] Running:", " ".join(cmd))
            subprocess.run(cmd, check=True)
        except subprocess.CalledProcessError as e:
            flash(f"SOC run failed: {e}", "danger")
            return redirect(url_for("index"))

        # Find latest outputs
        alerts_name = latest_output("alerts_", ".json")
        metrics_name = latest_output("metrics_", ".json")
        pdf_name = latest_output("executive_report_", ".pdf")

        if not (alerts_name and metrics_name and pdf_name):
            flash("Run completed but could not find output files.", "danger")
            return redirect(url_for("index"))

        metrics_path = os.path.join(OUTPUT_DIR, metrics_name)
        metrics_data = load_json_safe(metrics_path, default={"metrics": {}})
        metrics_summary = summarize_metrics(metrics_data)

        return render_template(
            "result.html",
            metrics=metrics_summary,
            alerts_file=alerts_name,
            metrics_file=metrics_name,
            pdf_file=pdf_name,
            dataset=os.path.basename(logs_path),
            sigma=os.path.basename(sigma_path),
            yara=os.path.basename(yara_path) if yara_path else None,
        )

    return render_template(
        "index.html",
        datasets=datasets,
        sigma_rules=sigma_rules,
        yara_rules=yara_rules,
    )


@app.route("/output/<path:filename>")
def download_output(filename):
    return send_from_directory(OUTPUT_DIR, filename, as_attachment=False)


if __name__ == "__main__":
    app.run(host="0.0.0.0", port=5000, debug=True)
