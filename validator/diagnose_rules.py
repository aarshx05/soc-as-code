#!/usr/bin/env python3
"""
diagnose_rules.py

Deep inspection tool for Sigma rules.
Used in CI to catch structural problems BEFORE log generation & validation.

Features:
 - Safe import handling (avoids stdlib 'test' import collisions)
 - Loads Sigma rules (via test.py load_sigma_rules)
 - Checks for:
     * missing logsource
     * missing detection blocks
     * empty selections
     * unsupported patterns
 - Provides a structured JSON diagnostic summary
 - Debug mode prints rule internals
"""

import os
import sys
import json
import argparse
import yaml
from pathlib import Path
from typing import Dict, Any, List

# -------------------------------------------------------------------
# Ensure repo root is importable (same fix used across all your tools)
# -------------------------------------------------------------------
REPO_ROOT = os.path.abspath(os.path.join(os.path.dirname(__file__), ".."))
if REPO_ROOT not in sys.path:
    sys.path.insert(0, REPO_ROOT)

# Prefer top-level test.py for load_sigma_rules
try:
    import importlib

    test_mod = importlib.import_module("test")
    load_sigma_rules = getattr(test_mod, "load_sigma_rules")
except Exception:
    # fallback to validator.test
    try:
        test_mod = importlib.import_module("validator.test")
        load_sigma_rules = getattr(test_mod, "load_sigma_rules")
    except Exception:
        load_sigma_rules = None

if load_sigma_rules is None:
    raise ImportError(
        "Could not import load_sigma_rules from test.py. "
        "Ensure test.py exists in repo root and defines load_sigma_rules()."
    )


# -------------------------------------------------------------------
# Utility functions
# -------------------------------------------------------------------

def load_yaml_file(path: Path):
    """Load yaml file safely."""
    try:
        with open(path, "r", encoding="utf-8") as f:
            return yaml.safe_load(f)
    except Exception as e:
        return {"__yaml_error__": str(e)}


def diagnose_rule(rule: Dict[str, Any], debug: bool = False) -> Dict[str, Any]:
    """
    Inspect one Sigma rule and detect:
    - missing logsource/product/category
    - missing detection blocks
    - empty or malformed selections
    - suspicious wildcard-only patterns
    """

    issues = []
    warnings = []

    rule_id = rule.get("id", "<missing>")
    title = rule.get("title", "<missing>")

    logsource = rule.get("logsource", {})
    detection = rule.get("detection", {})

    # ---- logsource checks ----
    if not isinstance(logsource, dict):
        issues.append("logsource must be a dictionary.")
    else:
        if not logsource.get("product") and not logsource.get("category"):
            issues.append("logsource missing both 'product' and 'category' fields.")

    # ---- detection checks ----
    if not isinstance(detection, dict) or len(detection) == 0:
        issues.append("detection block missing or empty.")
    else:
        selections = {
            k: v
            for k, v in detection.items()
            if k.lower() != "condition"
        }

        if not selections:
            issues.append("no detection selections found (only condition?).")

        # Analyze selection fields
        for sel_name, sel_body in selections.items():
            if not isinstance(sel_body, dict):
                issues.append(f"selection '{sel_name}' must contain key-value match pairs.")
                continue

            for field, pattern in sel_body.items():
                if pattern in (None, "", []):
                    warnings.append(f"field '{field}' in selection '{sel_name}' has empty pattern.")

                # Suspicious wildcards
                if isinstance(pattern, str) and pattern.strip() in ["*", "**", "***"]:
                    warnings.append(
                        f"field '{field}' uses wildcard-only pattern '{pattern}' (may cause high FP rate)."
                    )

                # Lists with empty values
                if isinstance(pattern, list) and any(x in ("", None) for x in pattern):
                    warnings.append(
                        f"field '{field}' selection contains empty list elements."
                    )

    if debug:
        print("\n--------------------------------")
        print(f"[DEBUG] Rule: {title} ({rule_id})")
        print("Logsource:", logsource)
        print("Detection:", detection)
        print("Issues :", issues)
        print("Warnings:", warnings)
        print("--------------------------------")

    return {
        "rule_id": rule_id,
        "title": title,
        "issues": issues,
        "warnings": warnings,
        "has_errors": len(issues) > 0
    }


def main():
    parser = argparse.ArgumentParser(description="Diagnose Sigma rules for structural problems")
    parser.add_argument("--rules-dir", required=True, help="Directory containing Sigma rules")
    parser.add_argument("--output-file", required=True, help="Where to save diagnostics JSON")
    parser.add_argument("--debug", action="store_true", help="Enable verbose debugging")
    args = parser.parse_args()

    rules_dir = Path(args.rules_dir)
    out_path = Path(args.output_file)
    out_path.parent.mkdir(parents=True, exist_ok=True)

    if args.debug:
        print(f"[DEBUG] Diagnosing rules under: {rules_dir}")
        print(f"[DEBUG] Output file: {out_path}")

    # Collect rule files
    rule_files = list(rules_dir.rglob("*.yml")) + list(rules_dir.rglob("*.yaml"))

    print(f"\n[+] Found {len(rule_files)} Sigma rule files for diagnosis")

    diagnostics = []
    total_rules = 0
    rules_with_errors = 0
    rules_with_warnings = 0

    for rule_file in rule_files:
        total_rules += 1
        try:
            rules = load_sigma_rules(str(rule_file))
        except Exception as e:
            diagnostics.append({
                "rule_file": str(rule_file),
                "rule_id": None,
                "title": None,
                "issues": [f"YAML load error: {e}"],
                "warnings": [],
                "has_errors": True,
            })
            rules_with_errors += 1
            continue

        for rule in rules:
            diag = diagnose_rule(rule, debug=args.debug)
            diag["rule_file"] = str(rule_file)
            diagnostics.append(diag)

            if diag["has_errors"]:
                rules_with_errors += 1
            elif diag["warnings"]:
                rules_with_warnings += 1

    summary = {
        "total_rules": total_rules,
        "files_scanned": len(rule_files),
        "rules_with_errors": rules_with_errors,
        "rules_with_warnings": rules_with_warnings,
        "diagnostics": diagnostics,
    }

    with open(out_path, "w", encoding="utf-8") as f:
        json.dump(summary, f, indent=2)

    print(f"\n📄 Diagnostics written to: {out_path}")
    print("\nSUMMARY:")
    print(f"  Total rules scanned   : {total_rules}")
    print(f"  Rules with errors     : {rules_with_errors}")
    print(f"  Rules with warnings   : {rules_with_warnings}")

    if rules_with_errors > 0:
        print("❌ Structural issues detected in rules")
        sys.exit(2)

    print("✅ All rules structurally valid")
    sys.exit(0)


if __name__ == "__main__":
    main()
