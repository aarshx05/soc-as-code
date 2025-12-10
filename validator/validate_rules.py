#!/usr/bin/env python3
"""
validate_rules.py

Combined lightweight Sigma/YAML rule validator + small synthetic log generator wrapper.

Why this file:
- Provides `validate_rules` CLI to validate Sigma YAML rule files (used by CI).
- Exposes `EnhancedLogGenerator.generate_for_sigma_rule(rule, count)` so other scripts
  (e.g. generate_logs.py) can import it as `from validator.validate_rules import EnhancedLogGenerator`.
- Defensive about imports and has a `--debug` flag.

Notes:
- This is intentionally conservative: validation checks for required keys and structure only.
- The embedded log generator is simple: it produces a few JSON-like events from rule detections.
  Replace or extend it later with your project's UniversalLogGenerator if you prefer richer behavior.
"""

from __future__ import annotations
import argparse
import sys
import yaml
import json
import re
import random
import string
from pathlib import Path
from typing import Dict, Any, List, Tuple, Optional
from datetime import datetime

# ---------------------------
# Basic YAML rule validator
# ---------------------------

REQUIRED_TOP_LEVEL_KEYS = ["id", "title", "logsource", "detection"]


def load_yaml(path: Path) -> Tuple[bool, Any]:
    """Load YAML and return (success, data_or_error)."""
    try:
        with open(path, "r", encoding="utf-8") as f:
            data = yaml.safe_load(f)
        return True, data
    except Exception as e:
        return False, {"error": str(e)}


def validate_rule_structure(data: Dict[str, Any]) -> List[str]:
    """Return a list of validation error strings (empty if OK)."""
    errors: List[str] = []

    if not isinstance(data, dict):
        errors.append("Top-level YAML is not a mapping/dictionary.")
        return errors

    for k in REQUIRED_TOP_LEVEL_KEYS:
        if k not in data:
            errors.append(f"Missing required key: '{k}'")

    # logsource should contain either category or product
    logsource = data.get("logsource")
    if isinstance(logsource, dict):
        if not (logsource.get("category") or logsource.get("product")):
            errors.append("logsource must include at least 'category' or 'product' field.")
    else:
        errors.append("logsource must be a mapping with 'category' or 'product'.")

    # detection should be a mapping with at least one selection
    detection = data.get("detection")
    if not isinstance(detection, dict) or len(detection) == 0:
        errors.append("detection must be a mapping with at least one selection block.")

    # id/title non-empty
    rid = data.get("id")
    if rid is None or (isinstance(rid, str) and rid.strip() == ""):
        errors.append("id is empty or missing.")

    title = data.get("title")
    if title is None or (isinstance(title, str) and title.strip() == ""):
        errors.append("title is empty or missing.")

    return errors


def collect_rule_paths(rules_dir: Path, changed_list: List[str]) -> List[Path]:
    """Return list of rule paths to validate. If changed_list provided, resolve them."""
    if changed_list:
        resolved: List[Path] = []
        for r in changed_list:
            p = Path(r)
            if not p.is_absolute():
                candidate = rules_dir / p
                if candidate.exists():
                    resolved.append(candidate)
                else:
                    rwd = Path.cwd() / p
                    if rwd.exists():
                        resolved.append(rwd)
                    else:
                        if p.exists():
                            resolved.append(p)
                        else:
                            # keep path for error message later
                            resolved.append(p)
            else:
                resolved.append(p)
        return resolved
    else:
        if not rules_dir.exists():
            return []
        files = sorted([p for p in rules_dir.rglob("*.yml")] + [p for p in rules_dir.rglob("*.yaml")])
        return files


def run_validation(rules_dir: str, changed_rules: List[str], debug: bool = False) -> int:
    rules_path = Path(rules_dir)
    changed_list = [s.strip() for s in changed_rules if s and s.strip()]
    rule_paths = collect_rule_paths(rules_path, changed_list)

    if not rule_paths:
        if changed_list:
            print("❌ No rule files found for the provided changed paths.")
            return 1
        else:
            print(f"⚠️ No rule files found in {rules_dir}")
            return 1

    total = 0
    failures = 0
    detailed_errors: List[Tuple[str, str]] = []

    for rp in rule_paths:
        total += 1
        if debug:
            print(f"[DEBUG] Validating {rp}")
        ok, data_or_err = load_yaml(rp)
        if not ok:
            failures += 1
            err = data_or_err.get("error", "Unknown YAML load error") if isinstance(data_or_err, dict) else str(data_or_err)
            detailed_errors.append((str(rp), f"YAML_PARSE_ERROR: {err}"))
            if debug:
                print(f"[DEBUG] YAML load failed for {rp}: {err}")
            continue

        data = data_or_err
        errs = validate_rule_structure(data)
        if errs:
            failures += 1
            detailed_errors.append((str(rp), "; ".join(errs)))
            if debug:
                print(f"[DEBUG] Validation errors for {rp}: {errs}")

    # Summary
    print("\n" + "=" * 60)
    print(f"Validated rules: {total}")
    if failures == 0:
        print("✅ All rules passed basic validation.")
    else:
        print(f"❌ Failed rules: {failures}")
        print("\nDetails:")
        for path, msg in detailed_errors:
            print(f" - {path}: {msg}")

    return 0 if failures == 0 else 1


# ---------------------------
# Simple EnhancedLogGenerator
# ---------------------------

class EnhancedLogGenerator:
    """
    Minimal synthetic log generator wrapper.

    Provides:
        EnhancedLogGenerator.generate_for_sigma_rule(rule: dict, count: int) -> List[dict]

    The implementation is intentionally small: it uses the top-most detection selection
    and creates simple JSON events that set the fields referenced in the selection.
    """

    @staticmethod
    def _is_selection(obj: Any) -> bool:
        return isinstance(obj, dict)

    @staticmethod
    def _pick_value_for_field(field: str, pattern: Any, idx: int) -> Any:
        # Try to produce reasonable values for common field names
        if pattern is None:
            return None
        if isinstance(pattern, bool):
            return pattern
        if isinstance(pattern, (int, float)):
            return pattern
        s = str(pattern)
        if '*' in s:
            core = s.strip('*')
            if core == "":
                return f"val_{idx}"
            return f"{core}_{idx}"
        if re.search(r"\\d", s):
            return re.sub(r"\\d+", str(random.randint(100, 999)), s)
        # common names
        if field.lower() in ("processname", "process_name"):
            return f"proc_{idx}.exe"
        if field.lower() in ("commandline", "cmdline"):
            return f"cmd /c {s or 'run'}"
        if field.lower() in ("sourceip", "src_ip", "source_ip", "c-ip"):
            return f"192.168.{(idx % 254) + 1}.{(idx % 250) + 1}"
        if field.lower() in ("destinationip", "dest_ip", "destination_ip"):
            return f"10.0.{(idx % 254) + 1}.{(idx % 250) + 1}"
        if field.lower() in ("image", "parentimage"):
            return f"/usr/bin/{s or 'bin'}"
        if field.lower() in ("url", "cs-host", "destinationhostname"):
            return f"example{idx}.com"
        # fallback
        if len(s) <= 3:
            return f"{s}{idx}"
        return s

    @classmethod
    def generate_for_sigma_rule(cls, rule: Dict[str, Any], count: int = 20) -> List[Dict[str, Any]]:
        detection = rule.get("detection", {})
        if not isinstance(detection, dict) or not detection:
            return []

        # pick the first selection block that looks like a dict
        selection = None
        for k, v in detection.items():
            if k.lower() == "condition":
                continue
            if cls._is_selection(v):
                selection = v
                break

        if selection is None:
            return []

        logs: List[Dict[str, Any]] = []
        # create approx 75% positive, 25% negative
        positive_count = max(1, int(count * 0.75))
        negative_count = max(0, count - positive_count)

        # positive logs (matching)
        for i in range(positive_count):
            event: Dict[str, Any] = {
                "_generated": True,
                "timestamp": datetime.utcnow().isoformat() + "Z",
                "_match_type": "positive"
            }
            for field, patt in selection.items():
                # fields may be 'Field|tag' - use left part
                field_name = str(field).split("|")[0]
                event[field_name] = cls._pick_value_for_field(field_name, patt, i)
            logs.append(event)

        # negative logs (non-matching)
        for i in range(negative_count):
            event: Dict[str, Any] = {
                "_generated": True,
                "timestamp": datetime.utcnow().isoformat() + "Z",
                "_match_type": "negative"
            }
            for field, patt in selection.items():
                field_name = str(field).split("|")[0]
                val = cls._pick_value_for_field(field_name, patt, i)
                # alter value to avoid match
                if isinstance(val, str):
                    event[field_name] = f"no_{val}"
                elif isinstance(val, (int, float)):
                    event[field_name] = val + 9999
                else:
                    event[field_name] = f"no_{i}"
            logs.append(event)

        return logs


# ---------------------------
# CLI
# ---------------------------

def main():
    parser = argparse.ArgumentParser(description="Validate Sigma YAML rule files and/or expose EnhancedLogGenerator")
    parser.add_argument("--rules-dir", default="rules/sigma", help="Directory containing sigma rules")
    parser.add_argument("--changed-sigma-rules", default="", help="Comma-separated list of changed rule paths")
    parser.add_argument("--debug", action="store_true", help="Enable debug output")
    parser.add_argument("--mode", choices=["validate", "list"], default="validate", help="Mode: validate rules (default) or list rules")
    args = parser.parse_args()

    if args.debug:
        print("[DEBUG] validate_rules invoked")
        print(f"[DEBUG] rules_dir={args.rules_dir} changed={args.changed_sigma_rules}")

    if args.mode == "list":
        # Simple listing of rule files
        p = Path(args.rules_dir)
        if not p.exists():
            print("No rules directory found.")
            sys.exit(1)
        files = list(p.rglob("*.yml")) + list(p.rglob("*.yaml"))
        for f in files:
            print(str(f))
        sys.exit(0)

    changed_list = [s.strip() for s in args.changed_sigma_rules.split(",") if s.strip()]
    rc = run_validation(args.rules_dir, changed_list, debug=args.debug)
    sys.exit(rc)


if __name__ == "__main__":
    main()
