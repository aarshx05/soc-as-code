#!/usr/bin/env python3
"""
compare_and_classify.py

Delta-based classifier that compares detection artifacts between a baseline run
and a current run and classifies new rules based on the total detection delta.

Usage (example):
  python3 compare_and_classify.py \
    --baseline-results results/baseline \
    --current-results results/current \
    --rules-dir rules/sigma \
    --changed-sigma-rules "rules/sigma/foo.yml,rules/sigma/bar.yml" \
    --output-file artifacts/classification.json \
    --debug
"""

from __future__ import annotations
import argparse
import json
import yaml
from pathlib import Path
from typing import Dict, List
from collections import defaultdict


class DeltaBasedClassifier:
    def __init__(self, baseline_dir: Path, current_dir: Path, rules_dir: Path, debug: bool = False):
        self.baseline_dir = baseline_dir
        self.current_dir = current_dir
        self.rules_dir = rules_dir
        self.debug = debug

        self.baseline_detections = self._load_detections(self.baseline_dir)
        self.current_detections = self._load_detections(self.current_dir)

        self.baseline_total = len(self.baseline_detections)
        self.current_total = len(self.current_detections)
        self.total_delta = self.current_total - self.baseline_total

        print("\n📊 DELTA-BASED DETECTION ANALYSIS:")
        print(f"   Baseline (old rules only): {self.baseline_total} detections")
        print(f"   Current (old + new rules): {self.current_total} detections")
        print(f"   Total Delta: {self.total_delta:+d} detections")

    def _load_detections(self, results_dir: Path) -> List[Dict]:
        """Load detections from a results directory. Expects detections.json"""
        detections_file = results_dir / "detections.json"
        if detections_file.exists():
            try:
                with open(detections_file, "r", encoding="utf-8") as f:
                    data = json.load(f)
                if isinstance(data, list):
                    if self.debug:
                        print(f"[DEBUG] Loaded {len(data)} detections from {detections_file}")
                    return data
                # sometimes file contains object with 'detections'
                if isinstance(data, dict) and "detections" in data and isinstance(data["detections"], list):
                    if self.debug:
                        print(f"[DEBUG] Loaded {len(data['detections'])} detections from {detections_file} (nested key)")
                    return data["detections"]
                if self.debug:
                    print(f"[DEBUG] Unexpected detections.json shape at {detections_file}; returning empty list")
            except Exception as e:
                print(f"   ⚠️ Error reading detections file {detections_file}: {e}")
                if self.debug:
                    import traceback; traceback.print_exc()
        else:
            if self.debug:
                print(f"[DEBUG] No detections file at {detections_file}")
        return []

    def _extract_rule_info_from_yaml(self, rule_path: str) -> Dict[str, str]:
        result = {"id": None, "title": None, "filename": Path(rule_path).stem}
        try:
            p = Path(rule_path)
            if p.exists():
                with open(p, "r", encoding="utf-8") as f:
                    rule_data = yaml.safe_load(f)
                if rule_data and isinstance(rule_data, dict):
                    result["id"] = str(rule_data.get("id") or "").strip() or None
                    result["title"] = str(rule_data.get("title") or "").strip() or None
            else:
                # try to find file by name in rules_dir
                candidates = list(self.rules_dir.rglob(f"{p.name}"))
                if candidates:
                    try:
                        with open(candidates[0], "r", encoding="utf-8") as f:
                            rule_data = yaml.safe_load(f)
                        if rule_data and isinstance(rule_data, dict):
                            result["id"] = str(rule_data.get("id") or "").strip() or None
                            result["title"] = str(rule_data.get("title") or "").strip() or None
                    except Exception:
                        pass
        except Exception as e:
            if self.debug:
                print(f"[DEBUG] Error extracting YAML info from {rule_path}: {e}")
        return result

    def _classify_by_delta(self, avg_delta: float, total_delta: int):
        """
        Returns (score, grade, reasoning)
        """
        # Strong thresholds
        if avg_delta >= 50:
            return 95, "STRONG", f"Excellent: total delta {total_delta} (~{avg_delta:.0f}/rule)."
        if avg_delta >= 30:
            return 85, "STRONG", f"Strong: total delta {total_delta} (~{avg_delta:.0f}/rule)."
        if avg_delta >= 20:
            return 75, "STRONG", f"Good: total delta {total_delta} (~{avg_delta:.0f}/rule)."
        if avg_delta >= 10:
            return 65, "STRONG", f"Decent: total delta {total_delta} (~{avg_delta:.0f}/rule)."
        # Neutral
        if avg_delta >= 5:
            return 55, "NEUTRAL", f"Moderate: total delta {total_delta} (~{avg_delta:.0f}/rule)."
        if avg_delta >= 2:
            return 45, "NEUTRAL", f"Low: total delta {total_delta} (~{avg_delta:.0f}/rule)."
        # Weak
        if avg_delta >= 1:
            return 35, "WEAK", f"Very low: {total_delta} total (~{avg_delta:.1f}/rule)."
        if total_delta == 0:
            return 20, "WEAK", "No new detections: rules did not trigger on test logs."
        # Negative delta
        return 0, "ERROR", f"Negative delta ({total_delta}): regression or generation failure."

    def classify_new_rules(self, new_rule_paths: List[str], total_new_rules: int) -> Dict:
        print("\n" + "=" * 70)
        print(f"🔍 CLASSIFYING {total_new_rules} NEW RULES")
        print("=" * 70)

        if total_new_rules == 0:
            print("   ⚠️ No new rules to classify")
            return {"summary": {"total_rules": 0, "by_grade": {}, "average_score": 0}, "rules": []}

        avg_delta_per_rule = self.total_delta / total_new_rules if total_new_rules else 0.0

        print(f"\n   📊 Delta Analysis: total_delta={self.total_delta}, new_rules={total_new_rules}, avg_delta_per_rule={avg_delta_per_rule:.2f}")

        score, grade, reasoning = self._classify_by_delta(avg_delta_per_rule, self.total_delta)

        classifications = []
        for rp in new_rule_paths:
            info = self._extract_rule_info_from_yaml(rp)
            classification = {
                "rule_name": info.get("filename"),
                "rule_path": rp,
                "rule_id": info.get("id"),
                "rule_title": info.get("title"),
                "classification": grade,
                "score": score,
                "reasoning": reasoning,
                "triggered": self.total_delta > 0,
                "detection_count": round(avg_delta_per_rule),
                "metrics": {
                    "baseline_total": self.baseline_total,
                    "current_total": self.current_total,
                    "total_delta": self.total_delta,
                    "avg_delta_per_rule": round(avg_delta_per_rule, 2),
                    "total_new_rules": total_new_rules,
                },
            }
            classifications.append(classification)
            print(f"\n   📄 {info.get('filename')} — ID: {info.get('id')} Title: {info.get('title')}")
            print(f"      Estimated contribution: ~{round(avg_delta_per_rule)} detections")

        report = {
            "summary": {
                "total_rules": total_new_rules,
                "by_grade": {grade: total_new_rules},
                "average_score": score,
                "total_delta": self.total_delta,
                "baseline_detections": self.baseline_total,
                "current_detections": self.current_total,
                "classification_method": "delta_based",
            },
            "rules": classifications,
        }

        return report

    def classify_individual_rule(self, rule_path: str) -> Dict:
        """Fallback for single-rule changes"""
        info = self._extract_rule_info_from_yaml(rule_path)
        score, grade, reasoning = self._classify_by_delta(float(self.total_delta), self.total_delta)
        if self.total_delta > 0:
            reasoning = reasoning.replace("rules", "rule").replace("Rules", "Rule")
        return {
            "rule_name": info.get("filename"),
            "rule_path": rule_path,
            "rule_id": info.get("id"),
            "rule_title": info.get("title"),
            "classification": grade,
            "score": score,
            "reasoning": reasoning,
            "triggered": self.total_delta > 0,
            "detection_count": self.total_delta,
            "metrics": {
                "baseline_total": self.baseline_total,
                "current_total": self.current_total,
                "delta": self.total_delta,
            },
        }


def parse_rule_list(rule_string: str) -> List[str]:
    if not rule_string:
        return []
    return [r.strip() for r in rule_string.split(",") if r.strip()]


def main():
    parser = argparse.ArgumentParser(description="Delta-based classifier - compares total detection counts")
    parser.add_argument("--baseline-results", required=True)
    parser.add_argument("--current-results", required=True)
    parser.add_argument("--rules-dir", default="rules/sigma")
    parser.add_argument("--changed-sigma-rules", default="")
    parser.add_argument("--changed-yara-rules", default="")
    parser.add_argument("--output-file", required=True)
    parser.add_argument("--debug", action="store_true", help="Enable debug logging")
    args = parser.parse_args()

    if args.debug:
        print("[DEBUG] Debug mode enabled for compare_and_classify.py")
        print(f"[DEBUG] baseline={args.baseline_results} current={args.current_results} rules_dir={args.rules_dir}")

    baseline_dir = Path(args.baseline_results)
    current_dir = Path(args.current_results)
    rules_dir = Path(args.rules_dir)
    output_file = Path(args.output_file)
    output_file.parent.mkdir(parents=True, exist_ok=True)

    changed_sigma = parse_rule_list(args.changed_sigma_rules)
    changed_yara = parse_rule_list(args.changed_yara_rules)
    all_new_rules = changed_sigma + changed_yara

    if not all_new_rules:
        print("⚠️ No changed rules to classify")
        report = {"summary": {"total_rules": 0, "by_grade": {}, "average_score": 0}, "rules": []}
    else:
        classifier = DeltaBasedClassifier(baseline_dir, current_dir, rules_dir, debug=args.debug)
        report = classifier.classify_new_rules(all_new_rules, len(all_new_rules))

    try:
        with open(output_file, "w", encoding="utf-8") as f:
            json.dump(report, f, indent=2)
        print(f"\n✅ Report saved to: {output_file}")
    except Exception as e:
        print(f"❌ Failed to write report to {output_file}: {e}")

    # Print final summary
    print("\n" + "=" * 70)
    print("📊 FINAL SUMMARY")
    print("=" * 70)
    print(f"Total rules: {report['summary'].get('total_rules', 0)}")
    print(f"Average score: {report['summary'].get('average_score', 0)}/100")
    by_grade = report["summary"].get("by_grade", {})
    if by_grade:
        print("\nGrade Distribution:")
        for grade in ["STRONG", "NEUTRAL", "WEAK", "ERROR"]:
            if grade in by_grade:
                print(f"   {grade}: {by_grade[grade]}")

if __name__ == "__main__":
    main()
