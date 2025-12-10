#!/usr/bin/env python3
"""
Check validation results with delta-based classification support
"""
import os
import sys
import json
import argparse
from pathlib import Path


def check_results(results_dir: str, classification_report: str = None, 
                 fail_on_bad_rules: bool = False):
    """Check validation results and classification report"""
    
    results_path = Path(results_dir)
    has_classification = classification_report and Path(classification_report).exists()
    
    print("\n" + "="*70)
    print("VALIDATION & CLASSIFICATION RESULTS")
    print("="*70)
    
    # Check if we have classification report
    if has_classification:
        print("\n📊 DELTA-BASED CLASSIFICATION REPORT FOUND")
        check_classification_report(classification_report, fail_on_bad_rules)
    
    # Also check traditional validation results if they exist
    results_file = results_path / 'validation_results.json'
    if results_file.exists():
        print("\n📈 DETECTION STATISTICS")
        check_traditional_results(results_file)
    else:
        print("\n⚠️ No validation results file found")
    
    print("\n" + "="*70)


def check_classification_report(report_file: str, fail_on_bad_rules: bool):
    """Check classification report and determine pass/fail"""
    
    with open(report_file, 'r') as f:
        report = json.load(f)
    
    summary = report.get('summary', {})
    rules = report.get('rules', [])
    
    print("\n" + "-"*70)
    print("📊 CLASSIFICATION SUMMARY")
    print("-"*70)
    
    total_rules = summary.get('total_rules', 0)
    avg_score = summary.get('average_score', 0)
    by_grade = summary.get('by_grade', {})
    total_delta = summary.get('total_delta', 0)
    baseline_detections = summary.get('baseline_detections', 0)
    current_detections = summary.get('current_detections', 0)
    
    print(f"\n📌 Detection Counts:")
    print(f"   Baseline (old rules): {baseline_detections} detections")
    print(f"   Current (old + new): {current_detections} detections")
    print(f"   Delta (new rules): {total_delta:+d} detections")
    
    print(f"\n📋 Rule Analysis:")
    print(f"   Total new rules: {total_rules}")
    print(f"   Average quality score: {avg_score:.1f}/100")
    
    if total_rules > 0:
        avg_contribution = total_delta / total_rules
        print(f"   Avg contribution per rule: ~{avg_contribution:.1f} detections")
    
    if by_grade:
        print("\n🎯 Grade Distribution:")
        grade_order = ['STRONG', 'NEUTRAL', 'WEAK', 'ERROR']
        for grade in grade_order:
            if grade in by_grade:
                count = by_grade[grade]
                icon = get_grade_icon(grade)
                pct = (count / total_rules * 100) if total_rules > 0 else 0
                print(f"  {icon} {grade:12} : {count} rule(s) ({pct:.0f}%)")
    
    # Detailed rule results
    if rules:
        print("\n" + "-"*70)
        print("📋 DETAILED RULE ANALYSIS")
        print("-"*70)
        
        for rule in sorted(rules, key=lambda r: r.get('score', 0), reverse=True):
            rule_name = rule.get('rule_name', 'Unknown')
            classification = rule.get('classification', 'UNKNOWN')
            score = rule.get('score', 0)
            triggered = rule.get('triggered', False)
            detection_count = rule.get('detection_count', 0)
            
            icon = get_grade_icon(classification)
            
            print(f"\n{icon} {rule_name}")
            print(f"   Classification: {classification} (Score: {score}/100)")
            print(f"   Triggered: {'Yes ✓' if triggered else 'No ✗'}")
            print(f"   Est. contribution: ~{detection_count} detections")
            
            reasoning = rule.get('reasoning', 'No reasoning provided')
            print(f"   Assessment: {reasoning[:200]}{'...' if len(reasoning) > 200 else ''}")
    
    # Determine overall pass/fail
    weak_rules = by_grade.get('WEAK', 0)
    error_rules = by_grade.get('ERROR', 0)
    strong_rules = by_grade.get('STRONG', 0)
    
    print("\n" + "="*70)
    
    if fail_on_bad_rules:
        if error_rules > 0:
            print(f"\n❌ VALIDATION FAILED - CRITICAL ERRORS")
            print(f"   {error_rules} rule(s) caused errors or negative impact")
            print(f"   These rules MUST be fixed before merging")
            sys.exit(1)
        
        elif weak_rules > 0:
            print(f"\n⚠️ VALIDATION PASSED WITH WARNINGS")
            print(f"   {weak_rules} rule(s) classified as WEAK")
            print(f"   These rules generated little to no detections")
            print(f"\n💡 Consider:")
            print(f"   • Running diagnose_rule.py on weak rules")
            print(f"   • Reviewing rule patterns for overly specific conditions")
            print(f"   • Checking if log source is supported")
            sys.exit(0)
        
        elif strong_rules == total_rules and total_rules > 0:
            print(f"\n✅ VALIDATION PASSED - EXCELLENT QUALITY")
            print(f"   All {total_rules} rule(s) classified as STRONG")
            print(f"   Total new detections: {total_delta}")
            sys.exit(0)
        
        else:
            print(f"\n✅ VALIDATION PASSED")
            print(f"   Rules meet minimum quality standards")
            print(f"   Total new detections: {total_delta}")
            sys.exit(0)
    
    else:
        # Report-only mode
        if error_rules > 0:
            print(f"\n⚠️ ERRORS DETECTED (not failing due to fail_on_bad_rules=False)")
            print(f"   {error_rules} rule(s) caused problems")
        elif weak_rules > 0:
            print(f"\n⚠️ WEAK RULES DETECTED (not failing due to fail_on_bad_rules=False)")
            print(f"   {weak_rules} rule(s) generated minimal detections")
        else:
            print(f"\n✅ ALL RULES MEET QUALITY STANDARDS")
        
        print(f"   Total new detections: {total_delta}")
        sys.exit(0)


def check_traditional_results(results_file: Path):
    """Check traditional validation results format"""
    
    with open(results_file, 'r') as f:
        results = json.load(f)
    
    print("-"*70)
    
    mode = results.get('mode', 'unknown')
    detections = results.get('detections', [])
    
    print(f"Mode: {mode.upper()}")
    print(f"Total detections: {len(detections)}")
    
    # Show statistics if available
    stats = results.get('statistics', {})
    if stats:
        total_events = stats.get('total_events_processed', 0)
        total_alerts = stats.get('total_alerts_generated', 0)
        
        print(f"Events processed: {total_events}")
        print(f"Alerts generated: {total_alerts}")
        
        if total_events > 0:
            alert_rate = (total_alerts / total_events * 100)
            print(f"Alert rate: {alert_rate:.2f}%")


def get_grade_icon(grade: str) -> str:
    """Get emoji icon for grade"""
    icons = {
        'STRONG': '✅',
        'NEUTRAL': '➖',
        'WEAK': '⚠️',
        'ERROR': '❌'
    }
    return icons.get(grade, '❓')


def main():
    parser = argparse.ArgumentParser(description='Check validation results')
    parser.add_argument('--results-dir', default='validation_results', 
                       help='Directory containing validation results')
    parser.add_argument('--classification-report', 
                       help='Path to classification report JSON file')
    parser.add_argument('--fail-on-bad-rules', type=lambda x: x.lower() == 'true',
                       default=False,
                       help='Fail if WEAK/ERROR rules are detected (true/false)')
    parser.add_argument('--debug', action='store_true', help='Enable debug logging')
parser.add_argument('--debug', action='store_true', help='Enable debug logging')
args = parser.parse_args()

    if getattr(args, 'debug', False):
        print("[DEBUG] Debug mode enabled for check_results.py")
    
    check_results(args.results_dir, args.classification_report, args.fail_on_bad_rules)


if __name__ == '__main__':
    main()
