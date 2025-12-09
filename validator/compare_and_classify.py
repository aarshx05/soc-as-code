#!/usr/bin/env python3
"""
ACTUAL FIX: Extract rule IDs from YAML files, not filenames
The issue: Detection JSON has rule_id from YAML (e.g., "SIG-001234")
           But we were matching against filename (e.g., "reg")
"""

import argparse
import json
import yaml
from pathlib import Path
from typing import Dict, List, Set
from collections import defaultdict


class WorkingClassifier:
    """
    Classifier that correctly matches rule IDs from YAML files
    """
    
    def __init__(self, baseline_dir: Path, current_dir: Path, rules_dir: Path):
        self.baseline_dir = baseline_dir
        self.current_dir = current_dir
        self.rules_dir = rules_dir
        
        # Load detections
        self.baseline_detections = self._load_detections(baseline_dir)
        self.current_detections = self._load_detections(current_dir)
        
        # Build rule detection maps
        self.baseline_rules = self._build_rule_map(self.baseline_detections)
        self.current_rules = self._build_rule_map(self.current_detections)
        
        # Calculate totals
        self.baseline_total = len(self.baseline_detections)
        self.current_total = len(self.current_detections)
        self.delta = self.current_total - self.baseline_total
        
        print(f"\n📊 DETECTION ANALYSIS:")
        print(f"   Baseline: {len(self.baseline_rules)} rules -> {self.baseline_total} alerts")
        print(f"   Current: {len(self.current_rules)} rules -> {self.current_total} alerts")
        print(f"   Delta: {self.delta:+d} alerts")
        
        # DEBUG: Show sample rule IDs
        print(f"\n🔍 Sample baseline rule IDs:")
        for rid in list(self.baseline_rules.keys())[:5]:
            print(f"      - {rid} ({len(self.baseline_rules[rid])} detections)")
        
        print(f"\n🔍 Sample current rule IDs:")
        for rid in list(self.current_rules.keys())[:5]:
            print(f"      - {rid} ({len(self.current_rules[rid])} detections)")
    
    def _load_detections(self, results_dir: Path) -> List[Dict]:
        """Load detections from results directory"""
        detections_file = results_dir / 'detections.json'
        if detections_file.exists():
            with open(detections_file, 'r') as f:
                data = json.load(f)
                print(f"\n   Loaded {len(data)} detections from {detections_file}")
                if data:
                    print(f"   Sample detection keys: {list(data[0].keys())}")
                return data
        print(f"\n   ⚠️  No detections file found at {detections_file}")
        return []
    
    def _build_rule_map(self, detections: List[Dict]) -> Dict[str, List[Dict]]:
        """Build map of rule_id -> list of detections"""
        rule_map = defaultdict(list)
        unknown_count = 0
        
        for detection in detections:
            rule_id = self._extract_rule_id(detection)
            if rule_id and rule_id != 'unknown':
                rule_map[rule_id].append(detection)
            else:
                unknown_count += 1
        
        if unknown_count > 0:
            print(f"   ⚠️  {unknown_count} detections had unknown rule IDs")
        
        return dict(rule_map)
    
    def _extract_rule_id(self, detection: Dict) -> str:
        """Extract rule identifier from detection JSON"""
        # Strategy 1: Direct rule_id field (most common)
        if 'rule_id' in detection and detection['rule_id']:
            return str(detection['rule_id']).strip()
        
        # Strategy 2: Check raw._source_rule_id
        if 'raw' in detection and isinstance(detection['raw'], dict):
            if '_source_rule_id' in detection['raw']:
                return str(detection['raw']['_source_rule_id']).strip()
        
        # Strategy 3: rule_title as fallback
        if 'rule_title' in detection and detection['rule_title']:
            return str(detection['rule_title']).strip()
        
        # Strategy 4: Check other common fields
        for key in ['rule_name', 'rule', 'id', 'signature_id']:
            if key in detection and detection[key]:
                return str(detection[key]).strip()
        
        return 'unknown'
    
    def _extract_rule_id_from_yaml(self, rule_path: str) -> str:
        """
        Extract the actual rule ID from the YAML file
        This is THE KEY FIX - we need the ID from inside the YAML, not the filename
        """
        try:
            with open(rule_path, 'r') as f:
                rule_data = yaml.safe_load(f)
                
                if not rule_data:
                    print(f"   ⚠️  Empty YAML file")
                    return None
                
                # Try to find the ID field (common in Sigma rules)
                if 'id' in rule_data:
                    rule_id = str(rule_data['id']).strip()
                    print(f"   Found ID in YAML: {rule_id}")
                    return rule_id
                
                # Fallback to title
                if 'title' in rule_data:
                    rule_title = str(rule_data['title']).strip()
                    print(f"   Using title as ID: {rule_title}")
                    return rule_title
                
                # Last resort: filename
                rule_name = Path(rule_path).stem
                print(f"   ⚠️  No ID/title in YAML, using filename: {rule_name}")
                return rule_name
                
        except Exception as e:
            print(f"   ❌ Error reading YAML: {e}")
            return None
    
    def classify_new_rule(self, rule_path: str) -> Dict:
        """
        Classify a new rule based on its actual contribution
        FIXED: Now extracts rule ID from YAML content
        """
        print(f"\n{'='*70}")
        print(f"🔍 ANALYZING: {rule_path}")
        print(f"{'='*70}")
        
        # Extract the actual rule ID from the YAML file
        rule_id_from_yaml = self._extract_rule_id_from_yaml(rule_path)
        
        if not rule_id_from_yaml:
            return {
                'rule_name': Path(rule_path).stem,
                'rule_path': rule_path,
                'classification': 'ERROR',
                'score': 0,
                'reasoning': 'Could not extract rule ID from YAML file',
                'triggered': False,
                'detection_count': 0,
                'metrics': {}
            }
        
        # Check if rule exists in baseline
        in_baseline = rule_id_from_yaml in self.baseline_rules
        in_current = rule_id_from_yaml in self.current_rules
        
        print(f"   In baseline: {in_baseline}")
        print(f"   In current: {in_current}")
        
        if in_baseline:
            baseline_count = len(self.baseline_rules[rule_id_from_yaml])
            current_count = len(self.current_rules.get(rule_id_from_yaml, []))
            
            return {
                'rule_name': Path(rule_path).stem,
                'rule_path': rule_path,
                'rule_id_from_yaml': rule_id_from_yaml,
                'classification': 'ERROR',
                'score': 0,
                'reasoning': f'Rule "{rule_id_from_yaml}" exists in baseline ({baseline_count} alerts). Not a new rule!',
                'triggered': True,
                'detection_count': current_count,
                'metrics': {
                    'baseline_alerts': self.baseline_total,
                    'current_alerts': self.current_total,
                    'delta': self.delta
                }
            }
        
        # Count detections from this rule
        rule_detection_count = len(self.current_rules.get(rule_id_from_yaml, []))
        
        print(f"✓ Rule ID from YAML: {rule_id_from_yaml}")
        print(f"✓ Detection count: {rule_detection_count}")
        
        # SCORING LOGIC
        if rule_detection_count == 0:
            score = 20
            grade = 'WEAK'
            reasoning = 'Rule did not trigger on any logs. Possible causes: (1) unsupported log source, (2) overly specific pattern, (3) syntax errors.'
        
        elif rule_detection_count >= 50:
            score = 95
            grade = 'STRONG'
            reasoning = f'Excellent! Rule detected {rule_detection_count} events. Very high-value detection capability.'
        
        elif rule_detection_count >= 20:
            score = 85
            grade = 'STRONG'
            reasoning = f'Strong detection capability with {rule_detection_count} alerts. High value addition.'
        
        elif rule_detection_count >= 10:
            score = 70
            grade = 'STRONG'
            reasoning = f'Good detection rate ({rule_detection_count} alerts). Solid contribution.'
        
        elif rule_detection_count >= 5:
            score = 55
            grade = 'NEUTRAL'
            reasoning = f'Moderate detection ({rule_detection_count} alerts). Rule works but has limited coverage.'
        
        elif rule_detection_count >= 2:
            score = 45
            grade = 'NEUTRAL'
            reasoning = f'Low detection rate ({rule_detection_count} alerts). Very narrow scope or insufficient test data.'
        
        else:  # 1 detection
            score = 30
            grade = 'WEAK'
            reasoning = f'Minimal detection (only {rule_detection_count} alert). Rule may be too restrictive.'
        
        # Efficiency adjustment
        if rule_detection_count > 0 and self.current_total > 0:
            efficiency = rule_detection_count / self.current_total
            
            if efficiency > 0.15:  # >15% of alerts
                score += 5
                reasoning += f' High efficiency ({efficiency:.1%}).'
            elif efficiency < 0.005 and rule_detection_count < 5:  # <0.5%
                score -= 5
                reasoning += f' Low efficiency ({efficiency:.1%}).'
        
        # Delta sanity check
        if rule_detection_count > 0 and self.delta <= 0:
            score -= 10
            reasoning += ' ⚠️  Total alerts unchanged (possible duplicate detection).'
        
        # Clamp score
        score = max(0, min(100, score))
        
        # Final grade
        if score >= 60:
            grade = 'STRONG'
        elif score >= 40:
            grade = 'NEUTRAL'
        else:
            grade = 'WEAK'
        
        result = {
            'rule_name': Path(rule_path).stem,
            'rule_path': rule_path,
            'rule_id_from_yaml': rule_id_from_yaml,
            'classification': grade,
            'score': score,
            'reasoning': reasoning,
            'triggered': rule_detection_count > 0,
            'detection_count': rule_detection_count,
            'metrics': {
                'baseline_total': self.baseline_total,
                'current_total': self.current_total,
                'delta': self.delta,
                'rule_contribution': rule_detection_count,
                'rule_contribution_pct': round(rule_detection_count / self.current_total * 100, 2) if self.current_total > 0 else 0
            }
        }
        
        print(f"\n✅ CLASSIFICATION: {grade} (Score: {score}/100)")
        print(f"   {reasoning}")
        
        return result


def parse_rule_list(rule_string: str) -> List[str]:
    """Parse comma-separated rule list"""
    if not rule_string or rule_string.strip() == '':
        return []
    return [r.strip() for r in rule_string.split(',') if r.strip()]


def main():
    parser = argparse.ArgumentParser(
        description='Fixed classifier - extracts rule IDs from YAML files'
    )
    parser.add_argument('--baseline-results', required=True)
    parser.add_argument('--current-results', required=True)
    parser.add_argument('--rules-dir', required=True, help='Directory containing rule files')
    parser.add_argument('--changed-sigma-rules', default='')
    parser.add_argument('--changed-yara-rules', default='')
    parser.add_argument('--output-file', required=True)
    parser.add_argument('--debug', action='store_true')
    
    args = parser.parse_args()
    
    baseline_dir = Path(args.baseline_results)
    current_dir = Path(args.current_results)
    rules_dir = Path(args.rules_dir)
    output_file = Path(args.output_file)
    
    output_file.parent.mkdir(parents=True, exist_ok=True)
    
    changed_sigma = parse_rule_list(args.changed_sigma_rules)
    changed_yara = parse_rule_list(args.changed_yara_rules)
    
    if not changed_sigma and not changed_yara:
        print("⚠️  No changed rules to classify")
        report = {
            'summary': {'total_rules': 0, 'by_grade': {}, 'average_score': 0},
            'rules': []
        }
    else:
        classifier = WorkingClassifier(baseline_dir, current_dir, rules_dir)
        
        classifications = []
        
        for rule_path in changed_sigma + changed_yara:
            result = classifier.classify_new_rule(rule_path)
            classifications.append(result)
        
        # Generate summary
        grade_counts = defaultdict(int)
        total_score = 0
        
        for c in classifications:
            grade_counts[c['classification']] += 1
            total_score += c['score']
        
        avg_score = total_score / len(classifications) if classifications else 0
        
        report = {
            'summary': {
                'total_rules': len(classifications),
                'by_grade': dict(grade_counts),
                'average_score': round(avg_score, 2)
            },
            'rules': classifications
        }
    
    with open(output_file, 'w') as f:
        json.dump(report, f, indent=2)
    
    print(f"\n{'='*70}")
    print("📊 FINAL SUMMARY")
    print(f"{'='*70}")
    print(f"Total rules: {report['summary']['total_rules']}")
    print(f"Average score: {report['summary']['average_score']}/100")
    print(f"\nGrade Distribution:")
    
    for grade in ['STRONG', 'NEUTRAL', 'WEAK', 'ERROR']:
        if grade in report['summary']['by_grade']:
            count = report['summary']['by_grade'][grade]
            print(f"   {grade}: {count}")
    
    print(f"\n✅ Report saved to: {output_file}")
    print(f"\n💡 SCORING GUIDE:")
    print(f"   STRONG (60-100): 10+ detections")
    print(f"   NEUTRAL (40-59): 2-9 detections")
    print(f"   WEAK (0-39): 0-1 detections")


if __name__ == '__main__':
    main()
