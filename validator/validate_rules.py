#!/usr/bin/env python3
"""
Rule Validator - Enhanced version with advanced log generation
Handles regex, wildcards, nested fields, NULL values, and complex patterns
"""
import os
import sys
import json
import yaml
import argparse
import re
import random
import string
from pathlib import Path
from typing import List, Dict, Any, Tuple
from datetime import datetime
from collections import defaultdict

# Import the SOC simulator components
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
from test import SOCSimulator, LogIngestor, load_sigma_rules, SigmaRule


class EnhancedLogGenerator:
    """Enhanced log generator that handles complex patterns including regex, wildcards, and nested fields"""

    @staticmethod
    def generate_for_sigma_rule(rule: Dict[str, Any], count: int = 10) -> List[Dict[str, Any]]:
        """Generate logs that should match a Sigma rule"""
        logs = []
        detection = rule.get('detection', {})

        # Extract all selection criteria
        selections = {}
        filters = {}
        for key, value in detection.items():
            if key == 'condition':
                continue
            if isinstance(value, dict):
                if key.startswith('filter'):
                    filters[key] = value
                else:
                    selections[key] = value

        if not selections:
            return logs

        # Generate matching logs
        for i in range(count):
            log = {'_generated': True, '_test_id': str(i)}

            # Pick the first selection to generate from
            first_selection = list(selections.values())[0]

            for field, pattern in first_selection.items():
                # Generate value that will actually match
                generated_value = EnhancedLogGenerator._generate_matching_value(field, pattern, i)
                
                # Handle nested field paths (e.g., "process.command_line")
                if '.' in field:
                    EnhancedLogGenerator._set_nested_field(log, field, generated_value)
                else:
                    log[field] = generated_value
                
                if i < 3:  # Only print first 3 for brevity
                    print(f"      Generated field '{field}' = '{generated_value}' for pattern '{pattern}'")

            # Add some context fields
            log['timestamp'] = datetime.utcnow().isoformat() + 'Z'
            log['host'] = f'test-host-{i % 3}'

            logs.append(log)

        # Also generate some non-matching logs (for false positive testing)
        for i in range(count // 2):
            log = {
                '_generated': True,
                '_test_id': f'negative-{i}',
                'timestamp': datetime.utcnow().isoformat() + 'Z',
                'host': f'test-host-{i % 3}',
                'EventID': 9999,
                'ProcessName': 'benign.exe',
                'Message': 'Normal activity'
            }
            logs.append(log)

        return logs

    @staticmethod
    def _set_nested_field(log: Dict[str, Any], field_path: str, value: Any):
        """Set a value in a nested dictionary structure"""
        parts = field_path.split('.')
        current = log
        
        for i, part in enumerate(parts[:-1]):
            if part not in current:
                current[part] = {}
            current = current[part]
        
        current[parts[-1]] = value

    @staticmethod
    def _generate_matching_value(field: str, pattern: Any, index: int = 0) -> Any:
        """Generate a value that matches the given pattern (enhanced version)"""
        if isinstance(pattern, list):
            # Pick different options for variety
            pattern = pattern[index % len(pattern)]

        # Handle NULL patterns
        if pattern is None:
            return None

        # Handle boolean patterns
        if isinstance(pattern, bool):
            return pattern

        # Handle numeric patterns
        if isinstance(pattern, int):
            return pattern

        pattern_str = str(pattern)

        # REGEX PATTERN DETECTION
        # Check if it looks like a regex pattern (contains .*, .+, ^, $, [], etc.)
        if EnhancedLogGenerator._is_regex_pattern(pattern_str):
            return EnhancedLogGenerator._generate_from_regex(pattern_str, index)

        # WILDCARD PATTERNS (* and ?)
        if '*' in pattern_str or '?' in pattern_str:
            return EnhancedLogGenerator._generate_from_wildcard(pattern_str, index)

        # EXACT MATCH - return as-is
        return pattern_str

    @staticmethod
    def _is_regex_pattern(s: str) -> bool:
        """Check if string looks like a regex pattern"""
        regex_indicators = ['.*', '.+', '^', '$', '[', ']', '(', ')', '|', '\\d', '\\w', '\\s']
        return any(indicator in s for indicator in regex_indicators)

    @staticmethod
    def _generate_from_regex(pattern: str, index: int) -> str:
        """Generate a string that matches a regex pattern"""
        # Remove anchors for simplicity
        pattern = pattern.replace('^', '').replace('$', '')
        
        # Handle common regex patterns
        result = pattern
        
        # Replace .* with random text
        if '.*' in result:
            parts = result.split('.*')
            result = f"text{index}_".join(parts)
        
        # Replace .+ with random text
        if '.+' in result:
            parts = result.split('.+')
            result = f"text{index}".join(parts)
        
        # Replace \d+ with numbers
        result = re.sub(r'\\d\+', lambda m: str(random.randint(100, 999)), result)
        result = re.sub(r'\\d', lambda m: str(random.randint(0, 9)), result)
        
        # Replace \w+ with alphanumeric
        result = re.sub(r'\\w\+', lambda m: ''.join(random.choices(string.ascii_letters, k=8)), result)
        result = re.sub(r'\\w', lambda m: random.choice(string.ascii_letters), result)
        
        # Handle character classes [A-Za-z0-9]
        def replace_char_class(match):
            char_class = match.group(0)
            if '[A-Za-z0-9+/]' in char_class:
                # Base64-like pattern
                base64_chars = string.ascii_letters + string.digits + '+/'
                length = 20  # Default length
                if '{' in pattern:
                    # Extract length from {n,m}
                    length_match = re.search(r'\{(\d+),?(\d+)?\}', pattern)
                    if length_match:
                        length = int(length_match.group(1))
                return ''.join(random.choices(base64_chars, k=length))
            elif '[A-Za-z]' in char_class:
                return ''.join(random.choices(string.ascii_letters, k=5))
            elif '[0-9]' in char_class:
                return ''.join(random.choices(string.digits, k=5))
            return 'X'
        
        result = re.sub(r'\[[^\]]+\]\{\d+,?\d*\}', replace_char_class, result)
        result = re.sub(r'\[[^\]]+\]', replace_char_class, result)
        
        # Handle quantifiers {n,m}
        result = re.sub(r'\{(\d+),?\d*\}', '', result)
        
        # Clean up any remaining regex syntax
        result = result.replace('\\', '')
        
        return result

    @staticmethod
    def _generate_from_wildcard(pattern: str, index: int) -> str:
        """Generate a string that matches a wildcard pattern"""
        # For patterns like "*cmd.exe*", we generate variations
        if pattern.startswith('*') and pattern.endswith('*'):
            # *middle* -> generate with prefix/suffix
            middle = pattern.strip('*')
            if middle:
                variations = [
                    middle,  # Just the pattern itself
                    f"prefix_{middle}",  # With prefix
                    f"{middle}_suffix",  # With suffix
                    f"test_{middle}_end",  # With both
                ]
                return variations[index % len(variations)]
            return "test_value"
        
        elif pattern.startswith('*'):
            # *suffix -> generate with optional prefix
            suffix = pattern.lstrip('*')
            if suffix:
                return suffix if index % 2 == 0 else f"prefix_{suffix}"
            return "test_value"
        
        elif pattern.endswith('*'):
            # prefix* -> generate with optional suffix
            prefix = pattern.rstrip('*')
            if prefix:
                return prefix if index % 2 == 0 else f"{prefix}_suffix"
            return "test_value"
        
        # Handle ? wildcards (single character)
        if '?' in pattern:
            # Replace each ? with a random character
            result = ""
            for char in pattern:
                if char == '?':
                    result += random.choice(string.ascii_lowercase)
                else:
                    result += char
            return result
        
        return pattern

    @staticmethod
    def generate_for_yara_rule(rule_content: str, count: int = 10) -> List[Dict[str, Any]]:
        """Generate logs that should match a YARA rule"""
        logs = []

        # Parse YARA rule to extract strings
        strings = []
        in_strings = False
        for line in rule_content.split('\n'):
            line = line.strip()
            if line.startswith('strings:'):
                in_strings = True
                continue
            if in_strings:
                if line.startswith('condition:'):
                    break
                if '=' in line and '"' in line:
                    parts = line.split('"')
                    if len(parts) >= 2:
                        strings.append(parts[1])

        # Generate matching logs
        for i in range(count):
            log = {
                '_generated': True,
                '_test_id': str(i),
                'timestamp': datetime.utcnow().isoformat() + 'Z',
                'host': f'test-host-{i % 3}',
            }

            if strings:
                log['message'] = f'Test message containing {strings[0]}'
                log['payload'] = ' '.join(strings[:2]) if len(strings) > 1 else strings[0]
            else:
                log['message'] = 'Generic suspicious activity'

            logs.append(log)

        # Generate non-matching logs
        for i in range(count // 2):
            log = {
                '_generated': True,
                '_test_id': f'negative-{i}',
                'timestamp': datetime.utcnow().isoformat() + 'Z',
                'host': f'test-host-{i % 3}',
                'message': 'Benign activity',
                'payload': 'Normal data'
            }
            logs.append(log)

        return logs


class RuleValidator:
    """Validates rules by generating test logs and running the simulator"""

    def __init__(self, output_dir: str):
        self.output_dir = Path(output_dir)
        self.output_dir.mkdir(parents=True, exist_ok=True)
        self.results = {
            'timestamp': datetime.utcnow().isoformat() + 'Z',
            'rules_tested': [],
            'total_passed': 0,
            'total_failed': 0,
            'details': []
        }

    def validate_sigma_rule(self, rule_path: str) -> Dict[str, Any]:
        """Validate a single Sigma rule"""
        print(f"\n[+] Validating Sigma rule: {rule_path}")

        rule_path = Path(rule_path)
        if not rule_path.exists():
            return self._create_error_result(str(rule_path), "Rule file not found", rule_type='sigma')

        try:
            # Load the rule
            rules = load_sigma_rules(str(rule_path))
            if not rules:
                return self._create_error_result(str(rule_path), "No rules found in file", rule_type='sigma')

            rule = rules[0]  # Validate first rule in file
            rule_id = rule.get('id', rule_path.stem)
            rule_title = rule.get('title', 'Untitled')

            print(f"    Rule ID: {rule_id}")
            print(f"    Title: {rule_title}")
            
            # Debug: Print the rule detection logic
            print(f"    Detection config: {json.dumps(rule.get('detection', {}), indent=6)}")

            # Generate test logs using enhanced generator
            print(f"    Generating test logs...")
            test_logs = EnhancedLogGenerator.generate_for_sigma_rule(rule, count=20)

            # Save test logs
            test_log_file = self.output_dir / f"test_logs_{rule_id}.jsonl"
            with open(test_log_file, 'w') as f:
                for log in test_logs:
                    f.write(json.dumps(log) + '\n')

            print(f"    Generated {len(test_logs)} test logs")
            
            # Debug: Test the rule manually on first few logs
            print(f"    Testing rule matching manually on first 3 logs...")
            sigma_rule_obj = SigmaRule(rule)
            for i, log in enumerate(test_logs[:3]):
                matched = sigma_rule_obj.matches(log)
                print(f"      Log {i}: {matched is not None}")
                if matched is None and i < 3:
                    print(f"        Log content: {json.dumps(log, indent=8)}")

            # Run simulator
            print(f"    Running simulator...")
            simulator = SOCSimulator(sigma_rules=rules, yara_path=None)
            simulator.process_logs(test_logs)

            alerts = simulator.export_alerts()
            metrics = simulator.export_metrics()

            # Analyze results
            expected_matches = sum(
                1 for log in test_logs
                if not str(log.get('_test_id', '')).startswith('negative')
            )
            actual_matches = len([a for a in alerts if a.get('rule_id') == rule_id])

            print(f"    Expected matches: {expected_matches}")
            print(f"    Actual matches: {actual_matches}")
            
            if actual_matches == 0 and expected_matches > 0:
                print(f"    WARNING: No matches detected!")

            # Calculate detection rate
            detection_rate = (actual_matches / expected_matches * 100) if expected_matches > 0 else 0

            # Determine pass/fail (50% threshold)
            passed = detection_rate >= 50

            result = {
                'rule_path': str(rule_path),
                'rule_id': rule_id,
                'rule_title': rule_title,
                'type': 'sigma',
                'passed': passed,
                'expected_matches': expected_matches,
                'actual_matches': actual_matches,
                'detection_rate': round(detection_rate, 2),
                'total_alerts': len(alerts),
                'metrics': metrics,
                'test_log_file': str(test_log_file)
            }

            if passed:
                print(f"    ✓ PASSED - Detection rate: {detection_rate:.1f}%")
                self.results['total_passed'] += 1
            else:
                print(f"    ✗ FAILED - Detection rate: {detection_rate:.1f}% (expected >= 50%)")
                self.results['total_failed'] += 1

            return result

        except Exception as e:
            import traceback
            traceback.print_exc()
            print(f"    ✗ ERROR - {str(e)}")
            return self._create_error_result(
                str(rule_path), 
                str(e), 
                rule_type='sigma',
                rule_title=rule.get('title') if 'rule' in locals() and isinstance(rule, dict) else None
            )

    def validate_yara_rule(self, rule_path: str) -> Dict[str, Any]:
        """Validate a single YARA rule"""
        print(f"\n[+] Validating YARA rule: {rule_path}")

        rule_path = Path(rule_path)
        if not rule_path.exists():
            return self._create_error_result(str(rule_path), "Rule file not found", rule_type='yara')

        try:
            # Check if yara is available
            try:
                import yara  # noqa: F401
            except ImportError:
                return self._create_error_result(str(rule_path), "yara-python not installed", rule_type='yara')

            # Load rule content
            with open(rule_path, 'r') as f:
                rule_content = f.read()

            rule_name = rule_path.stem
            print(f"    Rule: {rule_name}")

            # Generate test logs
            print(f"    Generating test logs...")
            test_logs = EnhancedLogGenerator.generate_for_yara_rule(rule_content, count=20)

            # Save test logs
            test_log_file = self.output_dir / f"test_logs_{rule_name}.jsonl"
            with open(test_log_file, 'w') as f:
                for log in test_logs:
                    f.write(json.dumps(log) + '\n')

            # Run simulator
            print(f"    Running simulator...")
            simulator = SOCSimulator(sigma_rules=[], yara_path=str(rule_path))
            simulator.process_logs(test_logs)

            alerts = simulator.export_alerts()
            metrics = simulator.export_metrics()

            # Analyze results
            expected_matches = sum(
                1 for log in test_logs
                if not str(log.get('_test_id', '')).startswith('negative')
            )
            actual_matches = len(alerts)

            detection_rate = (actual_matches / expected_matches * 100) if expected_matches > 0 else 0
            passed = detection_rate >= 50

            result = {
                'rule_path': str(rule_path),
                'rule_id': rule_name,
                'rule_title': f'YARA: {rule_name}',
                'type': 'yara',
                'passed': passed,
                'expected_matches': expected_matches,
                'actual_matches': actual_matches,
                'detection_rate': round(detection_rate, 2),
                'total_alerts': len(alerts),
                'metrics': metrics,
                'test_log_file': str(test_log_file)
            }

            if passed:
                print(f"    ✓ PASSED - Detection rate: {detection_rate:.1f}%")
                self.results['total_passed'] += 1
            else:
                print(f"    ✗ FAILED - Detection rate: {detection_rate:.1f}% (expected >= 50%)")
                self.results['total_failed'] += 1

            return result

        except Exception as e:
            print(f"    ✗ ERROR - {str(e)}")
            return self._create_error_result(str(rule_path), str(e), rule_type='yara')

    def _create_error_result(self, rule_path: str, error: str, rule_type: str = "unknown", rule_title: str = None) -> Dict[str, Any]:
        """Create an error result"""
        self.results['total_failed'] += 1
        return {
            'rule_path': rule_path,
            'rule_id': Path(rule_path).stem,
            'rule_title': rule_title or Path(rule_path).stem,
            'type': rule_type,
            'passed': False,
            'error': error
        }

    def save_results(self):
        """Save validation results to disk"""
        results_file = self.output_dir / 'validation_results.json'
        with open(results_file, 'w') as f:
            json.dump(self.results, f, indent=2)

        # Create a markdown summary
        self._create_markdown_summary()

        print(f"\n[+] Results saved to: {results_file}")

    def _create_markdown_summary(self):
        """Create a markdown summary for PR comments"""
        summary_file = self.output_dir / 'summary.md'

        with open(summary_file, 'w', encoding='utf-8') as f:
            f.write("# 🛡️ Security Rule Validation Results\n\n")

            total_tested = self.results.get('total_passed', 0) + self.results.get('total_failed', 0)
            pass_rate = (self.results.get('total_passed', 0) / total_tested * 100) if total_tested > 0 else 0

            f.write("## Summary\n\n")
            f.write(f"- **Total Rules Tested:** {total_tested}\n")
            f.write(f"- **Passed:** ✅ {self.results.get('total_passed', 0)}\n")
            f.write(f"- **Failed:** ❌ {self.results.get('total_failed', 0)}\n")
            f.write(f"- **Pass Rate:** {pass_rate:.1f}%\n\n")

            f.write("## Detailed Results\n\n")

            for detail in self.results.get('details', []):
                passed = detail.get('passed', False)
                status = "✅ PASSED" if passed else "❌ FAILED"
                rule_title = detail.get('rule_title') or detail.get('rule_id') or "Unknown"
                f.write(f"### {status} - {rule_title}\n\n")
                f.write(f"- **Rule ID:** `{detail.get('rule_id', 'unknown')}`\n")

                rule_type = detail.get('type', 'unknown')
                f.write(f"- **Type:** {str(rule_type).upper()}\n")
                f.write(f"- **Path:** `{detail.get('rule_path', 'N/A')}`\n")

                if 'error' in detail:
                    f.write(f"- **Error:** {detail.get('error')}\n\n")
                else:
                    f.write(f"- **Detection Rate:** {detail.get('detection_rate', 0)}%\n")
                    f.write(f"- **Expected Matches:** {detail.get('expected_matches', 0)}\n")
                    f.write(f"- **Actual Matches:** {detail.get('actual_matches', 0)}\n")
                    f.write(f"- **Total Alerts:** {detail.get('total_alerts', 0)}\n\n")


def main():
    parser = argparse.ArgumentParser(description='Validate Security Rules')
    parser.add_argument('--sigma-rules', help='Comma-separated list of Sigma rule files')
    parser.add_argument('--yara-rules', help='Comma-separated list of YARA rule files')
    parser.add_argument('--output-dir', default='validation_results', help='Output directory')
    args = parser.parse_args()

    validator = RuleValidator(args.output_dir)

    # Validate Sigma rules
    if args.sigma_rules:
        sigma_files = [f.strip() for f in args.sigma_rules.split(',') if f.strip()]
        for rule_file in sigma_files:
            result = validator.validate_sigma_rule(rule_file)
            validator.results['details'].append(result)
            validator.results['rules_tested'].append(rule_file)

    # Validate YARA rules
    if args.yara_rules:
        yara_files = [f.strip() for f in args.yara_rules.split(',') if f.strip()]
        for rule_file in yara_files:
            result = validator.validate_yara_rule(rule_file)
            validator.results['details'].append(result)
            validator.results['rules_tested'].append(rule_file)

    # Save results
    validator.save_results()

    # Exit with error code if any validations failed
    if validator.results['total_failed'] > 0:
        print(f"\n❌ Validation failed: {validator.results['total_failed']} rule(s) failed")
        sys.exit(1)
    else:
        print(f"\n✅ All {validator.results['total_passed']} rule(s) passed validation")
        sys.exit(0)


if __name__ == '__main__':
    main()
