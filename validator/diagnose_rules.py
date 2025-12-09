#!/usr/bin/env python3
"""
Diagnostic Tool: Shows exactly why a rule doesn't detect anything
Run this BEFORE pushing to GitHub to debug your rule
"""
import sys
import json
import yaml
from pathlib import Path

# Add validator to path
sys.path.insert(0, str(Path(__file__).parent))

from validator.validate_rules import UniversalLogGenerator
from test import SigmaRule


def diagnose_rule(rule_path: str):
    """Diagnose why a rule isn't detecting"""
    
    print(f"\n{'='*70}")
    print(f"🔬 DIAGNOSING RULE: {rule_path}")
    print(f"{'='*70}\n")
    
    # Load rule
    try:
        with open(rule_path, 'r') as f:
            rule = yaml.safe_load(f)
    except Exception as e:
        print(f"❌ ERROR: Cannot load rule: {e}")
        return False
    
    # Show rule content
    print("📋 RULE CONTENT:")
    print(f"   Title: {rule.get('title', 'N/A')}")
    print(f"   ID: {rule.get('id', 'N/A')}")
    print(f"   Level: {rule.get('level', 'N/A')}")
    
    logsource = rule.get('logsource', {})
    print(f"\n📂 LOGSOURCE:")
    for k, v in logsource.items():
        print(f"   {k}: {v}")
    
    detection = rule.get('detection', {})
    print(f"\n🔍 DETECTION:")
    print(f"   Condition: {detection.get('condition', 'N/A')}")
    
    # Show selections
    for key, value in detection.items():
        if key != 'condition' and isinstance(value, dict):
            print(f"\n   Selection '{key}':")
            for field, pattern in value.items():
                print(f"      {field}: {pattern}")
    
    # Detect log type
    log_type = UniversalLogGenerator._detect_log_type(logsource)
    print(f"\n🎯 DETECTED LOG TYPE: {log_type}")
    
    # Generate sample logs
    print(f"\n🧪 GENERATING SAMPLE LOGS...")
    try:
        sample_logs = UniversalLogGenerator.generate_for_rule(rule, count=5)
        
        if not sample_logs:
            print("❌ ERROR: Log generator returned 0 logs!")
            print("   This means the rule has no detection selections.")
            return False
        
        print(f"✅ Generated {len(sample_logs)} sample logs")
        
        # Show positive samples
        positive_logs = [l for l in sample_logs if l.get('_match_type') == 'positive']
        print(f"\n📊 POSITIVE SAMPLES (should match): {len(positive_logs)}")
        
        if positive_logs:
            print("\nSample Positive Log #1:")
            sample = positive_logs[0].copy()
            # Remove metadata for cleaner view
            for key in list(sample.keys()):
                if key.startswith('_'):
                    del sample[key]
            print(json.dumps(sample, indent=2))
        
        # Test if rule actually matches
        print(f"\n🎯 TESTING RULE MATCHING...")
        
        sigma_rule = SigmaRule(rule)
        matches = 0
        
        for log in positive_logs:
            matched_fields = sigma_rule.matches(log)
            if matched_fields is not None:
                matches += 1
        
        print(f"   Positive logs that matched: {matches}/{len(positive_logs)}")
        
        if matches == 0:
            print(f"\n❌ PROBLEM FOUND: Rule doesn't match its own generated logs!")
            print(f"\n🔍 DEBUGGING INFO:")
            
            # Show what the rule expects
            print(f"\n   Rule expects these fields:")
            selections = {k: v for k, v in detection.items() if k != 'condition' and isinstance(v, dict)}
            for sel_name, sel_fields in selections.items():
                print(f"   Selection '{sel_name}':")
                for field, pattern in sel_fields.items():
                    print(f"      {field} = {pattern}")
            
            # Show what the log has
            print(f"\n   Generated log has these fields:")
            if positive_logs:
                for field in sorted(positive_logs[0].keys()):
                    if not field.startswith('_'):
                        value = positive_logs[0][field]
                        print(f"      {field} = {value}")
            
            # Suggest fixes
            print(f"\n💡 POSSIBLE FIXES:")
            print(f"   1. Check if field names match exactly (case-sensitive)")
            print(f"   2. Verify the log generator understands your log source")
            print(f"   3. Simplify the rule pattern to be less restrictive")
            print(f"   4. Check if modifiers (|contains, |endswith, etc.) are needed")
            
            return False
        
        elif matches < len(positive_logs):
            print(f"\n⚠️  WARNING: Only {matches}/{len(positive_logs)} positive logs matched")
            print(f"   Some generated logs don't match the rule")
            return True
        
        else:
            print(f"\n✅ SUCCESS: All positive logs matched!")
            print(f"   Your rule should work correctly in CI/CD")
            return True
        
    except Exception as e:
        print(f"\n❌ ERROR during log generation or matching: {e}")
        import traceback
        traceback.print_exc()
        return False


def suggest_fixes(rule_path: str):
    """Suggest how to fix the rule"""
    
    with open(rule_path, 'r') as f:
        rule = yaml.safe_load(f)
    
    logsource = rule.get('logsource', {})
    detection = rule.get('detection', {})
    
    print(f"\n{'='*70}")
    print(f"💡 SUGGESTIONS TO MAKE YOUR RULE DETECT:")
    print(f"{'='*70}\n")
    
    # Suggestion 1: Use supported log sources
    product = logsource.get('product', '').lower()
    
    supported = ['windows', 'linux', 'azure', 'aws', 'okta', 'onelogin', 'm365', 'proxy', 'network']
    
    if product not in supported:
        print(f"1. ⚠️  LOG SOURCE SUPPORT")
        print(f"   Your product: '{product}'")
        print(f"   Supported products: {', '.join(supported)}")
        print(f"   → Change to a supported product or it won't generate logs")
    else:
        print(f"1. ✅ Log source '{product}' is supported")
    
    # Suggestion 2: Use common fields
    print(f"\n2. 📊 FIELD USAGE")
    
    selections = {k: v for k, v in detection.items() if k != 'condition' and isinstance(v, dict)}
    if selections:
        first_selection = list(selections.values())[0]
        fields = list(first_selection.keys())
        
        # Common fields per log type
        common_fields = {
            'windows': ['EventID', 'CommandLine', 'Image', 'ProcessName', 'User'],
            'linux': ['CommandLine', 'Image', 'User', 'TargetFilename'],
            'azure': ['CategoryValue', 'ResourceProviderValue', 'OperationNameValue', 'ResourceId'],
            'aws': ['eventName', 'eventSource', 'awsRegion', 'userIdentity'],
            'okta': ['eventType', 'actor', 'target', 'outcome'],
            'onelogin': ['event_type_id', 'user_name', 'actor_system'],
            'proxy': ['c-uri', 'cs-host', 'c-uri-extension'],
            'network': ['DestinationIp', 'DestinationPort', 'SourceIp']
        }
        
        recommended = common_fields.get(product, [])
        
        print(f"   Your fields: {fields}")
        if recommended:
            print(f"   Recommended fields for '{product}': {recommended}")
            
            # Check if using recommended fields
            using_common = any(f.split('|')[0] in recommended for f in fields)
            if not using_common:
                print(f"   ⚠️  You're not using common fields for this log source")
                print(f"   → Try using: {', '.join(recommended[:3])}")
            else:
                print(f"   ✅ Using common fields")
    
    # Suggestion 3: Simplify patterns
    print(f"\n3. 🎯 PATTERN SIMPLICITY")
    
    complex_patterns = False
    if selections:
        first_selection = list(selections.values())[0]
        for field, pattern in first_selection.items():
            if isinstance(pattern, str):
                if len(pattern) > 50 or pattern.count('*') > 3:
                    print(f"   ⚠️  Complex pattern in '{field}': {pattern[:50]}...")
                    complex_patterns = True
    
    if complex_patterns:
        print(f"   → Simplify patterns to match more broadly")
        print(f"   → Use wildcards sparingly")
    else:
        print(f"   ✅ Patterns look reasonable")
    
    # Suggestion 4: Test locally first
    print(f"\n4. 🧪 TESTING WORKFLOW")
    print(f"   Before pushing to GitHub:")
    print(f"   → Run: python validator/diagnose_rule.py {rule_path}")
    print(f"   → Verify it shows 'SUCCESS: All positive logs matched!'")
    print(f"   → Only then commit and push")
    
    print(f"\n{'='*70}\n")


if __name__ == '__main__':
    if len(sys.argv) < 2:
        print("Usage: python diagnose_rule.py <rule_file>")
        print("Example: python validator/diagnose_rule.py rules/sigma/aws4.yml")
        sys.exit(1)
    
    rule_path = sys.argv[1]
    
    if not Path(rule_path).exists():
        print(f"❌ ERROR: Rule file not found: {rule_path}")
        sys.exit(1)
    
    success = diagnose_rule(rule_path)
    
    if not success:
        suggest_fixes(rule_path)
        sys.exit(1)
    else:
        print(f"\n{'='*70}")
        print(f"✅ DIAGNOSIS COMPLETE: Rule is working!")
        print(f"{'='*70}\n")
        sys.exit(0)
