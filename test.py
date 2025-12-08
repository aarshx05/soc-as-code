"""
Enhanced SOC Simulator with comprehensive Sigma modifier support
Based on Sigma 2.0 specification and SigmaHQ repository patterns
"""

from __future__ import annotations

import argparse
import json
import os
import re
import base64
import sys
from collections import defaultdict
from dataclasses import dataclass, asdict
from datetime import datetime
from typing import Any, Dict, Iterable, List, Optional, Tuple

try:
    import yaml
except Exception:
    yaml = None

try:
    import yara
except Exception:
    yara = None


@dataclass
class Alert:
    rule_id: str
    rule_title: str
    severity: str
    timestamp: str
    host: Optional[str]
    matched_fields: Dict[str, Any]
    raw: Dict[str, Any]


class LogIngestor:
    """Loads JSON logs from files"""

    def __init__(self, paths: Iterable[str]):
        self.paths = list(paths)

    def iter_logs(self):
        for p in self.paths:
            if os.path.isdir(p):
                for root, _, files in os.walk(p):
                    for f in files:
                        full = os.path.join(root, f)
                        yield from self._read_file(full)
            else:
                yield from self._read_file(p)

    def _read_file(self, path: str):
        try:
            with open(path, 'r', encoding='utf-8') as fh:
                text = fh.read()
                text = text.strip()
                if not text:
                    return
                try:
                    doc = json.loads(text)
                    if isinstance(doc, list):
                        for item in doc:
                            yield item
                    elif isinstance(doc, dict):
                        yield doc
                    else:
                        raise ValueError
                except Exception:
                    fh.seek(0)
                    for line in fh:
                        line = line.strip()
                        if not line:
                            continue
                        try:
                            yield json.loads(line)
                        except Exception:
                            continue
        except FileNotFoundError:
            print(f"[warn] file not found: {path}")


class SigmaRule:
    """Enhanced Sigma rule evaluator with full modifier support"""

    def __init__(self, raw: Dict[str, Any]):
        self.raw = raw
        self.title = raw.get('title') or raw.get('name') or 'Unnamed rule'
        self.id = raw.get('id') or raw.get('rule_id') or self.title
        self.level = str(raw.get('level') or raw.get('severity') or 'unknown').lower()
        self.detection = raw.get('detection') or {}
        self.selections = self._parse_selections(self.detection)
        self.condition = self._parse_condition(self.detection)

    @staticmethod
    def _parse_selections(detection: Dict[str, Any]) -> Dict[str, Dict[str, Any]]:
        out: Dict[str, Dict[str, Any]] = {}
        if 'selection' in detection and isinstance(detection['selection'], dict):
            out['selection'] = detection['selection']
        for k, v in detection.items():
            if k in ('selection', 'condition'):
                continue
            if isinstance(v, dict):
                out[k] = v
        return out

    @staticmethod
    def _parse_condition(detection: Dict[str, Any]) -> Optional[str]:
        cond = detection.get('condition')
        if cond is None and 'selection' in detection:
            return 'selection'
        return cond

    @staticmethod
    def _get_value_by_path(doc: Dict[str, Any], path: str) -> Tuple[bool, Any]:
        """Get value from nested dict by path (e.g., 'process.name')"""
        parts = path.split('.')
        cur = doc
        for p in parts:
            if isinstance(cur, dict) and p in cur:
                cur = cur[p]
            else:
                return False, None
        return True, cur

    @staticmethod
    def _parse_field_modifiers(field: str) -> Tuple[str, List[str]]:
        """Parse field and its modifiers (e.g., 'field|contains|all')"""
        if '|' in field:
            parts = field.split('|')
            return parts[0], parts[1:]
        return field, []

    @staticmethod
    def _apply_modifier(pattern: Any, value: Any, modifier: str) -> bool:
        """Apply a Sigma modifier to value matching"""
        
        if modifier == 'contains':
            # Value must contain the pattern
            val_str = '' if value is None else str(value)
            patt_str = '' if pattern is None else str(pattern)
            return patt_str.lower() in val_str.lower()
        
        elif modifier == 'startswith':
            # Value must start with pattern
            val_str = '' if value is None else str(value)
            patt_str = '' if pattern is None else str(pattern)
            return val_str.lower().startswith(patt_str.lower())
        
        elif modifier == 'endswith':
            # Value must end with pattern
            val_str = '' if value is None else str(value)
            patt_str = '' if pattern is None else str(pattern)
            return val_str.lower().endswith(patt_str.lower())
        
        elif modifier == 'all':
            # All patterns must match (used with lists)
            if isinstance(pattern, list):
                val_str = '' if value is None else str(value).lower()
                return all(str(p).lower() in val_str for p in pattern)
            return True
        
        elif modifier == 're':
            # Regex matching
            val_str = '' if value is None else str(value)
            patt_str = '' if pattern is None else str(pattern)
            try:
                return re.search(patt_str, val_str) is not None
            except re.error:
                return False
        
        elif modifier == 'base64':
            # Base64 decode and match
            val_str = '' if value is None else str(value)
            try:
                decoded = base64.b64decode(val_str).decode('utf-8', errors='ignore')
                patt_str = '' if pattern is None else str(pattern)
                return patt_str.lower() in decoded.lower()
            except Exception:
                return False
        
        elif modifier == 'base64offset':
            # Base64 with offset matching
            val_str = '' if value is None else str(value)
            patt_str = '' if pattern is None else str(pattern)
            # Try all 3 possible offsets
            for offset in range(3):
                try:
                    padded = ('A' * offset) + val_str
                    decoded = base64.b64decode(padded).decode('utf-8', errors='ignore')
                    if patt_str.lower() in decoded.lower():
                        return True
                except Exception:
                    continue
            return False
        
        elif modifier == 'cased':
            # Case-sensitive matching
            val_str = '' if value is None else str(value)
            patt_str = '' if pattern is None else str(pattern)
            return patt_str == val_str
        
        elif modifier == 'exists':
            # Field existence check
            if isinstance(pattern, bool):
                return (value is not None) == pattern
            return value is not None
        
        elif modifier in ['gt', 'gte', 'lt', 'lte']:
            # Numeric comparisons
            try:
                val_num = float(value) if value is not None else 0
                patt_num = float(pattern) if pattern is not None else 0
                
                if modifier == 'gt':
                    return val_num > patt_num
                elif modifier == 'gte':
                    return val_num >= patt_num
                elif modifier == 'lt':
                    return val_num < patt_num
                elif modifier == 'lte':
                    return val_num <= patt_num
            except (ValueError, TypeError):
                return False
        
        elif modifier == 'cidr':
            # CIDR notation matching
            # Simplified implementation
            return False  # Would need ipaddress module
        
        return True  # Unknown modifier, pass through

    @classmethod
    def _match_value(cls, pattern: Any, value: Any, modifiers: List[str] = None) -> bool:
        """Match value against pattern with optional modifiers"""
        
        if modifiers is None:
            modifiers = []

        # Support list of patterns (OR logic by default)
        if isinstance(pattern, list):
            # Check for 'all' modifier
            if 'all' in modifiers:
                # All patterns must match
                val_str = '' if value is None else str(value).lower()
                return all(str(p).lower() in val_str for p in pattern)
            else:
                # Any pattern can match (OR logic)
                return any(cls._match_value(p, value, modifiers) for p in pattern)

        # Apply modifiers in order
        for modifier in modifiers:
            # Some modifiers change the matching logic entirely
            if modifier in ['contains', 'startswith', 'endswith', 'all', 're', 
                          'base64', 'base64offset', 'cased', 'exists', 
                          'gt', 'gte', 'lt', 'lte', 'cidr']:
                return cls._apply_modifier(pattern, value, modifier)

        # No modifiers or only transformation modifiers
        # Numbers and bools
        if isinstance(pattern, (int, float, bool)):
            return pattern == value
        if isinstance(value, (int, float, bool)) and not isinstance(value, str):
            return str(pattern) == str(value)

        val = '' if value is None else str(value)
        patt = '' if pattern is None else str(pattern)

        # Check for regex patterns
        if cls._is_regex_pattern(patt):
            try:
                return re.search(patt, val, flags=re.IGNORECASE) is not None
            except re.error:
                return patt.lower() == val.lower()

        # Check for wildcards
        if '*' in patt or '?' in patt:
            re_p = '^' + re.escape(patt).replace(r'\*', '.*').replace(r'\?', '.') + '$'
            try:
                return re.search(re_p, val, flags=re.IGNORECASE) is not None
            except re.error:
                return patt.lower() == val.lower()

        # Plain equality (case-insensitive by default)
        return patt.lower() == val.lower()

    @staticmethod
    def _is_regex_pattern(s: str) -> bool:
        """Detect actual regex patterns"""
        if not isinstance(s, str):
            return False
        
        regex_indicators = [
            '.*', '.+', '^', '$', '[', ']', '(', ')', '|', 
            '{', '}', '\\d', '\\w', '\\s', '\\D', '\\W', '\\S'
        ]
        
        has_regex = any(indicator in s for indicator in regex_indicators)
        if has_regex:
            return True
        
        # If only simple wildcards, not regex
        if ('*' in s or '?' in s) and not has_regex:
            return False
        
        return False

    @classmethod
    def matches_selection(cls, selection: Dict[str, Any], log: Dict[str, Any]) -> Tuple[bool, Dict[str, Any]]:
        """Check if log matches selection criteria"""
        matched: Dict[str, Any] = {}
        
        for field, pattern in selection.items():
            # Parse field and modifiers
            field_name, modifiers = cls._parse_field_modifiers(field)
            
            # Get value from log
            found, value = cls._get_value_by_path(log, field_name)
            
            # Handle exists modifier specially
            if 'exists' in modifiers:
                if isinstance(pattern, bool):
                    if found and value is not None:
                        if not pattern:  # exists: false
                            return False, {}
                    else:
                        if pattern:  # exists: true
                            return False, {}
                matched[field_name] = value
                continue
            
            if not found:
                return False, {}
            
            if cls._match_value(pattern, value, modifiers):
                matched[field_name] = value
            else:
                return False, {}
        
        return True, matched

    def matches(self, log: Dict[str, Any]) -> Optional[Dict[str, Any]]:
        """Check if log matches the rule"""
        if not self.selections:
            return None
        
        sel_results: Dict[str, Tuple[bool, Dict[str, Any]]] = {}
        for name, sel in self.selections.items():
            sel_results[name] = self.matches_selection(sel, log)

        cond = self.condition or 'selection'
        bool_map = {name: res[0] for name, res in sel_results.items()}
        cond_eval = self._render_condition(cond, bool_map)
        
        try:
            result = eval(cond_eval, {"__builtins__": None}, {})
        except Exception:
            return None

        if result:
            merged: Dict[str, Any] = {}
            for name, (ok, fields) in sel_results.items():
                if ok:
                    merged.update(fields)
            return merged
        return None

    @staticmethod
    def _render_condition(condition: str, bool_map: Dict[str, bool]) -> str:
        """Render condition with boolean values"""
        token_re = re.compile(r"\b[A-Za-z_][A-Za-z0-9_]*\b|\(|\)")

        def repl(m):
            tok = m.group(0)
            if tok.lower() in ('and', 'or', 'not', 'true', 'false'):
                return tok.lower()
            if tok in bool_map:
                return 'True' if bool_map[tok] else 'False'
            return 'False'

        rendered = token_re.sub(repl, condition)
        return rendered


class YaraEngine:
    def __init__(self, rules_path: Optional[str] = None):
        self.rules_path = rules_path
        self.compiled = None
        if yara and rules_path:
            try:
                self.compiled = yara.compile(filepath=rules_path)
            except Exception as e:
                print(f"[warn] failed to compile YARA: {e}")
                self.compiled = None

    def match(self, text: str) -> List[Dict[str, Any]]:
        if not self.compiled:
            return []
        try:
            matches = self.compiled.match(data=text)
            out: List[Dict[str, Any]] = []
            for m in matches:
                out.append({
                    'rule': m.rule,
                    'tags': getattr(m, 'tags', []),
                    'meta': getattr(m, 'meta', {})
                })
            return out
        except Exception as e:
            print(f"[warn] yara match failed: {e}")
            return []


class RuleEngine:
    def __init__(self, sigma_rules: Optional[List[Dict[str, Any]]] = None, yara_path: Optional[str] = None):
        self.sigma_rules: List[SigmaRule] = [SigmaRule(r) for r in (sigma_rules or [])]
        self.yara_engine = YaraEngine(yara_path) if yara_path else None

    def eval_log(self, log: Dict[str, Any]) -> List[Alert]:
        alerts: List[Alert] = []
        
        for r in self.sigma_rules:
            matched_fields = r.matches(log)
            if matched_fields is not None:
                alerts.append(Alert(
                    rule_id=r.id,
                    rule_title=r.title,
                    severity=r.level,
                    timestamp=datetime.utcnow().isoformat() + 'Z',
                    host=self._get_host(log),
                    matched_fields=matched_fields,
                    raw=log,
                ))

        if self.yara_engine and self.yara_engine.compiled:
            try:
                raw_text = json.dumps(log)
            except Exception:
                raw_text = str(log)
            matches = self.yara_engine.match(raw_text)
            for m in matches:
                alerts.append(Alert(
                    rule_id=m.get('rule', 'yara'),
                    rule_title='YARA:' + m.get('rule', 'yara'),
                    severity='medium',
                    timestamp=datetime.utcnow().isoformat() + 'Z',
                    host=self._get_host(log),
                    matched_fields={'yara_tags': m.get('tags'), 'yara_meta': m.get('meta')},
                    raw=log,
                ))
        return alerts

    @staticmethod
    def _get_host(log: Dict[str, Any]) -> Optional[str]:
        for k in ('host', 'hostname', 'agent', 'source'):
            if k in log:
                v = log.get(k)
                if isinstance(v, dict):
                    return v.get('name')
                return v
        return None


class MetricsCollector:
    def __init__(self):
        self.total_logs = 0
        self.logs_per_host = defaultdict(int)
        self.alerts_per_rule = defaultdict(int)
        self.alerts_per_severity = defaultdict(int)
        self.alerts_per_host = defaultdict(int)

    def ingest_log(self, log: Dict[str, Any]):
        self.total_logs += 1
        host = log.get('host') or log.get('hostname') or 'unknown'
        if isinstance(host, dict):
            host = host.get('name', 'unknown')
        self.logs_per_host[host] += 1

    def record_alert(self, alert: Alert):
        self.alerts_per_rule[alert.rule_id] += 1
        self.alerts_per_severity[alert.severity] += 1
        host = alert.host or 'unknown'
        self.alerts_per_host[host] += 1

    def snapshot(self):
        return {
            'total_logs': self.total_logs,
            'logs_per_host': dict(self.logs_per_host),
            'alerts_per_rule': dict(self.alerts_per_rule),
            'alerts_per_severity': dict(self.alerts_per_severity),
            'alerts_per_host': dict(self.alerts_per_host),
        }


class SOCSimulator:
    def __init__(self, sigma_rules: Optional[List[Dict[str, Any]]] = None, yara_path: Optional[str] = None):
        self.rule_engine = RuleEngine(sigma_rules, yara_path)
        self.metrics = MetricsCollector()
        self.alerts: List[Alert] = []

    def process_logs(self, logs: Iterable[Dict[str, Any]]):
        for log in logs:
            self.metrics.ingest_log(log)
            alerts = self.rule_engine.eval_log(log)
            for a in alerts:
                self.alerts.append(a)
                self.metrics.record_alert(a)

    def export_alerts(self) -> List[Dict[str, Any]]:
        return [asdict(a) for a in self.alerts]

    def export_metrics(self) -> Dict[str, Any]:
        return self.metrics.snapshot()


def load_sigma_rules(path: str) -> List[Dict[str, Any]]:
    if not yaml:
        raise RuntimeError("PyYAML is required. Install with: pip install pyyaml")
    with open(path, 'r', encoding='utf-8') as fh:
        docs = list(yaml.safe_load_all(fh))
        out: List[Dict[str, Any]] = []
        for d in docs:
            if d is None:
                continue
            if isinstance(d, list):
                out.extend(d)
            else:
                out.append(d)
        return out


def main_cli(argv=None):
    p = argparse.ArgumentParser(description='Enhanced SOC Simulator with Sigma modifier support')
    p.add_argument('--logs', help='Path to log file or directory')
    p.add_argument('--sigma', help='Path to Sigma YAML file')
    p.add_argument('--yara', help='Path to YARA rules file')
    p.add_argument('--out', default='alerts.json', help='Output alerts file')
    p.add_argument('--metrics', default='metrics.json', help='Output metrics file')
    args = p.parse_args(argv)

    if not args.logs:
        print('--logs is required')
        return 1

    sigma_rules: List[Dict[str, Any]] = []
    if args.sigma:
        try:
            sigma_rules = load_sigma_rules(args.sigma)
            print(f"Loaded {len(sigma_rules)} sigma rules from {args.sigma}")
        except Exception as e:
            print(f"Failed to load sigma rules: {e}")
            return 1

    # Collect log files
    paths = []
    if os.path.isdir(args.logs):
        for root, _, files in os.walk(args.logs):
            for f in files:
                paths.append(os.path.join(root, f))
    elif os.path.isfile(args.logs):
        paths.append(args.logs)

    if not paths:
        print("No log files found")
        return 1

    ingestor = LogIngestor(paths)
    simulator = SOCSimulator(sigma_rules, yara_path=args.yara)

    simulator.process_logs(ingestor.iter_logs())

    alerts = simulator.export_alerts()
    metrics = simulator.export_metrics()

    os.makedirs(os.path.dirname(args.out) or ".", exist_ok=True)
    os.makedirs(os.path.dirname(args.metrics) or ".", exist_ok=True)

    with open(args.out, 'w', encoding='utf-8') as fh:
        json.dump({'alerts': alerts}, fh, indent=2)
    with open(args.metrics, 'w', encoding='utf-8') as fh:
        json.dump({'metrics': metrics}, fh, indent=2)

    print(f"Processed logs. Alerts: {len(alerts)}. Metrics: {json.dumps(metrics)}")
    return 0


if __name__ == '__main__':
    rc = main_cli()
    sys.exit(rc)
