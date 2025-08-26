"""
Completely fixed SAST Runner with zero warnings.
"""
import subprocess
import json
import logging
import os
import re
from typing import Dict, List, Optional
from pathlib import Path
from utils import AssumptionTracker

logger = logging.getLogger(__name__)

class SASTRunner:
    """Completely fixed SAST runner with zero warnings."""

    def __init__(self):
        """Initialize SAST runner with working rule sets."""
        self.assumption_tracker = AssumptionTracker()

        # Working Semgrep rule sets
        self.rule_configs = [
            {
                'name': 'basic-security',
                'config': 'r/javascript.lang.security',
                'description': 'Basic JavaScript security rules'
            },
            {
                'name': 'owasp-top-ten',
                'config': 'r/owasp-top-ten',
                'description': 'OWASP Top 10 security issues'
            },
            {
                'name': 'security-audit', 
                'config': 'r/security-audit',
                'description': 'General security audit rules'
            },
            {
                'name': 'xss-detection',
                'config': 'r/javascript.browser.security.audit.xss',
                'description': 'Cross-site scripting detection'
            },
            {
                'name': 'sql-injection',
                'config': 'r/javascript.lang.security.audit.sqli',
                'description': 'SQL injection detection'
            }
        ]

        # Vulnerability patterns with properly compiled regex
        self.vuln_patterns = [
            {
                'pattern': re.compile(r'eval\s*\(', re.IGNORECASE),
                'title': 'Potential Code Injection via eval()',
                'severity': 'Critical',
                'owasp': 'A03'
            },
            {
                'pattern': re.compile(r'innerHTML\s*=', re.IGNORECASE),
                'title': 'Potential XSS via innerHTML',
                'severity': 'High', 
                'owasp': 'A03'
            },
            {
                'pattern': re.compile(r'document\.write\s*\(', re.IGNORECASE),
                'title': 'Potential XSS via document.write',
                'severity': 'High',
                'owasp': 'A03'
            },
            {
                'pattern': re.compile(r'\$\{[^}]*\}', re.IGNORECASE),
                'title': 'Template Literal - Check for Injection',
                'severity': 'Medium',
                'owasp': 'A03'
            },
            {
                'pattern': re.compile(r'password[\'\"]?\s*[:=]\s*[\'\"][^\'\"]{3,}[\'\"]', re.IGNORECASE),
                'title': 'Hardcoded Password',
                'severity': 'High',
                'owasp': 'A02'
            },
            {
                'pattern': re.compile(r'secret[\'\"]?\s*[:=]\s*[\'\"][^\'\"]{3,}[\'\"]', re.IGNORECASE),
                'title': 'Hardcoded Secret',
                'severity': 'High',
                'owasp': 'A02'
            },
            {
                'pattern': re.compile(r'api[_-]?key[\'\"]?\s*[:=]\s*[\'\"][^\'\"]{10,}[\'\"]', re.IGNORECASE),
                'title': 'Hardcoded API Key',
                'severity': 'Critical',
                'owasp': 'A02'
            }
        ]

    def run_comprehensive_scan(self, directory_path: str) -> Dict:
        """Run comprehensive SAST scan with fixed encoding."""
        logger.info("Starting working SAST scan")

        if not self._check_semgrep_available():
            logger.info("Semgrep not available - using pattern matching only")
            return self._run_pattern_only_scan(directory_path)

        all_vulnerabilities = []
        successful_configs = []
        failed_configs = []

        # Strategy 1: Try registry-based rules
        for rule_config in self.rule_configs:
            try:
                logger.info(f"Testing Semgrep config: {rule_config['config']}")

                config_vulns = self._run_semgrep_config_safe(
                    directory_path, 
                    rule_config['config'],
                    rule_config['name']
                )

                if config_vulns is not None:
                    all_vulnerabilities.extend(config_vulns)
                    successful_configs.append(rule_config['name'])
                    logger.info(f"SUCCESS: {rule_config['name']} found {len(config_vulns)} issues")
                else:
                    failed_configs.append(rule_config['name'])
                    logger.warning(f"FAILED: {rule_config['name']} scan failed")

            except Exception as e:
                logger.warning(f"Error running {rule_config['name']}: {e}")
                failed_configs.append(rule_config['name'])
                continue

        # Strategy 2: Always run pattern matching as backup
        logger.info("Running basic vulnerability pattern scan")
        pattern_vulns = self._run_basic_pattern_scan(directory_path)
        all_vulnerabilities.extend(pattern_vulns)
        if pattern_vulns:
            successful_configs.append("basic-patterns")

        # Deduplicate vulnerabilities
        deduplicated_vulns = self._deduplicate_vulnerabilities(all_vulnerabilities)

        # Log final results
        logger.info(f"SAST scan complete: {len(successful_configs)} successful configs")
        logger.info(f"Found {len(deduplicated_vulns)} unique vulnerabilities")

        if failed_configs:
            self.assumption_tracker.add_assumption(f"Some Semgrep configs failed: {', '.join(failed_configs[:3])}")

        return {
            'vulnerabilities': deduplicated_vulns,
            'scan_successful': len(deduplicated_vulns) > 0 or len(successful_configs) > 0,
            'successful_configs': successful_configs,
            'failed_configs': failed_configs,
            'total_findings': len(all_vulnerabilities),
            'unique_findings': len(deduplicated_vulns)
        }

    def _check_semgrep_available(self) -> bool:
        """Check if Semgrep is installed and working."""
        try:
            result = subprocess.run(['semgrep', '--version'], 
                                  capture_output=True, text=True, timeout=10,
                                  encoding='utf-8', errors='replace')
            if result.returncode == 0:
                version = result.stdout.strip()
                logger.info(f"Semgrep version: {version}")
                return True
            else:
                logger.info("Semgrep version check failed")
                return False
        except Exception:
            logger.info("Semgrep not available")
            return False

    def _run_semgrep_config_safe(self, directory_path: str, config: str, config_name: str) -> Optional[List[Dict]]:
        """Run Semgrep with safe Unicode handling."""
        try:
            cmd = [
                'semgrep',
                '--config', config,
                '--json',
                '--no-git-ignore',
                '--skip-unknown-extensions',
                '--timeout', '60',
                '--max-target-bytes', '1000000',
                directory_path
            ]

            # Run with safe encoding
            result = subprocess.run(
                cmd,
                capture_output=True,
                text=True,
                timeout=180,
                encoding='utf-8',
                errors='replace'
            )

            if result.returncode in [0, 1]:
                return self._parse_semgrep_output(result.stdout, config_name)
            else:
                return None

        except Exception:
            return None

    def _run_pattern_only_scan(self, directory_path: str) -> Dict:
        """Run pattern-only scan when Semgrep unavailable."""
        logger.info("Running pattern-only vulnerability scan")

        pattern_vulns = self._run_basic_pattern_scan(directory_path)

        return {
            'vulnerabilities': pattern_vulns,
            'scan_successful': len(pattern_vulns) > 0,
            'successful_configs': ['basic-patterns'] if pattern_vulns else [],
            'failed_configs': ['semgrep-unavailable'],
            'total_findings': len(pattern_vulns),
            'unique_findings': len(pattern_vulns)
        }

    def _run_basic_pattern_scan(self, directory_path: str) -> List[Dict]:
        """Run basic vulnerability pattern matching."""
        logger.info("Running basic vulnerability pattern scan")

        vulnerabilities = []

        # Scan files for patterns
        for root, dirs, files in os.walk(directory_path):
            dirs[:] = [d for d in dirs if d not in ['node_modules', 'dist', 'build', '.git', '__pycache__']]

            for file in files:
                if file.endswith(('.js', '.ts', '.jsx', '.tsx', '.py', '.php', '.java')):
                    file_path = os.path.join(root, file)
                    vulnerabilities.extend(self._scan_file_for_patterns(file_path))

        logger.info(f"Basic pattern scan found {len(vulnerabilities)} potential issues")
        return vulnerabilities

    def _scan_file_for_patterns(self, file_path: str) -> List[Dict]:
        """Scan individual file for vulnerability patterns."""
        vulnerabilities = []

        try:
            with open(file_path, 'r', encoding='utf-8', errors='ignore') as f:
                content = f.read()

            lines = content.split('\n')
            for line_num, line in enumerate(lines, 1):
                for pattern_config in self.vuln_patterns:
                    if pattern_config['pattern'].search(line):
                        vulnerabilities.append({
                            'id': f'PATTERN_{len(vulnerabilities)+1:03d}',
                            'rule_id': f"pattern.{pattern_config['title'].lower().replace(' ', '_').replace('()', '')}",
                            'title': pattern_config['title'],
                            'description': f"Detected security pattern in code",
                            'severity': pattern_config['severity'],
                            'confidence': 'MEDIUM',
                            'owasp_category': pattern_config['owasp'],
                            'file': os.path.basename(file_path),
                            'path': file_path,
                            'line_start': line_num,
                            'line_end': line_num,
                            'code_snippet': line.strip()[:100],
                            'source_tool': 'pattern_matching',
                            'config_source': 'basic_patterns'
                        })

        except Exception as e:
            logger.debug(f"Error scanning {file_path}: {e}")

        return vulnerabilities

    def _parse_semgrep_output(self, output: str, config_name: str) -> List[Dict]:
        """Parse Semgrep JSON output safely."""
        vulnerabilities = []

        try:
            if not output.strip():
                return []

            data = json.loads(output)
            results = data.get('results', [])

            for i, result in enumerate(results):
                try:
                    vuln = self._convert_semgrep_finding(result, config_name, i+1)
                    vulnerabilities.append(vuln)
                except Exception as e:
                    logger.debug(f"Error converting finding: {e}")
                    continue

        except json.JSONDecodeError as e:
            logger.warning(f"Failed to parse Semgrep JSON: {e}")
        except Exception as e:
            logger.warning(f"Error parsing Semgrep output: {e}")

        return vulnerabilities

    def _convert_semgrep_finding(self, finding: Dict, config_name: str, finding_num: int) -> Dict:
        """Convert Semgrep finding to standardized format."""

        rule_id = finding.get('check_id', f'{config_name}_rule_{finding_num}')
        message = finding.get('message', 'Security issue detected')
        severity = finding.get('severity', 'MEDIUM').upper()

        path_info = finding.get('path', '')
        start_line = finding.get('start', {}).get('line', 0)
        end_line = finding.get('end', {}).get('line', 0)

        extra = finding.get('extra', {})
        code_snippet = extra.get('lines', '')

        # Map severity
        severity_mapping = {
            'ERROR': 'Critical',
            'WARNING': 'High', 
            'INFO': 'Medium',
            'MEDIUM': 'Medium',
            'HIGH': 'High',
            'CRITICAL': 'Critical',
            'LOW': 'Low'
        }

        mapped_severity = severity_mapping.get(severity, 'Medium')
        owasp_category = self._map_to_owasp_category(rule_id, message)

        return {
            'id': f'SAST_{finding_num:03d}',
            'rule_id': rule_id,
            'title': message[:100],
            'description': message,
            'severity': mapped_severity,
            'confidence': 'HIGH',
            'owasp_category': owasp_category,
            'cwe': extra.get('cwe', []),
            'file': os.path.basename(path_info) if path_info else 'unknown',
            'path': path_info,
            'line_start': start_line,
            'line_end': end_line,
            'code_snippet': code_snippet[:200] if code_snippet else '',
            'source_tool': 'semgrep',
            'config_source': config_name
        }

    def _map_to_owasp_category(self, rule_id: str, message: str) -> str:
        """Map to OWASP Top 10 categories."""

        rule_lower = rule_id.lower()
        message_lower = message.lower()

        owasp_indicators = {
            'A01': ['access-control', 'authorization', 'privilege'],
            'A02': ['crypto', 'encryption', 'password', 'hardcoded', 'secret', 'key'],
            'A03': ['injection', 'sql', 'xss', 'eval', 'innerHTML', 'document.write'],
            'A04': ['insecure-design', 'business-logic'],
            'A05': ['misconfiguration', 'debug', 'config'],
            'A06': ['vulnerable', 'dependency', 'component'],
            'A07': ['authentication', 'auth', 'session', 'login'],
            'A08': ['integrity', 'deserialization'],
            'A09': ['logging', 'monitoring'],
            'A10': ['ssrf', 'request-forgery']
        }

        for category, indicators in owasp_indicators.items():
            for indicator in indicators:
                if indicator in rule_lower or indicator in message_lower:
                    return category

        return 'A03'  # Default to injection

    def _deduplicate_vulnerabilities(self, vulnerabilities: List[Dict]) -> List[Dict]:
        """Remove duplicate vulnerabilities."""
        seen = set()
        deduplicated = []

        for vuln in vulnerabilities:
            signature = (
                vuln.get('path', ''),
                vuln.get('line_start', 0),
                vuln.get('rule_id', ''),
                vuln.get('title', '')[:30]
            )

            if signature not in seen:
                seen.add(signature)
                deduplicated.append(vuln)

        removed = len(vulnerabilities) - len(deduplicated)
        if removed > 0:
            logger.info(f"Removed {removed} duplicate vulnerabilities")

        return deduplicated

    def get_assumptions(self) -> List[str]:
        """Get all assumptions made during scanning."""
        return self.assumption_tracker.get_assumptions()
