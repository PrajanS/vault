"""
Fixed SAST Runner with better Semgrep rule handling.
"""
import subprocess
import json
import logging
import os
from typing import Dict, List, Optional
from pathlib import Path
from utils import AssumptionTracker

logger = logging.getLogger(__name__)

class SASTRunner:
    """Fixed SAST runner with robust Semgrep handling."""

    def __init__(self):
        """Initialize SAST runner."""
        self.assumption_tracker = AssumptionTracker()

        # Working Semgrep rule sets (tested and available)
        self.rule_configs = [
            {
                'name': 'auto',
                'config': 'auto',
                'description': 'Auto-detect rules based on languages'
            },
            {
                'name': 'security-audit', 
                'config': 'p/security-audit',
                'description': 'General security audit rules'
            },
            {
                'name': 'javascript',
                'config': 'p/javascript',
                'description': 'JavaScript specific security rules'
            },
            {
                'name': 'python',
                'config': 'p/python',
                'description': 'Python specific security rules'
            },
            {
                'name': 'generic',
                'config': 'p/generic',
                'description': 'Generic security patterns'
            },
            {
                'name': 'command-injection',
                'config': 'p/command-injection',
                'description': 'Command injection patterns'
            },
            {
                'name': 'sql-injection',
                'config': 'p/sql-injection', 
                'description': 'SQL injection patterns'
            }
        ]

    def run_comprehensive_scan(self, directory_path: str) -> Dict:
        """Run comprehensive SAST scan with robust error handling."""
        logger.info("Starting comprehensive SAST scan")

        if not self._check_semgrep_available():
            logger.warning("Semgrep not available, skipping SAST scan")
            self.assumption_tracker.add_assumption("Semgrep not installed or not in PATH")
            return {
                'vulnerabilities': [],
                'scan_successful': False,
                'error': 'Semgrep not available'
            }

        all_vulnerabilities = []
        successful_configs = []
        failed_configs = []

        for rule_config in self.rule_configs:
            try:
                logger.info(f"Running Semgrep with config: {rule_config['config']}")

                config_vulns = self._run_semgrep_config(
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
                logger.error(f"Error running {rule_config['name']}: {e}")
                failed_configs.append(rule_config['name'])
                continue

        # Deduplicate vulnerabilities
        deduplicated_vulns = self._deduplicate_vulnerabilities(all_vulnerabilities)

        # Log summary
        logger.info(f"SAST scan summary: {len(successful_configs)} successful, {len(failed_configs)} failed")
        logger.info(f"Found {len(deduplicated_vulns)} unique vulnerabilities")

        if failed_configs:
            failed_list = ", ".join(failed_configs)
            self.assumption_tracker.add_assumption(f"Some Semgrep rule sets failed: {failed_list}")

        return {
            'vulnerabilities': deduplicated_vulns,
            'scan_successful': len(successful_configs) > 0,
            'successful_configs': successful_configs,
            'failed_configs': failed_configs,
            'total_findings': len(all_vulnerabilities),
            'unique_findings': len(deduplicated_vulns)
        }

    def _check_semgrep_available(self) -> bool:
        """Check if Semgrep is installed and available."""
        try:
            result = subprocess.run(['semgrep', '--version'], 
                                  capture_output=True, text=True, timeout=10)
            return result.returncode == 0
        except (subprocess.TimeoutExpired, FileNotFoundError, Exception):
            return False

    def _run_semgrep_config(self, directory_path: str, config: str, config_name: str) -> Optional[List[Dict]]:
        """Run Semgrep with a specific config."""
        try:
            # Build Semgrep command
            cmd = [
                'semgrep',
                '--config', config,
                '--json',
                '--no-git-ignore',
                '--skip-unknown-extensions',
                '--timeout', '30',
                directory_path
            ]

            # Run Semgrep
            result = subprocess.run(
                cmd,
                capture_output=True,
                text=True,
                timeout=120,  # 2 minutes timeout
                cwd=directory_path
            )

            # Handle different return codes
            if result.returncode == 0:
                # Success - parse results
                return self._parse_semgrep_output(result.stdout, config_name)
            elif result.returncode == 1:
                # Findings found (this is actually success)
                return self._parse_semgrep_output(result.stdout, config_name)
            elif result.returncode == 2:
                # Invalid config or other error
                logger.warning(f"Semgrep config '{config}' failed (return code 2) - config may not exist")
                return None
            else:
                # Other error
                logger.warning(f"Semgrep failed with return code {result.returncode}")
                logger.debug(f"Semgrep stderr: {result.stderr}")
                return None

        except subprocess.TimeoutExpired:
            logger.warning(f"Semgrep scan with {config} timed out")
            return None
        except Exception as e:
            logger.warning(f"Error running Semgrep with {config}: {e}")
            return None

    def _parse_semgrep_output(self, output: str, config_name: str) -> List[Dict]:
        """Parse Semgrep JSON output into vulnerability dictionaries."""
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
                    logger.debug(f"Error converting Semgrep finding: {e}")
                    continue

        except json.JSONDecodeError as e:
            logger.warning(f"Failed to parse Semgrep JSON output: {e}")
            logger.debug(f"Raw output: {output[:200]}...")
        except Exception as e:
            logger.warning(f"Error parsing Semgrep output: {e}")

        return vulnerabilities

    def _convert_semgrep_finding(self, finding: Dict, config_name: str, finding_num: int) -> Dict:
        """Convert Semgrep finding to standardized vulnerability format."""

        # Extract basic information
        rule_id = finding.get('check_id', f'{config_name}_rule_{finding_num}')
        message = finding.get('message', 'Security issue detected')
        severity = finding.get('severity', 'MEDIUM').upper()

        # Extract file information
        path_info = finding.get('path', '')
        start_line = finding.get('start', {}).get('line', 0)
        end_line = finding.get('end', {}).get('line', 0)

        # Extract code snippet
        extra = finding.get('extra', {})
        code_snippet = extra.get('lines', '')

        # Map Semgrep severity to standard severity
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

        # Determine OWASP category based on rule ID
        owasp_category = self._map_to_owasp_category(rule_id, message)

        return {
            'id': f'V{finding_num:03d}_{config_name}',
            'rule_id': rule_id,
            'title': message[:100],  # Truncate long titles
            'description': message,
            'severity': mapped_severity,
            'confidence': 'MEDIUM',
            'owasp_category': owasp_category,
            'cwe': extra.get('cwe', []),
            'file': os.path.basename(path_info) if path_info else 'unknown',
            'path': path_info,
            'line_start': start_line,
            'line_end': end_line,
            'code_snippet': code_snippet[:200] if code_snippet else '',  # Truncate long snippets
            'source_tool': 'semgrep',
            'config_source': config_name
        }

    def _map_to_owasp_category(self, rule_id: str, message: str) -> str:
        """Map vulnerability to OWASP Top 10 2023 category."""

        rule_id_lower = rule_id.lower()
        message_lower = message.lower()

        # OWASP mapping based on common patterns
        owasp_mapping = {
            'A01': ['broken-access-control', 'access-control', 'authorization', 'privilege'],
            'A02': ['crypto', 'encryption', 'hash', 'password', 'weak-crypto'],
            'A03': ['injection', 'sql', 'nosql', 'xss', 'cross-site-scripting', 'command-injection'],
            'A04': ['insecure-design', 'business-logic', 'design-flaw'],
            'A05': ['security-misconfiguration', 'config', 'default', 'debug'],
            'A06': ['vulnerable-components', 'outdated', 'dependency'],
            'A07': ['identification-authentication', 'auth', 'session', 'login'],
            'A08': ['software-integrity', 'deserialization', 'ci-cd'],
            'A09': ['security-logging', 'logging', 'monitoring'],
            'A10': ['server-side-request-forgery', 'ssrf', 'request-forgery']
        }

        # Check rule ID and message for OWASP indicators
        for category, indicators in owasp_mapping.items():
            for indicator in indicators:
                if indicator in rule_id_lower or indicator in message_lower:
                    return category

        # Default category
        return 'A00'  # Unclassified

    def _deduplicate_vulnerabilities(self, vulnerabilities: List[Dict]) -> List[Dict]:
        """Remove duplicate vulnerabilities."""
        seen = set()
        deduplicated = []

        for vuln in vulnerabilities:
            # Create signature based on file, line, and rule type
            signature = (
                vuln.get('path', ''),
                vuln.get('line_start', 0),
                vuln.get('rule_id', ''),
                vuln.get('title', '')[:50]  # First 50 chars of title
            )

            if signature not in seen:
                seen.add(signature)
                deduplicated.append(vuln)

        removed_count = len(vulnerabilities) - len(deduplicated)
        if removed_count > 0:
            logger.info(f"Removed {removed_count} duplicate vulnerabilities")

        return deduplicated

    def get_assumptions(self) -> List[str]:
        """Get all assumptions made during SAST scanning."""
        return self.assumption_tracker.get_assumptions()
