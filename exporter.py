"""
Exporter for analysis results to various formats (JSON, CSV).
"""
import os
import json
import csv
import logging
from typing import Dict, List, Any, Optional
from datetime import datetime
from utils import ensure_directory_exists

logger = logging.getLogger(__name__)

class AnalysisExporter:
    """Exporter for analysis results to multiple formats."""

    def __init__(self, output_directory: str = "output"):
        """Initialize exporter with output directory."""
        self.output_directory = output_directory
        ensure_directory_exists(self.output_directory)

    def export_all_results(self, analysis_results: Dict, base_filename: str = None) -> Dict[str, str]:
        """
        Export all analysis results to various formats.
        Returns dict mapping format to file path.
        """
        if not base_filename:
            timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
            base_filename = f"analysis_results_{timestamp}"

        exported_files = {}

        try:
            # Export main manifest JSON
            manifest_path = self.export_manifest_json(analysis_results, base_filename)
            exported_files['manifest'] = manifest_path

            # Export individual CSV files
            csv_files = self.export_csv_files(analysis_results, base_filename)
            exported_files.update(csv_files)

            # Export summary report
            summary_path = self.export_summary_report(analysis_results, base_filename)
            exported_files['summary'] = summary_path

            logger.info(f"Successfully exported {len(exported_files)} files")

        except Exception as e:
            logger.error(f"Error during export: {e}")

        return exported_files

    def export_manifest_json(self, analysis_results: Dict, base_filename: str) -> str:
        """Export main manifest JSON file."""
        filename = f"{base_filename}_manifest.json"
        filepath = os.path.join(self.output_directory, filename)

        try:
            with open(filepath, 'w', encoding='utf-8') as f:
                json.dump(analysis_results, f, indent=2, ensure_ascii=False, default=str)

            logger.info(f"Exported manifest JSON: {filepath}")
            return filepath

        except Exception as e:
            logger.error(f"Error exporting manifest JSON: {e}")
            raise

    def export_csv_files(self, analysis_results: Dict, base_filename: str) -> Dict[str, str]:
        """Export individual CSV files for different data types."""
        csv_files = {}

        # Export endpoints CSV
        if analysis_results.get('endpoints'):
            endpoints_path = self.export_endpoints_csv(
                analysis_results['endpoints'], f"{base_filename}_endpoints.csv"
            )
            csv_files['endpoints'] = endpoints_path

        # Export vulnerabilities CSV
        if analysis_results.get('sast_vulnerabilities'):
            vulns_path = self.export_vulnerabilities_csv(
                analysis_results['sast_vulnerabilities'], f"{base_filename}_vulnerabilities.csv"
            )
            csv_files['vulnerabilities'] = vulns_path

        # Export test cases CSV
        if analysis_results.get('test_cases'):
            tests_path = self.export_test_cases_csv(
                analysis_results['test_cases'], f"{base_filename}_test_cases.csv"
            )
            csv_files['test_cases'] = tests_path

        # Export coverage CSV
        if analysis_results.get('coverage_matrix'):
            coverage_path = self.export_coverage_csv(
                analysis_results['coverage_matrix'], f"{base_filename}_coverage.csv"
            )
            csv_files['coverage'] = coverage_path

        return csv_files

    def export_endpoints_csv(self, endpoints: List[Dict], filename: str) -> str:
        """Export endpoints to CSV file."""
        filepath = os.path.join(self.output_directory, filename)

        if not endpoints:
            logger.warning("No endpoints to export")
            return filepath

        try:
            fieldnames = [
                'id', 'path', 'method', 'language_hint', 'file', 'line',
                'auth_required', 'framework', 'param_count', 'parameters'
            ]

            with open(filepath, 'w', newline='', encoding='utf-8') as csvfile:
                writer = csv.DictWriter(csvfile, fieldnames=fieldnames)
                writer.writeheader()

                for endpoint in endpoints:
                    # Flatten parameters for CSV
                    params = endpoint.get('params', [])
                    param_names = [p.get('name', '') for p in params]

                    row = {
                        'id': endpoint.get('id', ''),
                        'path': endpoint.get('path', ''),
                        'method': endpoint.get('method', ''),
                        'language_hint': endpoint.get('language_hint', ''),
                        'file': endpoint.get('file', ''),
                        'line': endpoint.get('line', ''),
                        'auth_required': endpoint.get('auth_required', 'unknown'),
                        'framework': endpoint.get('framework', ''),
                        'param_count': len(params),
                        'parameters': '; '.join(param_names)
                    }
                    writer.writerow(row)

            logger.info(f"Exported {len(endpoints)} endpoints to: {filepath}")
            return filepath

        except Exception as e:
            logger.error(f"Error exporting endpoints CSV: {e}")
            raise

    def export_vulnerabilities_csv(self, vulnerabilities: List[Dict], filename: str) -> str:
        """Export vulnerabilities to CSV file."""
        filepath = os.path.join(self.output_directory, filename)

        if not vulnerabilities:
            logger.warning("No vulnerabilities to export")
            return filepath

        try:
            fieldnames = [
                'id', 'title', 'severity', 'owasp_category', 'cwe_id',
                'location', 'file', 'line_start', 'confidence', 'description'
            ]

            with open(filepath, 'w', newline='', encoding='utf-8') as csvfile:
                writer = csv.DictWriter(csvfile, fieldnames=fieldnames)
                writer.writeheader()

                for vuln in vulnerabilities:
                    row = {
                        'id': vuln.get('id', ''),
                        'title': vuln.get('title', ''),
                        'severity': vuln.get('severity', ''),
                        'owasp_category': vuln.get('owasp_category', ''),
                        'cwe_id': vuln.get('cwe_id', ''),
                        'location': vuln.get('location', ''),
                        'file': vuln.get('file', ''),
                        'line_start': vuln.get('line_start', ''),
                        'confidence': vuln.get('confidence', ''),
                        'description': vuln.get('description', '')[:200] + ('...' if len(vuln.get('description', '')) > 200 else '')
                    }
                    writer.writerow(row)

            logger.info(f"Exported {len(vulnerabilities)} vulnerabilities to: {filepath}")
            return filepath

        except Exception as e:
            logger.error(f"Error exporting vulnerabilities CSV: {e}")
            raise

    def export_test_cases_csv(self, test_cases: List[Dict], filename: str) -> str:
        """Export test cases to CSV file."""
        filepath = os.path.join(self.output_directory, filename)

        if not test_cases:
            logger.warning("No test cases to export")
            return filepath

        try:
            fieldnames = [
                'id', 'title', 'type', 'category', 'owasp_category', 'severity',
                'mapped_endpoints', 'step_count', 'expected_result', 'generated_by'
            ]

            with open(filepath, 'w', newline='', encoding='utf-8') as csvfile:
                writer = csv.DictWriter(csvfile, fieldnames=fieldnames)
                writer.writeheader()

                for test in test_cases:
                    steps = test.get('steps', [])
                    endpoints = test.get('mapped_endpoints', [])

                    row = {
                        'id': test.get('id', ''),
                        'title': test.get('title', ''),
                        'type': test.get('type', ''),
                        'category': test.get('category', ''),
                        'owasp_category': test.get('owasp_category', ''),
                        'severity': test.get('severity', ''),
                        'mapped_endpoints': '; '.join(endpoints) if isinstance(endpoints, list) else str(endpoints),
                        'step_count': len(steps) if isinstance(steps, list) else 0,
                        'expected_result': test.get('expected_result', '')[:150] + ('...' if len(test.get('expected_result', '')) > 150 else ''),
                        'generated_by': test.get('generated_by', 'unknown')
                    }
                    writer.writerow(row)

            logger.info(f"Exported {len(test_cases)} test cases to: {filepath}")
            return filepath

        except Exception as e:
            logger.error(f"Error exporting test cases CSV: {e}")
            raise

    def export_coverage_csv(self, coverage_matrix: Dict, filename: str) -> str:
        """Export coverage matrix to CSV file."""
        filepath = os.path.join(self.output_directory, filename)

        try:
            fieldnames = ['metric', 'value', 'percentage', 'details']

            with open(filepath, 'w', newline='', encoding='utf-8') as csvfile:
                writer = csv.DictWriter(csvfile, fieldnames=fieldnames)
                writer.writeheader()

                # Endpoint coverage
                writer.writerow({
                    'metric': 'Endpoint Coverage',
                    'value': f"{coverage_matrix.get('endpoints_with_tests', 0)}/{coverage_matrix.get('total_endpoints', 0)}",
                    'percentage': f"{coverage_matrix.get('endpoint_coverage_pct', 0)}%",
                    'details': 'Endpoints with test cases'
                })

                # OWASP coverage
                owasp_covered = coverage_matrix.get('owasp_categories_covered', [])
                writer.writerow({
                    'metric': 'OWASP Coverage',
                    'value': f"{len(owasp_covered)}/10",
                    'percentage': f"{coverage_matrix.get('owasp_coverage_pct', 0)}%",
                    'details': '; '.join(owasp_covered) if owasp_covered else 'None'
                })

                # Test statistics
                writer.writerow({
                    'metric': 'Total Test Cases',
                    'value': str(coverage_matrix.get('total_test_cases', 0)),
                    'percentage': '100%',
                    'details': 'All generated test cases'
                })

                # Security vs Business tests
                security_tests = coverage_matrix.get('security_tests', 0)
                total_tests = coverage_matrix.get('total_test_cases', 1)
                security_pct = round(security_tests / total_tests * 100, 1) if total_tests > 0 else 0

                writer.writerow({
                    'metric': 'Security Tests',
                    'value': str(security_tests),
                    'percentage': f"{security_pct}%",
                    'details': 'OWASP and security-focused tests'
                })

                business_tests = coverage_matrix.get('business_tests', 0)
                business_pct = round(business_tests / total_tests * 100, 1) if total_tests > 0 else 0

                writer.writerow({
                    'metric': 'Business Logic Tests',
                    'value': str(business_tests),
                    'percentage': f"{business_pct}%",
                    'details': 'Business rule validation tests'
                })

                # Gaps
                gaps = coverage_matrix.get('gaps', [])
                if gaps:
                    writer.writerow({
                        'metric': 'Coverage Gaps',
                        'value': str(len(gaps)),
                        'percentage': 'N/A',
                        'details': '; '.join(gaps)[:200]
                    })

            logger.info(f"Exported coverage matrix to: {filepath}")
            return filepath

        except Exception as e:
            logger.error(f"Error exporting coverage CSV: {e}")
            raise

    def export_summary_report(self, analysis_results: Dict, base_filename: str) -> str:
        """Export human-readable summary report."""
        filename = f"{base_filename}_summary.md"
        filepath = os.path.join(self.output_directory, filename)

        try:
            with open(filepath, 'w', encoding='utf-8') as f:
                f.write(self._generate_summary_content(analysis_results))

            logger.info(f"Exported summary report: {filepath}")
            return filepath

        except Exception as e:
            logger.error(f"Error exporting summary report: {e}")
            raise

    def _generate_summary_content(self, results: Dict) -> str:
        """Generate human-readable summary content."""
        content = []

        # Header
        analysis_date = results.get('meta', {}).get('analysis_date', 'Unknown')
        app_name = results.get('app_summary', {}).get('name', 'Unknown Application')

        content.append(f"# Security Analysis Report")
        content.append(f"**Application:** {app_name}")
        content.append(f"**Analysis Date:** {analysis_date}")
        content.append(f"**Generated by:** AI-Powered Static Analysis Tool")
        content.append("")

        # Executive Summary
        content.append("## Executive Summary")
        app_purpose = results.get('app_summary', {}).get('purpose', 'Not available')
        content.append(f"**Purpose:** {app_purpose}")
        content.append("")

        # Key Metrics
        content.append("## Key Metrics")

        endpoints_count = len(results.get('endpoints', []))
        vulns_count = len(results.get('sast_vulnerabilities', []))
        tests_count = len(results.get('test_cases', []))
        coverage = results.get('coverage_matrix', {})

        content.append(f"- **Endpoints Analyzed:** {endpoints_count}")
        content.append(f"- **Vulnerabilities Found:** {vulns_count}")
        content.append(f"- **Test Cases Generated:** {tests_count}")
        content.append(f"- **Endpoint Coverage:** {coverage.get('endpoint_coverage_pct', 0)}%")
        content.append(f"- **OWASP Coverage:** {coverage.get('owasp_coverage_pct', 0)}%")
        content.append("")

        # Vulnerabilities Breakdown
        if results.get('sast_vulnerabilities'):
            content.append("## Vulnerabilities by Severity")

            severity_counts = {}
            owasp_counts = {}

            for vuln in results['sast_vulnerabilities']:
                severity = vuln.get('severity', 'Unknown')
                owasp = vuln.get('owasp_category', 'Unknown')

                severity_counts[severity] = severity_counts.get(severity, 0) + 1
                owasp_counts[owasp] = owasp_counts.get(owasp, 0) + 1

            for severity in ['HIGH', 'MEDIUM', 'LOW', 'INFO']:
                count = severity_counts.get(severity, 0)
                content.append(f"- **{severity}:** {count}")

            content.append("")
            content.append("## OWASP Top 10 Categories Found")
            for owasp, count in sorted(owasp_counts.items()):
                if owasp != 'Unknown':
                    content.append(f"- **{owasp}:** {count} issues")
            content.append("")

        # Test Coverage
        content.append("## Test Coverage Analysis")

        if coverage.get('gaps'):
            content.append("### Coverage Gaps")
            for gap in coverage['gaps']:
                content.append(f"- {gap}")
            content.append("")

        # Recommendations
        content.append("## Recommendations")
        content.append("1. **Address High-Severity Vulnerabilities:** Focus on fixing HIGH severity issues first")
        content.append("2. **Improve Test Coverage:** Add tests for untested endpoints")
        content.append("3. **OWASP Compliance:** Ensure coverage of all OWASP Top 10 categories")
        content.append("4. **Regular Scans:** Implement regular security scanning in CI/CD pipeline")
        content.append("")

        # Technical Details
        sources_used = results.get('meta', {}).get('sources_used', {})
        content.append("## Analysis Sources")
        content.append(f"- **PDF Report:** {'Yes' if sources_used.get('pdf_present') else 'No'}")
        content.append(f"- **Code Files:** {sources_used.get('code_snippets_count', 0)} files analyzed")
        content.append(f"- **SAST Scan:** {'Yes' if sources_used.get('sast_findings_present') else 'No'}")
        content.append("")

        # Assumptions
        assumptions = results.get('meta', {}).get('assumptions', [])
        if assumptions:
            content.append("## Analysis Assumptions")
            for assumption in assumptions:
                content.append(f"- {assumption}")
            content.append("")

        # Footer
        content.append("---")
        content.append("*Report generated by AI-Powered Static Analysis and Test Generation Tool*")

        return "\n".join(content)

    def create_export_manifest(self, exported_files: Dict[str, str]) -> str:
        """Create a manifest of all exported files."""
        manifest_filename = "export_manifest.json"
        manifest_path = os.path.join(self.output_directory, manifest_filename)

        manifest_data = {
            "export_timestamp": datetime.now().isoformat(),
            "exported_files": exported_files,
            "file_count": len(exported_files),
            "formats": list(set([
                'json' if path.endswith('.json') else
                'csv' if path.endswith('.csv') else
                'markdown' if path.endswith('.md') else
                'unknown'
                for path in exported_files.values()
            ]))
        }

        try:
            with open(manifest_path, 'w', encoding='utf-8') as f:
                json.dump(manifest_data, f, indent=2, ensure_ascii=False)

            logger.info(f"Created export manifest: {manifest_path}")
            return manifest_path

        except Exception as e:
            logger.error(f"Error creating export manifest: {e}")
            raise
