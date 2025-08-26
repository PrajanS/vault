"""
Enhanced Test Case Generator with multi-pass generation for comprehensive coverage.
"""
import logging
from typing import Dict, List, Optional
from llm_client import LLMClient
from utils import AssumptionTracker, calculate_percentage

logger = logging.getLogger(__name__)

class TestGenerator:
    """Enhanced generator for comprehensive security and business logic test cases."""

    def __init__(self, llm_client: Optional[LLMClient] = None):
        """Initialize enhanced test generator."""
        self.llm_client = llm_client or LLMClient()
        self.assumption_tracker = AssumptionTracker()
        self.test_counter = 1

        # Enhanced OWASP Top 10 2023 test templates with multiple test scenarios
        self.owasp_templates = {
            'A01': {
                'name': 'Broken Access Control',
                'tests': [
                    'Test unauthorized access to admin endpoints',
                    'Test horizontal privilege escalation between users',
                    'Test vertical privilege escalation to admin',
                    'Test IDOR (Insecure Direct Object Reference) vulnerabilities',
                    'Test path traversal and directory access',
                    'Test CORS misconfiguration bypass',
                    'Test missing function-level access control',
                    'Test forced browsing to restricted pages',
                    'Test metadata manipulation attacks',
                    'Test JWT token manipulation and bypass'
                ]
            },
            'A02': {
                'name': 'Cryptographic Failures',
                'tests': [
                    'Test weak encryption algorithms (DES, MD5, SHA1)',
                    'Test hardcoded cryptographic keys and secrets',
                    'Test insecure data transmission over HTTP',
                    'Test weak password policies and storage',
                    'Test insufficient entropy in random number generation',
                    'Test SSL/TLS configuration weaknesses',
                    'Test certificate validation bypass',
                    'Test cryptographic key management flaws'
                ]
            },
            'A03': {
                'name': 'Injection',
                'tests': [
                    'Test SQL injection in database queries',
                    'Test NoSQL injection (MongoDB, CouchDB)',
                    'Test LDAP injection vulnerabilities',
                    'Test OS command injection',
                    'Test XSS (Cross-Site Scripting) - reflected',
                    'Test XSS (Cross-Site Scripting) - stored',
                    'Test XSS (Cross-Site Scripting) - DOM-based',
                    'Test XXE (XML External Entity) injection',
                    'Test SSTI (Server-Side Template Injection)',
                    'Test CRLF injection and HTTP response splitting',
                    'Test XPath injection vulnerabilities',
                    'Test expression language injection',
                    'Test code injection through eval() functions',
                    'Test header injection attacks',
                    'Test email injection vulnerabilities'
                ]
            },
            'A04': {
                'name': 'Insecure Design',
                'tests': [
                    'Test business logic flaws and bypasses',
                    'Test workflow manipulation and state bypasses',
                    'Test insecure design patterns implementation',
                    'Test insufficient anti-automation controls',
                    'Test missing rate limiting on critical functions',
                    'Test inadequate fraud detection mechanisms'
                ]
            },
            'A05': {
                'name': 'Security Misconfiguration',
                'tests': [
                    'Test default credentials and accounts',
                    'Test debug mode enabled in production',
                    'Test unnecessary services and features enabled',
                    'Test missing security headers (CSP, HSTS, etc.)',
                    'Test directory listing and file exposure',
                    'Test error handling information disclosure',
                    'Test CORS policy misconfigurations',
                    'Test cloud storage permissions (S3, etc.)'
                ]
            },
            'A06': {
                'name': 'Vulnerable Components',
                'tests': [
                    'Test outdated framework versions',
                    'Test known CVE exploits in dependencies',
                    'Test insecure third-party components',
                    'Test supply chain attack vectors',
                    'Test vulnerable JavaScript libraries'
                ]
            },
            'A07': {
                'name': 'Authentication Failures', 
                'tests': [
                    'Test weak authentication mechanisms',
                    'Test session management flaws',
                    'Test credential stuffing attacks',
                    'Test brute force attack protection',
                    'Test password reset token vulnerabilities',
                    'Test multi-factor authentication bypass',
                    'Test session fixation attacks',
                    'Test concurrent session handling',
                    'Test authentication bypass techniques'
                ]
            },
            'A08': {
                'name': 'Software Integrity Failures',
                'tests': [
                    'Test unsigned or unverified updates',
                    'Test CI/CD pipeline security weaknesses',
                    'Test supply chain attack vectors',
                    'Test code tampering detection',
                    'Test integrity validation of critical data'
                ]
            },
            'A09': {
                'name': 'Logging Failures',
                'tests': [
                    'Test insufficient security event logging',
                    'Test log injection vulnerabilities',
                    'Test sensitive data exposure in logs',
                    'Test log tampering and manipulation',
                    'Test audit trail completeness'
                ]
            },
            'A10': {
                'name': 'Server-Side Request Forgery',
                'tests': [
                    'Test SSRF vulnerabilities in URL parameters',
                    'Test internal service enumeration via SSRF',
                    'Test cloud metadata service access',
                    'Test DNS rebinding attacks',
                    'Test blind SSRF exploitation'
                ]
            }
        }

        # Additional security test categories
        self.additional_security_tests = {
            'Input_Validation': [
                'Test input length validation bypass',
                'Test special character handling',
                'Test Unicode and encoding attacks',
                'Test file upload restrictions bypass',
                'Test content type validation',
                'Test malformed data handling'
            ],
            'Session_Management': [
                'Test session timeout enforcement',
                'Test concurrent session limits',
                'Test session token entropy',
                'Test session hijacking protection',
                'Test logout functionality completeness'
            ],
            'Error_Handling': [
                'Test error message information disclosure',
                'Test stack trace exposure',
                'Test database error leakage',
                'Test application crash scenarios'
            ],
            'API_Security': [
                'Test REST API rate limiting',
                'Test GraphQL query depth limits',
                'Test API versioning security',
                'Test API key management',
                'Test JSON/XML bombing attacks'
            ]
        }

    def generate_all_test_cases(self, endpoints: List[Dict], vulnerabilities: List[Dict], 
                               business_rules: List[Dict]) -> List[Dict]:
        """Generate comprehensive test cases using multi-pass approach."""
        all_tests = []

        # Pass 1: LLM-generated comprehensive tests
        try:
            logger.info("Pass 1: Generating comprehensive security test cases using LLM")
            security_tests = self.llm_client.generate_comprehensive_security_tests(endpoints, vulnerabilities)

            for test in security_tests:
                test['generated_by'] = 'llm'
                test['category'] = 'security'
                test['pass'] = 1
                if 'id' not in test:
                    test['id'] = f'T{self.test_counter:03d}'
                    self.test_counter += 1

            all_tests.extend(security_tests)
            logger.info(f"Pass 1 complete: {len(security_tests)} LLM-generated security tests")

        except Exception as e:
            logger.error(f"Error in Pass 1 LLM test generation: {e}")
            self.assumption_tracker.add_assumption("LLM security test generation failed in Pass 1")

        # Pass 2: LLM-generated business logic tests
        try:
            logger.info("Pass 2: Generating business logic test cases using LLM")
            business_tests = self.llm_client.generate_business_logic_tests(endpoints, business_rules)

            for test in business_tests:
                test['generated_by'] = 'llm'
                test['category'] = 'business_logic'
                test['pass'] = 2
                if 'id' not in test:
                    test['id'] = f'T{self.test_counter:03d}'
                    self.test_counter += 1

            all_tests.extend(business_tests)
            logger.info(f"Pass 2 complete: {len(business_tests)} LLM-generated business tests")

        except Exception as e:
            logger.error(f"Error in Pass 2 LLM test generation: {e}")
            self.assumption_tracker.add_assumption("LLM business test generation failed in Pass 2")

        # Pass 3: Template-based OWASP tests (comprehensive)
        logger.info("Pass 3: Generating comprehensive OWASP template-based tests")
        template_tests = self._generate_comprehensive_template_tests(endpoints, vulnerabilities)
        all_tests.extend(template_tests)
        logger.info(f"Pass 3 complete: {len(template_tests)} template-based tests")

        # Pass 4: Endpoint-specific tests
        logger.info("Pass 4: Generating endpoint-specific test cases")
        endpoint_tests = self._generate_endpoint_specific_tests(endpoints)
        all_tests.extend(endpoint_tests)
        logger.info(f"Pass 4 complete: {len(endpoint_tests)} endpoint-specific tests")

        # Pass 5: Vulnerability-specific tests
        logger.info("Pass 5: Generating vulnerability-specific test cases")
        vuln_tests = self._generate_vulnerability_specific_tests(vulnerabilities)
        all_tests.extend(vuln_tests)
        logger.info(f"Pass 5 complete: {len(vuln_tests)} vulnerability-specific tests")

        # Pass 6: Business rule validation tests
        logger.info("Pass 6: Generating business rule validation tests")
        rule_tests = self._generate_business_rule_tests(business_rules, endpoints)
        all_tests.extend(rule_tests)
        logger.info(f"Pass 6 complete: {len(rule_tests)} business rule tests")

        # Post-processing
        all_tests = self._deduplicate_tests(all_tests)
        all_tests = self._validate_and_fix_tests(all_tests)
        all_tests = self._prioritize_tests(all_tests)

        logger.info(f"Multi-pass generation complete: {len(all_tests)} total test cases generated")
        return all_tests

    def _generate_comprehensive_template_tests(self, endpoints: List[Dict], 
                                             vulnerabilities: List[Dict]) -> List[Dict]:
        """Generate comprehensive template-based tests for all OWASP categories."""
        tests = []

        # Get OWASP categories from vulnerabilities
        found_owasp_categories = set()
        for vuln in vulnerabilities:
            owasp_cat = vuln.get('owasp_category')
            if owasp_cat and owasp_cat in self.owasp_templates:
                found_owasp_categories.add(owasp_cat)

        # If no vulnerabilities found, test all OWASP categories
        if not found_owasp_categories:
            found_owasp_categories = set(self.owasp_templates.keys())

        # Generate tests for each OWASP category
        for owasp_cat in found_owasp_categories:
            template = self.owasp_templates.get(owasp_cat, {})
            category_name = template.get('name', f'OWASP {owasp_cat}')
            test_templates = template.get('tests', [])

            for test_template in test_templates:
                # Map test to relevant endpoints
                relevant_endpoints = self._find_relevant_endpoints(
                    endpoints, owasp_cat, test_template
                )

                test = {
                    'id': f'T{self.test_counter:03d}',
                    'title': f'{test_template}',
                    'type': 'standard',
                    'category': 'security',
                    'owasp_category': owasp_cat,
                    'owasp_name': category_name,
                    'mapped_endpoints': [ep['id'] for ep in relevant_endpoints],
                    'steps': self._generate_test_steps(test_template, relevant_endpoints),
                    'expected_result': self._generate_expected_result(test_template, owasp_cat),
                    'severity': self._determine_test_severity(owasp_cat),
                    'generated_by': 'template',
                    'pass': 3,
                    'automation_level': self._determine_automation_level(test_template),
                    'prerequisites': self._generate_prerequisites(test_template),
                    'tools_required': self._suggest_tools(test_template)
                }

                tests.append(test)
                self.test_counter += 1

        # Add additional security tests
        for category, test_list in self.additional_security_tests.items():
            for test_template in test_list:
                relevant_endpoints = self._find_relevant_endpoints_for_category(
                    endpoints, category, test_template
                )

                test = {
                    'id': f'T{self.test_counter:03d}',
                    'title': f'{test_template}',
                    'type': 'additional',
                    'category': 'security',
                    'security_category': category,
                    'mapped_endpoints': [ep['id'] for ep in relevant_endpoints],
                    'steps': self._generate_test_steps(test_template, relevant_endpoints),
                    'expected_result': self._generate_expected_result(test_template, category),
                    'severity': 'Medium',
                    'generated_by': 'template',
                    'pass': 3,
                    'automation_level': self._determine_automation_level(test_template)
                }

                tests.append(test)
                self.test_counter += 1

        return tests

    def _generate_endpoint_specific_tests(self, endpoints: List[Dict]) -> List[Dict]:
        """Generate specific tests for each discovered endpoint."""
        tests = []

        for endpoint in endpoints:
            endpoint_id = endpoint.get('id', 'unknown')
            endpoint_path = endpoint.get('path', '/')
            endpoint_method = endpoint.get('method', 'GET')

            # Generate multiple tests per endpoint
            endpoint_test_templates = [
                f'Test {endpoint_method} {endpoint_path} with invalid authentication',
                f'Test {endpoint_method} {endpoint_path} with malformed parameters',
                f'Test {endpoint_method} {endpoint_path} with oversized payloads',
                f'Test {endpoint_method} {endpoint_path} with SQL injection payloads',
                f'Test {endpoint_method} {endpoint_path} with XSS payloads',
                f'Test {endpoint_method} {endpoint_path} rate limiting',
                f'Test {endpoint_method} {endpoint_path} error handling',
                f'Test {endpoint_method} {endpoint_path} with null/empty values'
            ]

            for test_template in endpoint_test_templates:
                test = {
                    'id': f'T{self.test_counter:03d}',
                    'title': test_template,
                    'type': 'endpoint_specific',
                    'category': 'security',
                    'mapped_endpoints': [endpoint_id],
                    'target_endpoint': endpoint_path,
                    'target_method': endpoint_method,
                    'steps': self._generate_endpoint_test_steps(test_template, endpoint),
                    'expected_result': f'Endpoint should handle test case securely',
                    'severity': 'Medium',
                    'generated_by': 'template',
                    'pass': 4,
                    'automation_level': 'high'
                }

                tests.append(test)
                self.test_counter += 1

        return tests

    def _generate_vulnerability_specific_tests(self, vulnerabilities: List[Dict]) -> List[Dict]:
        """Generate specific tests for each discovered vulnerability."""
        tests = []

        for vulnerability in vulnerabilities:
            vuln_id = vulnerability.get('id', 'unknown')
            vuln_title = vulnerability.get('title', 'Unknown Vulnerability')
            vuln_file = vulnerability.get('file', 'unknown')
            vuln_line = vulnerability.get('line_start', 0)
            owasp_cat = vulnerability.get('owasp_category', 'A00')

            # Generate verification and exploitation tests
            vuln_test_templates = [
                f'Verify {vuln_title} in {vuln_file}',
                f'Test exploitation of {vuln_title}',
                f'Test remediation bypass for {vuln_title}',
                f'Test impact assessment of {vuln_title}'
            ]

            for test_template in vuln_test_templates:
                test = {
                    'id': f'T{self.test_counter:03d}',
                    'title': test_template,
                    'type': 'vulnerability_specific',
                    'category': 'security',
                    'vulnerability_id': vuln_id,
                    'target_file': vuln_file,
                    'target_line': vuln_line,
                    'owasp_category': owasp_cat,
                    'steps': self._generate_vulnerability_test_steps(test_template, vulnerability),
                    'expected_result': f'Vulnerability should be properly identified and/or mitigated',
                    'severity': vulnerability.get('severity', 'Medium'),
                    'generated_by': 'template',
                    'pass': 5,
                    'automation_level': 'medium'
                }

                tests.append(test)
                self.test_counter += 1

        return tests

    def _generate_business_rule_tests(self, business_rules: List[Dict], 
                                    endpoints: List[Dict]) -> List[Dict]:
        """Generate comprehensive tests for business rule validation."""
        tests = []

        for rule in business_rules:
            rule_id = rule.get('id', 'unknown')
            rule_description = rule.get('description', 'Unknown rule')

            # Find endpoints relevant to this business rule
            relevant_endpoints = self._find_endpoints_for_business_rule(rule, endpoints)

            # Generate multiple test scenarios for each rule
            rule_test_templates = [
                f'Test positive validation of {rule_id}',
                f'Test negative validation of {rule_id}',
                f'Test boundary conditions for {rule_id}',
                f'Test bypass attempts for {rule_id}',
                f'Test error handling for {rule_id} violations'
            ]

            for test_template in rule_test_templates:
                test = {
                    'id': f'T{self.test_counter:03d}',
                    'title': test_template,
                    'type': 'business_rule',
                    'category': 'business_logic',
                    'business_rule_id': rule_id,
                    'business_rule_description': rule_description[:100],
                    'mapped_endpoints': [ep['id'] for ep in relevant_endpoints],
                    'steps': self._generate_business_rule_test_steps(test_template, rule, relevant_endpoints),
                    'expected_result': f'Business rule {rule_id} should be properly enforced',
                    'severity': 'Medium',
                    'generated_by': 'template',
                    'pass': 6,
                    'automation_level': 'low'
                }

                tests.append(test)
                self.test_counter += 1

        return tests

    def _generate_endpoint_test_steps(self, test_template: str, endpoint: Dict) -> List[str]:
        """Generate specific test steps for endpoint testing."""
        path = endpoint.get('path', '/')
        method = endpoint.get('method', 'GET')

        if 'invalid authentication' in test_template.lower():
            return [
                f"1. Send {method} request to {path} without authentication headers",
                f"2. Send {method} request to {path} with invalid/expired token",
                f"3. Send {method} request to {path} with malformed authorization header",
                "4. Verify all requests are rejected with appropriate status codes",
                "5. Confirm no sensitive data is returned in error responses"
            ]
        elif 'malformed parameters' in test_template.lower():
            return [
                f"1. Send {method} request to {path} with malformed JSON/XML",
                f"2. Send {method} request to {path} with invalid parameter types",
                f"3. Send {method} request to {path} with missing required parameters",
                f"4. Send {method} request to {path} with unexpected parameter names",
                "5. Verify proper error handling and input validation"
            ]
        elif 'sql injection' in test_template.lower():
            return [
                f"1. Identify input parameters in {method} {path}",
                "2. Inject SQL metacharacters: ', \" , ;, --, /**/",
                "3. Test UNION-based injection payloads",
                "4. Test time-based blind injection techniques",
                "5. Verify application properly sanitizes input"
            ]
        elif 'rate limiting' in test_template.lower():
            return [
                f"1. Send multiple rapid {method} requests to {path}",
                "2. Monitor response times and status codes",
                "3. Check for rate limiting headers and responses",
                "4. Test rate limit bypass techniques",
                "5. Verify legitimate requests are not blocked"
            ]
        else:
            return [
                f"1. Target endpoint: {method} {path}",
                "2. Execute test scenario with appropriate payloads",
                "3. Monitor application response and behavior",
                "4. Verify security controls are functioning",
                "5. Document any security issues found"
            ]

    def _generate_vulnerability_test_steps(self, test_template: str, vulnerability: Dict) -> List[str]:
        """Generate test steps for vulnerability verification."""
        vuln_type = vulnerability.get('rule_id', '').lower()
        file_location = vulnerability.get('location', 'unknown')

        if 'verify' in test_template.lower():
            return [
                f"1. Review vulnerability in {file_location}",
                "2. Analyze the vulnerable code pattern",
                "3. Identify attack vectors and entry points", 
                "4. Confirm vulnerability exists and is exploitable",
                "5. Document proof of concept if applicable"
            ]
        elif 'exploitation' in test_template.lower():
            return [
                "1. Craft specific payloads for this vulnerability type",
                f"2. Target the vulnerable code at {file_location}",
                "3. Attempt to exploit the vulnerability",
                "4. Assess the impact and potential damage",
                "5. Document successful exploitation techniques"
            ]
        else:
            return [
                f"1. Focus on vulnerability at {file_location}",
                "2. Execute vulnerability-specific test procedures",
                "3. Verify vulnerability behavior and impact",
                "4. Test potential remediation approaches",
                "5. Confirm fix effectiveness if implemented"
            ]

    def _generate_business_rule_test_steps(self, test_template: str, rule: Dict, 
                                         endpoints: List[Dict]) -> List[str]:
        """Generate test steps for business rule validation."""
        rule_desc = rule.get('description', 'Unknown rule')
        endpoint_paths = [ep.get('path', '/') for ep in endpoints[:3]]

        if 'positive validation' in test_template.lower():
            return [
                f"1. Test valid scenarios that should comply with: {rule_desc[:50]}...",
                f"2. Use endpoints: {', '.join(endpoint_paths)}",
                "3. Submit valid data that meets business rule requirements",
                "4. Verify rule is properly enforced and allows valid operations",
                "5. Confirm successful processing and appropriate responses"
            ]
        elif 'negative validation' in test_template.lower():
            return [
                f"1. Test invalid scenarios that should violate: {rule_desc[:50]}...",
                f"2. Use endpoints: {', '.join(endpoint_paths)}",
                "3. Submit data that intentionally violates the business rule",
                "4. Verify rule enforcement blocks invalid operations",
                "5. Confirm appropriate error messages and rejection handling"
            ]
        elif 'boundary conditions' in test_template.lower():
            return [
                f"1. Test edge cases for rule: {rule_desc[:50]}...",
                "2. Test minimum and maximum allowed values",
                "3. Test boundary values (just above/below limits)",
                "4. Test null, empty, and undefined edge cases",
                "5. Verify consistent rule enforcement at boundaries"
            ]
        else:
            return [
                f"1. Test business rule: {rule_desc[:50]}...",
                f"2. Target endpoints: {', '.join(endpoint_paths)}",
                "3. Execute business logic validation scenarios",
                "4. Verify rule compliance and enforcement",
                "5. Document any business logic vulnerabilities"
            ]

    def _find_endpoints_for_business_rule(self, rule: Dict, endpoints: List[Dict]) -> List[Dict]:
        """Find endpoints relevant to a specific business rule."""
        rule_desc = rule.get('description', '').lower()
        relevant = []

        # Match endpoints based on rule description keywords
        for endpoint in endpoints:
            path = endpoint.get('path', '').lower()
            method = endpoint.get('method', '').lower()

            # Look for keyword matches
            if any(keyword in rule_desc for keyword in ['user', 'login', 'auth'] if keyword in path):
                relevant.append(endpoint)
            elif any(keyword in rule_desc for keyword in ['payment', 'order', 'purchase'] if keyword in path):
                relevant.append(endpoint)
            elif any(keyword in rule_desc for keyword in ['admin', 'manage'] if keyword in path):
                relevant.append(endpoint)

        # If no matches, return first few endpoints
        if not relevant:
            relevant = endpoints[:3]

        return relevant

    def _prioritize_tests(self, tests: List[Dict]) -> List[Dict]:
        """Prioritize tests based on severity and type."""

        def priority_score(test):
            score = 0

            # Severity scoring
            severity_scores = {'Critical': 100, 'High': 80, 'Medium': 50, 'Low': 20}
            score += severity_scores.get(test.get('severity', 'Medium'), 50)

            # OWASP category scoring (higher for more critical categories)
            owasp_scores = {
                'A01': 90, 'A02': 85, 'A03': 95, 'A04': 70, 'A05': 60,
                'A06': 75, 'A07': 85, 'A08': 70, 'A09': 50, 'A10': 80
            }
            score += owasp_scores.get(test.get('owasp_category', 'A00'), 30)

            # Test type scoring
            type_scores = {
                'vulnerability_specific': 90,
                'endpoint_specific': 70,
                'business_rule': 60,
                'standard': 50,
                'additional': 40
            }
            score += type_scores.get(test.get('type', 'standard'), 50)

            return score

        # Sort by priority score (highest first)
        prioritized_tests = sorted(tests, key=priority_score, reverse=True)

        # Add priority field
        for i, test in enumerate(prioritized_tests):
            if i < len(prioritized_tests) * 0.2:  # Top 20%
                test['priority'] = 'Critical'
            elif i < len(prioritized_tests) * 0.5:  # Next 30%
                test['priority'] = 'High'
            elif i < len(prioritized_tests) * 0.8:  # Next 30%
                test['priority'] = 'Medium'
            else:  # Bottom 20%
                test['priority'] = 'Low'

        return prioritized_tests

    def _suggest_tools(self, test_template: str) -> List[str]:
        """Suggest testing tools for specific test types."""
        template_lower = test_template.lower()
        tools = []

        if 'sql injection' in template_lower:
            tools = ['SQLMap', 'Burp Suite', 'OWASP ZAP', 'w3af']
        elif 'xss' in template_lower:
            tools = ['XSSer', 'Burp Suite', 'OWASP ZAP', 'BeEF']
        elif 'brute force' in template_lower or 'authentication' in template_lower:
            tools = ['Hydra', 'Burp Suite Intruder', 'Medusa', 'John the Ripper']
        elif 'directory' in template_lower or 'path' in template_lower:
            tools = ['DirBuster', 'Gobuster', 'OWASP DirSearch', 'Burp Suite']
        elif 'ssl' in template_lower or 'tls' in template_lower:
            tools = ['SSLyze', 'testssl.sh', 'Nmap', 'OpenSSL']
        else:
            tools = ['Burp Suite', 'OWASP ZAP', 'Manual Testing']

        return tools

    def _generate_prerequisites(self, test_template: str) -> List[str]:
        """Generate prerequisites for test execution."""
        template_lower = test_template.lower()

        if 'authentication' in template_lower:
            return ['Valid user credentials', 'Test user account', 'Authentication mechanism understanding']
        elif 'admin' in template_lower:
            return ['Admin account access', 'Administrative privileges', 'System configuration knowledge']
        elif 'database' in template_lower or 'sql' in template_lower:
            return ['Database connection details', 'Sample data in database', 'SQL knowledge']
        elif 'api' in template_lower:
            return ['API documentation', 'Valid API keys/tokens', 'API endpoint access']
        else:
            return ['Application access', 'Testing environment', 'Basic security testing knowledge']

    def _find_relevant_endpoints_for_category(self, endpoints: List[Dict], 
                                            category: str, test_template: str) -> List[Dict]:
        """Find endpoints relevant to additional security categories."""
        relevant = []

        if category == 'Input_Validation':
            # Look for endpoints with parameters
            relevant = [ep for ep in endpoints if ep.get('params')]
        elif category == 'Session_Management':
            # Look for auth-related endpoints
            relevant = [ep for ep in endpoints 
                       if any(term in ep.get('path', '').lower() 
                             for term in ['login', 'logout', 'session', 'auth'])]
        elif category == 'API_Security':
            # Look for API endpoints
            relevant = [ep for ep in endpoints 
                       if '/api/' in ep.get('path', '').lower()]

        # Fallback to all POST/PUT/DELETE endpoints
        if not relevant:
            relevant = [ep for ep in endpoints 
                       if ep.get('method', '').upper() in ['POST', 'PUT', 'DELETE']]

        return relevant[:3]  # Limit to 3 endpoints

    def _find_relevant_endpoints(self, endpoints: List[Dict], owasp_category: str, 
                                test_template: str) -> List[Dict]:
        """Find endpoints relevant to a specific OWASP test."""
        relevant = []

        # Enhanced endpoint matching logic
        if owasp_category == 'A01':  # Access Control
            relevant = [ep for ep in endpoints if ep.get('auth_required') in ['yes', 'likely']]

        elif owasp_category == 'A02':  # Cryptographic Failures
            relevant = [ep for ep in endpoints 
                       if any(term in ep.get('path', '').lower() 
                             for term in ['login', 'auth', 'password', 'token', 'key', 'crypto'])]

        elif owasp_category == 'A03':  # Injection
            relevant = [ep for ep in endpoints if ep.get('params')]

        elif owasp_category == 'A07':  # Authentication
            relevant = [ep for ep in endpoints 
                       if any(term in ep.get('path', '').lower() 
                             for term in ['login', 'auth', 'session', 'user', 'signin'])]

        elif owasp_category == 'A10':  # SSRF
            relevant = [ep for ep in endpoints 
                       if any(term in ep.get('path', '').lower() 
                             for term in ['url', 'link', 'redirect', 'proxy', 'fetch'])]

        # If no specific matches, include all endpoints that accept input
        if not relevant:
            relevant = [ep for ep in endpoints 
                       if ep.get('method', '').upper() in ['POST', 'PUT', 'PATCH']]

        # Final fallback to first few endpoints
        if not relevant:
            relevant = endpoints[:3]

        return relevant

    def _generate_test_steps(self, test_template: str, endpoints: List[Dict]) -> List[str]:
        """Enhanced test step generation with more detailed procedures."""

        # Use existing logic but enhance with more detailed steps
        if 'sql injection' in test_template.lower():
            return [
                "1. Identify all input parameters (GET, POST, headers, cookies)",
                "2. Test with basic SQL metacharacters: ', \" , ;, --, /**/, ",
                "3. Attempt UNION-based injection: ' UNION SELECT 1,2,3--",
                "4. Test time-based blind injection: '; WAITFOR DELAY '00:00:05'--",
                "5. Test boolean-based blind injection: ' AND 1=1-- vs ' AND 1=2--",
                "6. Check for database error messages and information disclosure",
                "7. Verify proper input sanitization and parameterized queries"
            ]
        elif 'xss' in test_template.lower():
            return [
                "1. Identify all user input fields and reflection points",
                "2. Test basic XSS payload: <script>alert('XSS')</script>",
                "3. Test event handler XSS: <img src=x onerror=alert('XSS')>",
                "4. Test encoded payloads: %3Cscript%3Ealert('XSS')%3C/script%3E",
                "5. Test DOM-based XSS in JavaScript execution contexts",
                "6. Test stored XSS by submitting payloads and checking persistence",
                "7. Verify proper output encoding and CSP implementation"
            ]
        elif 'access control' in test_template.lower() or 'unauthorized' in test_template.lower():
            return [
                "1. Map all application endpoints and required privilege levels",
                "2. Attempt access without any authentication credentials",
                "3. Test with low-privilege user credentials on admin functions",
                "4. Test horizontal privilege escalation (access other users' data)",
                "5. Test vertical privilege escalation (access admin functions)",
                "6. Test direct object reference manipulation (IDOR)",
                "7. Verify consistent authorization enforcement across all endpoints"
            ]
        elif 'brute force' in test_template.lower():
            return [
                "1. Identify authentication and login endpoints",
                "2. Test account lockout after multiple failed attempts",
                "3. Check for CAPTCHA or rate limiting mechanisms",
                "4. Test password complexity requirements",
                "5. Attempt credential stuffing with common passwords",
                "6. Test for username enumeration vulnerabilities",
                "7. Verify proper logging and monitoring of failed attempts"
            ]
        else:
            # Generic enhanced test steps
            endpoint_paths = [ep.get('path', '/unknown') for ep in endpoints[:3]]
            return [
                f"1. Target endpoints: {', '.join(endpoint_paths)}",
                "2. Prepare appropriate test payloads and tools",
                "3. Execute test scenario with systematic approach",
                "4. Monitor application responses and error conditions", 
                "5. Verify security controls are properly implemented",
                "6. Document findings and evidence",
                "7. Validate remediation if fixes are applied"
            ]

    def _generate_expected_result(self, test_template: str, category: str) -> str:
        """Enhanced expected result generation."""
        if 'injection' in test_template.lower():
            return "Application should reject malicious input, use parameterized queries, and implement proper input validation without exposing database errors"
        elif 'access control' in test_template.lower():
            return "Application should consistently enforce authorization checks, deny unauthorized access with appropriate status codes, and maintain proper session security"
        elif 'xss' in test_template.lower():
            return "Application should encode all output, implement Content Security Policy (CSP), and prevent script execution from user input"
        elif 'brute force' in test_template.lower():
            return "Application should implement account lockout, rate limiting, CAPTCHA protection, and comprehensive audit logging"
        elif 'crypto' in test_template.lower() or 'encryption' in test_template.lower():
            return "Application should use strong encryption algorithms, secure key management, and proper certificate validation"
        else:
            return f"Application should be secure against {category} vulnerabilities with proper security controls implemented"

    def _determine_test_severity(self, owasp_category: str) -> str:
        """Enhanced severity determination."""
        critical_categories = ['A01', 'A03']  # Access Control, Injection
        high_severity = ['A02', 'A07', 'A08', 'A10']  # Crypto, Auth, Integrity, SSRF
        medium_severity = ['A04', 'A05', 'A06', 'A09']  # Design, Config, Components, Logging

        if owasp_category in critical_categories:
            return 'Critical'
        elif owasp_category in high_severity:
            return 'High'
        elif owasp_category in medium_severity:
            return 'Medium'
        else:
            return 'Low'

    def _determine_automation_level(self, test_template: str) -> str:
        """Determine test automation feasibility."""
        if any(term in test_template.lower() for term in ['injection', 'xss', 'brute force', 'scan']):
            return 'high'
        elif any(term in test_template.lower() for term in ['access', 'auth', 'session', 'api']):
            return 'medium'
        else:
            return 'low'

    def _deduplicate_tests(self, tests: List[Dict]) -> List[Dict]:
        """Enhanced deduplication with similarity checking."""
        seen = set()
        deduplicated = []

        for test in tests:
            # Create more comprehensive signature
            endpoints_sig = tuple(sorted(test.get('mapped_endpoints', [])))
            title_words = set(test.get('title', '').lower().split())

            signature = (
                test.get('owasp_category', ''),
                test.get('category', ''),
                endpoints_sig,
                frozenset(title_words)
            )

            if signature not in seen:
                seen.add(signature)
                deduplicated.append(test)

        logger.info(f"Removed {len(tests) - len(deduplicated)} duplicate tests")
        return deduplicated

    def _validate_and_fix_tests(self, tests: List[Dict]) -> List[Dict]:
        """Enhanced test validation and fixing."""
        valid_tests = []

        for test in tests:
            # Ensure required fields with better defaults
            if not test.get('id'):
                test['id'] = f'T{self.test_counter:03d}'
                self.test_counter += 1

            if not test.get('title'):
                test['title'] = f"Security Test Case {test['id']}"

            if not test.get('type'):
                test['type'] = 'standard'

            if not test.get('category'):
                test['category'] = 'security'

            if not test.get('steps'):
                test['steps'] = [
                    "1. Prepare test environment and tools",
                    "2. Execute security test scenario", 
                    "3. Analyze application response",
                    "4. Verify security controls",
                    "5. Document findings"
                ]

            if not test.get('expected_result'):
                test['expected_result'] = "Application should demonstrate secure behavior and proper security controls"

            if not test.get('severity'):
                test['severity'] = 'Medium'

            if not test.get('mapped_endpoints'):
                test['mapped_endpoints'] = []

            # Ensure steps is a list and properly formatted
            if isinstance(test.get('steps'), str):
                test['steps'] = [test['steps']]

            # Add additional metadata for enhanced tests
            if not test.get('automation_level'):
                test['automation_level'] = self._determine_automation_level(test.get('title', ''))

            if not test.get('prerequisites'):
                test['prerequisites'] = self._generate_prerequisites(test.get('title', ''))

            if not test.get('tools_required'):
                test['tools_required'] = self._suggest_tools(test.get('title', ''))

            valid_tests.append(test)

        return valid_tests

    def calculate_coverage_metrics(self, tests: List[Dict], endpoints: List[Dict], 
                                 vulnerabilities: List[Dict]) -> Dict:
        """Enhanced coverage metrics calculation."""

        # Endpoint coverage
        tested_endpoints = set()
        for test in tests:
            tested_endpoints.update(test.get('mapped_endpoints', []))

        total_endpoints = len(endpoints)
        endpoint_coverage_pct = calculate_percentage(len(tested_endpoints), total_endpoints)

        # OWASP coverage
        owasp_2023_categories = [f'A{i:02d}' for i in range(1, 11)]
        covered_owasp = set()

        for test in tests:
            owasp_cat = test.get('owasp_category')
            if owasp_cat and owasp_cat in owasp_2023_categories:
                covered_owasp.add(owasp_cat)

        owasp_coverage_pct = calculate_percentage(len(covered_owasp), len(owasp_2023_categories))

        # Test type analysis
        test_types = {}
        severity_distribution = {}

        for test in tests:
            test_type = test.get('type', 'unknown')
            test_types[test_type] = test_types.get(test_type, 0) + 1

            severity = test.get('severity', 'Medium')
            severity_distribution[severity] = severity_distribution.get(severity, 0) + 1

        # Identify gaps
        untested_endpoints = []
        for endpoint in endpoints:
            if endpoint.get('id') not in tested_endpoints:
                untested_endpoints.append(endpoint['id'])

        missing_owasp = [cat for cat in owasp_2023_categories if cat not in covered_owasp]

        gaps = []
        if untested_endpoints:
            gaps.append(f"Untested endpoints: {', '.join(untested_endpoints[:5])}")
        if missing_owasp:
            gaps.append(f"Missing OWASP categories: {', '.join(missing_owasp)}")

        return {
            'total_endpoints': total_endpoints,
            'endpoints_with_tests': len(tested_endpoints),
            'endpoint_coverage_pct': round(endpoint_coverage_pct, 1),
            'owasp_categories_covered': sorted(list(covered_owasp)),
            'owasp_coverage_pct': round(owasp_coverage_pct, 1),
            'total_test_cases': len(tests),
            'security_tests': len([t for t in tests if t.get('category') == 'security']),
            'business_tests': len([t for t in tests if t.get('category') == 'business_logic']),
            'test_type_distribution': test_types,
            'severity_distribution': severity_distribution,
            'critical_high_tests': severity_distribution.get('Critical', 0) + severity_distribution.get('High', 0),
            'automation_ready_tests': len([t for t in tests if t.get('automation_level') == 'high']),
            'gaps': gaps
        }

    def get_assumptions(self) -> List[str]:
        """Get all assumptions made during test generation."""
        return self.assumption_tracker.get_assumptions()
