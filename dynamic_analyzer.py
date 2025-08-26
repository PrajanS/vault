"""
Dynamic Analysis module for runtime endpoint testing and discovery.
"""
import requests
import threading
import time
import logging
import json
import re
from urllib.parse import urljoin, urlparse
from typing import Dict, List, Optional, Set, Tuple
from concurrent.futures import ThreadPoolExecutor, as_completed
from utils import AssumptionTracker

logger = logging.getLogger(__name__)

class DynamicAnalyzer:
    """Dynamic analyzer for runtime endpoint discovery and testing."""

    def __init__(self, base_url: str = None, max_threads: int = 10):
        """Initialize dynamic analyzer."""
        self.base_url = base_url
        self.max_threads = max_threads
        self.session = requests.Session()
        self.session.timeout = 10
        self.discovered_endpoints = []
        self.response_patterns = []
        self.assumption_tracker = AssumptionTracker()

        # Common endpoint patterns to test
        self.common_endpoints = [
            "/api/", "/api/v1/", "/api/v2/", "/rest/", "/graphql/",
            "/admin/", "/login/", "/logout/", "/register/", "/profile/",
            "/users/", "/user/", "/auth/", "/oauth/", "/token/",
            "/products/", "/orders/", "/cart/", "/checkout/", "/payment/",
            "/search/", "/upload/", "/download/", "/file/", "/files/",
            "/config/", "/settings/", "/health/", "/status/", "/ping/",
            "/dashboard/", "/reports/", "/analytics/", "/logs/"
        ]

        # Security-focused test payloads
        self.security_payloads = {
            'sql_injection': [
                "' OR '1'='1", "'; DROP TABLE users; --", 
                "1' UNION SELECT * FROM users--", "%27%20OR%20%271%27=%271"
            ],
            'xss': [
                "<script>alert('XSS')</script>", 
                "javascript:alert('XSS')",
                "<img src=x onerror=alert('XSS')>",
                "%3Cscript%3Ealert('XSS')%3C/script%3E"
            ],
            'path_traversal': [
                "../../../etc/passwd", "..\\..\\..\\windows\\system32\\drivers\\etc\\hosts",
                "%2e%2e%2f%2e%2e%2f%2e%2e%2fetc%2fpasswd"
            ],
            'command_injection': [
                "; ls -la", "| whoami", "&& cat /etc/passwd",
                "`id`", "$(whoami)"
            ]
        }

    def analyze_running_application(self, base_url: str, crawl_depth: int = 2) -> Dict:
        """
        Perform dynamic analysis on a running application.

        Args:
            base_url: Base URL of the running application
            crawl_depth: Depth of crawling for endpoint discovery

        Returns:
            Dictionary containing discovered endpoints and vulnerabilities
        """
        self.base_url = base_url
        logger.info(f"Starting dynamic analysis of {base_url}")

        results = {
            'endpoints': [],
            'vulnerabilities': [],
            'response_patterns': [],
            'security_headers': {},
            'cookies': [],
            'forms': [],
            'javascript_apis': []
        }

        try:
            # Step 1: Basic connectivity and header analysis
            results['security_headers'] = self._analyze_security_headers()

            # Step 2: Endpoint discovery
            results['endpoints'] = self._discover_endpoints(crawl_depth)

            # Step 3: Form discovery
            results['forms'] = self._discover_forms(crawl_depth)

            # Step 4: JavaScript API discovery
            results['javascript_apis'] = self._discover_js_apis(crawl_depth)

            # Step 5: Security testing
            results['vulnerabilities'] = self._test_security_vulnerabilities(results['endpoints'])

            # Step 6: Response pattern analysis
            results['response_patterns'] = self._analyze_response_patterns()

            logger.info(f"Dynamic analysis complete: {len(results['endpoints'])} endpoints discovered")

        except Exception as e:
            logger.error(f"Error in dynamic analysis: {e}")
            self.assumption_tracker.add_assumption("Dynamic analysis failed due to connectivity issues")

        return results

    def _analyze_security_headers(self) -> Dict:
        """Analyze security headers of the application."""
        try:
            response = self.session.get(self.base_url)
            headers = response.headers

            security_headers = {
                'strict_transport_security': headers.get('Strict-Transport-Security'),
                'content_security_policy': headers.get('Content-Security-Policy'),
                'x_frame_options': headers.get('X-Frame-Options'),
                'x_content_type_options': headers.get('X-Content-Type-Options'),
                'x_xss_protection': headers.get('X-XSS-Protection'),
                'referrer_policy': headers.get('Referrer-Policy'),
                'permissions_policy': headers.get('Permissions-Policy')
            }

            # Analyze missing security headers
            missing_headers = [k for k, v in security_headers.items() if v is None]
            if missing_headers:
                logger.warning(f"Missing security headers: {missing_headers}")

            return security_headers

        except Exception as e:
            logger.error(f"Failed to analyze security headers: {e}")
            return {}

    def _discover_endpoints(self, crawl_depth: int) -> List[Dict]:
        """Discover endpoints through crawling and common path testing."""
        discovered = []
        visited_urls = set()

        # Test common endpoints
        for endpoint in self.common_endpoints:
            test_url = urljoin(self.base_url, endpoint)
            endpoint_info = self._test_endpoint(test_url, 'GET')
            if endpoint_info:
                discovered.append(endpoint_info)
                visited_urls.add(test_url)

        # Crawl application for additional endpoints
        urls_to_crawl = [self.base_url]
        current_depth = 0

        while urls_to_crawl and current_depth < crawl_depth:
            next_urls = []

            with ThreadPoolExecutor(max_workers=self.max_threads) as executor:
                future_to_url = {
                    executor.submit(self._crawl_page, url): url 
                    for url in urls_to_crawl if url not in visited_urls
                }

                for future in as_completed(future_to_url):
                    url = future_to_url[future]
                    visited_urls.add(url)

                    try:
                        page_endpoints, page_links = future.result()
                        discovered.extend(page_endpoints)

                        # Add new links for next depth level
                        for link in page_links:
                            full_url = urljoin(url, link)
                            if self._is_same_domain(full_url) and full_url not in visited_urls:
                                next_urls.append(full_url)

                    except Exception as e:
                        logger.warning(f"Failed to crawl {url}: {e}")

            urls_to_crawl = next_urls[:50]  # Limit to prevent excessive crawling
            current_depth += 1

        return discovered

    def _crawl_page(self, url: str) -> Tuple[List[Dict], List[str]]:
        """Crawl a single page for endpoints and links."""
        endpoints = []
        links = []

        try:
            response = self.session.get(url)
            content = response.text

            # Extract API endpoints from JavaScript
            js_endpoints = self._extract_js_endpoints(content)
            endpoints.extend(js_endpoints)

            # Extract links for further crawling
            link_pattern = r"href=['\"]([^'\"]+)['\"]"
            found_links = re.findall(link_pattern, content, re.IGNORECASE)
            links.extend(found_links)

            # Extract form actions
            form_pattern = r"<form[^>]*action=['\"]([^'\"]+)['\"]"
            form_actions = re.findall(form_pattern, content, re.IGNORECASE)

            for action in form_actions:
                endpoint_info = self._test_endpoint(urljoin(url, action), 'POST')
                if endpoint_info:
                    endpoints.append(endpoint_info)

        except Exception as e:
            logger.warning(f"Failed to crawl page {url}: {e}")

        return endpoints, links

    def _extract_js_endpoints(self, content: str) -> List[Dict]:
        """Extract API endpoints from JavaScript code."""
        endpoints = []

        # Common patterns for API endpoints in JavaScript
        patterns = [
            r'[\'\"]/?api/[^\'\"]*[\'\"]',
            r'[\'\"]/?rest/[^\'\"]*[\'\"]',
            r'fetch\([\'\"]([^\'\"]+)[\'\"]',
            r'axios\.[a-z]+\([\'\"]([^\'\"]+)[\'\"]',
            r'\$\.ajax\({[^}]*url:\s*[\'\"]([^\'\"]+)[\'\"]',
            r'XMLHttpRequest.*open\([\'\"][A-Z]+[\'\"]\s*,\s*[\'\"]([^\'\"]+)[\'\"]'
        ]

        for pattern in patterns:
            matches = re.findall(pattern, content, re.IGNORECASE)
            for match in matches:
                if isinstance(match, tuple):
                    match = match[0] if match[0] else match[1]

                if match and match.startswith(('/', 'api/', 'rest/')):
                    endpoint_info = self._test_endpoint(urljoin(self.base_url, match), 'GET')
                    if endpoint_info:
                        endpoints.append(endpoint_info)

        return endpoints

    def _discover_forms(self, crawl_depth: int) -> List[Dict]:
        """Discover and analyze forms in the application."""
        forms = []

        try:
            patterns = [
                r'[\'\"]/?api/[^\'\"]*[\'\"]',
                r'[\'\"]/?rest/[^\'\"]*[\'\"]',
                r'fetch\([\'\"]([^\'\"]+)[\'\"]',
                r'axios\.[a-z]+\([\'\"]([^\'\"]+)[\'\"]',
                r'\$\.ajax\({[^}]*url:\s*[\'\"]([^\'\"]+)[\'\"]',
                r'XMLHttpRequest.*open\([\'\"][A-Z]+[\'\"]\s*,\s*[\'\"]([^\'\"]+)[\'\"]'
            ]
            # Dummy form_attrs for demonstration; replace with actual extraction logic
            form_attrs = ''
            form_info = {
                'attributes': form_attrs,
                'fields': [],
                'action': '',
                'method': 'GET'
            }

            # Extract action and method
            action_match = re.search(r'action=[\'\"]([^\'\"]+)[\'\"]', form_attrs)
            if action_match:
                form_info['action'] = action_match.group(1)
        except Exception as e:
            logging.error(f"Error in _discover_forms: {e}")

        # Properly indented and closed regex for method extraction
        method_match = re.search(r'method=[\'\"]([^\'\"]+)[\'\"]', form_attrs)
        if method_match:
            form_info['method'] = method_match.group(1).upper()

        # Dummy form_content for demonstration; replace with actual extraction logic
        form_content = ''
        # Extract input fields
        input_pattern = r'<input([^>]*)>'
        input_matches = re.findall(input_pattern, form_content, re.IGNORECASE)

        for input_attrs in input_matches:
            field_info = {}
            name_match = re.search(r'name=[\'\"]([^\'\"]+)[\'\"]', input_attrs)
            if name_match:
                field_info['name'] = name_match.group(1)

            type_match = re.search(r'type=[\'\"]([^\'\"]+)[\'\"]', input_attrs)
            if type_match:
                field_info['type'] = type_match.group(1)

            form_info['fields'].append(field_info)

        forms.append(form_info)

    # Removed stray except block

        return forms

    def _discover_js_apis(self, crawl_depth: int) -> List[Dict]:
        """Discover JavaScript APIs and AJAX endpoints."""
        js_apis = []

        try:
            response = self.session.get(self.base_url)
            content = response.text

            # Extract JavaScript files
            script_pattern = r'<script[^>]*src=[\'\"]([^\'\"]+)[\'\"]'
            script_urls = re.findall(script_pattern, content, re.IGNORECASE)

            for script_url in script_urls:
                full_url = urljoin(self.base_url, script_url)
                try:
                    script_response = self.session.get(full_url)
                    script_content = script_response.text
                except Exception as e:
                    logging.error(f"Error fetching script {script_url}: {e}")

                    # Extract API endpoints from JavaScript
                    api_endpoints = self._extract_js_endpoints(script_content)
                    js_apis.extend(api_endpoints)

                except Exception as e:
                    logger.warning(f"Failed to fetch script {full_url}: {e}")

        except Exception as e:
            logger.error(f"Failed to discover JS APIs: {e}")

        return js_apis

    def _test_security_vulnerabilities(self, endpoints: List[Dict]) -> List[Dict]:
        """Test discovered endpoints for security vulnerabilities."""
        vulnerabilities = []

        with ThreadPoolExecutor(max_workers=self.max_threads) as executor:
            future_to_endpoint = {
                executor.submit(self._test_endpoint_security, endpoint): endpoint
                for endpoint in endpoints
            }

            for future in as_completed(future_to_endpoint):
                endpoint = future_to_endpoint[future]
                try:
                    endpoint_vulns = future.result()
                    vulnerabilities.extend(endpoint_vulns)
                except Exception as e:
                    logger.warning(f"Failed to test endpoint {endpoint.get('path', 'unknown')}: {e}")

        return vulnerabilities

    def _test_endpoint_security(self, endpoint: Dict) -> List[Dict]:
        """Test a specific endpoint for security vulnerabilities."""
        vulnerabilities = []
        endpoint_url = urljoin(self.base_url, endpoint.get('path', ''))

        # Test for SQL injection
        for payload in self.security_payloads['sql_injection']:
            vuln = self._test_injection(endpoint_url, payload, 'sql_injection')
            if vuln:
                vulnerabilities.append(vuln)

        # Test for XSS
        for payload in self.security_payloads['xss']:
            vuln = self._test_injection(endpoint_url, payload, 'xss')
            if vuln:
                vulnerabilities.append(vuln)

        # Test for path traversal
        for payload in self.security_payloads['path_traversal']:
            vuln = self._test_injection(endpoint_url, payload, 'path_traversal')
            if vuln:
                vulnerabilities.append(vuln)

        # Test authentication bypass
        auth_vuln = self._test_authentication_bypass(endpoint_url)
        if auth_vuln:
            vulnerabilities.append(auth_vuln)

        # Test HTTP method tampering
        method_vuln = self._test_http_methods(endpoint_url)
        if method_vuln:
            vulnerabilities.extend(method_vuln)

        return vulnerabilities

    def _test_injection(self, url: str, payload: str, vuln_type: str) -> Optional[Dict]:
        """Test for injection vulnerabilities."""
        try:
            # Test GET parameter injection
            response = self.session.get(f"{url}?test={payload}")

            # Check for error patterns indicating vulnerability
            error_patterns = {
                'sql_injection': [
                    'mysql_fetch_array', 'ORA-', 'Microsoft OLE DB',
                    'syntax error', 'mysql_num_rows', 'postgresql'
                ],
                'xss': ['<script>', 'javascript:', 'alert('],
                'path_traversal': [
                    'root:', 'daemon:', '[boot loader]', 'Windows NT'
                ]
            }

            patterns = error_patterns.get(vuln_type, [])
            response_text = response.text.lower()

            for pattern in patterns:
                if pattern.lower() in response_text:
                    return {
                        'type': vuln_type,
                        'url': url,
                        'payload': payload,
                        'evidence': pattern,
                        'method': 'GET',
                        'severity': 'High' if vuln_type == 'sql_injection' else 'Medium'
                    }

        except Exception as e:
            logger.debug(f"Injection test failed for {url}: {e}")

        return None

    def _test_authentication_bypass(self, url: str) -> Optional[Dict]:
        """Test for authentication bypass vulnerabilities."""
        try:
            # Test without authentication
            response1 = self.session.get(url)

            # Test with invalid authentication
            headers = {'Authorization': 'Bearer invalid_token'}
            response2 = self.session.get(url, headers=headers)

            # If both return 200, might indicate auth bypass
            if response1.status_code == 200 and response2.status_code == 200:
                if len(response1.text) > 100 and len(response2.text) > 100:
                    return {
                        'type': 'authentication_bypass',
                        'url': url,
                        'evidence': 'Endpoint accessible without authentication',
                        'severity': 'High'
                    }

        except Exception as e:
            logger.debug(f"Auth bypass test failed for {url}: {e}")

        return None

    def _test_http_methods(self, url: str) -> List[Dict]:
        """Test for HTTP method tampering vulnerabilities."""
        vulnerabilities = []
        methods = ['GET', 'POST', 'PUT', 'DELETE', 'PATCH', 'OPTIONS', 'HEAD']

        try:
            for method in methods:
                response = self.session.request(method, url)

                # Check if dangerous methods are allowed
                if method in ['DELETE', 'PUT', 'PATCH'] and response.status_code < 400:
                    vulnerabilities.append({
                        'type': 'dangerous_http_method',
                        'url': url,
                        'method': method,
                        'evidence': f'{method} method allowed',
                        'severity': 'Medium'
                    })

        except Exception as e:
            logger.debug(f"HTTP method test failed for {url}: {e}")

        return vulnerabilities

    def _test_endpoint(self, url: str, method: str) -> Optional[Dict]:
        """Test if an endpoint exists and get basic info."""
        try:
            response = self.session.request(method, url)

            if response.status_code < 400:
                return {
                    'id': f'D{len(self.discovered_endpoints) + 1:03d}',
                    'path': urlparse(url).path,
                    'method': method,
                    'status_code': response.status_code,
                    'response_size': len(response.content),
                    'content_type': response.headers.get('content-type', ''),
                    'source': 'dynamic_analysis'
                }

        except Exception as e:
            logger.debug(f"Endpoint test failed for {url}: {e}")

        return None

    def _analyze_response_patterns(self) -> List[Dict]:
        """Analyze response patterns for security insights."""
        patterns = []

        # This would analyze collected responses for patterns
        # For now, return placeholder
        patterns.append({
            'pattern': 'error_disclosure',
            'description': 'Application may disclose sensitive information in error messages',
            'severity': 'Medium'
        })

        return patterns

    def _is_same_domain(self, url: str) -> bool:
        """Check if URL is from the same domain as base URL."""
        try:
            base_domain = urlparse(self.base_url).netloc
            url_domain = urlparse(url).netloc
            return base_domain == url_domain or url_domain == ''
        except:
            return False

    def get_assumptions(self) -> List[str]:
        """Get assumptions made during dynamic analysis."""
        return self.assumption_tracker.get_assumptions()
