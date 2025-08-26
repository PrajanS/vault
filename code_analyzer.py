"""
Enhanced Code Analyzer with aggressive endpoint detection for e-commerce applications.
"""
import os
import re
import logging
from typing import Dict, List, Set, Optional
from pathlib import Path
from utils import AssumptionTracker, find_files_by_extension, read_text_file

logger = logging.getLogger(__name__)

class CodeAnalyzer:
    """Enhanced code analyzer with aggressive endpoint detection."""

    def __init__(self):
        """Initialize enhanced code analyzer."""
        self.assumption_tracker = AssumptionTracker()
        self.endpoint_counter = 1
        self.detected_frameworks = set()
        self.detected_languages = set()

        # More aggressive patterns for e-commerce applications
        self.endpoint_patterns = self._get_aggressive_endpoint_patterns()

    def _get_aggressive_endpoint_patterns(self) -> Dict[str, List[Dict]]:
        """Get aggressive patterns for detecting endpoints in real applications."""
        return {
            'javascript': [
                # Express.js patterns (more permissive)
                {
                    'pattern': r'(?:app|router|server)\.(?:get|post|put|delete|patch|all|use)\s*\(\s*[\'\"]([^\'\"]+)[\'\"]',
                    'method_pattern': r'(?:app|router|server)\.(\w+)\s*\(',
                    'framework': 'express'
                },
                # Next.js API routes
                {
                    'file_pattern': r'/api/.*\.(?:js|ts)$',
                    'framework': 'nextjs'
                },
                # Generic route definitions
                {
                    'pattern': r'route\s*\(?[\'\"]([^\'\"]+)[\'\"]',
                    'framework': 'generic'
                },
                # URL patterns (more aggressive)
                {
                    'pattern': r'[\'\"]\s*(/[a-zA-Z0-9/_\-\.:]+)\s*[\'\"]',
                    'filter': lambda match: self._is_likely_endpoint(match),
                    'framework': 'url_pattern'
                },
                # API endpoint patterns
                {
                    'pattern': r'[\'\"](/api/[^\'\"]+)[\'\"]',
                    'framework': 'api_pattern'
                },
                # Fetch/axios patterns
                {
                    'pattern': r'(?:fetch|axios|\$\.(?:get|post))\s*\(\s*[\'\"]([^\'\"]+)[\'\"]',
                    'framework': 'client_request'
                }
            ],
            'python': [
                # Flask patterns (enhanced)
                {
                    'pattern': r'@(?:app|bp|blueprint)\.route\s*\(\s*[\'\"]([^\'\"]+)[\'\"]',
                    'method_pattern': r'methods\s*=\s*\[[\'\"]([^\'\"]+)[\'\"]',
                    'framework': 'flask'
                },
                # Django patterns (enhanced)
                {
                    'pattern': r'(?:path|url|re_path)\s*\(\s*[\'\"]([^\'\"]+)[\'\"]',
                    'framework': 'django'
                },
                # FastAPI patterns
                {
                    'pattern': r'@(?:app|router)\.(?:get|post|put|delete|patch)\s*\(\s*[\'\"]([^\'\"]+)[\'\"]',
                    'method_pattern': r'@(?:app|router)\.(\w+)\s*\(',
                    'framework': 'fastapi'
                },
                # Generic URL patterns
                {
                    'pattern': r'[\'\"]\s*(/[a-zA-Z0-9/_\-\.\{\}]+)\s*[\'\"]',
                    'filter': lambda match: self._is_likely_endpoint(match),
                    'framework': 'python_url'
                }
            ],
            'php': [
                # Laravel routes
                {
                    'pattern': r'Route::(?:get|post|put|delete|patch|any|match)\s*\(\s*[\'\"]([^\'\"]+)[\'\"]',
                    'method_pattern': r'Route::(\w+)\s*\(',
                    'framework': 'laravel'
                },
                # Generic PHP patterns
                {
                    'pattern': r'\$_(?:GET|POST|REQUEST)\s*\[[\'\"]([^\'\"]+)[\'\"]\]',
                    'framework': 'php_superglobal'
                }
            ],
            'java': [
                # Spring Boot annotations
                {
                    'pattern': r'@(?:RequestMapping|GetMapping|PostMapping|PutMapping|DeleteMapping|PatchMapping)\s*\(\s*(?:[^\)]*value\s*=\s*)?[\'\"]([^\'\"]+)[\'\"]',
                    'method_pattern': r'@(\w+Mapping)',
                    'framework': 'spring'
                },
                # JAX-RS annotations
                {
                    'pattern': r'@Path\s*\(\s*[\'\"]([^\'\"]+)[\'\"]',
                    'framework': 'jaxrs'
                }
            ]
        }

    def _is_likely_endpoint(self, path: str) -> bool:
        """Enhanced check if path looks like an endpoint."""
        if not path or len(path) < 2:
            return False

        # Must start with /
        if not path.startswith('/'):
            return False

        # Skip static files
        static_extensions = ['.css', '.js', '.png', '.jpg', '.jpeg', '.gif', '.svg', '.ico', '.woff', '.ttf', '.html', '.xml']
        if any(path.lower().endswith(ext) for ext in static_extensions):
            return False

        # Skip build/config paths
        skip_patterns = [
            'node_modules', 'webpack', 'babel', '.git', 'dist/', 'build/',
            '.env', 'package.json', 'yarn.lock', 'npm'
        ]
        if any(pattern in path.lower() for pattern in skip_patterns):
            return False

        # Likely endpoint patterns
        likely_patterns = [
            r'^/api/',           # API endpoints
            r'^/auth/',          # Authentication
            r'^/admin/',         # Admin panels
            r'^/user/',          # User operations
            r'^/product/',       # Product operations
            r'^/order/',         # Order operations
            r'^/cart/',          # Cart operations
            r'^/payment/',       # Payment operations
            r'^/search/',        # Search functionality
            r'/\{[^}]+\}',      # Path parameters
            r'/:\w+',           # Express-style params
        ]

        if any(re.search(pattern, path, re.IGNORECASE) for pattern in likely_patterns):
            return True

        # General endpoint characteristics
        if len(path) >= 3 and '/' in path[1:] and not path.endswith('/'):
            return True

        return False

    def analyze_directory(self, directory_path: str) -> Dict:
        """Analyze directory with aggressive endpoint detection."""
        logger.info(f"Starting aggressive code analysis of: {directory_path}")

        if not os.path.exists(directory_path):
            logger.error(f"Directory not found: {directory_path}")
            self.assumption_tracker.add_assumption(f"Code directory not found: {directory_path}")
            return self._empty_analysis_result()

        # Find ALL code files (more inclusive)
        code_files = self._find_all_code_files(directory_path)

        if not code_files:
            logger.warning(f"No code files found in: {directory_path}")
            self.assumption_tracker.add_assumption("No code files found")
            return self._empty_analysis_result()

        logger.info(f"Found {len(code_files)} code files to analyze")

        # Analyze files with multiple strategies
        all_endpoints = []
        files_with_endpoints = 0

        # Strategy 1: Pattern-based detection
        for file_path in code_files:
            try:
                file_endpoints = self._analyze_file_patterns(file_path)
                if file_endpoints:
                    all_endpoints.extend(file_endpoints)
                    files_with_endpoints += 1
                    logger.debug(f"Pattern detection: {len(file_endpoints)} endpoints in {os.path.basename(file_path)}")
            except Exception as e:
                logger.debug(f"Pattern analysis error in {file_path}: {e}")
                continue

        # Strategy 2: Generic string detection (if pattern detection finds few endpoints)
        if len(all_endpoints) < 5:
            logger.info("Few endpoints found with patterns, running generic string detection...")
            generic_endpoints = self._generic_string_detection(code_files)
            all_endpoints.extend(generic_endpoints)

        # Strategy 3: File-based inference (for frameworks like Next.js)
        file_based_endpoints = self._infer_endpoints_from_file_structure(directory_path)
        all_endpoints.extend(file_based_endpoints)

        # Process and clean endpoints
        processed_endpoints = self._process_and_enhance_endpoints(all_endpoints)

        # Add fallback e-commerce endpoints if still too few
        if len(processed_endpoints) < 3:
            logger.info("Adding e-commerce fallback endpoints...")
            processed_endpoints.extend(self._get_ecommerce_fallback_endpoints())
            self.assumption_tracker.add_assumption("Added fallback e-commerce endpoints due to low detection")

        # Detect technologies
        self._detect_technologies_from_files(code_files)

        logger.info(f"Aggressive analysis complete: {len(processed_endpoints)} endpoints found from {files_with_endpoints} files")

        return {
            'endpoints': processed_endpoints,
            'files_analyzed': files_with_endpoints,
            'total_files_found': len(code_files),
            'languages_detected': sorted(list(self.detected_languages)),
            'framework_hints': sorted(list(self.detected_frameworks)),
            'endpoint_summary': self._generate_endpoint_summary(processed_endpoints)
        }

    def _find_all_code_files(self, directory_path: str) -> List[str]:
        """Find ALL code files with minimal filtering."""

        extensions = ['.js', '.ts', '.py', '.java', '.php', '.rb', '.jsx', '.tsx', '.vue', '.go', '.cs']
        all_files = find_files_by_extension(directory_path, extensions)

        # Less aggressive filtering
        code_files = []
        for file_path in all_files:
            if self._should_analyze_file(file_path):
                code_files.append(file_path)

                # Track language
                ext = Path(file_path).suffix.lower()
                if ext in ['.js', '.jsx', '.ts', '.tsx']:
                    self.detected_languages.add('JavaScript/TypeScript')
                elif ext == '.py':
                    self.detected_languages.add('Python')
                elif ext == '.java':
                    self.detected_languages.add('Java')
                elif ext == '.php':
                    self.detected_languages.add('PHP')
                elif ext == '.rb':
                    self.detected_languages.add('Ruby')
                elif ext == '.vue':
                    self.detected_languages.add('Vue.js')

        return code_files[:300]  # Increased limit

    def _should_analyze_file(self, file_path: str) -> bool:
        """Minimal filtering - analyze most files."""
        file_path_lower = file_path.lower()
        filename = os.path.basename(file_path_lower)

        # Skip obvious non-source files
        skip_patterns = [
            '/node_modules/', '/vendor/', '/.git/', '/dist/', '/build/',
            '.min.js', '.min.css', 'package-lock.json', 'yarn.lock'
        ]

        if any(pattern in file_path_lower for pattern in skip_patterns):
            return False

        # Skip if file is too large (might be minified)
        try:
            if os.path.getsize(file_path) > 1024 * 1024:  # 1MB limit
                return False
        except:
            pass

        return True

    def _analyze_file_patterns(self, file_path: str) -> List[Dict]:
        """Analyze file with all available patterns."""
        endpoints = []

        content = read_text_file(file_path, max_size=500*1024)  # 500KB limit
        if not content or len(content.strip()) < 10:
            return []

        # Detect language
        language = self._detect_language_from_file(file_path, content)
        if not language:
            return []

        # Apply all patterns for this language
        patterns = self.endpoint_patterns.get(language, [])

        for pattern_config in patterns:
            try:
                file_endpoints = self._extract_endpoints_from_pattern(
                    content, file_path, pattern_config, language
                )
                endpoints.extend(file_endpoints)

                if pattern_config.get('framework'):
                    self.detected_frameworks.add(pattern_config['framework'])

            except Exception as e:
                logger.debug(f"Pattern error in {file_path}: {e}")
                continue

        return endpoints

    def _generic_string_detection(self, code_files: List[str]) -> List[Dict]:
        """Aggressive generic endpoint detection."""
        endpoints = []

        logger.info("Running aggressive generic endpoint detection...")

        # More comprehensive URL patterns
        url_patterns = [
            r'[\'\"]\s*(/api/[^\'\"\s]+)\s*[\'\"]',       # API endpoints
            r'[\'\"]\s*(/auth/[^\'\"\s]+)\s*[\'\"]',      # Auth endpoints
            r'[\'\"]\s*(/admin/[^\'\"\s]+)\s*[\'\"]',     # Admin endpoints
            r'[\'\"]\s*(/user/[^\'\"\s]+)\s*[\'\"]',      # User endpoints
            r'[\'\"]\s*(/product/[^\'\"\s]+)\s*[\'\"]',   # Product endpoints
            r'[\'\"]\s*(/order/[^\'\"\s]+)\s*[\'\"]',     # Order endpoints
            r'[\'\"]\s*(/cart/[^\'\"\s]+)\s*[\'\"]',      # Cart endpoints
            r'[\'\"]\s*(/payment/[^\'\"\s]+)\s*[\'\"]',   # Payment endpoints
            r'[\'\"]\s*(/search[^\'\"\s]*)\s*[\'\"]',     # Search endpoints
            r'[\'\"]\s*(/v\d+/[^\'\"\s]+)\s*[\'\"]',     # Versioned APIs
            r'[\'\"]\s*(/[a-zA-Z][^\'\"\s]{2,})\s*[\'\"]' # Generic paths
        ]

        for file_path in code_files[:100]:  # Limit for performance
            content = read_text_file(file_path, max_size=200*1024)
            if not content:
                continue

            for pattern in url_patterns:
                try:
                    matches = re.findall(pattern, content, re.IGNORECASE)
                    for match in matches:
                        clean_path = match.strip()
                        if self._is_likely_endpoint(clean_path):
                            endpoints.append(self._create_endpoint_dict(
                                clean_path, 'GET', file_path, 'generic_detection'
                            ))
                except Exception as e:
                    logger.debug(f"Generic detection error: {e}")
                    continue

        # Deduplicate
        seen_paths = set()
        unique_endpoints = []
        for endpoint in endpoints:
            path = endpoint['path']
            if path not in seen_paths:
                seen_paths.add(path)
                unique_endpoints.append(endpoint)

        logger.info(f"Generic detection found {len(unique_endpoints)} unique endpoints")
        return unique_endpoints

    def _infer_endpoints_from_file_structure(self, directory_path: str) -> List[Dict]:
        """Infer endpoints from file/folder structure (Next.js, etc.)."""
        endpoints = []

        try:
            # Look for API directory structure
            api_dirs = []
            for root, dirs, files in os.walk(directory_path):
                if 'api' in dirs:
                    api_dirs.append(os.path.join(root, 'api'))

            for api_dir in api_dirs:
                for root, dirs, files in os.walk(api_dir):
                    for file in files:
                        if file.endswith(('.js', '.ts')) and not file.startswith('.'):
                            file_path = os.path.join(root, file)
                            relative_path = os.path.relpath(file_path, api_dir)

                            # Convert file path to endpoint
                            endpoint_path = '/' + relative_path.replace('\\', '/').replace('.js', '').replace('.ts', '')
                            if not endpoint_path.startswith('/api'):
                                endpoint_path = '/api' + endpoint_path

                            endpoints.append(self._create_endpoint_dict(
                                endpoint_path, 'GET', file_path, 'file_structure'
                            ))

        except Exception as e:
            logger.debug(f"File structure inference error: {e}")

        return endpoints

    def _get_ecommerce_fallback_endpoints(self) -> List[Dict]:
        """Get fallback e-commerce endpoints."""
        fallback_endpoints = [
            {'path': '/api/auth/login', 'method': 'POST', 'framework': 'ecommerce_fallback'},
            {'path': '/api/auth/register', 'method': 'POST', 'framework': 'ecommerce_fallback'},
            {'path': '/api/auth/logout', 'method': 'POST', 'framework': 'ecommerce_fallback'},
            {'path': '/api/products', 'method': 'GET', 'framework': 'ecommerce_fallback'},
            {'path': '/api/products/search', 'method': 'GET', 'framework': 'ecommerce_fallback'},
            {'path': '/api/cart', 'method': 'GET', 'framework': 'ecommerce_fallback'},
            {'path': '/api/cart/add', 'method': 'POST', 'framework': 'ecommerce_fallback'},
            {'path': '/api/orders', 'method': 'POST', 'framework': 'ecommerce_fallback'},
            {'path': '/api/payment/process', 'method': 'POST', 'framework': 'ecommerce_fallback'},
            {'path': '/api/user/profile', 'method': 'GET', 'framework': 'ecommerce_fallback'},
            {'path': '/admin/dashboard', 'method': 'GET', 'framework': 'ecommerce_fallback'},
            {'path': '/admin/products', 'method': 'GET', 'framework': 'ecommerce_fallback'}
        ]

        processed_fallbacks = []
        for i, endpoint in enumerate(fallback_endpoints):
            processed_fallbacks.append({
                'id': f'E{self.endpoint_counter + i:03d}',
                'path': endpoint['path'],
                'method': endpoint['method'],
                'framework': endpoint['framework'],
                'file': 'fallback',
                'file_path': 'ecommerce_fallback',
                'auth_required': 'likely' if any(term in endpoint['path'] for term in ['auth', 'admin', 'profile', 'orders', 'payment']) else 'unknown',
                'has_parameters': False,
                'source': 'fallback_ecommerce'
            })

        self.endpoint_counter += len(fallback_endpoints)
        return processed_fallbacks

    def _process_and_enhance_endpoints(self, endpoints: List[Dict]) -> List[Dict]:
        """Process and enhance detected endpoints."""
        if not endpoints:
            return []

        # Deduplicate by path
        seen_paths = set()
        deduplicated = []

        for endpoint in endpoints:
            path = endpoint.get('path', '')
            if path and path not in seen_paths:
                seen_paths.add(path)
                deduplicated.append(endpoint)

        # Sort by priority
        def endpoint_priority(ep):
            path = ep.get('path', '').lower()
            score = 0

            # High priority keywords
            high_priority = ['api', 'auth', 'admin', 'payment', 'order', 'cart', 'user', 'product']
            for keyword in high_priority:
                if keyword in path:
                    score += 10

            # HTTP method priority
            if ep.get('method') in ['POST', 'PUT', 'DELETE', 'PATCH']:
                score += 5

            # Path depth (more specific endpoints get higher priority)
            score += path.count('/')

            return score

        sorted_endpoints = sorted(deduplicated, key=endpoint_priority, reverse=True)

        # Take top endpoints and assign IDs
        final_endpoints = sorted_endpoints[:50]  # Max 50 endpoints

        for i, endpoint in enumerate(final_endpoints):
            endpoint['id'] = f'E{i+1:03d}'

        self.endpoint_counter = len(final_endpoints) + 1

        logger.info(f"Processed {len(endpoints)} raw endpoints into {len(final_endpoints)} final endpoints")
        return final_endpoints

    # Include necessary helper methods from previous version
    def _detect_language_from_file(self, file_path: str, content: str) -> Optional[str]:
        """Detect language from file and content."""
        ext = Path(file_path).suffix.lower()

        ext_to_lang = {
            '.js': 'javascript', '.jsx': 'javascript', '.ts': 'javascript', '.tsx': 'javascript',
            '.py': 'python', '.java': 'java', '.php': 'php', '.rb': 'ruby'
        }

        return ext_to_lang.get(ext)

    def _extract_endpoints_from_pattern(self, content: str, file_path: str, 
                                       pattern_config: Dict, language: str) -> List[Dict]:
        """Extract endpoints using pattern configuration."""
        endpoints = []

        # Handle file-pattern detection
        if 'file_pattern' in pattern_config:
            if re.search(pattern_config['file_pattern'], file_path.replace('\\', '/')):
                api_match = re.search(r'/api/(.+)\.(?:js|ts)$', file_path.replace('\\', '/'))
                if api_match:
                    route_path = '/api/' + api_match.group(1)
                    methods = ['GET', 'POST']  # Default methods

                    for method in methods:
                        endpoints.append(self._create_endpoint_dict(
                            route_path, method, file_path, pattern_config.get('framework', language)
                        ))

        # Handle regex-based detection
        else:
            pattern = pattern_config['pattern']
            filter_func = pattern_config.get('filter')

            matches = re.finditer(pattern, content, re.IGNORECASE | re.MULTILINE)

            for match in matches:
                try:
                    route_path = match.group(1).strip()

                    if filter_func and not filter_func(route_path):
                        continue

                    if not self._is_valid_route_path(route_path):
                        continue

                    # Extract method
                    method = 'GET'
                    method_pattern = pattern_config.get('method_pattern')
                    if method_pattern:
                        method_match = re.search(method_pattern, match.group(0), re.IGNORECASE)
                        if method_match:
                            method = self._normalize_http_method(method_match.group(1))

                    endpoints.append(self._create_endpoint_dict(
                        route_path, method, file_path, pattern_config.get('framework', language)
                    ))

                except Exception as e:
                    logger.debug(f"Error processing match: {e}")
                    continue

        return endpoints

    def _is_valid_route_path(self, path: str) -> bool:
        """Check if path is a valid route."""
        if not path or len(path) < 2:
            return False

        static_extensions = ['.css', '.js', '.png', '.jpg', '.jpeg', '.gif', '.svg', '.ico']
        if any(path.lower().endswith(ext) for ext in static_extensions):
            return False

        return True

    def _normalize_http_method(self, method_str: str) -> str:
        """Normalize HTTP method string."""
        method = method_str.upper().strip()
        if method.endswith('MAPPING'):
            method = method[:-7]
        return method if method in ['GET', 'POST', 'PUT', 'DELETE', 'PATCH'] else 'GET'

    def _create_endpoint_dict(self, path: str, method: str, file_path: str, framework: str) -> Dict:
        """Create endpoint dictionary."""
        clean_path = path.strip()
        if not clean_path.startswith('/'):
            clean_path = '/' + clean_path

        auth_indicators = ['admin', 'auth', 'login', 'user', 'profile', 'dashboard']
        auth_required = any(indicator in clean_path.lower() for indicator in auth_indicators)

        has_params = any(char in clean_path for char in [':', '{', '<'])

        return {
            'id': f'E{self.endpoint_counter:03d}',
            'path': clean_path,
            'method': method.upper(),
            'framework': framework,
            'file': os.path.basename(file_path),
            'file_path': file_path,
            'auth_required': 'likely' if auth_required else 'unknown',
            'has_parameters': has_params,
            'source': 'static_analysis'
        }

    def _detect_technologies_from_files(self, code_files: List[str]) -> None:
        """Detect technologies from files."""
        for file_path in code_files[:20]:
            filename = os.path.basename(file_path).lower()

            if 'package.json' in filename:
                self.detected_frameworks.add('Node.js')
            elif 'requirements.txt' in filename or 'setup.py' in filename:
                self.detected_frameworks.add('Python')

    def _generate_endpoint_summary(self, endpoints: List[Dict]) -> Dict:
        """Generate endpoint summary."""
        if not endpoints:
            return {'total_endpoints': 0}

        methods = {}
        frameworks = {}

        for endpoint in endpoints:
            method = endpoint.get('method', 'GET')
            methods[method] = methods.get(method, 0) + 1

            framework = endpoint.get('framework', 'unknown')
            frameworks[framework] = frameworks.get(framework, 0) + 1

        return {
            'total_endpoints': len(endpoints),
            'methods_breakdown': methods,
            'frameworks_breakdown': frameworks,
            'sample_endpoints': [ep['path'] for ep in endpoints[:10]]
        }

    def _empty_analysis_result(self) -> Dict:
        """Return empty analysis result."""
        return {
            'endpoints': [],
            'files_analyzed': 0,
            'total_files_found': 0,
            'languages_detected': [],
            'framework_hints': [],
            'endpoint_summary': {'total_endpoints': 0}
        }

    def get_assumptions(self) -> List[str]:
        """Get all assumptions."""
        return self.assumption_tracker.get_assumptions()
