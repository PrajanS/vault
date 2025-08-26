"""
Fixed LLM Client with robust JSON parsing for security test generation.
"""
import os
import json
import logging
import requests
import re
from typing import Dict, List, Optional
from utils import AssumptionTracker

logger = logging.getLogger(__name__)

class LLMClient:
    """Fixed LLM client with robust JSON parsing."""

    def __init__(self):
        """Initialize LLM client with proper authentication."""
        self.assumption_tracker = AssumptionTracker()
        self.api_key = self._get_api_key()
        self.model = self._get_model()
        self.base_url = self._get_base_url()

        if not self.api_key:
            logger.warning("No LLM API key found - template-based generation will be used")
            self.assumption_tracker.add_assumption("No LLM API key configured")

    def _get_api_key(self) -> Optional[str]:
        """Get API key from environment variables."""
        api_keys = [
            'OPENROUTER_API_KEY',
            'CLAUDE_API_KEY',
            'LLM_API_KEY', 
            'GEMINI_API_KEY'
        ]

        for key_var in api_keys:
            api_key = os.getenv(key_var)
            if api_key and len(api_key.strip()) > 10:
                logger.info(f"Using API key from {key_var}")
                return api_key.strip()

        return None

    def _get_model(self) -> str:
        """Get model from environment or use default."""
        model = os.getenv('LLM_MODEL', '').strip()

        if not model:
            if os.getenv('CLAUDE_API_KEY'):
                if os.getenv('OPENROUTER_API_KEY'):
                    model = 'anthropic/claude-3.5-sonnet'
                else:
                    model = 'claude-3-5-sonnet-20241022'
            elif os.getenv('GEMINI_API_KEY'):
                model = 'gemini-1.5-pro'
            elif os.getenv('OPENROUTER_API_KEY'):
                model = 'anthropic/claude-3.5-sonnet'
            else:
                model = 'anthropic/claude-3.5-sonnet'

        return model

    def _get_base_url(self) -> str:
        """Get appropriate base URL based on API key."""
        if os.getenv('OPENROUTER_API_KEY'):
            return 'https://openrouter.ai/api/v1'
        elif os.getenv('CLAUDE_API_KEY') and not os.getenv('OPENROUTER_API_KEY'):
            return 'https://api.anthropic.com/v1'
        elif os.getenv('GEMINI_API_KEY'):
            return 'https://generativelanguage.googleapis.com/v1beta'
        else:
            return 'https://openrouter.ai/api/v1'

    def generate_comprehensive_security_tests(self, endpoints: List[Dict], vulnerabilities: List[Dict]) -> List[Dict]:
        """Generate focused security test cases with robust JSON parsing."""

        if not self.api_key:
            logger.info("No API key available - skipping LLM security test generation")
            return []

        try:
            context = self._prepare_security_context(endpoints[:10], vulnerabilities[:8])

            # Simplified prompt that's more likely to produce valid JSON
            prompt = f"""Generate security test cases for this application.

APPLICATION CONTEXT:
{context}

Generate exactly 15 security test cases in valid JSON format. Each test should focus on a specific OWASP Top 10 vulnerability.

Return ONLY a JSON array with this exact structure:
[
  {{
    "title": "Test SQL injection in login endpoint",
    "category": "security",
    "owasp_category": "A03",
    "severity": "High",
    "steps": [
      "Navigate to login endpoint",
      "Input SQL injection payload in username field",
      "Submit form and analyze response",
      "Verify application properly sanitizes input"
    ],
    "expected_result": "Application should reject malicious SQL and display generic error",
    "automation_level": "high"
  }}
]

Provide exactly 15 test cases in valid JSON format:"""

            response_text = self._make_llm_request(prompt)
            if response_text:
                return self._robust_parse_test_response(response_text, max_tests=20)

        except Exception as e:
            logger.error(f"Security test generation failed: {e}")
            self.assumption_tracker.add_assumption(f"LLM security test generation failed: {str(e)}")

        return []

    def generate_business_logic_tests(self, endpoints: List[Dict], business_rules: List[Dict]) -> List[Dict]:
        """Generate focused business logic test cases."""

        if not self.api_key or not business_rules:
            logger.info("Skipping business logic test generation")
            return []

        try:
            context = self._prepare_business_context(endpoints[:8], business_rules[:6])

            # Simplified prompt for business logic
            prompt = f"""Generate business logic test cases for this e-commerce application.

BUSINESS CONTEXT:
{context}

Generate exactly 10 business logic test cases in valid JSON format.

Return ONLY a JSON array with this structure:
[
  {{
    "title": "Test product purchase workflow",
    "category": "business_logic",
    "severity": "Medium",
    "steps": [
      "Add product to cart",
      "Navigate to checkout",
      "Complete payment process",
      "Verify order confirmation"
    ],
    "expected_result": "Order should be created successfully with correct details",
    "automation_level": "medium"
  }}
]

Provide exactly 10 test cases in valid JSON format:"""

            response_text = self._make_llm_request(prompt)
            if response_text:
                return self._robust_parse_test_response(response_text, max_tests=15)

        except Exception as e:
            logger.error(f"Business logic test generation failed: {e}")
            self.assumption_tracker.add_assumption(f"LLM business test generation failed: {str(e)}")

        return []

    def extract_app_features(self, combined_text: str) -> Dict:
        """Extract app features with robust JSON parsing."""

        if not self.api_key:
            logger.info("No API key available - using fallback app features")
            return self._get_fallback_features()

        try:
            limited_text = combined_text[:3000] if len(combined_text) > 3000 else combined_text

            prompt = f"""Analyze this application and extract key information.

APPLICATION DATA:
{limited_text}

Return ONLY valid JSON with this exact structure:
{{
  "name": "E-commerce Application",
  "purpose": "Online shopping platform",
  "major_features": ["User registration", "Product catalog", "Shopping cart"],
  "critical_business_rules": [
    {{"id": "BR001", "description": "Users must authenticate to access checkout"}},
    {{"id": "BR002", "description": "Payment information must be validated"}}
  ],
  "technology_stack": ["JavaScript", "Node.js"],
  "security_features": ["Authentication", "Input validation"]
}}

Provide valid JSON only:"""

            response_text = self._make_llm_request(prompt)
            if response_text:
                return self._robust_parse_app_features(response_text)

        except Exception as e:
            logger.error(f"App feature extraction failed: {e}")
            self.assumption_tracker.add_assumption(f"LLM app feature extraction failed: {str(e)}")

        return self._get_fallback_features()

    def _robust_parse_test_response(self, response_text: str, max_tests: int = 30) -> List[Dict]:
        """Robust parsing of LLM test response with multiple fallback strategies."""

        # Strategy 1: Direct JSON parsing
        try:
            json_match = self._extract_json_from_text(response_text)
            if json_match:
                tests = json.loads(json_match)
                if isinstance(tests, list):
                    return self._validate_and_clean_tests(tests, max_tests)
        except json.JSONDecodeError:
            pass

        # Strategy 2: Fix common JSON issues and retry
        try:
            fixed_json = self._fix_common_json_issues(response_text)
            if fixed_json:
                tests = json.loads(fixed_json)
                if isinstance(tests, list):
                    return self._validate_and_clean_tests(tests, max_tests)
        except json.JSONDecodeError:
            pass

        # Strategy 3: Extract individual test objects
        try:
            individual_tests = self._extract_individual_test_objects(response_text)
            if individual_tests:
                return self._validate_and_clean_tests(individual_tests, max_tests)
        except Exception:
            pass

        # Strategy 4: Parse as text and convert to structured format
        try:
            text_tests = self._parse_as_structured_text(response_text)
            if text_tests:
                return self._validate_and_clean_tests(text_tests, max_tests)
        except Exception:
            pass

        logger.warning("All JSON parsing strategies failed for LLM response")
        logger.debug(f"Response text: {response_text[:200]}...")
        return []

    def _extract_json_from_text(self, text: str) -> Optional[str]:
        """Extract JSON array from text."""
        # Find JSON array bounds
        start_idx = text.find('[')
        if start_idx == -1:
            return None

        # Find matching closing bracket
        bracket_count = 0
        end_idx = -1

        for i in range(start_idx, len(text)):
            if text[i] == '[':
                bracket_count += 1
            elif text[i] == ']':
                bracket_count -= 1
                if bracket_count == 0:
                    end_idx = i + 1
                    break

        if end_idx == -1:
            end_idx = text.rfind(']') + 1

        if start_idx >= 0 and end_idx > start_idx:
            return text[start_idx:end_idx]

        return None

    def _fix_common_json_issues(self, text: str) -> Optional[str]:
        """Fix common JSON formatting issues."""
        json_text = self._extract_json_from_text(text)
        if not json_text:
            return None

        # Common fixes
        fixes = [
            # Remove trailing commas
            (r',\s*}', '}'),
            (r',\s*]', ']'),
            # Fix quotes
            (r'([{,]\s*)(\w+):', r'\1"\2":'),
            # Fix multiline strings
            (r'"([^"]*\n[^"]*)"', lambda m: '"' + m.group(1).replace('\n', ' ').strip() + '"'),
            # Remove comments
            (r'//.*?\n', ''),
            (r'/\*.*?\*/', ''),
        ]

        fixed_text = json_text
        for pattern, replacement in fixes:
            fixed_text = re.sub(pattern, replacement, fixed_text, flags=re.MULTILINE | re.DOTALL)

        return fixed_text

    def _extract_individual_test_objects(self, text: str) -> List[Dict]:
        """Extract individual test objects from malformed JSON."""
        tests = []

        # Look for individual test objects
        object_pattern = r'{[^{}]*"title"[^{}]*}'
        matches = re.findall(object_pattern, text, re.DOTALL)

        for match in matches:
            try:
                # Try to parse individual object
                fixed_match = self._fix_common_json_issues(match)
                if fixed_match:
                    test_obj = json.loads(fixed_match)
                    tests.append(test_obj)
            except:
                continue

        return tests

    def _parse_as_structured_text(self, text: str) -> List[Dict]:
        """Parse response as structured text when JSON fails."""
        tests = []

        # Look for test patterns in text
        test_patterns = [
            r'(?i)test[^\n]*:?\s*([^\n]+)',
            r'(?i)title[^\n]*:?\s*([^\n]+)',
            r'(?i)\d+\.\s*([^\n]+)'
        ]

        test_count = 0
        for pattern in test_patterns:
            matches = re.findall(pattern, text)
            for match in matches[:10]:  # Limit matches
                if len(match.strip()) > 10:  # Valid test name
                    test_count += 1
                    tests.append({
                        'title': match.strip()[:100],
                        'category': 'security',
                        'severity': 'Medium',
                        'steps': ['Execute security test', 'Analyze results', 'Verify security controls'],
                        'expected_result': 'Application should demonstrate secure behavior',
                        'automation_level': 'medium',
                        'owasp_category': 'A03'
                    })

                    if test_count >= 10:
                        break

            if test_count >= 10:
                break

        return tests

    def _validate_and_clean_tests(self, tests: List[Dict], max_tests: int) -> List[Dict]:
        """Validate and clean test cases."""
        valid_tests = []

        for test in tests[:max_tests]:
            if not isinstance(test, dict):
                continue

            # Ensure required fields
            if not test.get('title'):
                continue

            # Set defaults for missing fields
            test.setdefault('category', 'security')
            test.setdefault('severity', 'Medium')
            test.setdefault('automation_level', 'medium')
            test.setdefault('owasp_category', 'A03')

            # Ensure steps is a list
            if not isinstance(test.get('steps'), list):
                test['steps'] = ['Execute test case', 'Analyze results', 'Verify expected behavior']

            # Limit step length
            test['steps'] = [str(step)[:100] for step in test['steps'][:4]]

            # Set expected result if missing
            if not test.get('expected_result'):
                test['expected_result'] = 'Application should demonstrate secure behavior'

            valid_tests.append(test)

        logger.info(f"Validated {len(valid_tests)} tests from LLM response")
        return valid_tests

    def _robust_parse_app_features(self, response_text: str) -> Dict:
        """Robust parsing of app features response."""

        # Try direct JSON parsing
        try:
            json_text = self._extract_json_from_text(response_text)
            if not json_text:
                # Look for object instead of array
                start_idx = response_text.find('{')
                end_idx = response_text.rfind('}') + 1
                if start_idx >= 0 and end_idx > start_idx:
                    json_text = response_text[start_idx:end_idx]

            if json_text:
                features = json.loads(json_text)
                return self._validate_app_features(features)
        except:
            pass

        # Try fixing common issues
        try:
            fixed_text = self._fix_common_json_issues(response_text)
            if fixed_text:
                features = json.loads(fixed_text)
                return self._validate_app_features(features)
        except:
            pass

        logger.warning("Failed to parse app features from LLM response")
        return self._get_fallback_features()

    def _validate_app_features(self, features: Dict) -> Dict:
        """Validate and clean app features."""
        if not isinstance(features, dict):
            return self._get_fallback_features()

        # Set defaults
        features.setdefault('name', 'E-commerce Application')
        features.setdefault('purpose', 'E-commerce platform for online shopping')
        features.setdefault('major_features', [])
        features.setdefault('critical_business_rules', [])
        features.setdefault('technology_stack', [])
        features.setdefault('security_features', [])

        # Ensure business rules have correct format
        if isinstance(features.get('critical_business_rules'), list):
            rules = []
            for i, rule in enumerate(features['critical_business_rules'][:8]):
                if isinstance(rule, dict) and rule.get('description'):
                    rules.append(rule)
                elif isinstance(rule, str):
                    rules.append({'id': f'BR{i+1:03d}', 'description': rule})
            features['critical_business_rules'] = rules

        return features

    def _make_llm_request(self, prompt: str) -> Optional[str]:
        """Make API request with proper authentication."""
        try:
            headers = self._get_request_headers()
            data = self._get_request_data(prompt)
            url = self._get_request_url()

            logger.debug(f"Making request to {url} with model {self.model}")

            response = requests.post(
                url, 
                headers=headers, 
                json=data, 
                timeout=90
            )

            if response.status_code == 200:
                return self._extract_response_content(response.json())
            else:
                logger.error(f"API request failed: {response.status_code} - {response.text}")
                return None

        except Exception as e:
            logger.error(f"LLM request error: {e}")
            return None

    def _get_request_headers(self) -> Dict[str, str]:
        """Get appropriate request headers based on API."""
        headers = {'Content-Type': 'application/json'}

        if 'anthropic.com' in self.base_url:
            headers['x-api-key'] = self.api_key
            headers['anthropic-version'] = '2023-06-01'
        elif 'openrouter.ai' in self.base_url:
            headers['Authorization'] = f'Bearer {self.api_key}'
            headers['HTTP-Referer'] = 'https://ai-static-analyzer.com'
            headers['X-Title'] = 'AI Static Analysis Tool'
        elif 'googleapis.com' in self.base_url:
            headers['Authorization'] = f'Bearer {self.api_key}'
        else:
            headers['Authorization'] = f'Bearer {self.api_key}'

        return headers

    def _get_request_data(self, prompt: str) -> Dict:
        """Get appropriate request data based on API."""
        if 'anthropic.com' in self.base_url:
            return {
                'model': self.model,
                'max_tokens': 2000,
                'messages': [{'role': 'user', 'content': prompt}]
            }
        elif 'googleapis.com' in self.base_url:
            return {
                'contents': [{'parts': [{'text': prompt}]}]
            }
        else:
            return {
                'model': self.model,
                'messages': [{'role': 'user', 'content': prompt}],
                'max_tokens': 2000,
                'temperature': 0.3
            }

    def _get_request_url(self) -> str:
        """Get appropriate request URL based on API."""
        if 'anthropic.com' in self.base_url:
            return f'{self.base_url}/messages'
        elif 'googleapis.com' in self.base_url:
            return f'{self.base_url}/models/{self.model}:generateContent'
        else:
            return f'{self.base_url}/chat/completions'

    def _extract_response_content(self, response_json: Dict) -> Optional[str]:
        """Extract content from API response."""
        try:
            if 'choices' in response_json:
                return response_json['choices'][0]['message']['content']
            elif 'content' in response_json:
                if isinstance(response_json['content'], list):
                    return response_json['content'][0]['text']
                else:
                    return response_json['content']
            elif 'candidates' in response_json:
                return response_json['candidates'][0]['content']['parts'][0]['text']
            else:
                logger.error(f"Unknown response format: {response_json}")
                return None
        except (KeyError, IndexError) as e:
            logger.error(f"Error extracting response content: {e}")
            return None

    def _prepare_security_context(self, endpoints: List[Dict], vulnerabilities: List[Dict]) -> str:
        """Prepare security context for LLM."""
        context = []

        if endpoints:
            context.append("ENDPOINTS:")
            for i, endpoint in enumerate(endpoints[:8]):
                path = endpoint.get('path', 'unknown')
                method = endpoint.get('method', 'GET')
                context.append(f"  {i+1}. {method} {path}")

        if vulnerabilities:
            context.append("\nVULNERABILITIES:")
            for i, vuln in enumerate(vulnerabilities[:5]):
                title = vuln.get('title', 'Unknown')
                severity = vuln.get('severity', 'Medium')
                context.append(f"  {i+1}. {title} ({severity})")

        context.append("\nFOCUS: Authentication, input validation, business logic security")

        return "\n".join(context) if context else "E-commerce application security testing"

    def _prepare_business_context(self, endpoints: List[Dict], business_rules: List[Dict]) -> str:
        """Prepare business context for LLM."""
        context = []

        if business_rules:
            context.append("BUSINESS RULES:")
            for i, rule in enumerate(business_rules[:5]):
                desc = rule.get('description', 'Unknown rule')[:80]
                context.append(f"  {i+1}. {desc}")

        business_endpoints = [ep for ep in endpoints 
                            if any(term in ep.get('path', '').lower() 
                                  for term in ['order', 'payment', 'cart', 'product', 'checkout'])]

        if business_endpoints:
            context.append("\nBUSINESS ENDPOINTS:")
            for i, endpoint in enumerate(business_endpoints[:5]):
                path = endpoint.get('path', 'unknown')
                method = endpoint.get('method', 'GET')
                context.append(f"  {i+1}. {method} {path}")

        return "\n".join(context) if context else "E-commerce business logic validation"

    def _get_fallback_features(self) -> Dict:
        """Get fallback app features."""
        return {
            'name': 'E-commerce Application',
            'purpose': 'E-commerce platform for online shopping and payments',
            'major_features': [
                'User registration and authentication',
                'Product catalog and search', 
                'Shopping cart functionality',
                'Payment processing',
                'Order management',
                'User profiles and accounts'
            ],
            'critical_business_rules': [
                {'id': 'BR001', 'description': 'Users must authenticate to access protected resources'},
                {'id': 'BR002', 'description': 'Payment information must be validated before processing'},
                {'id': 'BR003', 'description': 'Orders must have valid products and quantities'},
                {'id': 'BR004', 'description': 'User input must be validated and sanitized'}
            ],
            'technology_stack': ['JavaScript', 'Node.js', 'Web Application'],
            'security_features': ['Authentication', 'Input validation', 'Payment security']
        }

    def get_assumptions(self) -> List[str]:
        """Get all assumptions made."""
        return self.assumption_tracker.get_assumptions()
