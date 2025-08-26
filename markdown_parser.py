"""
Markdown Parser for extracting application features and workflows from Markdown documents.
"""
import logging
import re
from pathlib import Path
from typing import Dict, List, Optional, Tuple
from utils import AssumptionTracker

logger = logging.getLogger(__name__)

class MarkdownParser:
    """Parser for extracting text and structure from Markdown documents."""

    def __init__(self):
        """Initialize Markdown parser."""
        self.assumption_tracker = AssumptionTracker()

    def extract_text_from_markdown(self, md_path: str) -> Tuple[str, Dict]:
        """
        Extract text from Markdown file.
        Returns: (extracted_text, metadata)
        """
        if not Path(md_path).exists():
            logger.error(f"Markdown file not found: {md_path}")
            self.assumption_tracker.add_assumption("Markdown file not provided or not found")
            return "", {"sections": 0, "title": "unknown"}

        try:
            with open(md_path, 'r', encoding='utf-8') as f:
                content = f.read()

            # Extract metadata
            metadata = self._analyze_markdown_structure(content)
            metadata["file_path"] = md_path
            metadata["file_size"] = len(content)

            # Clean up the content (remove excessive markdown syntax)
            cleaned_content = self._clean_markdown_content(content)

            logger.info(f"Successfully extracted text from Markdown file: {len(cleaned_content)} characters")
            return cleaned_content.strip(), metadata

        except Exception as e:
            logger.error(f"Error extracting text from Markdown: {e}")
            self.assumption_tracker.add_assumption("Markdown extraction failed, analysis limited")
            return "", {"sections": 0, "title": "unknown"}

    def _clean_markdown_content(self, content: str) -> str:
        """Clean markdown syntax while preserving structure and content."""
        # Remove code blocks but keep their content
        content = re.sub(r'```[\w]*\n([\s\S]*?)```', r'\1', content)
        content = re.sub(r'`([^`]+)`', r'\1', content)

        # Convert headers to plain text with spacing
        content = re.sub(r'^#{1,6}\s*(.*)$', r'\1\n', content, flags=re.MULTILINE)

        # Remove markdown formatting
        content = re.sub(r'\*\*([^*]+)\*\*', r'\1', content)  # Bold
        content = re.sub(r'\*([^*]+)\*', r'\1', content)  # Italic
        content = re.sub(r'__([^_]+)__', r'\1', content)  # Bold alt
        content = re.sub(r'_([^_]+)_', r'\1', content)  # Italic alt

        # Remove links but keep text
        content = re.sub(r'\[([^\]]+)\]\([^\)]+\)', r'\1', content)

        # Remove images
        content = re.sub(r'!\[([^\]]*)\]\([^\)]+\)', r'\1', content)

        # Clean up list items
        content = re.sub(r'^\s*[-*+]\s+', '• ', content, flags=re.MULTILINE)
        content = re.sub(r'^\s*\d+\.\s+', '• ', content, flags=re.MULTILINE)

        # Remove excessive whitespace
        content = re.sub(r'\n\s*\n', '\n\n', content)
        content = re.sub(r' +', ' ', content)

        return content

    def _analyze_markdown_structure(self, content: str) -> Dict:
        """Analyze markdown structure to identify sections and metadata."""

        # Extract title (first H1)
        title_match = re.search(r'^#\s+(.+)$', content, re.MULTILINE)
        title = title_match.group(1) if title_match else "unknown"

        # Find all headers
        headers = []
        header_pattern = r'^(#{1,6})\s+(.+)$'
        for match in re.finditer(header_pattern, content, re.MULTILINE):
            level = len(match.group(1))
            text = match.group(2).strip()
            headers.append({
                "level": level,
                "text": text,
                "line": content[:match.start()].count('\n') + 1
            })

        # Count different elements
        code_blocks = len(re.findall(r'```[\s\S]*?```', content))
        lists = len(re.findall(r'^\s*[-*+]\s+', content, re.MULTILINE))
        links = len(re.findall(r'\[([^\]]+)\]\([^\)]+\)', content))

        return {
            "title": title,
            "sections": len(headers),
            "headers": headers[:10],  # Limit to first 10
            "code_blocks": code_blocks,
            "lists": lists,
            "links": links,
            "word_count": len(content.split()),
            "line_count": content.count('\n') + 1
        }

    def extract_features_from_text(self, text: str) -> Dict[str, List[str]]:
        """
        Extract potential application features from markdown text using pattern matching.
        This is a fallback method when LLM is not available.
        """
        features = {
            "authentication": [],
            "authorization": [],
            "data_management": [],
            "api_endpoints": [],
            "business_logic": [],
            "security_features": []
        }

        # Common patterns for different feature types
        patterns = {
            "authentication": [
                r"login", r"sign[- ]in", r"authentication", r"oauth", r"sso", r"jwt",
                r"password", r"credential", r"token", r"session"
            ],
            "authorization": [
                r"permission", r"role", r"access[- ]control", r"authorization", r"rbac",
                r"acl", r"privilege", r"admin", r"user[- ]management"
            ],
            "data_management": [
                r"database", r"crud", r"create", r"update", r"delete", r"insert",
                r"query", r"search", r"filter", r"sort", r"pagination"
            ],
            "api_endpoints": [
                r"/api/", r"rest", r"graphql", r"endpoint", r"service", r"microservice",
                r"get", r"post", r"put", r"delete", r"patch"
            ],
            "business_logic": [
                r"workflow", r"process", r"business[- ]rule", r"validation", r"calculation",
                r"algorithm", r"logic", r"rule[- ]engine"
            ],
            "security_features": [
                r"encrypt", r"decrypt", r"hash", r"ssl", r"tls", r"https", r"csrf",
                r"xss", r"sanitiz", r"validat", r"audit", r"log", r"monitor"
            ]
        }

        text_lower = text.lower()

        for category, category_patterns in patterns.items():
            found_features = set()

            for pattern in category_patterns:
                import re
                matches = re.finditer(pattern, text_lower)
                for match in matches:
                    # Extract context around the match
                    start = max(0, match.start() - 30)
                    end = min(len(text), match.end() + 30)
                    context = text[start:end].strip()

                    # Clean up the context
                    context = re.sub(r'\s+', ' ', context)
                    if len(context) > 100:
                        context = context[:100] + "..."

                    found_features.add(context)

            features[category] = list(found_features)[:5]  # Limit to top 5

        return features

    def extract_business_rules(self, text: str) -> List[Dict]:
        """Extract potential business rules from markdown text."""
        business_rules = []

        # Patterns that often indicate business rules
        rule_patterns = [
            r"must be", r"should be", r"cannot be", r"required to",
            r"if.*then", r"when.*then", r"rule:", r"policy:",
            r"constraint", r"validation", r"requirement"
        ]

        import re
        sentences = re.split(r'[.!?]', text)

        rule_id = 1
        for sentence in sentences:
            sentence = sentence.strip()
            if len(sentence) < 20:  # Skip very short sentences
                continue

            sentence_lower = sentence.lower()
            for pattern in rule_patterns:
                if re.search(pattern, sentence_lower):
                    business_rules.append({
                        "id": f"BR{rule_id:03d}",
                        "description": sentence[:200] + ("..." if len(sentence) > 200 else ""),
                        "source": "markdown"
                    })
                    rule_id += 1
                    break

            if len(business_rules) >= 10:  # Limit to 10 rules
                break

        return business_rules

    def extract_technical_requirements(self, text: str) -> List[Dict]:
        """Extract technical requirements and specifications."""
        requirements = []

        # Look for technical requirement patterns
        tech_patterns = [
            r"requirement", r"specification", r"must support", r"shall",
            r"performance", r"scalability", r"availability", r"security"
        ]

        lines = text.split('\n')
        req_id = 1

        for line in lines:
            line = line.strip()
            if len(line) < 10:
                continue

            line_lower = line.lower()
            for pattern in tech_patterns:
                if re.search(pattern, line_lower):
                    requirements.append({
                        "id": f"TR{req_id:03d}",
                        "description": line[:150] + ("..." if len(line) > 150 else ""),
                        "category": "technical",
                        "source": "markdown"
                    })
                    req_id += 1
                    break

            if len(requirements) >= 15:  # Limit to 15 requirements
                break

        return requirements

    def get_assumptions(self) -> List[str]:
        """Get all assumptions made during markdown parsing."""
        return self.assumption_tracker.get_assumptions()

    def analyze_document_sections(self, md_path: str) -> Dict:
        """Analyze document sections and structure."""
        if not Path(md_path).exists():
            return {"sections": [], "toc": []}

        try:
            with open(md_path, 'r', encoding='utf-8') as f:
                content = f.read()

            # Extract headers as table of contents
            toc = []
            header_pattern = r'^(#{1,6})\s+(.+)$'

            for match in re.finditer(header_pattern, content, re.MULTILINE):
                level = len(match.group(1))
                text = match.group(2).strip()
                line_num = content[:match.start()].count('\n') + 1

                toc.append({
                    "level": level,
                    "title": text,
                    "line": line_num
                })

            return {
                "sections": toc,
                "toc": toc,
                "total_sections": len(toc)
            }

        except Exception as e:
            logger.error(f"Error analyzing document sections: {e}")
            return {"sections": [], "toc": []}
