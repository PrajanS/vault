"""
PDF Parser for extracting application features and workflows from PDF reports.
"""
import logging
import pymupdf  # PyMuPDF
from pathlib import Path
from typing import Dict, List, Optional, Tuple
from utils import AssumptionTracker

logger = logging.getLogger(__name__)

class PDFParser:
    """Parser for extracting text and structure from PDF documents."""

    def __init__(self):
        """Initialize PDF parser."""
        self.assumption_tracker = AssumptionTracker()

    def extract_text_from_pdf(self, pdf_path: str) -> Tuple[str, Dict]:
        """
        Extract text from PDF file.
        Returns: (extracted_text, metadata)
        """
        if not Path(pdf_path).exists():
            logger.error(f"PDF file not found: {pdf_path}")
            self.assumption_tracker.add_assumption("PDF file not provided or not found")
            return "", {"pages": 0, "title": "unknown"}

        try:
            doc = pymupdf.open(pdf_path)
            extracted_text = ""
            metadata = {
                "pages": len(doc),
                "title": doc.metadata.get('title', 'unknown'),
                "author": doc.metadata.get('author', 'unknown'),
                "subject": doc.metadata.get('subject', ''),
                "creator": doc.metadata.get('creator', ''),
                "producer": doc.metadata.get('producer', ''),
                "creation_date": str(doc.metadata.get('creationDate', '')),
                "modification_date": str(doc.metadata.get('modDate', ''))
            }

            # Extract text from each page
            for page_num in range(len(doc)):
                page = doc[page_num]

                # Get text with layout information
                text_dict = page.get_text("dict")
                page_text = self._extract_structured_text(text_dict)

                extracted_text += f"\n--- Page {page_num + 1} ---\n"
                extracted_text += page_text

            doc.close()

            logger.info(f"Successfully extracted text from {len(doc)} pages")
            return extracted_text.strip(), metadata

        except Exception as e:
            logger.error(f"Error extracting text from PDF: {e}")
            self.assumption_tracker.add_assumption("PDF extraction failed, analysis limited")
            return "", {"pages": 0, "title": "unknown"}

    def _extract_structured_text(self, text_dict: Dict) -> str:
        """Extract structured text from PyMuPDF text dictionary."""
        text_content = []

        for block in text_dict.get("blocks", []):
            if block.get("type") == 0:  # Text block
                block_text = ""

                for line in block.get("lines", []):
                    line_text = ""

                    for span in line.get("spans", []):
                        span_text = span.get("text", "").strip()
                        if span_text:
                            # Preserve important formatting
                            font_size = span.get("size", 12)
                            font_flags = span.get("flags", 0)

                            # Detect headings (larger font or bold)
                            if font_size > 14 or font_flags & 2**4:  # Bold flag
                                span_text = f"\n**{span_text}**\n"

                            line_text += span_text + " "

                    if line_text.strip():
                        block_text += line_text.strip() + "\n"

                if block_text.strip():
                    text_content.append(block_text.strip())

        return "\n".join(text_content)

    def extract_features_from_text(self, text: str) -> Dict[str, List[str]]:
        """
        Extract potential application features from text using pattern matching.
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
        """Extract potential business rules from text."""
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
                        "source": "pdf"
                    })
                    rule_id += 1
                    break

            if len(business_rules) >= 10:  # Limit to 10 rules
                break

        return business_rules

    def get_assumptions(self) -> List[str]:
        """Get all assumptions made during PDF parsing."""
        return self.assumption_tracker.get_assumptions()

    def analyze_document_structure(self, pdf_path: str) -> Dict:
        """Analyze document structure to identify sections."""
        if not Path(pdf_path).exists():
            return {"sections": [], "toc": []}

        try:
            doc = pymupdf.open(pdf_path)

            # Try to extract table of contents
            toc = doc.get_toc()

            # Analyze document structure
            sections = []
            for page_num in range(len(doc)):
                page = doc[page_num]
                text_dict = page.get_text("dict")

                # Look for headings (larger font size or bold)
                for block in text_dict.get("blocks", []):
                    if block.get("type") == 0:  # Text block
                        for line in block.get("lines", []):
                            for span in line.get("spans", []):
                                font_size = span.get("size", 12)
                                font_flags = span.get("flags", 0)
                                text = span.get("text", "").strip()

                                # Potential section header
                                if (font_size > 14 or font_flags & 2**4) and len(text) > 5:
                                    sections.append({
                                        "page": page_num + 1,
                                        "text": text,
                                        "font_size": font_size,
                                        "is_bold": bool(font_flags & 2**4)
                                    })

            doc.close()

            return {
                "sections": sections[:20],  # Limit to 20 sections
                "toc": toc[:20] if toc else []  # Limit to 20 TOC entries
            }

        except Exception as e:
            logger.error(f"Error analyzing document structure: {e}")
            return {"sections": [], "toc": []}
