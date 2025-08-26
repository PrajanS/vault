"""
Enhanced utilities with Windows-compatible logging.
"""
import os
import sys
import logging
import json
from typing import List, Optional, Dict, Any
from datetime import datetime
from pathlib import Path

def setup_logging(level: str = "INFO") -> logging.Logger:
    """Setup logging with Windows-compatible formatting."""

    # Convert string level to logging constant
    numeric_level = getattr(logging, level.upper(), logging.INFO)

    # Create formatter without Unicode symbols for Windows compatibility
    formatter = logging.Formatter(
        '%(asctime)s - %(name)s - %(levelname)s - %(message)s'
    )

    # Setup console handler with UTF-8 encoding
    console_handler = logging.StreamHandler(sys.stdout)
    if hasattr(sys.stdout, 'reconfigure'):
        try:
            sys.stdout.reconfigure(encoding='utf-8')
        except:
            pass

    console_handler.setFormatter(formatter)
    console_handler.setLevel(numeric_level)

    # Setup file handler
    log_dir = Path("logs")
    log_dir.mkdir(exist_ok=True)

    file_handler = logging.FileHandler(
        log_dir / "analysis.log", 
        encoding='utf-8'
    )
    file_handler.setFormatter(formatter)
    file_handler.setLevel(logging.DEBUG)

    # Configure root logger
    root_logger = logging.getLogger()
    root_logger.setLevel(logging.DEBUG)

    # Remove existing handlers
    for handler in root_logger.handlers[:]:
        root_logger.removeHandler(handler)

    # Add our handlers
    root_logger.addHandler(console_handler)
    root_logger.addHandler(file_handler)

    return root_logger

def ensure_directory_exists(directory_path: str) -> None:
    """Ensure directory exists, create if not."""
    Path(directory_path).mkdir(parents=True, exist_ok=True)

def get_current_timestamp() -> str:
    """Get current timestamp in ISO format."""
    return datetime.now().isoformat()

def calculate_percentage(numerator: int, denominator: int) -> float:
    """Calculate percentage safely."""
    if denominator == 0:
        return 0.0
    return (numerator / denominator) * 100

def find_files_by_extension(directory: str, extensions: List[str]) -> List[str]:
    """Find files by extension in directory."""
    files = []
    for root, dirs, filenames in os.walk(directory):
        # Skip common directories that don't contain source code
        dirs[:] = [d for d in dirs if d not in {
            'node_modules', 'vendor', 'dist', 'build', '.git', 
            '__pycache__', 'target', '.next', 'public', 'static'
        }]

        for filename in filenames:
            if any(filename.lower().endswith(ext.lower()) for ext in extensions):
                files.append(os.path.join(root, filename))
    return files

def merge_dictionaries(*dicts: Dict) -> Dict:
    """Merge multiple dictionaries."""
    result = {}
    for d in dicts:
        if isinstance(d, dict):
            result.update(d)
    return result

class AssumptionTracker:
    """Track assumptions made during analysis."""

    def __init__(self):
        self.assumptions = []

    def add_assumption(self, assumption: str) -> None:
        """Add an assumption."""
        if assumption not in self.assumptions:
            self.assumptions.append(assumption)

    def get_assumptions(self) -> List[str]:
        """Get all assumptions."""
        return self.assumptions.copy()

    def clear(self) -> None:
        """Clear all assumptions."""
        self.assumptions.clear()

def safe_json_load(file_path: str) -> Optional[Dict]:
    """Safely load JSON file."""
    try:
        with open(file_path, 'r', encoding='utf-8') as f:
            return json.load(f)
    except Exception:
        return None

def safe_json_dump(data: Dict, file_path: str) -> bool:
    """Safely dump JSON to file."""
    try:
        ensure_directory_exists(os.path.dirname(file_path))
        with open(file_path, 'w', encoding='utf-8') as f:
            json.dump(data, f, indent=2, ensure_ascii=False)
        return True
    except Exception:
        return False

def sanitize_filename(filename: str) -> str:
    """Sanitize filename for Windows compatibility."""
    invalid_chars = '<>:"/\\|?*'
    for char in invalid_chars:
        filename = filename.replace(char, '_')
    return filename[:100]  # Limit length

def get_file_size(file_path: str) -> int:
    """Get file size safely."""
    try:
        return os.path.getsize(file_path)
    except Exception:
        return 0

def is_binary_file(file_path: str) -> bool:
    """Check if file is binary."""
    try:
        with open(file_path, 'rb') as f:
            chunk = f.read(1024)
            return b'\0' in chunk
    except Exception:
        return True

def read_text_file(file_path: str, max_size: int = 1024*1024) -> Optional[str]:
    """Read text file safely with size limit."""
    try:
        if get_file_size(file_path) > max_size:
            return None

        if is_binary_file(file_path):
            return None

        with open(file_path, 'r', encoding='utf-8', errors='ignore') as f:
            return f.read()
    except Exception:
        return None
