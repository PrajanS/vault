"""
Configuration module for AI Security Analysis Tool
Handles OpenRouter API settings and defaults.
"""
import os
import logging
from typing import Optional

logger = logging.getLogger(__name__)

class Config:
    """Configuration class for the application."""

    def __init__(self):
        """Initialize configuration with OpenRouter defaults."""
        self.setup_openrouter_defaults()

    def setup_openrouter_defaults(self):
        """Setup OpenRouter configuration with sensible defaults."""

        # OpenRouter API Key
        self.api_key = os.getenv('OPENROUTER_API_KEY')
        if not self.api_key:
            logger.warning("OPENROUTER_API_KEY not set - LLM features will be limited")

        # Model Configuration
        self.model = os.getenv('LLM_MODEL', 'anthropic/claude-3.5-sonnet')

        # Token Limits
        self.max_tokens = int(os.getenv('LLM_MAX_TOKENS', '1500'))

        # API Settings
        self.api_base_url = 'https://openrouter.ai/api/v1'

        # Request Settings
        self.timeout = 90
        self.temperature = 0.3

        # Application Settings
        self.upload_max_size = 50 * 1024 * 1024  # 50MB
        self.session_timeout = 3600  # 1 hour

        logger.info(f"OpenRouter Config - Model: {self.model}, Max Tokens: {self.max_tokens}")

    @property
    def is_llm_enabled(self) -> bool:
        """Check if LLM features are enabled."""
        return bool(self.api_key)

    def get_request_headers(self) -> dict:
        """Get headers for OpenRouter API requests."""
        if not self.api_key:
            return {}

        return {
            'Authorization': f'Bearer {self.api_key}',
            'Content-Type': 'application/json',
            'HTTP-Referer': 'https://ai-security-analyzer.com',
            'X-Title': 'AI Security Analysis Tool'
        }

    def get_request_data(self, prompt: str) -> dict:
        """Get request data for OpenRouter API."""
        return {
            'model': self.model,
            'messages': [
                {'role': 'user', 'content': prompt}
            ],
            'max_tokens': self.max_tokens,
            'temperature': self.temperature
        }

    def validate_config(self) -> list:
        """Validate configuration and return any issues."""
        issues = []

        if not self.api_key:
            issues.append("OPENROUTER_API_KEY not set")

        if self.max_tokens < 100:
            issues.append(f"LLM_MAX_TOKENS ({self.max_tokens}) is too low, minimum 100")
        elif self.max_tokens > 4000:
            issues.append(f"LLM_MAX_TOKENS ({self.max_tokens}) is very high, may cause billing issues")

        if not self.model:
            issues.append("LLM_MODEL not set")

        return issues

    def print_config(self):
        """Print current configuration."""
        print("🔧 AI Security Analysis Tool Configuration")
        print("=" * 45)
        print(f"API Key: {'✅ Set' if self.api_key else '❌ Not Set'}")
        print(f"Model: {self.model}")
        print(f"Max Tokens: {self.max_tokens}")
        print(f"LLM Enabled: {'✅ Yes' if self.is_llm_enabled else '❌ No'}")
        print(f"Upload Limit: {self.upload_max_size // 1024 // 1024}MB")
        print("=" * 45)

        issues = self.validate_config()
        if issues:
            print("⚠️ Configuration Issues:")
            for issue in issues:
                print(f"  • {issue}")
        else:
            print("✅ Configuration is valid")
        print()

# Global configuration instance
config = Config()

def setup_environment():
    """Setup environment variables if not already set."""

    # Set defaults if not already set
    env_vars = {
        'LLM_MODEL': 'anthropic/claude-3.5-sonnet',
        'LLM_MAX_TOKENS': '1500'
    }

    for var, default_value in env_vars.items():
        if not os.getenv(var):
            os.environ[var] = default_value
            logger.info(f"Set default {var}={default_value}")

    # Print warning about API key
    if not os.getenv('OPENROUTER_API_KEY'):
        print("⚠️ WARNING: OPENROUTER_API_KEY not set!")
        print("Set it with: export OPENROUTER_API_KEY="your_api_key_here"")
        print("The tool will work with limited functionality without it.")
        print()

if __name__ == "__main__":
    setup_environment()
    config.print_config()
