#!/bin/bash
# Environment Setup Script for AI Security Analysis Tool

echo "Setting up AI Security Analysis Tool environment..."

# Set default OpenRouter configuration
echo "Setting default OpenRouter environment variables..."

# Only set if not already set
if [ -z "$OPENROUTER_API_KEY" ]; then
    echo "WARNING: OPENROUTER_API_KEY not set. Please set it with:"
    echo "export OPENROUTER_API_KEY="your_openrouter_api_key_here""
else
    echo "✅ OPENROUTER_API_KEY is set"
fi

# Set default model
export LLM_MODEL="${LLM_MODEL:-anthropic/claude-3.5-sonnet}"
echo "✅ LLM_MODEL set to: $LLM_MODEL"

# Set default max tokens
export LLM_MAX_TOKENS="${LLM_MAX_TOKENS:-1500}"
echo "✅ LLM_MAX_TOKENS set to: $LLM_MAX_TOKENS"

echo ""
echo "Environment Configuration:"
echo "- Model: $LLM_MODEL"
echo "- Max Tokens: $LLM_MAX_TOKENS"
echo "- API Key: $([ -n "$OPENROUTER_API_KEY" ] && echo "Set" || echo "NOT SET")"

echo ""
echo "To set your API key permanently, add this to your ~/.bashrc or ~/.zshrc:"
echo "export OPENROUTER_API_KEY="your_openrouter_api_key_here""

# Check Python dependencies
echo ""
echo "Checking Python dependencies..."
python3 -c "import flask, pandas, requests" 2>/dev/null && echo "✅ Core dependencies available" || echo "❌ Missing dependencies - run: pip install -r requirements.txt"

echo ""
echo "Setup complete! You can now run the web application:"
echo "python3 app.py"
