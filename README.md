# AI-Powered Static Analysis and Test Generation Tool

A comprehensive Python tool that combines PDF analysis, source code scanning, and AI-powered test generation to create security test cases and coverage reports.

## Features

- **PDF Report Analysis**: Extract application features and business rules from PDF documentation
- **Multi-Language Code Analysis**: Support for JavaScript/Node.js, Python, Java, React, and more
- **SAST Integration**: Optional Semgrep integration for vulnerability scanning  
- **AI Test Generation**: Use Gemini 2.5 Pro to generate intelligent security and business logic tests
- **Comprehensive Coverage**: OWASP Top 10 2023 compliance and endpoint coverage metrics
- **Multiple Export Formats**: JSON, CSV, and Markdown reports

## Quick Start

### Prerequisites

- Python 3.10 or higher
- (Optional) Semgrep CLI for vulnerability scanning
- Gemini API key for AI-powered features

### Installation

1. Clone or download the repository
2. Install dependencies:
   ```bash
   pip install -r requirements.txt
   ```

3. Set up environment variables:
   ```bash
   export GEMINI_API_KEY="your-gemini-api-key"
   ```

### Basic Usage

Analyze a codebase with PDF documentation:
```bash
python main.py --pdf report.pdf --code ./src --output ./results
```

Analyze code only:
```bash
python main.py --code ./src --output ./results
```

PDF analysis only:
```bash
python main.py --pdf report.pdf --output ./results
```

## Configuration

### Environment Variables

Create a `.env` file in the project root:
```bash
# Required for AI features
GEMINI_API_KEY=your_gemini_api_key_here

# Optional: Custom Semgrep configuration
SEMGREP_CONFIG=auto
```

### API Key Setup

The tool uses Gemini 2.5 Pro via OpenRouter. You can get an API key from:
1. **OpenRouter**: https://openrouter.ai/ (Recommended)
2. **Google AI Studio**: https://makersuite.google.com/app/apikey

#### OpenRouter Setup (Recommended)
1. Sign up at https://openrouter.ai/
2. Generate an API key
3. Set `GEMINI_API_KEY=your_openrouter_key`

#### Google AI Studio Setup  
1. Get API key from https://makersuite.google.com/app/apikey
2. Set `GEMINI_API_KEY=your_google_api_key`

## Command Line Options

### Input Options
```bash
--pdf PATH              Path to PDF report
--code PATH             Path to source code directory  
--output DIR            Output directory (default: output)
--output-name NAME      Base name for output files
```

### Analysis Options
```bash
--no-sast              Disable Semgrep SAST scanning
--no-llm               Disable AI-powered analysis
--semgrep-config CFG   Semgrep configuration (default: auto)
--semgrep-rules PATH   Custom Semgrep rules file
```

### Output Options
```bash
--json-only            Export JSON only (no CSV)
--csv-only             Export CSV only (no JSON)
--no-export           Skip file export
```

### Other Options
```bash
--log-level LEVEL     Set logging level (DEBUG/INFO/WARNING/ERROR)
--quiet, -q           Suppress output
--verbose, -v         Enable verbose output
--validate-only       Validate inputs without running
--dry-run             Show analysis plan without running
```

## Output Files

The tool generates several output files:

### JSON Files
- `*_manifest.json` - Complete analysis results in structured format
- `export_manifest.json` - List of all generated files

### CSV Files  
- `*_endpoints.csv` - All discovered API endpoints
- `*_vulnerabilities.csv` - SAST findings and vulnerabilities
- `*_test_cases.csv` - Generated security and business logic tests
- `*_coverage.csv` - Coverage metrics and analysis

### Reports
- `*_summary.md` - Human-readable analysis summary
- `analysis.log` - Detailed execution logs

## Docker Usage

### Build the Docker image:
```bash
docker build -t ai-static-analyzer .
```

### Run analysis:
```bash
# Mount your code and PDF files
docker run -v $(pwd)/examples:/input -v $(pwd)/output:/app/output \
  -e GEMINI_API_KEY=your_key \
  ai-static-analyzer --pdf /input/report.pdf --code /input/code
```

### Interactive mode:
```bash
docker run -it -v $(pwd):/workspace ai-static-analyzer bash
```

## Supported Languages and Frameworks

### Languages
- JavaScript/TypeScript
- Python  
- Java
- Ruby
- PHP
- Go

### Frameworks
- **JavaScript**: Express.js, Next.js, React Router
- **Python**: Flask, Django, FastAPI
- **Java**: Spring Boot, Spring MVC
- **Generic**: REST APIs, HTTP endpoints

## Examples

### Example 1: Full Analysis
```bash
python main.py \
  --pdf examples/pdf/app_specification.pdf \
  --code examples/code/my_app \
  --output results \
  --log-level INFO
```

### Example 2: Security Focus
```bash  
python main.py \
  --code ./src \
  --semgrep-config p/security-audit \
  --json-only \
  --output security_results
```

### Example 3: Business Logic Testing
```bash
python main.py \
  --pdf business_requirements.pdf \
  --no-sast \
  --output business_tests
```

## Architecture

```
┌─────────────────┐    ┌──────────────────┐    ┌─────────────────┐
│   PDF Parser    │    │  Code Analyzer   │    │  SAST Runner    │
│   (PyMuPDF)     │    │ (Multi-language) │    │   (Semgrep)     │
└─────────────────┘    └──────────────────┘    └─────────────────┘
         │                        │                        │
         └──────────────┬─────────────────┬─────────────────┘
                        │                 │
              ┌─────────▼─────────┐      │
              │   Orchestrator    │      │
              │   (Workflow)      │      │
              └─────────┬─────────┘      │
                        │                │
         ┌──────────────▼──────────────┐ │
         │     LLM Client              │ │
         │   (Gemini 2.5 Pro)         │ │
         └──────────────┬──────────────┘ │
                        │                │
         ┌──────────────▼──────────────┐ │
         │   Test Generator            │ │
         │  (Security + Business)      │ │
         └──────────────┬──────────────┘ │
                        │                │
         ┌──────────────▼──────────────┐ │
         │     Exporter                │ │
         │  (JSON, CSV, Markdown)      │◄┘
         └─────────────────────────────┘
```

## Troubleshooting

### Common Issues

1. **Missing API Key**
   ```
   Error: GEMINI_API_KEY environment variable is required
   ```
   Solution: Set your API key in environment variables

2. **Semgrep Not Found**
   ```
   Warning: Semgrep not available, SAST scanning disabled
   ```
   Solution: Install Semgrep with `pip install semgrep`

3. **PDF Parsing Errors**  
   ```
   Error extracting text from PDF
   ```
   Solution: Ensure PDF is not password-protected or corrupted

4. **No Code Files Found**
   ```
   Warning: No code files found in directory
   ```
   Solution: Check directory path and supported file extensions

### Debug Mode
Enable verbose logging for detailed troubleshooting:
```bash
python main.py --verbose --log-level DEBUG [other options]
```

### Log Files
Check `analysis.log` and `logs/prompts/` for detailed execution information.

## Contributing

1. Fork the repository
2. Create a feature branch
3. Add tests for new functionality
4. Submit a pull request

## License

This project is provided as-is for educational and research purposes.

## Support

For issues and questions:
1. Check the troubleshooting section
2. Review log files for error details  
3. Ensure all prerequisites are installed
4. Verify API key configuration

---

## Technical Implementation

### Key Components

1. **main.py** - CLI entry point with argparse
2. **orchestrator.py** - Workflow coordination
3. **pdf_parser.py** - PDF text extraction using PyMuPDF
4. **code_analyzer.py** - Multi-language endpoint detection
5. **sast_runner.py** - Semgrep integration
6. **llm_client.py** - Gemini API integration
7. **test_generator.py** - AI-powered test case generation
8. **exporter.py** - Multi-format result export
9. **utils.py** - Shared utilities

### File Structure
```
repo/
├── main.py                  # CLI entry point
├── orchestrator.py          # Main workflow coordinator
├── pdf_parser.py           # PDF analysis
├── code_analyzer.py        # Code scanning
├── sast_runner.py          # Security scanning
├── llm_client.py           # AI integration
├── test_generator.py       # Test case generation
├── exporter.py            # Result export
├── utils.py               # Utilities
├── requirements.txt       # Dependencies
├── Dockerfile            # Container config
└── README.md            # Documentation
```

This tool is designed to be extensible and can be easily adapted for additional languages, frameworks, or analysis types.
