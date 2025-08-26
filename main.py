#!/usr/bin/env python3
"""
AI-Powered Static Analysis and Test Generation Tool v2.0

Enhanced main entry point supporting dynamic analysis and comprehensive testing.
"""
import os
import sys
import argparse
import logging
from pathlib import Path

from orchestrator import AnalysisOrchestrator
from utils import setup_logging

def parse_arguments():
    """Parse command line arguments."""
    parser = argparse.ArgumentParser(
        prog='ai-static-analyzer',
        description='AI-Powered Static Analysis and Test Generation Tool v2.0',
        epilog='Example: %(prog)s --report report.md --code ./src --app-url http://localhost:3000 --output ./results'
    )

    # Input arguments
    parser.add_argument(
        '--report', '--report-path',
        type=str,
        help='Path to PDF or Markdown report describing the application'
    )

    # Keep --pdf for backward compatibility
    parser.add_argument(
        '--pdf', '--pdf-path',
        type=str,
        help='Path to PDF report (deprecated, use --report instead)'
    )

    parser.add_argument(
        '--markdown', '--md',
        type=str,
        help='Path to Markdown report (deprecated, use --report instead)'
    )

    parser.add_argument(
        '--code', '--code-directory', 
        type=str,
        help='Path to source code directory to analyze'
    )

    parser.add_argument(
        '--app-url', '--url',
        type=str,
        help='URL of running application for dynamic analysis (e.g., http://localhost:3000)'
    )

    # Output arguments
    parser.add_argument(
        '--output', '-o',
        type=str,
        default='output',
        help='Output directory for results (default: output)'
    )

    parser.add_argument(
        '--output-name',
        type=str,
        help='Base name for output files (default: auto-generated)'
    )

    # Analysis options
    parser.add_argument(
        '--no-sast',
        action='store_true',
        help='Disable SAST scanning with Semgrep'
    )

    parser.add_argument(
        '--enable-dynamic', '--dynamic',
        action='store_true',
        help='Enable dynamic analysis of running application'
    )

    parser.add_argument(
        '--no-llm',
        action='store_true', 
        help='Disable LLM-powered analysis (use templates only)'
    )

    parser.add_argument(
        '--no-export',
        action='store_true',
        help='Disable result export (analyze only)'
    )

    # LLM configuration
    parser.add_argument(
        '--llm-model',
        type=str,
        help='LLM model to use (e.g., anthropic/claude-3.5-sonnet, google/gemini-2.0-flash-exp)'
    )

    # Semgrep options
    parser.add_argument(
        '--semgrep-config',
        type=str,
        default='auto',
        help='Semgrep configuration to use (default: auto)'
    )

    parser.add_argument(
        '--semgrep-rules',
        type=str,
        help='Path to custom Semgrep rules file'
    )

    # Dynamic analysis options
    parser.add_argument(
        '--crawl-depth',
        type=int,
        default=2,
        help='Depth for dynamic crawling (default: 2)'
    )

    parser.add_argument(
        '--max-threads',
        type=int,
        default=10,
        help='Maximum threads for dynamic analysis (default: 10)'
    )

    # Output format options
    parser.add_argument(
        '--json-only',
        action='store_true',
        help='Export JSON manifest only (no CSV files)'
    )

    parser.add_argument(
        '--csv-only',
        action='store_true',
        help='Export CSV files only (no JSON manifest)'
    )

    # Logging options
    parser.add_argument(
        '--log-level',
        choices=['DEBUG', 'INFO', 'WARNING', 'ERROR'],
        default='INFO',
        help='Set logging level (default: INFO)'
    )

    parser.add_argument(
        '--quiet', '-q',
        action='store_true',
        help='Suppress console output (errors only)'
    )

    parser.add_argument(
        '--verbose', '-v',
        action='store_true',
        help='Enable verbose output (DEBUG level)'
    )

    # Validation options
    parser.add_argument(
        '--validate-only',
        action='store_true',
        help='Validate inputs and show analysis plan without running'
    )

    parser.add_argument(
        '--dry-run',
        action='store_true',
        help='Show what would be analyzed without actually running'
    )

    # Environment options
    parser.add_argument(
        '--env-file',
        type=str,
        help='Path to .env file for environment variables'
    )

    # Version information
    parser.add_argument(
        '--version',
        action='version',
        version='AI Static Analyzer v2.0.0 - Enhanced with Dynamic Analysis'
    )

    return parser.parse_args()

def setup_environment(args):
    """Setup environment variables and configurations."""
    # Load environment file if specified
    if args.env_file:
        try:
            from dotenv import load_dotenv
            load_dotenv(args.env_file)
            print(f"Loaded environment from: {args.env_file}")
        except ImportError:
            print("Warning: python-dotenv not installed, cannot load .env file")
        except Exception as e:
            print(f"Warning: Could not load .env file: {e}")

    # Set LLM model from command line if specified
    if args.llm_model:
        os.environ['LLM_MODEL'] = args.llm_model

    # Check for any LLM API key (multiple options supported)
    api_key_vars = [
        'OPENROUTER_API_KEY',
        'LLM_API_KEY',
        'CLAUDE_API_KEY', 
        'GEMINI_API_KEY'
    ]

    available_keys = []
    for var in api_key_vars:
        if os.getenv(var):
            available_keys.append(var)

    if not available_keys and not args.no_llm:
        print("Warning: No LLM API key found in environment variables")
        print("Supported variables: " + ", ".join(api_key_vars))
        print("LLM features will be disabled. Use --no-llm to explicitly disable LLM features.")
        return False
    elif available_keys:
        print(f"Found API key: {available_keys[0]}")

    return True

def resolve_report_path(args):
    """Resolve report path from various argument options."""
    # Priority: --report > --pdf > --markdown
    if args.report:
        return args.report
    elif args.pdf:
        return args.pdf
    elif args.markdown:
        return args.markdown
    else:
        return None

def validate_inputs(args):
    """Validate input arguments."""
    errors = []
    warnings = []

    # Resolve report path
    report_path = resolve_report_path(args)

    # Check if at least one input is provided
    if not report_path and not args.code and not args.app_url:
        errors.append("At least one input must be provided: --report, --code, or --app-url")

    # Validate report path
    if report_path:
        report_file = Path(report_path)
        if not report_file.exists():
            errors.append(f"Report file not found: {report_path}")
        else:
            file_ext = report_file.suffix.lower()
            if file_ext not in ['.pdf', '.md']:
                warnings.append(f"Report file should be .pdf or .md: {report_path}")

    # Show deprecation warnings
    if args.pdf:
        warnings.append("--pdf is deprecated, use --report instead")
    if args.markdown:
        warnings.append("--markdown is deprecated, use --report instead")

    # Validate code directory
    if args.code:
        code_path = Path(args.code)
        if not code_path.exists():
            errors.append(f"Code directory not found: {args.code}")
        elif not code_path.is_dir():
            errors.append(f"Code path is not a directory: {args.code}")
        else:
            # Check if directory contains code files
            code_extensions = ['.js', '.ts', '.py', '.java', '.rb', '.php', '.go', '.jsx', '.tsx']
            code_files = []
            for ext in code_extensions:
                code_files.extend(list(code_path.rglob(f'*{ext}')))

            if not code_files:
                warnings.append(f"No code files found in directory: {args.code}")

    # Validate app URL
    if args.app_url:
        import re
        url_pattern = r'^https?://.+'
        if not re.match(url_pattern, args.app_url):
            errors.append(f"Invalid application URL format: {args.app_url}")

        # Check if dynamic analysis is enabled when URL is provided
        if not args.enable_dynamic:
            warnings.append("Application URL provided but dynamic analysis not enabled. Use --enable-dynamic to enable dynamic analysis.")

    # Check dynamic analysis requirements
    if args.enable_dynamic and not args.app_url:
        errors.append("Dynamic analysis enabled but no --app-url provided")

    # Validate Semgrep rules file
    if args.semgrep_rules:
        rules_path = Path(args.semgrep_rules)
        if not rules_path.exists():
            errors.append(f"Semgrep rules file not found: {args.semgrep_rules}")

    # Validate output directory
    try:
        Path(args.output).mkdir(parents=True, exist_ok=True)
    except Exception as e:
        errors.append(f"Cannot create output directory '{args.output}': {e}")

    # Validate dynamic analysis parameters
    if args.crawl_depth < 1 or args.crawl_depth > 5:
        warnings.append("Crawl depth should be between 1 and 5 for optimal performance")

    if args.max_threads < 1 or args.max_threads > 50:
        warnings.append("Max threads should be between 1 and 50 for optimal performance")

    # Conflicting options
    if args.json_only and args.csv_only:
        errors.append("Cannot specify both --json-only and --csv-only")

    if args.quiet and args.verbose:
        warnings.append("Both --quiet and --verbose specified, using verbose")

    return errors, warnings

def show_analysis_plan(args):
    """Show what will be analyzed without running."""
    report_path = resolve_report_path(args)

    print("\n=== ENHANCED ANALYSIS PLAN ===")
    print(f"Report Document: {'Yes' if report_path else 'No'}")
    if report_path:
        file_ext = Path(report_path).suffix.lower()
        report_type = "PDF" if file_ext == '.pdf' else "Markdown" if file_ext == '.md' else "Unknown"
        print(f"  Path: {report_path}")
        print(f"  Type: {report_type}")

    print(f"Source Code: {'Yes' if args.code else 'No'}")
    if args.code:
        print(f"  Directory: {args.code}")

    print(f"Dynamic Analysis: {'Yes' if args.enable_dynamic else 'No'}")
    if args.enable_dynamic and args.app_url:
        print(f"  Target URL: {args.app_url}")
        print(f"  Crawl Depth: {args.crawl_depth}")
        print(f"  Max Threads: {args.max_threads}")

    print(f"SAST Scanning: {'No' if args.no_sast else 'Yes'}")
    if not args.no_sast:
        print(f"  Semgrep Config: {args.semgrep_config}")
        if args.semgrep_rules:
            print(f"  Custom Rules: {args.semgrep_rules}")

    print(f"LLM Analysis: {'No' if args.no_llm else 'Yes'}")
    if not args.no_llm:
        # Check for any API key
        api_keys = ['OPENROUTER_API_KEY', 'LLM_API_KEY', 'CLAUDE_API_KEY', 'GEMINI_API_KEY']
        found_key = None
        for key_var in api_keys:
            if os.getenv(key_var):
                found_key = key_var
                break

        api_key_status = f"Set ({found_key})" if found_key else "Not Set"
        print(f"  API Key: {api_key_status}")

        model = args.llm_model or os.getenv('LLM_MODEL', 'auto-detect')
        print(f"  Model: {model}")

    print(f"Export Results: {'No' if args.no_export else 'Yes'}")
    if not args.no_export:
        print(f"  Output Directory: {args.output}")
        if args.output_name:
            print(f"  Base Filename: {args.output_name}")

    print("\n=== EXPECTED OUTPUTS ===")
    if not args.no_export:
        if not args.csv_only:
            print("- manifest.json (comprehensive results)")
        if not args.json_only:
            print("- endpoints.csv (static + dynamic endpoints)")
            print("- vulnerabilities.csv (SAST + dynamic findings)") 
            print("- test_cases.csv (comprehensive test suite)")
            print("- coverage.csv (enhanced coverage metrics)")
        print("- summary.md (executive summary report)")

        if args.enable_dynamic:
            print("- Dynamic analysis specific outputs:")
            print("  - Security headers analysis")
            print("  - Form discovery results")
            print("  - JavaScript API endpoints")
    else:
        print("- Analysis results in memory only")

    print("\n=== ESTIMATED TEST CASES ===")
    estimated_tests = 50  # Base estimate
    if args.code:
        estimated_tests += 30  # Code-based tests
    if args.enable_dynamic:
        estimated_tests += 40  # Dynamic analysis tests
    if report_path:
        estimated_tests += 25  # Business logic tests

    print(f"Expected test cases: {estimated_tests}-{estimated_tests * 2} (depending on complexity)")
    print()

def run_analysis(args):
    """Run the complete enhanced analysis workflow."""

    # Setup logging
    log_level = 'ERROR' if args.quiet else ('DEBUG' if args.verbose else args.log_level)
    logger = setup_logging(log_level)

    logger.info("Starting AI-Powered Static Analysis Tool v2.0.0")

    try:
        # Resolve report path
        report_path = resolve_report_path(args)

        # Initialize orchestrator
        orchestrator = AnalysisOrchestrator(output_directory=args.output)

        # Validate inputs using orchestrator
        input_issues = orchestrator.validate_inputs(report_path, args.code, args.app_url)
        if input_issues:
            for issue in input_issues:
                logger.error(issue)
            return 1

        # Configure analysis options
        analysis_config = {
            'report_path': report_path,
            'code_directory': args.code,
            'app_url': args.app_url,
            'enable_sast': not args.no_sast,
            'enable_dynamic': args.enable_dynamic,
            'enable_llm': not args.no_llm,
            'enable_export': not args.no_export
        }

        # Run enhanced analysis
        print("Running enhanced analysis workflow...")
        print("This may take several minutes for comprehensive analysis...")

        results = orchestrator.run_targeted_analysis(**analysis_config)

        # Show enhanced summary
        summary = orchestrator.get_analysis_summary()
        print("\n=== ENHANCED ANALYSIS SUMMARY ===")
        for key, value in summary.items():
            if key != "error":
                formatted_key = key.replace('_', ' ').title()
                print(f"{formatted_key}: {value}")

        # Show export information
        if results.get('export_info') and not args.no_export:
            exported_files = results['export_info']['exported_files']
            print(f"\n=== EXPORTED FILES ({len(exported_files)}) ===")
            for file_type, file_path in exported_files.items():
                print(f"{file_type}: {file_path}")

        # Show key statistics
        if summary.get('total_test_cases', 0) > 0:
            print(f"\n=== KEY ACHIEVEMENTS ===")
            print(f"✓ Generated {summary['total_test_cases']} comprehensive test cases")
            print(f"✓ Achieved {summary['endpoint_coverage']} endpoint coverage")
            print(f"✓ Achieved {summary['owasp_coverage']} OWASP Top 10 coverage")
            if summary.get('dynamic_analysis_performed'):
                print(f"✓ Performed dynamic analysis on running application")
            print(f"✓ {summary['automation_ready_tests']} tests ready for automation")

        logger.info("Enhanced analysis completed successfully")
        return 0

    except KeyboardInterrupt:
        logger.info("Analysis cancelled by user")
        return 130
    except Exception as e:
        logger.error(f"Analysis failed: {e}")
        if args.verbose:
            import traceback
            traceback.print_exc()
        return 1
    finally:
        # Cleanup if needed
        try:
            orchestrator.cleanup_temp_files()
        except:
            pass

def main():
    """Main entry point."""
    # Parse arguments
    args = parse_arguments()

    # Setup environment
    env_ok = setup_environment(args)
    if not env_ok and not args.no_llm:
        args.no_llm = True  # Auto-disable LLM if environment not ready

    # Validate inputs
    errors, warnings = validate_inputs(args)

    # Show warnings
    if warnings and not args.quiet:
        for warning in warnings:
            print(f"Warning: {warning}")

    # Show errors and exit if any
    if errors:
        for error in errors:
            print(f"Error: {error}")
        return 1

    # Handle special modes
    if args.dry_run or args.validate_only:
        show_analysis_plan(args)
        if args.validate_only:
            print("Validation complete. Use without --validate-only to run analysis.")
        return 0

    # Show analysis plan if verbose
    if args.verbose and not args.quiet:
        show_analysis_plan(args)

    # Run the enhanced analysis
    return run_analysis(args)

if __name__ == '__main__':
    sys.exit(main())
