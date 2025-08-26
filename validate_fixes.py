#!/usr/bin/env python3
"""
Test Case Validation Script - Check if fixes are working properly.
"""
import sys
import logging
from orchestrator import AnalysisOrchestrator

def validate_test_generation(code_directory):
    """Validate that test generation is now reasonable."""

    print("🔍 VALIDATING TEST CASE GENERATION FIXES...")
    print("=" * 50)

    try:
        # Initialize orchestrator
        orchestrator = AnalysisOrchestrator("validation_output")

        # Run analysis without LLM to test template generation
        print("\n1. Testing static analysis and template-based test generation...")
        results = orchestrator.run_targeted_analysis(
            code_directory=code_directory,
            enable_sast=False,  # Skip SAST for faster validation
            enable_dynamic=False,  # Skip dynamic for validation
            enable_llm=False,  # Test without LLM first
            enable_export=False  # Skip export for validation
        )

        # Get summary
        summary = orchestrator.get_analysis_summary()

        print("\n📊 VALIDATION RESULTS:")
        print("-" * 30)
        print(f"Total Endpoints Found: {summary.get('total_endpoints', 0)}")
        print(f"Total Test Cases Generated: {summary.get('total_test_cases', 0)}")
        print(f"Critical/High Priority Tests: {summary.get('critical_high_tests', 0)}")
        print(f"Automation Ready Tests: {summary.get('automation_ready_tests', 0)}")

        # Validation criteria
        total_tests = summary.get('total_test_cases', 0)
        total_endpoints = summary.get('total_endpoints', 0)

        print("\n✅ VALIDATION CHECKS:")
        print("-" * 20)

        # Check 1: Reasonable number of endpoints
        if total_endpoints <= 100:
            print(f"✅ Endpoint limit: {total_endpoints} ≤ 100 (PASS)")
        else:
            print(f"❌ Endpoint limit: {total_endpoints} > 100 (FAIL)")

        # Check 2: Reasonable number of test cases
        if 20 <= total_tests <= 250:
            print(f"✅ Test case count: {total_tests} in reasonable range 20-250 (PASS)")
        elif total_tests < 20:
            print(f"⚠️  Test case count: {total_tests} < 20 (LOW - but acceptable)")
        else:
            print(f"❌ Test case count: {total_tests} > 250 (FAIL - still too many)")

        # Check 3: Test-to-endpoint ratio
        if total_endpoints > 0:
            ratio = total_tests / total_endpoints
            if ratio <= 5:  # Max 5 tests per endpoint on average
                print(f"✅ Test/Endpoint ratio: {ratio:.1f} ≤ 5.0 (PASS)")
            else:
                print(f"❌ Test/Endpoint ratio: {ratio:.1f} > 5.0 (FAIL)")

        # Overall assessment
        if total_tests <= 250 and total_endpoints <= 100:
            print("\n🎉 VALIDATION PASSED!")
            print("✅ Test generation is now reasonable and practical")
            print(f"✅ Reduced from 5800+ to {total_tests} high-quality tests")
        else:
            print("\n⚠️  VALIDATION NEEDS IMPROVEMENT")
            print("Some limits are still too high - check the fixes")

        return total_tests <= 250 and total_endpoints <= 100

    except Exception as e:
        print(f"\n❌ VALIDATION FAILED: {e}")
        return False

def main():
    if len(sys.argv) != 2:
        print("Usage: python validate_fixes.py <code_directory>")
        print("Example: python validate_fixes.py ./ecommerce_sanity_stripe-main")
        return 1

    code_directory = sys.argv[1]

    # Suppress verbose logging for validation
    logging.basicConfig(level=logging.WARNING)

    success = validate_test_generation(code_directory)

    if success:
        print("\n🎯 NEXT STEPS:")
        print("- Run full analysis: python main.py --code ./your_code --output results")
        print("- Should now generate 50-200 practical test cases")
        print("- No more 5800+ test case explosions!")
        return 0
    else:
        print("\n🔧 ISSUES DETECTED:")
        print("- Some fixes may need further adjustment")
        print("- Check the component logs for details")
        return 1

if __name__ == "__main__":
    sys.exit(main())
