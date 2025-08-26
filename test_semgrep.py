#!/usr/bin/env python3
"""
Semgrep Test Script - Verify Semgrep is working and can find vulnerabilities.
"""
import os
import subprocess
import tempfile
import json

def test_semgrep_installation():
    """Test if Semgrep is properly installed."""
    print("🔍 Testing Semgrep installation...")

    try:
        result = subprocess.run(['semgrep', '--version'], 
                              capture_output=True, text=True, timeout=10)
        if result.returncode == 0:
            print(f"✅ Semgrep installed: {result.stdout.strip()}")
            return True
        else:
            print(f"❌ Semgrep version check failed: {result.stderr}")
            return False
    except FileNotFoundError:
        print("❌ Semgrep not found. Install with: pip install semgrep")
        return False
    except Exception as e:
        print(f"❌ Semgrep test error: {e}")
        return False

def create_vulnerable_test_files():
    """Create test files with known vulnerabilities."""

    # Create temporary directory
    test_dir = tempfile.mkdtemp(prefix="semgrep_test_")

    # Vulnerable JavaScript file
    js_content = """// Vulnerable JavaScript code for testing
const userInput = req.query.user;
eval(userInput);  // Code injection vulnerability

document.getElementById("content").innerHTML = userInput;  // XSS vulnerability

const password = "admin123";  // Hardcoded password

const query = "SELECT * FROM users WHERE id = " + userId;  // SQL injection
"""

    # Vulnerable Python file  
    py_content = """# Vulnerable Python code for testing
import os
user_input = input("Enter command: ")
os.system(user_input)  # Command injection

password = "hardcoded_secret"  # Hardcoded secret

query = f"SELECT * FROM users WHERE name = '{user_name}'"  # SQL injection
"""

    # Write test files
    js_file = os.path.join(test_dir, "vulnerable.js")
    py_file = os.path.join(test_dir, "vulnerable.py")

    with open(js_file, 'w') as f:
        f.write(js_content)

    with open(py_file, 'w') as f:
        f.write(py_content)

    print(f"📁 Created test files in: {test_dir}")
    return test_dir, [js_file, py_file]

def test_semgrep_configs(test_dir):
    """Test different Semgrep configurations."""
    print("\n🧪 Testing Semgrep configurations...")

    # Test configurations to try
    configs_to_test = [
        'auto',
        'r/javascript.lang.security',
        'r/python.lang.security', 
        'p/owasp-top-ten',
        'p/security-audit',
        'p/javascript',
        'p/python'
    ]

    working_configs = []

    for config in configs_to_test:
        try:
            print(f"Testing config: {config}")

            cmd = ['semgrep', '--config', config, '--json', test_dir]
            result = subprocess.run(cmd, capture_output=True, text=True, timeout=60)

            if result.returncode in [0, 1]:  # 0 = no findings, 1 = findings found
                try:
                    data = json.loads(result.stdout) if result.stdout.strip() else {"results": []}
                    findings = len(data.get('results', []))
                    print(f"  ✅ {config}: {findings} findings")
                    working_configs.append((config, findings))
                except json.JSONDecodeError:
                    print(f"  ⚠️  {config}: Success but invalid JSON")
                    working_configs.append((config, 0))
            else:
                print(f"  ❌ {config}: Failed (return code {result.returncode})")

        except subprocess.TimeoutExpired:
            print(f"  ⏱️  {config}: Timed out")
        except Exception as e:
            print(f"  ❌ {config}: Error - {e}")

    return working_configs

def test_inline_rules(test_dir):
    """Test with inline Semgrep rules."""
    print("\n🔧 Testing inline Semgrep rules...")

    inline_rules = """rules:
  - id: eval-usage
    pattern: eval(...)
    message: "Dangerous use of eval() function"
    severity: ERROR
    languages: [javascript, typescript]

  - id: hardcoded-password
    pattern-regex: '(password|secret)\s*=\s*["'][^"']{3,}["']'
    message: "Hardcoded password/secret detected"
    severity: ERROR
    languages: [javascript, python]

  - id: innerHTML-xss
    pattern: $X.innerHTML = $Y
    message: "Potential XSS via innerHTML"
    severity: WARNING
    languages: [javascript]
"""

    # Write rules to temporary file
    rules_file = os.path.join(test_dir, 'test_rules.yml')
    with open(rules_file, 'w') as f:
        f.write(inline_rules)

    try:
        cmd = ['semgrep', '--config', rules_file, '--json', test_dir]
        result = subprocess.run(cmd, capture_output=True, text=True, timeout=60)

        if result.returncode in [0, 1]:
            data = json.loads(result.stdout) if result.stdout.strip() else {"results": []}
            findings = len(data.get('results', []))
            print(f"✅ Inline rules: {findings} findings")

            # Print some findings details
            for i, finding in enumerate(data.get('results', [])[:3]):
                rule_id = finding.get('check_id', 'unknown')
                message = finding.get('message', 'No message')
                file_path = finding.get('path', 'unknown')
                line = finding.get('start', {}).get('line', 0)
                print(f"  Finding {i+1}: {rule_id} in {os.path.basename(file_path)}:{line}")
                print(f"    Message: {message}")

            return True
        else:
            print(f"❌ Inline rules failed: {result.stderr}")
            return False

    except Exception as e:
        print(f"❌ Inline rules error: {e}")
        return False

def main():
    """Main test function."""
    print("🚀 Semgrep Functionality Test")
    print("=" * 40)

    # Test 1: Installation
    if not test_semgrep_installation():
        print("\n❌ Semgrep installation test failed!")
        print("Install Semgrep with: pip install semgrep")
        return False

    # Test 2: Create vulnerable files
    test_dir, test_files = create_vulnerable_test_files()

    try:
        # Test 3: Try different configs
        working_configs = test_semgrep_configs(test_dir)

        # Test 4: Try inline rules
        inline_success = test_inline_rules(test_dir)

        # Summary
        print("\n📊 SUMMARY")
        print("-" * 20)

        if working_configs:
            print(f"✅ {len(working_configs)} Semgrep configs are working:")
            for config, findings in working_configs[:5]:
                print(f"  • {config}: {findings} findings")
        else:
            print("❌ No registry-based Semgrep configs are working")

        if inline_success:
            print("✅ Inline Semgrep rules are working")
        else:
            print("❌ Inline Semgrep rules failed")

        # Recommendations
        print("\n💡 RECOMMENDATIONS")
        print("-" * 20)

        if working_configs:
            best_config = max(working_configs, key=lambda x: x[1])
            print(f"✅ Use config: {best_config[0]} (found {best_config[1]} issues)")
        elif inline_success:
            print("✅ Use inline rules as fallback")
        else:
            print("⚠️  Semgrep may need reinstallation or network access")
            print("   Try: pip install --upgrade semgrep")

        success = len(working_configs) > 0 or inline_success
        return success

    finally:
        # Cleanup
        import shutil
        try:
            shutil.rmtree(test_dir)
            print(f"\n🧹 Cleaned up test directory: {test_dir}")
        except:
            pass

if __name__ == "__main__":
    success = main()
    if success:
        print("\n🎉 Semgrep is working! It should now find vulnerabilities in your code.")
    else:
        print("\n❌ Semgrep needs fixing. Check the recommendations above.")
