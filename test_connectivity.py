#!/usr/bin/env python3
"""
Simple connectivity test for dynamic analysis.
"""
import requests
import sys
import argparse
from urllib.parse import urlparse

def test_connectivity(url, timeout=10):
    """Test if URL is accessible."""
    print(f"Testing connectivity to: {url}")

    try:
        # Parse URL to validate format
        parsed = urlparse(url)
        if not parsed.scheme or not parsed.netloc:
            print("❌ Invalid URL format. Use http://localhost:3000 or https://example.com")
            return False

        # Make request
        response = requests.get(url, timeout=timeout)

        print(f"✅ Connection successful!")
        print(f"   Status Code: {response.status_code}")
        print(f"   Response Size: {len(response.content)} bytes")
        print(f"   Content Type: {response.headers.get('content-type', 'unknown')}")

        # Check some basic security headers
        security_headers = {
            'X-Frame-Options': response.headers.get('X-Frame-Options'),
            'X-Content-Type-Options': response.headers.get('X-Content-Type-Options'),
            'Content-Security-Policy': response.headers.get('Content-Security-Policy')
        }

        print("\n🔒 Security Headers:")
        for header, value in security_headers.items():
            status = "✅" if value else "❌"
            print(f"   {status} {header}: {value or 'Not set'}")

        if response.status_code < 500:
            print("\n✅ Ready for dynamic analysis!")
            return True
        else:
            print(f"\n⚠️  Server error ({response.status_code}), but connection established")
            print("   Dynamic analysis may still work")
            return True

    except requests.exceptions.ConnectionError:
        print("❌ Connection failed - cannot reach the application")
        print("   • Make sure your application is running")
        print("   • Check if the URL and port are correct")
        print("   • Verify no firewall is blocking connections")
        return False

    except requests.exceptions.Timeout:
        print(f"❌ Connection timeout after {timeout} seconds")
        print("   • Application may be slow to respond")
        print("   • Try increasing timeout or check application health")
        return False

    except Exception as e:
        print(f"❌ Unexpected error: {e}")
        return False

def main():
    parser = argparse.ArgumentParser(description="Test connectivity for dynamic analysis")
    parser.add_argument("url", help="URL to test (e.g., http://localhost:3000)")
    parser.add_argument("--timeout", type=int, default=10, help="Request timeout in seconds")

    args = parser.parse_args()

    print("🔍 Dynamic Analysis Connectivity Test")
    print("=" * 40)

    success = test_connectivity(args.url, args.timeout)

    print("\n" + "=" * 40)
    if success:
        print("🎉 Your application is ready for dynamic analysis!")
        print(f"\n📝 Run the full analysis with:")
        print(f"python main.py --code ./your_code --app-url {args.url} --enable-dynamic --output results")
    else:
        print("❌ Fix connectivity issues before running dynamic analysis")
        print(f"\n📝 Run static analysis only with:")
        print(f"python main.py --code ./your_code --output results")

    return 0 if success else 1

if __name__ == "__main__":
    sys.exit(main())
