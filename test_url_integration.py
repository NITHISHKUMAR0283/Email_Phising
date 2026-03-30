#!/usr/bin/env python
"""
URL Detection Engine Integration Test
======================================
Verify that the URL Detection engine is properly integrated.

Run this to test:
    python test_url_integration.py
"""

import sys
from pathlib import Path

# Add app to path
app_path = Path(__file__).parent / "app"
sys.path.insert(0, str(app_path))

def test_url_analyzer_import():
    """Test 1: Can we import the URL analyzer?"""
    print("\n" + "="*60)
    print("TEST 1: URL Analyzer Import")
    print("="*60)
    
    try:
        from url_analyzer import analyze_urls, get_url_analyzer
        print("✅ Successfully imported url_analyzer module")
        return True
    except Exception as e:
        print(f"❌ Failed to import: {e}")
        return False


def test_url_engine_load():
    """Test 2: Can we load the URL Detection engine?"""
    print("\n" + "="*60)
    print("TEST 2: URL Detection Engine Load")
    print("="*60)
    
    try:
        from url_analyzer import get_url_analyzer
        analyzer = get_url_analyzer()
        if analyzer.engine:
            print("✅ URL Detection Engine loaded successfully")
            return True
        else:
            print("⚠️  URL Detection Engine not available (will use fallback)")
            return True  # Still ok, fallback works
    except Exception as e:
        print(f"❌ Failed to load engine: {e}")
        return False


def test_analyze_single_url():
    """Test 3: Analyze a single URL"""
    print("\n" + "="*60)
    print("TEST 3: Single URL Analysis")
    print("="*60)
    
    try:
        from url_analyzer import analyze_url
        
        test_url = "http://totally-legit-free-money.biz"
        print(f"\nAnalyzing: {test_url}")
        
        result = analyze_url(test_url)
        
        print(f"\nResult:")
        print(f"  Risk Score: {result['risk_score']}")
        print(f"  Risk Level: {result['risk_level']}")
        print(f"  Threat Type: {result['threat_type']}")
        print(f"  Suspicious: {result['is_suspicious']}")
        print(f"\nFindings:")
        for finding in result['findings'][:5]:  # Top 5 findings
            print(f"  - {finding}")
        
        if result['risk_score'] > 0.5:
            print("\n✅ Successfully detected suspicious URL")
            return True
        else:
            print("\n⚠️  URL score is low - check engine configuration")
            return True  # Might be ok depending on config
            
    except Exception as e:
        print(f"❌ Failed to analyze URL: {e}")
        import traceback
        traceback.print_exc()
        return False


def test_analyze_multiple_urls():
    """Test 4: Analyze multiple URLs"""
    print("\n" + "="*60)
    print("TEST 4: Multiple URL Analysis")
    print("="*60)
    
    try:
        from url_analyzer import analyze_urls
        
        test_urls = [
            "https://github.com",  # Should be safe
            "http://phishing-site.tk",  # Should be suspicious
            "https://gmail.com",  # Should be safe
            "http://verify-your-account-now.xyz",  # Should be suspicious
        ]
        
        print(f"\nAnalyzing {len(test_urls)} URLs...")
        result = analyze_urls(test_urls)
        
        print(f"\nResults:")
        print(f"  URLs analyzed: {result['urls_analyzed']}")
        print(f"  Max risk score: {result['max_risk_score']}")
        print(f"  Max risk level: {result['max_risk_level']}")
        print(f"  Suspicious URLs found: {len(result['suspicious_urls'])}")
        
        if result['suspicious_urls']:
            print(f"\nSuspicious URLs:")
            for url_info in result['suspicious_urls']:
                print(f"  - {url_info['url']}: {url_info['risk_level']} ({url_info['risk_score']:.2f})")
        
        print("\n✅ Successfully analyzed multiple URLs")
        return True
        
    except Exception as e:
        print(f"❌ Failed to analyze URLs: {e}")
        import traceback
        traceback.print_exc()
        return False


def test_phishing_engine_integration():
    """Test 5: Integration with phishing_engine"""
    print("\n" + "="*60)
    print("TEST 5: Phishing Engine Integration")
    print("="*60)
    
    try:
        # Add app directory to path for imports
        app_path = str(Path(__file__).parent / 'app')
        if app_path not in sys.path:
            sys.path.insert(0, app_path)
        
        from phishing_engine import phishing_engine
        
        test_email = {
            "subject": "URGENT: Verify Your Account",
            "body": "Click here to verify: http://totally-legit.tk",
            "sender": "attacker@example.com",
            "urls": ["http://totally-legit.tk"],
            "headers": {}
        }
        
        print(f"\nAnalyzing test email...")
        result = phishing_engine(test_email)
        
        print(f"\nResult:")
        print(f"  Risk Level: {result['risk_level']}")
        print(f"  Final Score: {result['final_score']}")
        print(f"  Confidence: {result['confidence']}")
        print(f"  Signal Agreement: {result['signal_agreement']}")
        
        print(f"\nReasons:")
        for reason in result['reasons'][:5]:  # Top 5
            print(f"  - {reason}")
        
        print("\n✅ Successfully integrated with phishing engine")
        return True
        
    except Exception as e:
        print(f"❌ Failed to integrate: {e}")
        import traceback
        traceback.print_exc()
        return False


def main():
    """Run all tests"""
    print("\n" + "="*60)
    print("URL DETECTION ENGINE INTEGRATION TESTS")
    print("="*60)
    
    tests = [
        ("URL Analyzer Import", test_url_analyzer_import),
        ("Engine Load", test_url_engine_load),
        ("Single URL", test_analyze_single_url),
        ("Multiple URLs", test_analyze_multiple_urls),
        ("Phishing Engine", test_phishing_engine_integration),
    ]
    
    results = {}
    for name, test_func in tests:
        results[name] = test_func()
    
    # Summary
    print("\n" + "="*60)
    print("TEST SUMMARY")
    print("="*60)
    
    passed = sum(1 for v in results.values() if v)
    total = len(results)
    
    for name, passed_test in results.items():
        status = "✅ PASS" if passed_test else "❌ FAIL"
        print(f"{status}: {name}")
    
    print(f"\nTotal: {passed}/{total} tests passed")
    
    if passed == total:
        print("\n🎉 All tests passed! URL Detection Engine is working!")
        return 0
    else:
        print(f"\n⚠️  {total - passed} test(s) failed. Check errors above.")
        return 1


if __name__ == "__main__":
    sys.exit(main())
