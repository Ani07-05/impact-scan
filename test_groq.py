#!/usr/bin/env python3
"""
Quick test script to verify Groq integration works.
"""
import os
import sys
from pathlib import Path

# Add src to path
sys.path.insert(0, str(Path(__file__).parent / "src"))

def test_groq_import():
    """Test if Groq can be imported"""
    print("Test 1: Importing groq library...")
    try:
        from groq import Groq
        print("  ✓ groq library imported successfully")
        return True
    except ImportError as e:
        print(f"  ✗ Failed to import groq: {e}")
        print("    Install with: pip install groq")
        return False

def test_api_key():
    """Test if API key is available"""
    print("\nTest 2: Checking GROQ_API_KEY...")
    key = os.environ.get("GROQ_API_KEY")
    if key:
        preview = key[:20] + "..." if len(key) > 20 else key
        print(f"  ✓ GROQ_API_KEY found: {preview}")
        return True
    else:
        print("  ✗ GROQ_API_KEY not set")
        print("    Set with: export GROQ_API_KEY=gsk_xxxxxxxx")
        return False

def test_analyzer_import():
    """Test if GroqRepoAnalyzer can be imported"""
    print("\nTest 3: Importing GroqRepoAnalyzer...")
    try:
        from impact_scan.core.groq_repo_analyzer import GroqRepoAnalyzer
        print("  ✓ GroqRepoAnalyzer imported successfully")
        return True
    except ImportError as e:
        print(f"  ✗ Failed to import GroqRepoAnalyzer: {e}")
        return False

def test_system_prompts():
    """Test if system prompts can be imported"""
    print("\nTest 4: Importing system prompts...")
    try:
        from impact_scan.core.groq_system_prompt import (
            CODEBASE_ANALYSIS_PROMPT,
            CUSTOM_RULES_GENERATION_PROMPT,
        )
        print(f"  ✓ CODEBASE_ANALYSIS_PROMPT loaded ({len(CODEBASE_ANALYSIS_PROMPT)} chars)")
        print(f"  ✓ CUSTOM_RULES_GENERATION_PROMPT loaded ({len(CUSTOM_RULES_GENERATION_PROMPT)} chars)")
        return True
    except ImportError as e:
        print(f"  ✗ Failed to import prompts: {e}")
        return False

def test_groq_connection():
    """Test if we can connect to Groq API"""
    print("\nTest 5: Testing Groq API connection...")
    
    key = os.environ.get("GROQ_API_KEY")
    if not key:
        print("  ⊘ Skipped (no API key)")
        return None
    
    try:
        from groq import Groq
        client = Groq(api_key=key)
        
        # Simple test message
        response = client.chat.completions.create(
            model="llama-3.3-70b-versatile",
            max_tokens=50,
            messages=[
                {"role": "user", "content": "Say 'Groq is working!' in one short sentence."}
            ]
        )
        
        result = response.choices[0].message.content
        print(f"  ✓ Groq API responded: {result[:60]}...")
        return True
    except Exception as e:
        print(f"  ✗ Groq API error: {e}")
        return False

def main():
    """Run all tests"""
    print("=" * 60)
    print("GROQ INTEGRATION TEST SUITE")
    print("=" * 60)
    
    results = {
        "groq_import": test_groq_import(),
        "api_key": test_api_key(),
        "analyzer_import": test_analyzer_import(),
        "system_prompts": test_system_prompts(),
        "groq_connection": test_groq_connection(),
    }
    
    print("\n" + "=" * 60)
    print("TEST SUMMARY")
    print("=" * 60)
    
    passed = sum(1 for v in results.values() if v is True)
    failed = sum(1 for v in results.values() if v is False)
    skipped = sum(1 for v in results.values() if v is None)
    
    for test_name, result in results.items():
        status = "✓ PASS" if result is True else ("✗ FAIL" if result is False else "⊘ SKIP")
        print(f"{test_name:30} {status}")
    
    print(f"\nTotal: {passed} passed, {failed} failed, {skipped} skipped")
    
    if failed > 0:
        print("\n❌ Some tests failed. Fix errors above.")
        return 1
    elif passed == 5:
        print("\n✅ All tests passed! Ready to use init-repo:")
        print("   impact-scan init-repo /path/to/repo")
        return 0
    else:
        print("\n⚠️  Some tests skipped. Check setup.")
        return 0

if __name__ == "__main__":
    sys.exit(main())
