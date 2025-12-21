"""Test script to verify Groq AI rule generation"""
import asyncio
import os
from pathlib import Path
from impact_scan.core.repo_analyzer import RepoAnalyzer
from impact_scan.utils import schema

async def test_groq_rule_generation():
    """Test that Groq AI generates custom rules"""
    test_path = Path("d:\\oss\\impact-scan\\hexa")

    if not test_path.exists():
        print(f"Test path {test_path} does not exist, skipping test")
        return

    # Check if API key is set in environment
    if not os.environ.get("GROQ_API_KEY"):
        print("ERROR: GROQ_API_KEY environment variable not set")
        print("Set it with: export GROQ_API_KEY=gsk_xxxxxxxx")
        return

    print("=" * 60)
    print("Testing Groq AI Rule Generation")
    print("=" * 60)
    print(f"\nRepository: {test_path}")

    analyzer = RepoAnalyzer(test_path)

    # Run analysis first
    print("\n[1/3] Analyzing repository...")
    analysis = analyzer.analyze()
    print(f"  - Primary language: {analysis['primary_language']}")
    print(f"  - Frameworks: {', '.join(analysis['frameworks']) if analysis['frameworks'] else 'None'}")
    print(f"  - Total files: {analysis['total_files']}")

    # Create AI config
    print("\n[2/3] Setting up Groq AI configuration...")
    api_keys = schema.APIKeys()

    if not api_keys.groq:
        print("  [ERROR] Groq API key not found!")
        return

    print(f"  - API key found: {api_keys.groq[:10]}...")

    class AIConfig:
        def __init__(self):
            self.api_keys = api_keys
            self.ai_provider = 'groq'

    ai_config = AIConfig()
    print(f"  - Provider: {ai_config.ai_provider}")

    # Generate rules with Groq
    print("\n[3/3] Generating custom rules with Groq AI...")
    print("  (This may take a few seconds...)")

    try:
        custom_rules = await analyzer.generate_custom_rules(ai_config=ai_config)

        print(f"\n[SUCCESS] Generated {len(custom_rules)} custom rules!")
        print("\n" + "=" * 60)
        print("Generated Rules:")
        print("=" * 60)

        for i, rule in enumerate(custom_rules, 1):
            print(f"\n{i}. {rule.get('name', 'Unnamed Rule')}")
            print(f"   ID: {rule.get('id', 'N/A')}")
            print(f"   Severity: {rule.get('severity', 'N/A')}")
            print(f"   Description: {rule.get('description', 'N/A')}")
            print(f"   Pattern: {rule.get('pattern', 'N/A')}")
            print(f"   Enabled: {rule.get('enabled', 'N/A')}")

        print("\n" + "=" * 60)
        print("[PASS] Groq AI rule generation test successful!")
        print("=" * 60)

        return custom_rules

    except RuntimeError as e:
        print(f"\n[FAIL] RuntimeError: {e}")
        raise
    except Exception as e:
        print(f"\n[FAIL] Unexpected error: {e}")
        import traceback
        traceback.print_exc()
        raise

if __name__ == "__main__":
    asyncio.run(test_groq_rule_generation())
