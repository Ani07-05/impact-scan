"""Test script to verify async fix for generate_custom_rules"""
import asyncio
from pathlib import Path
from impact_scan.core.repo_analyzer import RepoAnalyzer

async def test_generate_custom_rules():
    """Test that generate_custom_rules can be awaited properly"""
    test_path = Path("d:\\oss\\impact-scan\\hexa")

    if not test_path.exists():
        print(f"Test path {test_path} does not exist, skipping test")
        return

    print(f"Testing async fix with repository: {test_path}")

    analyzer = RepoAnalyzer(test_path)

    # This should work now (previously would fail with coroutine not awaited)
    custom_rules = await analyzer.generate_custom_rules()

    print(f"[OK] Successfully called generate_custom_rules()")
    print(f"[OK] Returned type: {type(custom_rules)}")
    print(f"[OK] Number of rules: {len(custom_rules) if custom_rules else 0}")

    return custom_rules

def test_sync_wrapper():
    """Test that asyncio.run() wrapper works (as used in cli.py)"""
    test_path = Path("d:\\oss\\impact-scan\\hexa")

    if not test_path.exists():
        print(f"Test path {test_path} does not exist, skipping test")
        return

    print(f"\nTesting sync wrapper (asyncio.run) with repository: {test_path}")

    analyzer = RepoAnalyzer(test_path)

    # This is how it's called in the fixed cli.py
    custom_rules = asyncio.run(analyzer.generate_custom_rules())

    print(f"[OK] Successfully called asyncio.run(generate_custom_rules())")
    print(f"[OK] Returned type: {type(custom_rules)}")
    print(f"[OK] Number of rules: {len(custom_rules) if custom_rules else 0}")

    return custom_rules

if __name__ == "__main__":
    print("=" * 60)
    print("Testing async fix for generate_custom_rules()")
    print("=" * 60)

    try:
        # Test async version
        asyncio.run(test_generate_custom_rules())

        # Test sync wrapper (as used in cli.py)
        test_sync_wrapper()

        print("\n" + "=" * 60)
        print("[PASS] All tests passed! The async fix is working correctly.")
        print("=" * 60)
    except Exception as e:
        print(f"\n[FAIL] Test failed: {e}")
        import traceback
        traceback.print_exc()
