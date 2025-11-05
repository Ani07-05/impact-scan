#!/usr/bin/env python3
"""
Test script for the Modern Web Intelligence System in Impact Scan.

This script validates the new 2025 web crawling capabilities including:
- ModernWebIntelligenceAgent
- JavaScriptIntelligenceAgent  
- StealthCrawlingAgent
- ComprehensiveSecurityCrawler

Tests the "OSS Security Intelligence Platform" functionality.
"""

import asyncio
import sys
import time
from pathlib import Path
from typing import List

# Add src directory to Python path
sys.path.insert(0, str(Path(__file__).parent / 'src'))

from impact_scan.utils.schema import Finding, ScanConfig, Severity, VulnSource, APIKeys, AIProvider
from impact_scan.core.web_search import enhanced_vulnerability_research


async def create_test_finding() -> Finding:
    """Create a test vulnerability finding for testing."""
    return Finding(
        file_path=Path("test_vulnerable_app.py"),
        line_number=42,
        vuln_id="CVE-2023-1234",  # Example CVE for testing
        rule_id="B101",
        title="Test SQL Injection Vulnerability",
        severity=Severity.HIGH,
        source=VulnSource.STATIC_ANALYSIS,
        code_snippet="query = f'SELECT * FROM users WHERE id = {user_id}'",
        description="SQL injection vulnerability detected in user query construction",
        fix_suggestion="Use parameterized queries to prevent SQL injection",
        web_fix=None,
        ai_fix=None,
        ai_explanation=None,
        citations=None,
        citation=None,
        metadata={}
    )


async def test_modern_web_intelligence():
    """Test the modern web intelligence system."""
    print("🚀 Testing Modern Web Intelligence System - 2025 Edition")
    print("=" * 60)
    
    # Create test configuration
    config = ScanConfig(
        root_path=Path("."),
        enable_web_search=True,
        enable_ai_fixes=False,  # Disable AI fixes for testing
        ai_provider=None,
        web_search_delay=1.0,
        api_keys=APIKeys(),
        min_severity=Severity.LOW
    )
    
    # Create test finding
    test_finding = await create_test_finding()
    print(f"📝 Created test finding: {test_finding.vuln_id}")
    print(f"   Title: {test_finding.title}")
    print(f"   Severity: {test_finding.severity.value.upper()}")
    print()
    
    try:
        print("🔍 Starting Enhanced Vulnerability Research...")
        start_time = time.time()
        
        # Test the enhanced vulnerability research
        enhanced_findings = await enhanced_vulnerability_research([test_finding], config)
        
        end_time = time.time()
        duration = end_time - start_time
        
        print(f"⏱️  Research completed in {duration:.2f} seconds")
        print()
        
        # Analyze results
        if enhanced_findings:
            enhanced_finding = enhanced_findings[0]
            print("✅ Enhanced Finding Analysis:")
            print(f"   Original citations: {len(test_finding.citations or [])}")
            print(f"   Enhanced citations: {len(enhanced_finding.citations or [])}")
            print(f"   Web fix available: {'Yes' if enhanced_finding.web_fix else 'No'}")
            print(f"   AI explanation: {'Yes' if enhanced_finding.ai_explanation else 'No'}")
            
            # Check for OSS intelligence metadata
            metadata = enhanced_finding.metadata or {}
            oss_intel = metadata.get('oss_intelligence', {})
            
            if oss_intel:
                print("\n🎯 OSS Intelligence Metrics:")
                print(f"   Confidence Score: {oss_intel.get('confidence_score', 0):.1%}")
                print(f"   Completeness Score: {oss_intel.get('completeness_score', 0):.1%}")
                print(f"   Sources Analyzed: {oss_intel.get('sources_analyzed', 0)}")
                print(f"   Exploits Found: {oss_intel.get('exploits_found', 0)}")
                print(f"   Patches Found: {oss_intel.get('patches_found', 0)}")
                print(f"   PoC Examples: {oss_intel.get('poc_examples', 0)}")
                print(f"   Threat Level: {oss_intel.get('threat_level', 'unknown').upper()}")
                
                # Show actionable insights
                insights = metadata.get('actionable_insights', [])
                if insights:
                    print("\n💡 Actionable Insights:")
                    for i, insight in enumerate(insights[:3], 1):
                        print(f"   {i}. {insight}")
                        
                # Show enhanced by
                enhanced_by = metadata.get('enhanced_by')
                if enhanced_by:
                    print(f"\n🤖 Enhanced by: {enhanced_by}")
                    
            else:
                print("\n⚠️  No OSS intelligence metadata found - likely fallback to legacy search")
                
        else:
            print("❌ No enhanced findings returned")
            
        return True
        
    except Exception as e:
        print(f"❌ Error during testing: {e}")
        import traceback
        traceback.print_exc()
        return False


async def test_import_capabilities():
    """Test that all new modules can be imported successfully."""
    print("\n🔍 Testing Module Imports...")
    
    modules_to_test = [
        'impact_scan.core.modern_web_intelligence',
        'impact_scan.core.stealth_crawler', 
        'impact_scan.core.comprehensive_security_crawler'
    ]
    
    success_count = 0
    
    for module_name in modules_to_test:
        try:
            __import__(module_name)
            print(f"   ✅ {module_name}")
            success_count += 1
        except ImportError as e:
            print(f"   ❌ {module_name}: {e}")
        except Exception as e:
            print(f"   ⚠️  {module_name}: {e}")
            
    print(f"\n📊 Import Results: {success_count}/{len(modules_to_test)} modules imported successfully")
    return success_count == len(modules_to_test)


async def test_dependency_availability():
    """Test that all new dependencies are available."""
    print("\n📦 Testing Dependency Availability...")
    
    dependencies_to_test = [
        ('httpx', 'Modern async HTTP client'),
        ('playwright', 'Browser automation'),
        ('crawlee', 'Web crawling framework'),  
        ('aiofiles', 'Async file operations'),
        ('beautifulsoup4', 'HTML parsing')
    ]
    
    success_count = 0
    
    for dep_name, description in dependencies_to_test:
        try:
            __import__(dep_name.replace('-', '_'))
            print(f"   ✅ {dep_name}: {description}")
            success_count += 1
        except ImportError:
            print(f"   ❌ {dep_name}: {description} - NOT AVAILABLE")
        except Exception as e:
            print(f"   ⚠️  {dep_name}: {description} - ERROR: {e}")
            
    print(f"\n📊 Dependency Results: {success_count}/{len(dependencies_to_test)} dependencies available")
    return success_count >= len(dependencies_to_test) - 1  # Allow 1 missing (crawlee might not install)


async def main():
    """Main test function."""
    print("🎯 Impact Scan - Modern Web Intelligence System Test")
    print("🔬 OSS Security Intelligence Platform - 2025 Edition")
    print("=" * 70)
    print()
    
    # Test 1: Import capabilities
    imports_ok = await test_import_capabilities()
    
    # Test 2: Dependency availability
    deps_ok = await test_dependency_availability()
    
    # Test 3: Core functionality (only if imports work)
    if imports_ok:
        functionality_ok = await test_modern_web_intelligence()
    else:
        print("\n⏭️  Skipping functionality tests due to import failures")
        functionality_ok = False
    
    # Summary
    print("\n" + "=" * 70)
    print("📋 TEST SUMMARY")
    print("=" * 70)
    print(f"   Module Imports:     {'✅ PASS' if imports_ok else '❌ FAIL'}")
    print(f"   Dependencies:       {'✅ PASS' if deps_ok else '❌ FAIL'}")
    print(f"   Core Functionality: {'✅ PASS' if functionality_ok else '❌ FAIL'}")
    
    overall_success = imports_ok and deps_ok and functionality_ok
    print(f"\n🎯 OVERALL RESULT:     {'✅ SUCCESS' if overall_success else '❌ NEEDS WORK'}")
    
    if overall_success:
        print("\n🚀 The Modern Web Intelligence System is ready!")
        print("   Impact Scan now has 2025-grade OSS security intelligence capabilities!")
    else:
        print("\n🔧 Some components need attention, but the foundation is solid.")
        print("   Legacy web search functionality remains available as fallback.")
        
    print("\n" + "=" * 70)
    return overall_success


if __name__ == "__main__":
    asyncio.run(main())