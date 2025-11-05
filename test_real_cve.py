#!/usr/bin/env python3
"""
Test with a real CVE to validate NVD API integration
"""

import sys
import asyncio
from pathlib import Path

# Add src directory to Python path
sys.path.insert(0, str(Path(__file__).parent / 'src'))

from impact_scan.utils.schema import Finding, Severity, VulnSource, ScanConfig, APIKeys
from impact_scan.core.modern_web_intelligence import ModernWebIntelligenceAgent

def create_real_cve_vulnerability() -> Finding:
    """Create a finding with a real CVE for testing."""
    return Finding(
        file_path=Path("test.py"),
        line_number=1,
        vuln_id="CVE-2023-43804",  # Real recent CVE in urllib3
        rule_id="CVE-2023-43804",
        title="urllib3: Cookie request header isn't stripped during cross-origin redirects",
        severity=Severity.MEDIUM,
        source=VulnSource.DEPENDENCY,
        code_snippet="import urllib3",
        description="urllib3 before v1.26.17 and v2.0.5 vulnerable to cookie injection during redirects",
        fix_suggestion=None,
        web_fix=None,
        ai_fix=None,
        ai_explanation=None,
        citations=None,
        citation=None,
        metadata={}
    )

async def test_real_cve_research():
    """Test the web intelligence system with a real CVE."""
    print("🚀 Testing Real CVE Research")
    print("🎯 CVE-2023-43804 (urllib3 vulnerability)")
    print("=" * 60)
    
    # Create test vulnerability with real CVE
    vuln = create_real_cve_vulnerability()
    
    print("📋 CVE DETAILS")
    print("-" * 20)
    print(f"📄 CVE: {vuln.vuln_id}")
    print(f"⚠️  Severity: {vuln.severity.value.upper()}")
    print(f"📝 Issue: {vuln.description}")
    print()
    
    # Test the modern web intelligence agent
    config = ScanConfig(
        root_path=Path("."),
        enable_web_search=True,
        enable_ai_fixes=False,
        ai_provider=None,
        web_search_delay=1.0,
        api_keys=APIKeys(),
        min_severity=Severity.LOW
    )
    
    print("🔍 RUNNING NVD API + GITHUB INTELLIGENCE...")
    print("-" * 45)
    
    # Initialize the agent
    agent = ModernWebIntelligenceAgent(config)
    await agent.initialize()
    
    try:
        # Research the real CVE
        intelligence = await agent.research_vulnerability(vuln)
        
        print("📊 COMPREHENSIVE INTELLIGENCE RESULTS:")
        print("-" * 40)
        print(f"🎯 Confidence Score: {intelligence.confidence_score:.1%}")
        print(f"📈 Severity Score: {intelligence.severity_score:.2f}")
        print(f"⚡ Exploitability: {intelligence.exploitability_score:.2f}")
        print(f"🔗 Sources Found: {len(intelligence.sources)}")
        print(f"📋 Advisories: {len(intelligence.advisories)}")
        print(f"🔗 Related CVEs: {len(intelligence.related_cves)}")
        print(f"💥 Exploits Found: {len(intelligence.exploits)}")
        print(f"🛡️  Patches Found: {len(intelligence.patches)}")
        print(f"📚 Citations: {len(intelligence.citations)}")
        print()
        
        if intelligence.advisories:
            print("📋 SECURITY ADVISORIES:")
            print("-" * 25)
            for i, advisory in enumerate(intelligence.advisories[:3], 1):
                source = advisory.get('source', 'Unknown')
                desc = advisory.get('description', '')[:100]
                print(f"{i}. [{source}] {desc}...")
            print()
            
        if intelligence.related_cves:
            print("🔗 RELATED CVEs:")
            print("-" * 15)
            for cve in intelligence.related_cves[:5]:
                print(f"• {cve}")
            print()
            
        if intelligence.patches:
            print("🛡️  PATCHES FOUND:")
            print("-" * 17)
            for i, patch in enumerate(intelligence.patches[:3], 1):
                source = patch.get('source', 'Unknown')
                if 'patched_version' in patch:
                    print(f"{i}. [{source}] {patch.get('package', '')} → {patch.get('patched_version', '')}")
                else:
                    print(f"{i}. [{source}] {patch.get('url', '')[:70]}...")
            print()
            
        if intelligence.sources:
            print("🌐 INTELLIGENCE SOURCES:")
            print("-" * 25)
            for i, source in enumerate(intelligence.sources, 1):
                print(f"{i}. {source}")
            print()
            
        print("🎯 NVD API + GITHUB INTELLIGENCE VERDICT:")
        print("-" * 40)
        if intelligence.severity_score > 5.0:
            print("⚠️  HIGH RISK: This CVE has a high severity score")
        elif intelligence.advisories:
            print("✅ COMPREHENSIVE DATA: Successfully retrieved official vulnerability data")
        else:
            print("⚠️  LIMITED DATA: Could not retrieve comprehensive CVE data")
            
        print(f"✅ NVD API integration: {'WORKING' if any('nvd.nist.gov' in src for src in intelligence.sources) else 'NOT TESTED'}")
        print(f"✅ GitHub API integration: {'WORKING' if any(adv.get('source') == 'GitHub Security Advisory' for adv in intelligence.advisories) else 'LIMITED (rate limited)'}")
        
    except Exception as e:
        print(f"❌ Error during CVE research: {e}")
        import traceback
        traceback.print_exc()
        
    finally:
        await agent.cleanup()
        
    print()
    print("🎊 REAL CVE TEST COMPLETE!")
    print("=" * 60)

if __name__ == "__main__":
    asyncio.run(test_real_cve_research())