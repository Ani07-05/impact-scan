#!/usr/bin/env python3
"""
Demo: OSS Security Intelligence Platform in Action

This script demonstrates how Impact Scan goes beyond basic static analysis
to become the "Nmap of Codebases" - showing comprehensive security intelligence
gathering for real vulnerabilities found in the Impact Scan project itself.
"""

import asyncio
import sys
from pathlib import Path

# Add src directory to Python path
sys.path.insert(0, str(Path(__file__).parent / 'src'))

from impact_scan.utils.schema import Finding, ScanConfig, Severity, VulnSource, APIKeys
from impact_scan.core.web_search import enhanced_vulnerability_research


async def create_real_vulnerability_example() -> Finding:
    """
    Create a Finding based on actual vulnerability detected in Impact Scan's own code.
    
    This is a real B404 vulnerability found in the agents/recon.py file where
    subprocess module is imported (flagged as potentially dangerous).
    """
    return Finding(
        file_path=Path("src/impact_scan/agents/recon.py"),
        line_number=8,
        vuln_id="B404",  # Real Bandit rule ID
        rule_id="B404",
        title="blacklist",  # Bandit's title for this rule
        severity=Severity.LOW,
        source=VulnSource.STATIC_ANALYSIS,
        code_snippet="import subprocess",
        description="Consider possible security implications associated with the subprocess module.",
        fix_suggestion=None,
        web_fix=None,
        ai_fix=None,
        ai_explanation=None,
        citations=None,
        citation=None,
        metadata={}
    )


async def create_subprocess_vulnerability_example() -> Finding:
    """Create a more interesting subprocess vulnerability example."""
    return Finding(
        file_path=Path("src/impact_scan/core/dep_audit.py"),
        line_number=51,
        vuln_id="B603",
        rule_id="B603", 
        title="subprocess_without_shell_equals_true",
        severity=Severity.LOW,
        source=VulnSource.STATIC_ANALYSIS,
        code_snippet="""subprocess.run(
    ["pnpm", "audit", "--json"],
    capture_output=True,
    text=True,
    shell=False,  # Explicitly disable shell to prevent injection
)""",
        description="subprocess call - check for execution of untrusted input.",
        fix_suggestion=None,
        web_fix=None,
        ai_fix=None,
        ai_explanation=None,
        citations=None,
        citation=None,
        metadata={}
    )


def display_vulnerability_analysis(finding: Finding, enhanced_finding: Finding):
    """Display comprehensive vulnerability analysis."""
    print("🔍 VULNERABILITY ANALYSIS")
    print("=" * 50)
    print(f"📁 File: {finding.file_path}")
    print(f"📏 Line: {finding.line_number}")
    print(f"🆔 ID: {finding.vuln_id}")
    print(f"⚠️  Severity: {finding.severity.value.upper()}")
    print(f"📝 Description: {finding.description}")
    print()
    
    # Show code snippet
    print("💻 VULNERABLE CODE:")
    print("-" * 20)
    print(finding.code_snippet)
    print()
    
    # Check for OSS intelligence enhancements
    metadata = enhanced_finding.metadata or {}
    oss_intel = metadata.get('oss_intelligence', {})
    
    if oss_intel:
        print("🎯 OSS SECURITY INTELLIGENCE")
        print("=" * 50)
        print(f"🎯 Confidence Score: {oss_intel.get('confidence_score', 0):.1%}")
        print(f"📊 Completeness: {oss_intel.get('completeness_score', 0):.1%}")
        print(f"🔗 Sources Analyzed: {oss_intel.get('sources_analyzed', 0)}")
        print(f"💥 Exploits Found: {oss_intel.get('exploits_found', 0)}")
        print(f"🛡️  Patches Found: {oss_intel.get('patches_found', 0)}")
        print(f"🛠️  PoC Examples: {oss_intel.get('poc_examples', 0)}")
        print(f"⚡ Threat Level: {oss_intel.get('threat_level', 'unknown').upper()}")
        print(f"⏰ Enhanced: {oss_intel.get('intelligence_timestamp', 'N/A')}")
        print()
        
        # Show actionable insights
        insights = metadata.get('actionable_insights', [])
        if insights:
            print("💡 ACTIONABLE INSIGHTS")
            print("=" * 50)
            for i, insight in enumerate(insights, 1):
                print(f"{i}. {insight}")
            print()
            
        # Show risk assessment
        risk_assessment = metadata.get('risk_assessment', {})
        if risk_assessment:
            print("📈 RISK ASSESSMENT")
            print("=" * 50)
            print(f"Base Severity: {risk_assessment.get('base_severity_score', 0):.2f}")
            print(f"Exploit Factor: {risk_assessment.get('exploit_factor', 0):.2f}")
            print(f"PoC Factor: {risk_assessment.get('poc_factor', 0):.2f}")
            print(f"Patch Factor: {risk_assessment.get('patch_factor', 0):.2f}")
            print(f"📊 FINAL RISK SCORE: {risk_assessment.get('final_risk_score', 0):.2f}")
            print()
    else:
        print("ℹ️  OSS Intelligence: Using legacy search fallback")
        print()
        
    # Show citations
    if enhanced_finding.citations:
        print("📚 CITATIONS & SOURCES")
        print("=" * 50)
        for i, citation in enumerate(enhanced_finding.citations, 1):
            print(f"{i}. {citation}")
        print()
        
    # Show web fixes
    if enhanced_finding.web_fix:
        print("🌐 WEB RESEARCH FIXES")
        print("=" * 50)
        print(enhanced_finding.web_fix)
        print()
        
    # Show AI explanations
    if enhanced_finding.ai_explanation:
        print("🤖 AI ANALYSIS")
        print("=" * 50)
        print(enhanced_finding.ai_explanation)
        print()
        
    print("✅ Analysis Complete!")
    print("=" * 70)


async def demo_oss_security_intelligence():
    """Demonstrate the OSS Security Intelligence Platform in action."""
    print("🚀 OSS Security Intelligence Platform Demo")
    print("🎯 Impact Scan: The 'Nmap of Codebases'")
    print("=" * 70)
    print()
    print("This demo shows how Impact Scan transforms from basic static analysis")
    print("into comprehensive security intelligence gathering...")
    print()
    
    # Create test configuration (without API keys for demo)
    config = ScanConfig(
        root_path=Path("."),
        enable_web_search=True,
        enable_ai_fixes=False,
        ai_provider=None,
        web_search_delay=1.0,
        api_keys=APIKeys(),  # No API keys - will use fallback
        min_severity=Severity.LOW
    )
    
    # Demo 1: B404 subprocess import vulnerability
    print("📋 DEMO 1: Subprocess Import Vulnerability (B404)")
    print("=" * 70)
    
    vuln_1 = await create_real_vulnerability_example()
    print("🔍 Running OSS Security Intelligence Research...")
    print("   (This may take a few moments as we research across multiple sources)")
    print()
    
    enhanced_findings = await enhanced_vulnerability_research([vuln_1], config)
    enhanced_vuln_1 = enhanced_findings[0] if enhanced_findings else vuln_1
    
    display_vulnerability_analysis(vuln_1, enhanced_vuln_1)
    print()
    
    # Demo 2: B603 subprocess execution vulnerability  
    print("📋 DEMO 2: Subprocess Execution Vulnerability (B603)")
    print("=" * 70)
    
    vuln_2 = await create_subprocess_vulnerability_example()
    print("🔍 Running Enhanced Security Research...")
    print()
    
    enhanced_findings_2 = await enhanced_vulnerability_research([vuln_2], config)
    enhanced_vuln_2 = enhanced_findings_2[0] if enhanced_findings_2 else vuln_2
    
    display_vulnerability_analysis(vuln_2, enhanced_vuln_2)
    print()
    
    # Summary
    print("🎊 OSS SECURITY INTELLIGENCE PLATFORM SUMMARY")
    print("=" * 70)
    print("✅ Successfully demonstrated comprehensive vulnerability research")
    print("✅ Analyzed real vulnerabilities from Impact Scan's own codebase")  
    print("✅ Showed fallback capabilities when API keys not available")
    print("✅ Displayed structured intelligence gathering and risk assessment")
    print()
    print("🚀 WITH API KEYS (Gemini, OpenAI, Anthropic), you would see:")
    print("   • AI-powered vulnerability explanations")
    print("   • Comprehensive web research across 40+ security sources")
    print("   • PoC discovery and exploitation analysis")
    print("   • Vendor patch information and remediation guidance")
    print("   • Threat intelligence and real-world usage data")
    print()
    print("🎯 This is how Impact Scan becomes the 'Nmap of Codebases'!")
    print("=" * 70)


async def main():
    """Main demo function."""
    try:
        await demo_oss_security_intelligence()
    except Exception as e:
        print(f"❌ Error during demo: {e}")
        import traceback
        traceback.print_exc()


if __name__ == "__main__":
    asyncio.run(main())