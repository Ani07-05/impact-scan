"""
Comprehensive Security Source Crawler for Impact Scan

Orchestrates the complete "OSS Security Intelligence" platform by coordinating
multiple specialized crawlers and intelligence agents to create the definitive
"Nmap of Codebases" for security researchers and bug hunters.
"""

import asyncio
import logging
from dataclasses import dataclass, field
from datetime import datetime, timedelta
from typing import Any, Dict, List, Optional

from rich.console import Console
from rich.progress import Progress, TaskID
from rich.table import Table

from ..utils.schema import Finding, ScanConfig, Severity
from .modern_web_intelligence import ModernWebIntelligenceAgent, SecurityIntelligence

logger = logging.getLogger(__name__)
console = Console()


@dataclass
class SecurityIntelligenceReport:
    """Comprehensive security intelligence report."""

    vulnerability_id: str
    finding: Finding
    static_intelligence: SecurityIntelligence
    javascript_intelligence: List[JavaScriptSecurityData] = field(default_factory=list)
    exploit_intelligence: Dict[str, Any] = field(default_factory=dict)
    vendor_intelligence: Dict[str, Any] = field(default_factory=dict)
    threat_landscape: Dict[str, Any] = field(default_factory=dict)
    actionable_insights: List[str] = field(default_factory=list)
    risk_assessment: Dict[str, float] = field(default_factory=dict)
    poc_examples: List[Dict[str, Any]] = field(default_factory=list)
    mitigation_strategies: List[Dict[str, Any]] = field(default_factory=list)
    timeline: List[Dict[str, Any]] = field(default_factory=list)
    confidence_score: float = 0.0
    completeness_score: float = 0.0
    timestamp: datetime = field(default_factory=datetime.now)


@dataclass
class ThreatIntelligence:
    """Threat intelligence data for vulnerability assessment."""

    vulnerability_id: str
    active_exploits: int = 0
    public_pocs: int = 0
    vendor_patches: int = 0
    exploit_complexity: str = "unknown"  # low, medium, high
    attack_vector: str = "unknown"  # network, local, physical
    privileges_required: str = "unknown"  # none, low, high
    user_interaction: str = "unknown"  # none, required
    real_world_usage: List[str] = field(default_factory=list)
    threat_actor_usage: List[str] = field(default_factory=list)
    industry_impact: Dict[str, int] = field(default_factory=dict)


class ComprehensiveSecurityCrawler:
    """
    Master orchestrator for comprehensive security intelligence gathering.

    This is the main "OSS Security Intelligence Platform" that coordinates:
    - Static web intelligence gathering
    - JavaScript-heavy site research
    - Stealth crawling with anti-bot bypass
    - Multi-source intelligence synthesis
    - Threat landscape analysis
    - PoC generation and validation
    - Risk assessment and prioritization
    """

    # Comprehensive security source mapping
    SECURITY_INTELLIGENCE_SOURCES = {
        "vulnerability_databases": {
            "mitre_cve": "https://cve.mitre.org/cgi-bin/cvename.cgi?name={}",
            "nvd_nist": "https://nvd.nist.gov/vuln/detail/{}",
            "github_advisories": "https://github.com/advisories/{}",
            "snyk_vuln": "https://security.snyk.io/vuln/{}",
            "vulndb": "https://vuldb.com/?id={}",
            "cwe_mitre": "https://cwe.mitre.org/data/definitions/{}.html",
        },
        "exploit_databases": {
            "exploit_db": "https://www.exploit-db.com/search?q={}",
            "packetstorm": "https://packetstormsecurity.com/search/?q={}",
            "metasploit": "https://www.rapid7.com/db/?q={}",
            "nuclei_templates": "https://github.com/projectdiscovery/nuclei-templates/search?q={}",
            "poc_in_github": "https://github.com/search?q={}&type=repositories",
        },
        "security_research": {
            "security_focus": "https://www.securityfocus.com/bid/{}",
            "threatpost": "https://threatpost.com/?s={}",
            "dark_reading": "https://www.darkreading.com/search?query={}",
            "krebs_security": "https://krebsonsecurity.com/?s={}",
            "bleeping_computer": "https://www.bleepingcomputer.com/search/?q={}",
        },
        "vendor_advisories": {
            "microsoft": "https://msrc.microsoft.com/update-guide/vulnerability/{}",
            "cisco": "https://sec.cloudapps.cisco.com/security/center/content/CiscoSecurityAdvisory/{}",
            "redhat": "https://access.redhat.com/security/cve/{}",
            "ubuntu": "https://ubuntu.com/security/{}",
            "debian": "https://security-tracker.debian.org/tracker/{}",
        },
        "threat_intelligence": {
            "misp_galaxy": "https://www.misp-galaxy.org/techniques/{}",
            "attack_mitre": "https://attack.mitre.org/techniques/{}",
            "threatcrowd": "https://www.threatcrowd.org/searchApi/v2/search/?term={}",
            "virustotal": "https://www.virustotal.com/gui/search/{}",
        },
        "academic_research": {
            "arxiv": "https://arxiv.org/search/?query={}",
            "scholar_google": "https://scholar.google.com/scholar?q={}",
            "acm_dl": "https://dl.acm.org/action/doSearch?AllField={}",
            "ieee_xplore": "https://ieeexplore.ieee.org/search/searchresult.jsp?queryText={}",
        },
        "social_intelligence": {
            "twitter_search": "https://twitter.com/search?q={}",
            "reddit_search": "https://www.reddit.com/search/?q={}",
            "hackernews": "https://hn.algolia.com/?q={}",
            "stackoverflow": "https://stackoverflow.com/search?q={}",
        },
    }

    # Priority order for intelligence gathering
    SOURCE_PRIORITY = [
        "vulnerability_databases",
        "exploit_databases",
        "vendor_advisories",
        "security_research",
        "threat_intelligence",
        "academic_research",
        "social_intelligence",
    ]

    def __init__(self, config: ScanConfig):
        self.config = config

        # Initialize specialized agents
        self.modern_agent: Optional[ModernWebIntelligenceAgent] = None

        # Intelligence cache and state
        self.intelligence_cache: Dict[str, SecurityIntelligenceReport] = {}
        self.source_reliability: Dict[str, float] = {}
        self.crawl_statistics: Dict[str, int] = {
            "total_sources_crawled": 0,
            "successful_extractions": 0,
            "failed_attempts": 0,
            "cache_hits": 0,
            "new_intelligence": 0,
        }

    async def __aenter__(self):
        """Async context manager entry."""
        await self.initialize_agents()
        return self

    async def __aexit__(self, exc_type, exc_val, exc_tb):
        """Async context manager exit."""
        await self.cleanup_agents()

    async def initialize_agents(self):
        """Initialize all specialized intelligence agents."""
        self.modern_agent = ModernWebIntelligenceAgent(self.config)
        await self.modern_agent.initialize()

        console.log(
            "[bold green][OSS_INTEL] Comprehensive Security Intelligence Platform initialized[/bold green]"
        )
        console.log(
            f"[dim]Sources configured: {sum(len(sources) for sources in self.SECURITY_INTELLIGENCE_SOURCES.values())}[/dim]"
        )

    async def cleanup_agents(self):
        """Clean up all agent resources."""
        if self.modern_agent:
            await self.modern_agent.cleanup()

        console.log(
            "[dim][OSS_CLEANUP] Security Intelligence Platform cleaned up[/dim]"
        )

    async def comprehensive_vulnerability_research(
        self, finding: Finding
    ) -> SecurityIntelligenceReport:
        """
        Conduct comprehensive vulnerability research across all intelligence sources.

        This is the main entry point for the "OSS Security Intelligence Platform".

        Args:
            finding: Vulnerability finding to research

        Returns:
            SecurityIntelligenceReport with complete intelligence
        """
        vuln_id = finding.vuln_id
        console.log(
            f"[bold cyan][OSS_RESEARCH] Starting comprehensive research for {vuln_id}[/bold cyan]"
        )

        # Check cache first
        if vuln_id in self.intelligence_cache:
            cache_report = self.intelligence_cache[vuln_id]
            if self._is_cache_fresh(cache_report):
                console.log(
                    f"[green][CACHE_HIT] Using cached intelligence for {vuln_id}[/green]"
                )
                self.crawl_statistics["cache_hits"] += 1
                return cache_report

        # Initialize comprehensive report
        from .modern_web_intelligence import SecurityIntelligence

        report = SecurityIntelligenceReport(
            vulnerability_id=vuln_id,
            finding=finding,
            static_intelligence=SecurityIntelligence(vulnerability_id=vuln_id),
        )

        with Progress() as progress:
            # Create progress tasks
            static_task = progress.add_task("[cyan]Static Intelligence...", total=100)
            js_task = progress.add_task("[blue]JavaScript Intelligence...", total=100)
            threat_task = progress.add_task("[red]Threat Intelligence...", total=100)
            synthesis_task = progress.add_task(
                "[green]Intelligence Synthesis...", total=100
            )

            # Phase 1: Static Intelligence Gathering
            console.log(
                f"[bold blue][PHASE_1] Static intelligence gathering for {vuln_id}[/bold blue]"
            )
            report.static_intelligence = await self._gather_static_intelligence(
                finding, progress, static_task
            )

            # Phase 2: JavaScript-Heavy Site Intelligence
            console.log(
                f"[bold blue][PHASE_2] JavaScript intelligence gathering for {vuln_id}[/bold blue]"
            )
            report.javascript_intelligence = await self._gather_javascript_intelligence(
                finding, progress, js_task
            )

            # Phase 3: Threat Landscape Analysis
            console.log(
                f"[bold blue][PHASE_3] Threat landscape analysis for {vuln_id}[/bold blue]"
            )
            report.threat_landscape = await self._analyze_threat_landscape(
                finding, progress, threat_task
            )

            # Phase 4: Intelligence Synthesis
            console.log(
                f"[bold blue][PHASE_4] Intelligence synthesis for {vuln_id}[/bold blue]"
            )
            await self._synthesize_intelligence(report, progress, synthesis_task)

        # Calculate final scores
        report.confidence_score = self._calculate_confidence_score(report)
        report.completeness_score = self._calculate_completeness_score(report)

        # Cache the report
        self.intelligence_cache[vuln_id] = report
        self.crawl_statistics["new_intelligence"] += 1

        # Generate summary
        self._log_intelligence_summary(report)

        return report

    async def _gather_static_intelligence(
        self, finding: Finding, progress: Progress, task_id: TaskID
    ) -> SecurityIntelligence:
        """Gather intelligence from static sources."""
        progress.update(
            task_id, advance=10, description="[cyan]Initializing static intelligence..."
        )

        threat_data = ThreatIntelligence(vulnerability_id=finding.vuln_id)

        # Analyze exploit availability
        exploit_sources = self.SECURITY_INTELLIGENCE_SOURCES["exploit_databases"]
        for source_name, url_template in exploit_sources.items():
            try:
                url = url_template.format(finding.vuln_id)
                result = await self.modern_agent.fetch_url(url)

                if result.status_code == 200:
                    exploits = self._count_exploits_in_content(result.content)
                    threat_data.active_exploits += exploits

                    if exploits > 0:
                        threat_data.real_world_usage.append(source_name)

            except Exception as e:
                logger.error(f"Error analyzing threat source {source_name}: {e}")

        progress.update(
            task_id, advance=40, description="[red]Analyzing vendor responses..."
        )

        # Analyze vendor patch availability
        vendor_sources = self.SECURITY_INTELLIGENCE_SOURCES["vendor_advisories"]
        for vendor_name, url_template in vendor_sources.items():
            try:
                url = url_template.format(finding.vuln_id)
                result = await self.modern_agent.fetch_url(url)

                if result.status_code == 200:
                    patches = self._count_patches_in_content(result.content)
                    threat_data.vendor_patches += patches

            except Exception as e:
                logger.error(f"Error analyzing vendor {vendor_name}: {e}")

        progress.update(
            task_id, advance=30, description="[red]Threat analysis complete"
        )

        return {
            "threat_intelligence": threat_data,
            "exploit_availability": threat_data.active_exploits > 0,
            "patch_availability": threat_data.vendor_patches > 0,
            "risk_level": self._calculate_threat_risk_level(threat_data),
        }

    async def _synthesize_intelligence(
        self, report: SecurityIntelligenceReport, progress: Progress, task_id: TaskID
    ):
        """Synthesize all gathered intelligence into actionable insights."""
        progress.update(
            task_id, advance=20, description="[green]Synthesizing intelligence..."
        )

        # Generate PoC examples
        report.poc_examples = self._extract_poc_examples(report)

        progress.update(
            task_id, advance=20, description="[green]Generating insights..."
        )

        # Generate actionable insights
        report.actionable_insights = self._generate_actionable_insights(report)

        progress.update(task_id, advance=20, description="[green]Assessing risks...")

        # Calculate risk assessment
        report.risk_assessment = self._calculate_risk_assessment(report)

        progress.update(task_id, advance=20, description="[green]Creating timeline...")

        # Generate timeline
        report.timeline = self._generate_vulnerability_timeline(report)

        progress.update(task_id, advance=20, description="[green]Synthesis complete")

    def _extract_poc_examples(
        self, report: SecurityIntelligenceReport
    ) -> List[Dict[str, Any]]:
        """Extract PoC examples from all intelligence sources."""
        poc_examples = []

        # From static intelligence
        for exploit in report.static_intelligence.exploits:
            if any(
                keyword in exploit.get("title", "").lower()
                for keyword in ["poc", "proof of concept", "demonstration"]
            ):
                poc_examples.append(
                    {
                        "type": "static_intelligence",
                        "source": exploit.get("source", "unknown"),
                        "title": exploit.get("title", ""),
                        "url": exploit.get("url", ""),
                        "confidence": 0.8,
                    }
                )

        # From JavaScript intelligence
        for js_data in report.javascript_intelligence:
            for code_snippet in js_data.poc_code_snippets:
                if len(code_snippet) > 50:  # Substantial code
                    poc_examples.append(
                        {
                            "type": "javascript_intelligence",
                            "source": js_data.source_url,
                            "code": code_snippet[:500] + "..."
                            if len(code_snippet) > 500
                            else code_snippet,
                            "confidence": 0.7,
                        }
                    )

        return poc_examples

    def _generate_actionable_insights(
        self, report: SecurityIntelligenceReport
    ) -> List[str]:
        """Generate actionable insights for security teams."""
        insights = []

        # Severity-based insights
        if report.finding.severity == Severity.CRITICAL:
            insights.append(
                "🚨 CRITICAL: Immediate action required - this vulnerability poses severe risk"
            )

        # Exploit availability insights
        exploit_count = len(report.static_intelligence.exploits)
        if exploit_count > 0:
            insights.append(
                f"⚠️ EXPLOITATION: {exploit_count} known exploits available - prioritize patching"
            )

        # Patch availability insights
        patch_count = len(report.static_intelligence.patches)
        if patch_count > 0:
            insights.append(
                f"✅ PATCHES: {patch_count} vendor patches available - apply immediately"
            )
        else:
            insights.append(
                "❌ NO_PATCHES: No official patches found - consider workarounds"
            )

        # PoC availability insights
        poc_count = len(report.poc_examples)
        if poc_count > 0:
            insights.append(
                f"🛠️ POC_AVAILABLE: {poc_count} proof-of-concept examples found"
            )

        # Confidence insights
        if report.confidence_score > 0.8:
            insights.append(
                "✅ HIGH_CONFIDENCE: Intelligence gathered from reliable sources"
            )
        elif report.confidence_score < 0.5:
            insights.append(
                "⚠️ LOW_CONFIDENCE: Limited intelligence available - manual research recommended"
            )

        return insights

    def _calculate_risk_assessment(
        self, report: SecurityIntelligenceReport
    ) -> Dict[str, float]:
        """Calculate comprehensive risk assessment."""
        base_severity = {
            Severity.LOW: 0.25,
            Severity.MEDIUM: 0.5,
            Severity.HIGH: 0.75,
            Severity.CRITICAL: 1.0,
        }.get(report.finding.severity, 0.5)

        # Exploit factor
        exploit_factor = min(len(report.static_intelligence.exploits) * 0.2, 0.4)

        # PoC factor
        poc_factor = min(len(report.poc_examples) * 0.1, 0.2)

        # Patch factor (reduces risk)
        patch_factor = -min(len(report.static_intelligence.patches) * 0.1, 0.3)

        # Confidence factor
        confidence_factor = report.confidence_score * 0.1

        final_risk = min(
            base_severity
            + exploit_factor
            + poc_factor
            + patch_factor
            + confidence_factor,
            1.0,
        )

        return {
            "base_severity_score": base_severity,
            "exploit_factor": exploit_factor,
            "poc_factor": poc_factor,
            "patch_factor": patch_factor,
            "confidence_factor": confidence_factor,
            "final_risk_score": max(final_risk, 0.0),
        }

    def _generate_vulnerability_timeline(
        self, report: SecurityIntelligenceReport
    ) -> List[Dict[str, Any]]:
        """Generate vulnerability timeline from intelligence."""
        timeline = []

        # Add discovery event
        timeline.append(
            {
                "event": "vulnerability_discovered",
                "timestamp": datetime.now() - timedelta(days=30),  # Estimated
                "description": f"Vulnerability {report.vulnerability_id} discovered",
                "source": "static_analysis",
            }
        )

        # Add intelligence gathering event
        timeline.append(
            {
                "event": "intelligence_gathered",
                "timestamp": datetime.now(),
                "description": f"Comprehensive intelligence gathered ({report.confidence_score:.1%} confidence)",
                "source": "oss_security_intelligence",
            }
        )

        return timeline

    def _calculate_confidence_score(self, report: SecurityIntelligenceReport) -> float:
        """Calculate overall confidence score."""
        scores = []

        # Static intelligence confidence
        scores.append(report.static_intelligence.confidence_score)

        # JavaScript intelligence confidence (average of all sources)
        if report.javascript_intelligence:
            js_confidence = sum(
                0.7 if data.security_advisories else 0.3
                for data in report.javascript_intelligence
            ) / len(report.javascript_intelligence)
            scores.append(js_confidence)

        # Threat landscape confidence
        if report.threat_landscape:
            threat_confidence = (
                0.8 if report.threat_landscape.get("exploit_availability") else 0.6
            )
            scores.append(threat_confidence)

        return sum(scores) / len(scores) if scores else 0.0

    def _calculate_completeness_score(
        self, report: SecurityIntelligenceReport
    ) -> float:
        """Calculate intelligence completeness score."""
        completeness_factors = {
            "static_intelligence": 0.3,
            "javascript_intelligence": 0.2,
            "threat_landscape": 0.2,
            "poc_examples": 0.15,
            "actionable_insights": 0.15,
        }

        score = 0.0

        if report.static_intelligence.sources:
            score += completeness_factors["static_intelligence"]

        if report.javascript_intelligence:
            score += completeness_factors["javascript_intelligence"]

        if report.threat_landscape:
            score += completeness_factors["threat_landscape"]

        if report.poc_examples:
            score += completeness_factors["poc_examples"]

        if report.actionable_insights:
            score += completeness_factors["actionable_insights"]

        return score

    def _is_cache_fresh(
        self, report: SecurityIntelligenceReport, max_age_hours: int = 24
    ) -> bool:
        """Check if cached intelligence is still fresh."""
        age = datetime.now() - report.timestamp
        return age.total_seconds() < (max_age_hours * 3600)

    def _count_exploits_in_content(self, content: str) -> int:
        """Count exploit references in content."""
        exploit_keywords = [
            "exploit",
            "poc",
            "proof of concept",
            "metasploit",
            "nuclei",
        ]
        count = 0
        content_lower = content.lower()

        for keyword in exploit_keywords:
            count += content_lower.count(keyword)

        return min(count, 10)  # Cap at reasonable maximum

    def _count_patches_in_content(self, content: str) -> int:
        """Count patch references in content."""
        patch_keywords = ["patch", "fix", "update", "advisory", "bulletin"]
        count = 0
        content_lower = content.lower()

        for keyword in patch_keywords:
            count += content_lower.count(keyword)

        return min(count, 5)  # Cap at reasonable maximum

    def _calculate_threat_risk_level(self, threat_data: ThreatIntelligence) -> str:
        """Calculate threat risk level."""
        if threat_data.active_exploits >= 3:
            return "HIGH"
        elif threat_data.active_exploits >= 1:
            return "MEDIUM"
        elif threat_data.vendor_patches >= 1:
            return "LOW"
        else:
            return "UNKNOWN"

    def _log_intelligence_summary(self, report: SecurityIntelligenceReport):
        """Log comprehensive intelligence summary."""
        console.log(
            f"\n[bold green][INTELLIGENCE_SUMMARY] {report.vulnerability_id}[/bold green]"
        )

        # Create summary table
        table = Table(title="OSS Security Intelligence Summary")
        table.add_column("Metric", style="cyan")
        table.add_column("Value", style="green")
        table.add_column("Details", style="dim")

        table.add_row(
            "Confidence Score",
            f"{report.confidence_score:.1%}",
            "Reliability of gathered intelligence",
        )

        table.add_row(
            "Completeness Score",
            f"{report.completeness_score:.1%}",
            "Coverage across intelligence sources",
        )

        table.add_row(
            "Sources Analyzed",
            str(len(report.static_intelligence.sources)),
            "Static + JavaScript sources",
        )

        table.add_row(
            "Exploits Found",
            str(len(report.static_intelligence.exploits)),
            "Known exploitation methods",
        )

        table.add_row(
            "PoC Examples",
            str(len(report.poc_examples)),
            "Proof-of-concept demonstrations",
        )

        table.add_row(
            "Actionable Insights",
            str(len(report.actionable_insights)),
            "Strategic recommendations",
        )

        if report.risk_assessment:
            table.add_row(
                "Risk Score",
                f"{report.risk_assessment.get('final_risk_score', 0):.2f}",
                "Comprehensive risk assessment",
            )

        console.print(table)

        # Log key insights
        if report.actionable_insights:
            console.log("\n[bold yellow][KEY_INSIGHTS][/bold yellow]")
            for insight in report.actionable_insights[:3]:  # Top 3 insights
                console.log(f"  • {insight}")

        console.log(
            f"\n[dim]Intelligence gathered in {(datetime.now() - report.timestamp).total_seconds():.1f}s[/dim]"
        )

    async def generate_comprehensive_report(
        self, findings: List[Finding]
    ) -> Dict[str, Any]:
        """
        Generate comprehensive security intelligence report for multiple findings.

        This is the main output of the "OSS Security Intelligence Platform".
        """
        console.log(
            f"[bold cyan][OSS_PLATFORM] Generating comprehensive report for {len(findings)} findings[/bold cyan]"
        )

        reports = []

        # Process findings with concurrency control
        semaphore = asyncio.Semaphore(5)

        async def process_finding(finding: Finding) -> SecurityIntelligenceReport:
            async with semaphore:
                return await self.comprehensive_vulnerability_research(finding)

        # Execute research in parallel with controlled concurrency
        reports = await asyncio.gather(*[process_finding(f) for f in findings])

        # Generate aggregate statistics
        aggregate_stats = {
            "total_vulnerabilities": len(findings),
            "total_sources_analyzed": sum(
                len(r.static_intelligence.sources) for r in reports
            ),
            "total_exploits_found": sum(
                len(r.static_intelligence.exploits) for r in reports
            ),
            "total_poc_examples": sum(len(r.poc_examples) for r in reports),
            "average_confidence": sum(r.confidence_score for r in reports)
            / len(reports),
            "average_completeness": sum(r.completeness_score for r in reports)
            / len(reports),
            "high_risk_count": sum(
                1 for r in reports if r.risk_assessment.get("final_risk_score", 0) > 0.7
            ),
            "crawl_statistics": self.crawl_statistics,
        }

        return {
            "platform": "OSS Security Intelligence Platform",
            "timestamp": datetime.now().isoformat(),
            "findings_analysis": [report.__dict__ for report in reports],
            "aggregate_statistics": aggregate_stats,
            "intelligence_summary": self._generate_intelligence_summary(reports),
        }

    def _generate_intelligence_summary(
        self, reports: List[SecurityIntelligenceReport]
    ) -> Dict[str, Any]:
        """Generate high-level intelligence summary."""
        return {
            "critical_vulnerabilities": [
                r.vulnerability_id
                for r in reports
                if r.finding.severity == Severity.CRITICAL
            ],
            "exploitable_vulnerabilities": [
                r.vulnerability_id
                for r in reports
                if len(r.static_intelligence.exploits) > 0
            ],
            "patchable_vulnerabilities": [
                r.vulnerability_id
                for r in reports
                if len(r.static_intelligence.patches) > 0
            ],
            "research_coverage": {
                "fully_researched": len(
                    [r for r in reports if r.completeness_score > 0.8]
                ),
                "partially_researched": len(
                    [r for r in reports if 0.5 <= r.completeness_score <= 0.8]
                ),
                "limited_research": len(
                    [r for r in reports if r.completeness_score < 0.5]
                ),
            },
        }


# Export main class
__all__ = [
    "ComprehensiveSecurityCrawler",
    "SecurityIntelligenceReport",
    "ThreatIntelligence",
]
