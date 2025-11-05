#!/usr/bin/env python3
"""
Advanced Web Vulnerability Search Agent
A powerful security agent that searches for vulnerabilities and provides fixes.
"""

import requests
import json
import time
import re
from dataclasses import dataclass
from typing import List, Dict, Any, Optional
from pathlib import Path
import os
import hashlib
from rich.console import Console
from rich.table import Table
from rich.panel import Panel
from rich.progress import Progress, SpinnerColumn, TextColumn
from rich.live import Live

console = Console()

@dataclass
class VulnFinding:
    """Represents a vulnerability finding"""
    title: str
    severity: str
    cve_id: Optional[str]
    description: str
    affected_versions: List[str]
    fix_available: bool
    fix_description: str
    references: List[str]
    score: float

class WebVulnAgent:
    """Advanced web vulnerability search agent"""
    
    def __init__(self, api_keys: Dict[str, str] = None):
        self.api_keys = api_keys or {}
        self.session = requests.Session()
        self.session.headers.update({
            'User-Agent': 'WebVulnAgent/1.0 Security Research Tool'
        })
        self.cache = {}
        
    def search_nvd_database(self, query: str, limit: int = 10) -> List[VulnFinding]:
        """Search NIST NVD database for vulnerabilities"""
        try:
            console.log("[blue]🔍 Searching NVD database...[/blue]")
            url = "https://services.nvd.nist.gov/rest/json/cves/2.0"
            params = {
                'keywordSearch': query,
                'resultsPerPage': limit,
                'startIndex': 0
            }
            
            response = self.session.get(url, params=params, timeout=10)
            response.raise_for_status()
            data = response.json()
            
            findings = []
            for vuln in data.get('vulnerabilities', []):
                cve = vuln.get('cve', {})
                cve_id = cve.get('id', '')
                
                # Extract metrics
                metrics = cve.get('metrics', {})
                score = 0.0
                severity = 'UNKNOWN'
                
                if 'cvssMetricV31' in metrics:
                    cvss = metrics['cvssMetricV31'][0]['cvssData']
                    score = cvss.get('baseScore', 0.0)
                    severity = cvss.get('baseSeverity', 'UNKNOWN')
                elif 'cvssMetricV2' in metrics:
                    cvss = metrics['cvssMetricV2'][0]['cvssData']
                    score = cvss.get('baseScore', 0.0)
                    if score >= 7.0: severity = 'HIGH'
                    elif score >= 4.0: severity = 'MEDIUM'
                    else: severity = 'LOW'
                
                # Extract description
                descriptions = cve.get('descriptions', [])
                description = ""
                for desc in descriptions:
                    if desc.get('lang') == 'en':
                        description = desc.get('value', '')
                        break
                
                # Extract references
                references = []
                refs = cve.get('references', [])
                for ref in refs[:5]:  # Limit to 5 references
                    references.append(ref.get('url', ''))
                
                finding = VulnFinding(
                    title=f"{cve_id}: {description[:100]}...",
                    severity=severity,
                    cve_id=cve_id,
                    description=description,
                    affected_versions=[],
                    fix_available=len(references) > 0,
                    fix_description="Check references for fix information",
                    references=references,
                    score=score
                )
                findings.append(finding)
            
            console.log(f"[green]✅ Found {len(findings)} vulnerabilities in NVD[/green]")
            return findings
            
        except Exception as e:
            console.log(f"[red]❌ NVD search failed: {e}[/red]")
            return []
    
    def search_exploit_db(self, query: str) -> List[Dict[str, Any]]:
        """Search Exploit-DB for known exploits"""
        try:
            console.log("[blue]🔍 Searching Exploit-DB...[/blue]")
            # Use the searchsploit API alternative
            url = "https://www.exploit-db.com/searchsploit"
            params = {
                'searchsploit': query,
                'json': 'true'
            }
            
            response = self.session.get(url, params=params, timeout=10)
            if response.status_code == 200:
                try:
                    data = response.json()
                    console.log(f"[green]✅ Found {len(data.get('results', []))} exploits[/green]")
                    return data.get('results', [])[:10]
                except:
                    pass
            
            console.log("[yellow]⚠️ Exploit-DB search unavailable[/yellow]")
            return []
            
        except Exception as e:
            console.log(f"[red]❌ Exploit-DB search failed: {e}[/red]")
            return []
    
    def search_github_advisories(self, query: str) -> List[Dict[str, Any]]:
        """Search GitHub Security Advisories"""
        try:
            console.log("[blue]🔍 Searching GitHub Advisories...[/blue]")
            # GitHub GraphQL API for security advisories
            api_key = self.api_keys.get('github')
            if not api_key:
                console.log("[yellow]⚠️ GitHub API key not provided[/yellow]")
                return []
            
            url = "https://api.github.com/graphql"
            headers = {
                'Authorization': f'Bearer {api_key}',
                'Content-Type': 'application/json'
            }
            
            graphql_query = """
            query($query: String!) {
                search(query: $query, type: REPOSITORY, first: 10) {
                    edges {
                        node {
                            ... on Repository {
                                name
                                url
                                vulnerabilityAlerts(first: 5) {
                                    nodes {
                                        createdAt
                                        securityVulnerability {
                                            advisory {
                                                summary
                                                description
                                                severity
                                                references {
                                                    url
                                                }
                                            }
                                        }
                                    }
                                }
                            }
                        }
                    }
                }
            }
            """
            
            payload = {
                'query': graphql_query,
                'variables': {'query': query}
            }
            
            response = self.session.post(url, headers=headers, json=payload, timeout=10)
            if response.status_code == 200:
                data = response.json()
                console.log("[green]✅ GitHub advisories retrieved[/green]")
                return data.get('data', {}).get('search', {}).get('edges', [])
            
            return []
            
        except Exception as e:
            console.log(f"[red]❌ GitHub advisories search failed: {e}[/red]")
            return []
    
    def search_cve_mitre(self, cve_id: str) -> Dict[str, Any]:
        """Get detailed CVE information from MITRE"""
        try:
            console.log(f"[blue]🔍 Searching MITRE for {cve_id}...[/blue]")
            url = f"https://cve.mitre.org/cgi-bin/cvekey.cgi?keyword={cve_id}"
            response = self.session.get(url, timeout=10)
            
            if response.status_code == 200:
                # Simple parsing of MITRE response
                content = response.text
                if cve_id.upper() in content:
                    console.log(f"[green]✅ Found {cve_id} in MITRE[/green]")
                    return {
                        'found': True,
                        'url': url,
                        'content_preview': content[:500]
                    }
            
            return {'found': False}
            
        except Exception as e:
            console.log(f"[red]❌ MITRE search failed: {e}[/red]")
            return {'found': False}
    
    def comprehensive_vuln_search(self, target: str, search_type: str = "general") -> Dict[str, Any]:
        """Perform comprehensive vulnerability search"""
        console.print(Panel.fit(
            f"🔍 Starting comprehensive vulnerability search for: [bold cyan]{target}[/bold cyan]",
            title="Web Vulnerability Agent",
            border_style="blue"
        ))
        
        results = {
            'target': target,
            'search_type': search_type,
            'nvd_findings': [],
            'exploit_db_results': [],
            'github_advisories': [],
            'mitre_results': {},
            'summary': {},
            'recommendations': []
        }
        
        with Progress(
            SpinnerColumn(),
            TextColumn("[progress.description]{task.description}"),
            console=console
        ) as progress:
            
            # Search NVD
            task1 = progress.add_task("Searching NVD database...", total=None)
            results['nvd_findings'] = self.search_nvd_database(target)
            progress.update(task1, description="✅ NVD search complete")
            
            # Search Exploit-DB
            task2 = progress.add_task("Searching Exploit-DB...", total=None)
            results['exploit_db_results'] = self.search_exploit_db(target)
            progress.update(task2, description="✅ Exploit-DB search complete")
            
            # Search GitHub if API key available
            if self.api_keys.get('github'):
                task3 = progress.add_task("Searching GitHub Advisories...", total=None)
                results['github_advisories'] = self.search_github_advisories(target)
                progress.update(task3, description="✅ GitHub search complete")
            
            # If we found CVEs, search MITRE for details
            cve_pattern = re.compile(r'CVE-\d{4}-\d{4,7}')
            found_cves = []
            for finding in results['nvd_findings']:
                if finding.cve_id:
                    found_cves.append(finding.cve_id)
            
            if found_cves:
                task4 = progress.add_task("Searching MITRE...", total=None)
                results['mitre_results'] = {}
                for cve in found_cves[:3]:  # Limit to 3 CVEs
                    results['mitre_results'][cve] = self.search_cve_mitre(cve)
                progress.update(task4, description="✅ MITRE search complete")
        
        # Generate summary
        results['summary'] = self._generate_summary(results)
        results['recommendations'] = self._generate_recommendations(results)
        
        return results
    
    def _generate_summary(self, results: Dict[str, Any]) -> Dict[str, Any]:
        """Generate search results summary"""
        nvd_count = len(results['nvd_findings'])
        exploit_count = len(results['exploit_db_results'])
        github_count = len(results['github_advisories'])
        
        # Severity breakdown
        severity_counts = {'CRITICAL': 0, 'HIGH': 0, 'MEDIUM': 0, 'LOW': 0, 'UNKNOWN': 0}
        high_score_vulns = []
        
        for finding in results['nvd_findings']:
            severity_counts[finding.severity] += 1
            if finding.score >= 7.0:
                high_score_vulns.append(finding)
        
        return {
            'total_sources': 3 if self.api_keys.get('github') else 2,
            'nvd_vulnerabilities': nvd_count,
            'known_exploits': exploit_count,
            'github_advisories': github_count,
            'severity_breakdown': severity_counts,
            'high_severity_count': len(high_score_vulns),
            'highest_score': max([f.score for f in results['nvd_findings']], default=0.0)
        }
    
    def _generate_recommendations(self, results: Dict[str, Any]) -> List[str]:
        """Generate security recommendations"""
        recommendations = []
        
        summary = results['summary']
        nvd_findings = results['nvd_findings']
        
        if summary['highest_score'] >= 9.0:
            recommendations.append("🚨 CRITICAL: Immediate action required - vulnerabilities with score 9.0+ detected")
        elif summary['highest_score'] >= 7.0:
            recommendations.append("⚠️ HIGH: Prioritize patching - high severity vulnerabilities found")
        
        if summary['known_exploits'] > 0:
            recommendations.append(f"💣 {summary['known_exploits']} known exploits found - implement additional monitoring")
        
        if summary['nvd_vulnerabilities'] > 10:
            recommendations.append("📊 Large number of vulnerabilities detected - consider comprehensive security audit")
        
        # Fix recommendations
        fixed_vulns = [f for f in nvd_findings if f.fix_available]
        if fixed_vulns:
            recommendations.append(f"🔧 {len(fixed_vulns)} vulnerabilities have available fixes - review references")
        
        if not recommendations:
            recommendations.append("✅ No critical vulnerabilities detected in current search scope")
        
        return recommendations
    
    def display_results(self, results: Dict[str, Any]):
        """Display search results in formatted tables"""
        console.print("\n")
        console.rule(f"[bold blue]Vulnerability Search Results for: {results['target']}")
        
        # Summary table
        summary_table = Table(title="Search Summary", show_header=True)
        summary_table.add_column("Metric", style="cyan")
        summary_table.add_column("Count", style="yellow")
        
        summary = results['summary']
        summary_table.add_row("NVD Vulnerabilities", str(summary['nvd_vulnerabilities']))
        summary_table.add_row("Known Exploits", str(summary['known_exploits']))
        summary_table.add_row("GitHub Advisories", str(summary['github_advisories']))
        summary_table.add_row("Highest CVSS Score", f"{summary['highest_score']:.1f}")
        
        console.print(summary_table)
        console.print()
        
        # Severity breakdown
        if summary['nvd_vulnerabilities'] > 0:
            severity_table = Table(title="Severity Breakdown", show_header=True)
            severity_table.add_column("Severity", style="cyan")
            severity_table.add_column("Count", style="yellow")
            
            for severity, count in summary['severity_breakdown'].items():
                if count > 0:
                    severity_style = {
                        'CRITICAL': 'bold red',
                        'HIGH': 'red',
                        'MEDIUM': 'yellow',
                        'LOW': 'green',
                        'UNKNOWN': 'dim'
                    }.get(severity, 'white')
                    severity_table.add_row(f"[{severity_style}]{severity}[/{severity_style}]", str(count))
            
            console.print(severity_table)
            console.print()
        
        # Top vulnerabilities
        if results['nvd_findings']:
            vuln_table = Table(title="Top Vulnerabilities", show_header=True)
            vuln_table.add_column("CVE ID", style="cyan", width=15)
            vuln_table.add_column("Severity", style="yellow", width=10)
            vuln_table.add_column("Score", style="red", width=6)
            vuln_table.add_column("Description", style="white", width=50)
            
            top_vulns = sorted(results['nvd_findings'], key=lambda x: x.score, reverse=True)[:10]
            for vuln in top_vulns:
                severity_style = {
                    'CRITICAL': 'bold red',
                    'HIGH': 'red',
                    'MEDIUM': 'yellow',
                    'LOW': 'green'
                }.get(vuln.severity, 'white')
                
                vuln_table.add_row(
                    vuln.cve_id or "N/A",
                    f"[{severity_style}]{vuln.severity}[/{severity_style}]",
                    f"{vuln.score:.1f}",
                    vuln.description[:47] + "..." if len(vuln.description) > 50 else vuln.description
                )
            
            console.print(vuln_table)
            console.print()
        
        # Recommendations
        console.print(Panel.fit(
            "\n".join(results['recommendations']),
            title="🎯 Security Recommendations",
            border_style="green"
        ))
    
    def save_report(self, results: Dict[str, Any], filename: str = None):
        """Save results to JSON file"""
        if not filename:
            timestamp = int(time.time())
            filename = f"vuln_search_report_{timestamp}.json"
        
        # Convert findings to dict for JSON serialization
        json_results = results.copy()
        json_results['nvd_findings'] = [
            {
                'title': f.title,
                'severity': f.severity,
                'cve_id': f.cve_id,
                'description': f.description,
                'score': f.score,
                'references': f.references,
                'fix_available': f.fix_available
            }
            for f in results['nvd_findings']
        ]
        
        with open(filename, 'w') as f:
            json.dump(json_results, f, indent=2, default=str)
        
        console.print(f"[green]💾 Report saved to: {filename}[/green]")

def main():
    """Main function for CLI usage"""
    import argparse
    
    parser = argparse.ArgumentParser(description="Advanced Web Vulnerability Search Agent")
    parser.add_argument("target", help="Target to search for vulnerabilities (e.g., 'apache', 'CVE-2021-44228')")
    parser.add_argument("--github-token", help="GitHub API token for advisory search")
    parser.add_argument("--output", "-o", help="Output file for JSON report")
    parser.add_argument("--type", choices=["general", "cve", "product"], default="general", 
                       help="Type of search to perform")
    
    args = parser.parse_args()
    
    # Setup API keys
    api_keys = {}
    if args.github_token:
        api_keys['github'] = args.github_token
    
    # Initialize agent
    agent = WebVulnAgent(api_keys=api_keys)
    
    # Perform search
    results = agent.comprehensive_vuln_search(args.target, args.type)
    
    # Display results
    agent.display_results(results)
    
    # Save report if requested
    if args.output:
        agent.save_report(results, args.output)
    else:
        agent.save_report(results)

if __name__ == "__main__":
    main()