"""
Modern Web Intelligence Agent for Impact Scan - 2025 Edition

This module provides state-of-the-art web crawling and intelligence gathering
capabilities for comprehensive OSS security research. Acts as the "Nmap of Codebases"
for security researchers and bug hunters.
"""

import asyncio
import time
import hashlib
import random
from typing import List, Dict, Any, Optional, Union
from pathlib import Path
from dataclasses import dataclass, field
from datetime import datetime
import json
import logging

import httpx
import aiofiles
from bs4 import BeautifulSoup
from playwright.async_api import async_playwright, Browser, Page
from rich.console import Console

from ..utils.schema import Finding, ScanConfig, Severity, VulnSource

logger = logging.getLogger(__name__)
console = Console()


@dataclass
class SecurityIntelligence:
    """Structured security intelligence data."""
    vulnerability_id: str
    sources: List[str] = field(default_factory=list)
    exploits: List[Dict[str, Any]] = field(default_factory=list)
    patches: List[Dict[str, Any]] = field(default_factory=list)
    advisories: List[Dict[str, Any]] = field(default_factory=list)
    poc_examples: List[str] = field(default_factory=list)
    vendor_responses: List[Dict[str, Any]] = field(default_factory=list)
    related_cves: List[str] = field(default_factory=list)
    severity_score: float = 0.0
    exploitability_score: float = 0.0
    confidence_score: float = 0.0
    citations: List[str] = field(default_factory=list)
    timestamp: datetime = field(default_factory=datetime.now)


@dataclass
class CrawlResult:
    """Result from web crawling operation."""
    url: str
    status_code: int
    content: str
    title: str
    extracted_data: Dict[str, Any] = field(default_factory=dict)
    error: Optional[str] = None
    timestamp: datetime = field(default_factory=datetime.now)


class ModernWebIntelligenceAgent:
    """
    2025 Web Intelligence Agent using modern crawling technologies.
    
    Features:
    - Async HTTP client with connection pooling
    - JavaScript rendering via Playwright
    - Anti-bot protection bypass
    - Multi-source intelligence gathering
    - Advanced caching and rate limiting
    """
    
    # Security-focused target sites
    SECURITY_SOURCES = {
        'cve_mitre': 'https://cve.mitre.org/cgi-bin/cvename.cgi?name={}',
        'nvd_nist': 'https://nvd.nist.gov/vuln/detail/{}',
        'github_advisories': 'https://github.com/advisories/{}',
        'snyk_database': 'https://security.snyk.io/vuln/{}',
        'exploit_db': 'https://www.exploit-db.com/search?q={}',
        'security_focus': 'https://www.securityfocus.com/bid/{}',
        'packetstorm': 'https://packetstormsecurity.com/search/?q={}',
        'vulndb': 'https://vuldb.com/?id={}',
        'cwe_mitre': 'https://cwe.mitre.org/data/definitions/{}.html',
        'owasp_top10': 'https://owasp.org/www-project-top-ten/',
    }
    
    # Vendor-specific documentation sources
    VENDOR_DOCS = {
        'python': {
            'django': 'https://docs.djangoproject.com/en/stable/releases/security/',
            'flask': 'https://flask.palletsprojects.com/en/stable/security/',
            'requests': 'https://requests.readthedocs.io/en/master/user/advanced/#ssl-cert-verification',
            'numpy': 'https://numpy.org/doc/stable/release/',
            'pandas': 'https://pandas.pydata.org/pandas-docs/stable/whatsnew/',
            'pillow': 'https://pillow.readthedocs.io/en/stable/releasenotes/',
            'sqlalchemy': 'https://docs.sqlalchemy.org/en/20/changelog/',
        },
        'javascript': {
            'react': 'https://reactjs.org/blog/',
            'angular': 'https://angular.io/guide/security',
            'vue': 'https://vuejs.org/guide/best-practices/security.html',
            'express': 'https://expressjs.com/en/advanced/best-practice-security.html',
            'node': 'https://nodejs.org/en/blog/vulnerability/',
        }
    }
    
    # User agents for stealth crawling
    USER_AGENTS = [
        'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36',
        'Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36',
        'Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36',
        'Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:121.0) Gecko/20100101 Firefox/121.0',
        'Mozilla/5.0 (Macintosh; Intel Mac OS X 10.15; rv:121.0) Gecko/20100101 Firefox/121.0',
    ]
    
    def __init__(self, config: ScanConfig):
        self.config = config
        self.session: Optional[httpx.AsyncClient] = None
        self.browser: Optional[Browser] = None
        self.cache = {}
        self.rate_limiter = {}
        self.request_count = 0
        self.max_cache_size = 1000
        
        # Rate limiting configuration
        self.base_delay = 1.0  # Base delay between requests
        self.max_delay = 10.0  # Maximum delay
        self.retry_attempts = 3
        
    async def __aenter__(self):
        """Async context manager entry."""
        await self.initialize()
        return self
        
    async def __aexit__(self, exc_type, exc_val, exc_tb):
        """Async context manager exit."""
        await self.cleanup()
        
    async def initialize(self):
        """Initialize HTTP client and browser."""
        # Initialize async HTTP client with optimized settings
        self.session = httpx.AsyncClient(
            timeout=30.0,
            limits=httpx.Limits(max_keepalive_connections=20, max_connections=100),
            headers={
                'User-Agent': random.choice(self.USER_AGENTS),
                'Accept': 'text/html,application/xhtml+xml,application/xml;q=0.9,image/webp,*/*;q=0.8',
                'Accept-Language': 'en-US,en;q=0.5',
                'Accept-Encoding': 'gzip, deflate',
                'DNT': '1',
                'Connection': 'keep-alive',
                'Upgrade-Insecure-Requests': '1',
            }
        )
        
        console.log("[bold green][INIT] Modern Web Intelligence Agent initialized[/bold green]")
        
    async def cleanup(self):
        """Clean up resources."""
        if self.session:
            await self.session.aclose()
        if self.browser:
            await self.browser.close()
            
        console.log("[dim][CLEANUP] Web Intelligence Agent resources cleaned up[/dim]")
        
    async def _rate_limit(self, domain: str):
        """Advanced rate limiting per domain."""
        current_time = time.time()
        
        if domain not in self.rate_limiter:
            self.rate_limiter[domain] = {'last_request': 0, 'delay': self.base_delay}
            
        domain_data = self.rate_limiter[domain]
        time_since_last = current_time - domain_data['last_request']
        
        if time_since_last < domain_data['delay']:
            sleep_time = domain_data['delay'] - time_since_last
            console.log(f"[dim][RATE_LIMIT] Waiting {sleep_time:.1f}s for {domain}[/dim]")
            await asyncio.sleep(sleep_time)
            
        domain_data['last_request'] = time.time()
        
    def _get_cache_key(self, url: str, params: Dict[str, Any] = None) -> str:
        """Generate cache key for URL and parameters."""
        cache_data = f"{url}_{str(sorted((params or {}).items()))}"
        return hashlib.md5(cache_data.encode(), usedforsecurity=False).hexdigest()
        
    async def fetch_url(self, url: str, use_javascript: bool = False, **kwargs) -> CrawlResult:
        """
        Fetch URL with optional JavaScript rendering.
        
        Args:
            url: URL to fetch
            use_javascript: Whether to use Playwright for JS rendering
            **kwargs: Additional parameters for the request
            
        Returns:
            CrawlResult with fetched data
        """
        cache_key = self._get_cache_key(url, kwargs)
        
        # Check cache first
        if cache_key in self.cache:
            console.log(f"[green][CACHE_HIT] {url[:50]}...[/green]")
            return self.cache[cache_key]
            
        try:
            domain = httpx.URL(url).host
            await self._rate_limit(domain)
            
            if use_javascript:
                result = await self._fetch_with_playwright(url, **kwargs)
            else:
                result = await self._fetch_with_httpx(url, **kwargs)
                
            # Cache successful results
            if result.status_code == 200 and len(self.cache) < self.max_cache_size:
                self.cache[cache_key] = result
                
            self.request_count += 1
            console.log(f"[blue][FETCH] ({self.request_count}) {url[:50]}... [{result.status_code}][/blue]")
            
            return result
            
        except Exception as e:
            logger.error(f"Error fetching {url}: {e}")
            return CrawlResult(
                url=url,
                status_code=0,
                content="",
                title="",
                error=str(e)
            )
            
    async def _fetch_with_httpx(self, url: str, **kwargs) -> CrawlResult:
        """Fetch URL using async HTTP client."""
        response = await self.session.get(url, **kwargs)
        soup = BeautifulSoup(response.content, 'html.parser')
        
        title = ""
        title_tag = soup.find('title')
        if title_tag:
            title = title_tag.get_text().strip()
            
        return CrawlResult(
            url=url,
            status_code=response.status_code,
            content=response.text,
            title=title,
            extracted_data=self._extract_structured_data(soup)
        )
        
    async def _fetch_with_playwright(self, url: str, **kwargs) -> CrawlResult:
        """Fetch URL using Playwright for JavaScript rendering."""
        if not self.browser:
            playwright = await async_playwright().start()
            self.browser = await playwright.chromium.launch(
                headless=True,
                args=[
                    '--no-sandbox',
                    '--disable-blink-features=AutomationControlled',
                    '--disable-dev-shm-usage',
                ]
            )
            
        # Create context with proper user agent
        context = await self.browser.new_context(
            user_agent=random.choice(self.USER_AGENTS),
            viewport={'width': 1920, 'height': 1080}
        )
        
        # Stealth configuration
        await context.add_init_script("""
            Object.defineProperty(navigator, 'webdriver', {get: () => undefined});
            Object.defineProperty(navigator, 'plugins', {get: () => [1, 2, 3, 4, 5]});
            Object.defineProperty(navigator, 'languages', {get: () => ['en-US', 'en']});
        """)
        
        page = await context.new_page()
        
        try:
            response = await page.goto(url, wait_until='networkidle', timeout=30000)
            content = await page.content()
            title = await page.title()
            
            soup = BeautifulSoup(content, 'html.parser')
            
            return CrawlResult(
                url=url,
                status_code=response.status if response else 0,
                content=content,
                title=title,
                extracted_data=self._extract_structured_data(soup)
            )
            
        finally:
            await page.close()
            await context.close()
            
    def _extract_structured_data(self, soup: BeautifulSoup) -> Dict[str, Any]:
        """Extract structured data from HTML."""
        data = {}
        
        # Extract meta tags
        meta_tags = soup.find_all('meta')
        data['meta'] = {
            tag.get('name', tag.get('property', 'unknown')): tag.get('content', '')
            for tag in meta_tags if tag.get('content')
        }
        
        # Extract headings
        data['headings'] = {
            f'h{i}': [h.get_text().strip() for h in soup.find_all(f'h{i}')]
            for i in range(1, 7)
        }
        
        # Extract links
        links = soup.find_all('a', href=True)
        data['links'] = [{'text': link.get_text().strip(), 'href': link['href']} for link in links]
        
        # Extract code blocks
        code_blocks = soup.find_all(['code', 'pre'])
        data['code_blocks'] = [block.get_text().strip() for block in code_blocks]
        
        return data
        
    async def research_vulnerability(self, finding: Finding) -> SecurityIntelligence:
        """
        Comprehensive vulnerability research across multiple sources.
        
        Args:
            finding: Vulnerability finding to research
            
        Returns:
            SecurityIntelligence object with gathered data
        """
        intelligence = SecurityIntelligence(vulnerability_id=finding.vuln_id)
        
        console.log(f"[bold cyan][RESEARCH] Starting deep research for {finding.vuln_id}[/bold cyan]")
        
        # Parallel research across multiple sources
        research_tasks = [
            self._research_cve_databases(finding, intelligence),
            self._research_exploit_databases(finding, intelligence),
            self._research_vendor_documentation(finding, intelligence),
            self._research_security_advisories(finding, intelligence),
            self._research_academic_sources(finding, intelligence),
        ]
        
        await asyncio.gather(*research_tasks, return_exceptions=True)
        
        # Calculate confidence and scores
        intelligence.confidence_score = self._calculate_confidence_score(intelligence)
        intelligence.severity_score = self._calculate_severity_score(finding, intelligence)
        intelligence.exploitability_score = self._calculate_exploitability_score(intelligence)
        
        console.log(f"[bold green][RESEARCH_COMPLETE] {finding.vuln_id} - "
                   f"Confidence: {intelligence.confidence_score:.2f}, "
                   f"Sources: {len(intelligence.sources)}[/bold green]")
        
        return intelligence
        
    async def _research_cve_databases(self, finding: Finding, intelligence: SecurityIntelligence):
        """Research CVE and vulnerability databases using modern APIs."""
        
        # 1. NVD API 2.0 - Official NIST vulnerability database
        await self._query_nvd_api(finding, intelligence)
        
        # 2. GitHub Security Advisories API
        await self._query_github_advisories_api(finding, intelligence)
        
        # 3. Fallback to web scraping for other sources
        fallback_sources = ['cve_mitre', 'snyk_database']
        for source in fallback_sources:
            try:
                url_template = self.SECURITY_SOURCES.get(source)
                if url_template and finding.vuln_id:
                    url = url_template.format(finding.vuln_id)
                    result = await self.fetch_url(url)
                    
                    if result.status_code == 200:
                        intelligence.sources.append(url)
                        intelligence.citations.append(url)
                        
                        # Extract CVE-specific data
                        if 'cve.mitre.org' in url:
                            self._extract_mitre_data(result, intelligence)
                            
            except Exception as e:
                logger.error(f"Error researching {source} for {finding.vuln_id}: {e}")
    
    async def _query_nvd_api(self, finding: Finding, intelligence: SecurityIntelligence):
        """Query the NVD API 2.0 for comprehensive vulnerability data."""
        try:
            # NVD API 2.0 endpoint
            base_url = "https://services.nvd.nist.gov/rest/json/cves/2.0"
            
            # Build query parameters
            params = {}
            if finding.vuln_id and finding.vuln_id.startswith('CVE-'):
                params['cveId'] = finding.vuln_id
            elif finding.rule_id:
                # Search by keywords if not a direct CVE
                params['keywordSearch'] = f"{finding.rule_id} {finding.title}"
                params['resultsPerPage'] = 5
            else:
                return
            
            # Make API request with proper headers
            headers = {
                'User-Agent': 'Impact-Scan/1.0 (https://github.com/security-research)',
                'Accept': 'application/json'
            }
            
            async with httpx.AsyncClient(timeout=30.0) as client:
                response = await client.get(base_url, params=params, headers=headers)
                
                if response.status_code == 200:
                    data = response.json()
                    await self._process_nvd_response(data, intelligence)
                    intelligence.sources.append(f"{base_url}?{'&'.join(f'{k}={v}' for k, v in params.items())}")
                elif response.status_code == 403:
                    logger.warning("NVD API rate limit exceeded - implement API key for higher limits")
                else:
                    logger.warning(f"NVD API returned status {response.status_code}")
                    
        except Exception as e:
            logger.error(f"Error querying NVD API: {e}")
    
    async def _process_nvd_response(self, data: dict, intelligence: SecurityIntelligence):
        """Process NVD API response and extract vulnerability data."""
        try:
            vulnerabilities = data.get('vulnerabilities', [])
            
            for vuln_item in vulnerabilities:
                cve = vuln_item.get('cve', {})
                
                # Extract CVE ID
                cve_id = cve.get('id', 'Unknown')
                intelligence.related_cves.append(cve_id)
                
                # Extract descriptions
                descriptions = cve.get('descriptions', [])
                for desc in descriptions:
                    if desc.get('lang') == 'en':
                        intelligence.advisories.append({
                            'source': 'NVD',
                            'description': desc.get('value', ''),
                            'cve_id': cve_id
                        })
                
                # Extract CVSS metrics
                metrics = cve.get('metrics', {})
                
                # CVSS v3.1 (preferred)
                if 'cvssMetricV31' in metrics:
                    for metric in metrics['cvssMetricV31']:
                        cvss_data = metric.get('cvssData', {})
                        intelligence.severity_score = max(
                            intelligence.severity_score,
                            float(cvss_data.get('baseScore', 0.0))
                        )
                        intelligence.exploitability_score = max(
                            intelligence.exploitability_score,
                            float(cvss_data.get('exploitabilityScore', 0.0))
                        )
                
                # CVSS v3.0 (fallback)
                elif 'cvssMetricV30' in metrics:
                    for metric in metrics['cvssMetricV30']:
                        cvss_data = metric.get('cvssData', {})
                        intelligence.severity_score = max(
                            intelligence.severity_score,
                            float(cvss_data.get('baseScore', 0.0))
                        )
                
                # Extract references (potential exploits/patches)
                references = cve.get('references', [])
                for ref in references:
                    url = ref.get('url', '')
                    tags = ref.get('tags', [])
                    
                    intelligence.citations.append(url)
                    
                    # Categorize references
                    if any(tag in ['Exploit', 'Proof of Concept'] for tag in tags):
                        intelligence.exploits.append({
                            'url': url,
                            'source': 'NVD',
                            'type': 'reference',
                            'tags': tags
                        })
                    elif any(tag in ['Patch', 'Vendor Advisory'] for tag in tags):
                        intelligence.patches.append({
                            'url': url,
                            'source': 'NVD',
                            'type': 'patch',
                            'tags': tags
                        })
                
        except Exception as e:
            logger.error(f"Error processing NVD response: {e}")
    
    async def _query_github_advisories_api(self, finding: Finding, intelligence: SecurityIntelligence):
        """Query GitHub Security Advisories using GraphQL API."""
        try:
            # GitHub GraphQL endpoint
            url = "https://api.github.com/graphql"
            
            # Build GraphQL query
            query = """
            query($searchQuery: String!) {
              search(query: $searchQuery, type: REPOSITORY, first: 10) {
                nodes {
                  ... on Repository {
                    securityAdvisories(first: 5) {
                      nodes {
                        ghsaId
                        summary
                        description
                        severity
                        publishedAt
                        updatedAt
                        references {
                          url
                        }
                        vulnerabilities(first: 5) {
                          nodes {
                            package {
                              name
                              ecosystem
                            }
                            vulnerableVersionRange
                            firstPatchedVersion {
                              identifier
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
            
            # Construct search query
            if finding.vuln_id and finding.vuln_id.startswith('CVE-'):
                search_query = f"is:public {finding.vuln_id}"
            else:
                search_query = f"is:public {finding.rule_id} {finding.title}"
            
            variables = {"searchQuery": search_query}
            
            # Note: Requires GitHub API token for higher rate limits
            headers = {
                'User-Agent': 'Impact-Scan/1.0',
                'Accept': 'application/vnd.github.v3+json'
            }
            
            # Check if GitHub token is available
            github_token = self.config.api_keys.github_token if hasattr(self.config, 'api_keys') and hasattr(self.config.api_keys, 'github_token') else None
            if github_token:
                headers['Authorization'] = f'Bearer {github_token}'
            
            async with httpx.AsyncClient(timeout=30.0) as client:
                response = await client.post(
                    url,
                    json={'query': query, 'variables': variables},
                    headers=headers
                )
                
                if response.status_code == 200:
                    data = response.json()
                    await self._process_github_advisories_response(data, intelligence)
                else:
                    logger.warning(f"GitHub API returned status {response.status_code}")
                    
        except Exception as e:
            logger.error(f"Error querying GitHub Advisories API: {e}")
    
    async def _process_github_advisories_response(self, data: dict, intelligence: SecurityIntelligence):
        """Process GitHub Security Advisories API response."""
        try:
            search_results = data.get('data', {}).get('search', {}).get('nodes', [])
            
            for repo in search_results:
                advisories = repo.get('securityAdvisories', {}).get('nodes', [])
                
                for advisory in advisories:
                    ghsa_id = advisory.get('ghsaId', '')
                    summary = advisory.get('summary', '')
                    description = advisory.get('description', '')
                    severity = advisory.get('severity', 'UNKNOWN')
                    
                    # Add to intelligence
                    intelligence.advisories.append({
                        'source': 'GitHub Security Advisory',
                        'id': ghsa_id,
                        'summary': summary,
                        'description': description,
                        'severity': severity,
                        'published_at': advisory.get('publishedAt', ''),
                        'updated_at': advisory.get('updatedAt', '')
                    })
                    
                    # Add references
                    references = advisory.get('references', [])
                    for ref in references:
                        url = ref.get('url', '')
                        if url:
                            intelligence.citations.append(url)
                    
                    # Process vulnerabilities for patch information
                    vulnerabilities = advisory.get('vulnerabilities', {}).get('nodes', [])
                    for vuln in vulnerabilities:
                        package = vuln.get('package', {})
                        patched_version = vuln.get('firstPatchedVersion', {})
                        
                        if patched_version:
                            intelligence.patches.append({
                                'source': 'GitHub Advisory',
                                'package': package.get('name', ''),
                                'ecosystem': package.get('ecosystem', ''),
                                'patched_version': patched_version.get('identifier', ''),
                                'vulnerable_range': vuln.get('vulnerableVersionRange', ''),
                                'advisory_id': ghsa_id
                            })
                    
                    # Map severity to score
                    severity_mapping = {
                        'LOW': 3.0,
                        'MODERATE': 5.0,
                        'HIGH': 7.0,
                        'CRITICAL': 9.0
                    }
                    score = severity_mapping.get(severity, 0.0)
                    intelligence.severity_score = max(intelligence.severity_score, score)
                    
        except Exception as e:
            logger.error(f"Error processing GitHub Advisories response: {e}")
                
    async def _research_exploit_databases(self, finding: Finding, intelligence: SecurityIntelligence):
        """Research exploit databases and PoC repositories."""
        exploit_sources = ['exploit_db', 'packetstorm', 'vulndb']
        
        for source in exploit_sources:
            try:
                url_template = self.SECURITY_SOURCES.get(source)
                if url_template:
                    # Search by vulnerability ID and description
                    search_terms = [finding.vuln_id, finding.title, finding.description[:50]]
                    
                    for term in search_terms:
                        if term:
                            url = url_template.format(term.replace(' ', '+'))
                            result = await self.fetch_url(url, use_javascript=True)
                            
                            if result.status_code == 200:
                                exploits = self._extract_exploit_data(result)
                                intelligence.exploits.extend(exploits)
                                
                                if exploits:
                                    intelligence.sources.append(url)
                                    break
                                    
            except Exception as e:
                logger.error(f"Error researching exploits for {finding.vuln_id}: {e}")
                
    async def _research_vendor_documentation(self, finding: Finding, intelligence: SecurityIntelligence):
        """Research vendor-specific security documentation."""
        # Determine relevant vendors based on file path and context
        file_path = str(finding.file_path).lower()
        relevant_vendors = []
        
        if any(framework in file_path for framework in ['django', 'flask', 'requests']):
            relevant_vendors.extend(['django', 'flask', 'requests'])
        if any(ext in file_path for ext in ['.js', '.ts', '.jsx', '.tsx']):
            relevant_vendors.extend(['react', 'angular', 'vue', 'express', 'node'])
            
        for vendor in relevant_vendors:
            try:
                vendor_docs = self.VENDOR_DOCS.get('python', {}).get(vendor) or \
                             self.VENDOR_DOCS.get('javascript', {}).get(vendor)
                             
                if vendor_docs:
                    result = await self.fetch_url(vendor_docs)
                    if result.status_code == 200:
                        patches = self._extract_vendor_patches(result, finding)
                        intelligence.patches.extend(patches)
                        
                        if patches:
                            intelligence.sources.append(vendor_docs)
                            intelligence.citations.append(vendor_docs)
                            
            except Exception as e:
                logger.error(f"Error researching vendor docs for {vendor}: {e}")
                
    async def _research_security_advisories(self, finding: Finding, intelligence: SecurityIntelligence):
        """Research security advisories and bulletins."""
        # This would integrate with security advisory APIs and RSS feeds
        # Implementation would depend on specific advisory sources
        pass
        
    async def _research_academic_sources(self, finding: Finding, intelligence: SecurityIntelligence):
        """Research academic papers and security research."""
        # This would integrate with academic databases and security research platforms
        # Implementation would depend on available APIs
        pass
        
    def _extract_mitre_data(self, result: CrawlResult, intelligence: SecurityIntelligence):
        """Extract data from MITRE CVE pages."""
        soup = BeautifulSoup(result.content, 'html.parser')
        
        # Extract CVE description
        desc_divs = soup.find_all('div', {'data-testid': 'vuln-description'})
        for div in desc_divs:
            text = div.get_text().strip()
            if text and len(text) > 50:
                intelligence.advisories.append({
                    'source': 'MITRE',
                    'description': text,
                    'url': result.url
                })
                
    def _extract_nvd_data(self, result: CrawlResult, intelligence: SecurityIntelligence):
        """Extract data from NVD pages."""
        # Implementation for NVD-specific data extraction
        pass
        
    def _extract_github_advisory_data(self, result: CrawlResult, intelligence: SecurityIntelligence):
        """Extract data from GitHub Security Advisories."""
        # Implementation for GitHub advisory data extraction
        pass
        
    def _extract_exploit_data(self, result: CrawlResult) -> List[Dict[str, Any]]:
        """Extract exploit information from exploit databases."""
        exploits = []
        soup = BeautifulSoup(result.content, 'html.parser')
        
        # Look for exploit listings, download links, PoC code
        exploit_links = soup.find_all('a', href=True)
        for link in exploit_links:
            href = link.get('href', '')
            text = link.get_text().strip()
            
            if any(keyword in text.lower() for keyword in ['exploit', 'poc', 'proof of concept', 'demonstration']):
                exploits.append({
                    'title': text,
                    'url': href,
                    'source': result.url
                })
                
        return exploits
        
    def _extract_vendor_patches(self, result: CrawlResult, finding: Finding) -> List[Dict[str, Any]]:
        """Extract patch information from vendor documentation."""
        patches = []
        soup = BeautifulSoup(result.content, 'html.parser')
        
        # Look for security-related announcements, changelogs, etc.
        security_sections = soup.find_all(['div', 'section'], 
                                        class_=lambda x: x and 'security' in x.lower())
        
        for section in security_sections:
            text = section.get_text().strip()
            if len(text) > 100:  # Substantial content
                patches.append({
                    'content': text[:500] + '...' if len(text) > 500 else text,
                    'source': result.url,
                    'vendor': self._determine_vendor_from_url(result.url)
                })
                
        return patches
        
    def _determine_vendor_from_url(self, url: str) -> str:
        """Determine vendor from URL."""
        for vendor, doc_url in self.VENDOR_DOCS.get('python', {}).items():
            if vendor in url:
                return vendor
        for vendor, doc_url in self.VENDOR_DOCS.get('javascript', {}).items():
            if vendor in url:
                return vendor
        return 'unknown'
        
    def _calculate_confidence_score(self, intelligence: SecurityIntelligence) -> float:
        """Calculate confidence score based on available intelligence."""
        score = 0.0
        
        # Base score from number of sources
        score += min(len(intelligence.sources) * 0.2, 0.6)
        
        # Bonus for high-quality sources
        quality_sources = ['cve.mitre.org', 'nvd.nist.gov', 'github.com']
        for source in intelligence.sources:
            if any(qs in source for qs in quality_sources):
                score += 0.1
                
        # Bonus for exploits found
        if intelligence.exploits:
            score += 0.2
            
        # Bonus for vendor patches
        if intelligence.patches:
            score += 0.1
            
        return min(score, 1.0)
        
    def _calculate_severity_score(self, finding: Finding, intelligence: SecurityIntelligence) -> float:
        """Calculate enhanced severity score."""
        base_severity = {
            Severity.LOW: 0.25,
            Severity.MEDIUM: 0.5,
            Severity.HIGH: 0.75,
            Severity.CRITICAL: 1.0
        }.get(finding.severity, 0.5)
        
        # Adjust based on exploit availability
        if intelligence.exploits:
            base_severity = min(base_severity + 0.2, 1.0)
            
        # Adjust based on patch availability
        if intelligence.patches:
            base_severity = max(base_severity - 0.1, 0.1)
            
        return base_severity
        
    def _calculate_exploitability_score(self, intelligence: SecurityIntelligence) -> float:
        """Calculate exploitability score."""
        score = 0.0
        
        # Base score from exploit availability
        if intelligence.exploits:
            score = 0.7
            
            # Bonus for PoC code
            for exploit in intelligence.exploits:
                if any(keyword in exploit.get('title', '').lower() 
                      for keyword in ['poc', 'proof of concept', 'demonstration']):
                    score = min(score + 0.2, 1.0)
                    break
                    
        return score


# Export the main class
__all__ = ['ModernWebIntelligenceAgent', 'SecurityIntelligence', 'CrawlResult']