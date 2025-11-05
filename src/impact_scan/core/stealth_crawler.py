"""
Stealth Crawler and JavaScript Intelligence Agent for Impact Scan

Advanced web crawling with anti-bot protection bypass and JavaScript rendering
for comprehensive security intelligence gathering on modern web applications.
"""

import asyncio
import random
import time
import json
from typing import List, Dict, Any, Optional, Set
from dataclasses import dataclass, field
from pathlib import Path
import logging

from playwright.async_api import async_playwright, Browser, Page, Playwright, BrowserContext
# from crawlee.playwright_crawler import PlaywrightCrawler, PlaywrightCrawlingContext
# from crawlee.storages import Dataset
import httpx
from rich.console import Console

from ..utils.schema import Finding, ScanConfig
from .modern_web_intelligence import SecurityIntelligence, CrawlResult

logger = logging.getLogger(__name__)
console = Console()


@dataclass
class StealthConfig:
    """Configuration for stealth crawling operations."""
    max_concurrency: int = 5
    request_delay_min: float = 1.0
    request_delay_max: float = 3.0
    retry_attempts: int = 3
    timeout: float = 30.0
    use_proxy_rotation: bool = False
    proxy_list: List[str] = field(default_factory=list)
    browser_args: List[str] = field(default_factory=lambda: [
        '--no-sandbox',
        '--disable-blink-features=AutomationControlled',
        '--disable-dev-shm-usage',
        '--disable-background-timer-throttling',
        '--disable-backgrounding-occluded-windows',
        '--disable-renderer-backgrounding',
        '--disable-features=TranslateUI',
        '--disable-ipc-flooding-protection',
    ])


@dataclass
class JavaScriptSecurityData:
    """Extracted security-relevant data from JavaScript-heavy sites."""
    vulnerability_id: str
    source_url: str
    security_advisories: List[Dict[str, Any]] = field(default_factory=list)
    exploit_demos: List[Dict[str, Any]] = field(default_factory=list)
    patch_information: List[Dict[str, Any]] = field(default_factory=list)
    poc_code_snippets: List[str] = field(default_factory=list)
    vendor_responses: List[Dict[str, Any]] = field(default_factory=list)
    dynamic_content: Dict[str, Any] = field(default_factory=dict)
    api_endpoints: List[str] = field(default_factory=list)
    security_headers: Dict[str, str] = field(default_factory=dict)


class JavaScriptIntelligenceAgent:
    """
    Advanced JavaScript-capable intelligence agent for modern security sites.
    
    Handles:
    - Single Page Applications (SPAs)
    - Dynamic content loading
    - API endpoint discovery
    - Security header analysis
    - Interactive security demonstrations
    """
    
    def __init__(self, config: ScanConfig, stealth_config: StealthConfig = None):
        self.config = config
        self.stealth_config = stealth_config or StealthConfig()
        self.playwright: Optional[Playwright] = None
        self.browser: Optional[Browser] = None
        self.contexts: List[BrowserContext] = []
        self.discovered_apis: Set[str] = set()
        
    async def __aenter__(self):
        """Async context manager entry."""
        await self.initialize()
        return self
        
    async def __aexit__(self, exc_type, exc_val, exc_tb):
        """Async context manager exit."""
        await self.cleanup()
        
    async def initialize(self):
        """Initialize Playwright and browser instances."""
        self.playwright = await async_playwright().start()
        
        # Launch browser with stealth configuration
        self.browser = await self.playwright.chromium.launch(
            headless=True,
            args=self.stealth_config.browser_args
        )
        
        console.log("[bold green][JS_AGENT] JavaScript Intelligence Agent initialized[/bold green]")
        
    async def cleanup(self):
        """Clean up browser resources."""
        for context in self.contexts:
            await context.close()
        if self.browser:
            await self.browser.close()
        if self.playwright:
            await self.playwright.stop()
            
        console.log("[dim][JS_CLEANUP] JavaScript Agent resources cleaned up[/dim]")
        
    async def create_stealth_context(self) -> BrowserContext:
        """Create a browser context with advanced stealth features."""
        context = await self.browser.new_context(
            viewport={'width': 1920, 'height': 1080},
            user_agent='Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36',
            locale='en-US',
            timezone_id='America/New_York',
            permissions=['geolocation'],
            extra_http_headers={
                'Accept-Language': 'en-US,en;q=0.9',
                'Accept-Encoding': 'gzip, deflate, br',
                'Cache-Control': 'no-cache',
                'Pragma': 'no-cache',
                'Sec-Fetch-Dest': 'document',
                'Sec-Fetch-Mode': 'navigate',
                'Sec-Fetch-Site': 'none',
                'Sec-Fetch-User': '?1',
                'Upgrade-Insecure-Requests': '1',
            }
        )
        
        # Advanced stealth scripts
        await context.add_init_script("""
            // Remove webdriver property
            Object.defineProperty(navigator, 'webdriver', {
                get: () => undefined,
            });
            
            // Mock plugins
            Object.defineProperty(navigator, 'plugins', {
                get: () => [1, 2, 3, 4, 5],
            });
            
            // Mock languages
            Object.defineProperty(navigator, 'languages', {
                get: () => ['en-US', 'en'],
            });
            
            // Mock Chrome runtime
            window.chrome = {
                runtime: {},
            };
            
            // Override permissions API
            const originalQuery = window.navigator.permissions.query;
            window.navigator.permissions.query = (parameters) => (
                parameters.name === 'notifications' ?
                    Promise.resolve({ state: Uint8Array.from([1]) }) :
                    originalQuery(parameters)
            );
            
            // Mock getters
            Object.defineProperty(navigator, 'hardwareConcurrency', {
                get: () => 8,
            });
            
            Object.defineProperty(navigator, 'deviceMemory', {
                get: () => 8,
            });
        """)
        
        self.contexts.append(context)
        return context
        
    async def research_javascript_heavy_site(self, url: str, vulnerability_id: str) -> JavaScriptSecurityData:
        """
        Research security information from JavaScript-heavy sites.
        
        Args:
            url: Target URL to research
            vulnerability_id: Vulnerability identifier
            
        Returns:
            JavaScriptSecurityData with extracted information
        """
        data = JavaScriptSecurityData(
            vulnerability_id=vulnerability_id,
            source_url=url
        )
        
        context = await self.create_stealth_context()
        page = await context.new_page()
        
        try:
            # Set up network monitoring
            await self._setup_network_monitoring(page, data)
            
            console.log(f"[bold cyan][JS_RESEARCH] Researching {url} for {vulnerability_id}[/bold cyan]")
            
            # Navigate with advanced waiting strategies
            await page.goto(url, wait_until='networkidle', timeout=self.stealth_config.timeout * 1000)
            
            # Wait for dynamic content to load
            await asyncio.sleep(random.uniform(2, 5))
            
            # Extract security headers
            response = await page.goto(url)
            if response:
                data.security_headers = response.headers
                
            # Extract security-relevant content
            await self._extract_security_advisories(page, data)
            await self._extract_exploit_demonstrations(page, data)
            await self._extract_patch_information(page, data)
            await self._extract_poc_code(page, data)
            await self._extract_vendor_responses(page, data)
            
            # Analyze dynamic content
            await self._analyze_dynamic_content(page, data)
            
            # Discover API endpoints
            await self._discover_api_endpoints(page, data)
            
            console.log(f"[bold green][JS_SUCCESS] Extracted data from {url}: "
                       f"Advisories: {len(data.security_advisories)}, "
                       f"Exploits: {len(data.exploit_demos)}, "
                       f"APIs: {len(data.api_endpoints)}[/bold green]")
                       
        except Exception as e:
            logger.error(f"Error researching JavaScript site {url}: {e}")
            
        finally:
            await page.close()
            await context.close()
            
        return data
        
    async def _setup_network_monitoring(self, page: Page, data: JavaScriptSecurityData):
        """Set up network request monitoring to discover API endpoints."""
        async def handle_request(request):
            url = request.url
            
            # Track API endpoints
            if any(api_indicator in url for api_indicator in ['/api/', '/v1/', '/v2/', '/graphql', '/rest']):
                data.api_endpoints.append(url)
                self.discovered_apis.add(url)
                
        async def handle_response(response):
            # Analyze security-relevant responses
            if response.status == 200:
                content_type = response.headers.get('content-type', '')
                if 'application/json' in content_type:
                    try:
                        json_data = await response.json()
                        if any(sec_keyword in str(json_data).lower() 
                              for sec_keyword in ['vulnerability', 'exploit', 'cve', 'security']):
                            data.dynamic_content[response.url] = json_data
                    except:
                        pass
                        
        page.on('request', handle_request)
        page.on('response', handle_response)
        
    async def _extract_security_advisories(self, page: Page, data: JavaScriptSecurityData):
        """Extract security advisory information from the page."""
        # Look for security advisory sections
        advisory_selectors = [
            '[class*="advisory"]', '[class*="security"]', '[class*="vulnerability"]',
            '[id*="advisory"]', '[id*="security"]', '[id*="vulnerability"]',
            'section[class*="cve"]', 'div[class*="bulletin"]'
        ]
        
        for selector in advisory_selectors:
            try:
                elements = await page.locator(selector).all()
                for element in elements:
                    text = await element.text_content()
                    if text and len(text.strip()) > 50:
                        data.security_advisories.append({
                            'selector': selector,
                            'content': text.strip()[:1000],  # Limit content size
                            'html': await element.inner_html()
                        })
            except:
                continue
                
    async def _extract_exploit_demonstrations(self, page: Page, data: JavaScriptSecurityData):
        """Extract exploit demonstration content."""
        # Look for exploit demos, PoC sections
        exploit_selectors = [
            '[class*="exploit"]', '[class*="poc"]', '[class*="demo"]',
            '[class*="proof"]', '[class*="example"]', 'pre', 'code'
        ]
        
        for selector in exploit_selectors:
            try:
                elements = await page.locator(selector).all()
                for element in elements:
                    text = await element.text_content()
                    if text and any(keyword in text.lower() 
                                  for keyword in ['exploit', 'poc', 'payload', 'attack']):
                        data.exploit_demos.append({
                            'selector': selector,
                            'content': text.strip()[:2000],  # Larger limit for code
                            'type': 'code' if selector in ['pre', 'code'] else 'text'
                        })
            except:
                continue
                
    async def _extract_patch_information(self, page: Page, data: JavaScriptSecurityData):
        """Extract patch and fix information."""
        patch_selectors = [
            '[class*="patch"]', '[class*="fix"]', '[class*="update"]',
            '[class*="changelog"]', '[class*="release"]'
        ]
        
        for selector in patch_selectors:
            try:
                elements = await page.locator(selector).all()
                for element in elements:
                    text = await element.text_content()
                    if text and any(keyword in text.lower() 
                                  for keyword in ['patch', 'fix', 'update', 'resolved']):
                        data.patch_information.append({
                            'selector': selector,
                            'content': text.strip()[:1000],
                            'links': await self._extract_links_from_element(element)
                        })
            except:
                continue
                
    async def _extract_poc_code(self, page: Page, data: JavaScriptSecurityData):
        """Extract PoC code snippets."""
        code_selectors = ['pre', 'code', '[class*="highlight"]', '[class*="code"]']
        
        for selector in code_selectors:
            try:
                elements = await page.locator(selector).all()
                for element in elements:
                    text = await element.text_content()
                    if text and len(text.strip()) > 20:  # Substantial code content
                        # Check if it looks like security-relevant code
                        if any(keyword in text.lower() for keyword in [
                            'import', 'function', 'class', 'def', 'var', 'let', 'const',
                            'exploit', 'payload', 'attack', 'injection', 'xss', 'sql'
                        ]):
                            data.poc_code_snippets.append(text.strip())
            except:
                continue
                
    async def _extract_vendor_responses(self, page: Page, data: JavaScriptSecurityData):
        """Extract vendor response information."""
        vendor_selectors = [
            '[class*="vendor"]', '[class*="response"]', '[class*="statement"]',
            '[class*="official"]', '[class*="acknowledge"]'
        ]
        
        for selector in vendor_selectors:
            try:
                elements = await page.locator(selector).all()
                for element in elements:
                    text = await element.text_content()
                    if text and len(text.strip()) > 50:
                        data.vendor_responses.append({
                            'content': text.strip()[:1000],
                            'timestamp': await self._extract_timestamp(element),
                            'source': 'page_content'
                        })
            except:
                continue
                
    async def _analyze_dynamic_content(self, page: Page, data: JavaScriptSecurityData):
        """Analyze dynamically loaded content."""
        # Scroll to trigger lazy loading
        await page.evaluate("""
            window.scrollTo(0, document.body.scrollHeight);
        """)
        
        await asyncio.sleep(2)
        
        # Look for AJAX-loaded content
        try:
            # Wait for any dynamic security content
            await page.wait_for_function("""
                () => document.querySelectorAll('[class*="security"], [class*="vulnerability"]').length > 0
            """, timeout=5000)
        except:
            pass
            
        # Extract any new content that appeared
        dynamic_elements = await page.locator('[data-loaded="true"], [class*="loaded"]').all()
        for element in dynamic_elements:
            try:
                text = await element.text_content()
                if text and any(keyword in text.lower() 
                              for keyword in ['security', 'vulnerability', 'exploit']):
                    data.dynamic_content['lazy_loaded'] = text.strip()[:1000]
            except:
                continue
                
    async def _discover_api_endpoints(self, page: Page, data: JavaScriptSecurityData):
        """Discover API endpoints through JavaScript analysis."""
        # Extract API endpoints from JavaScript code
        api_discovery_script = r"""
            () => {
                const scripts = Array.from(document.querySelectorAll('script'));
                const apiEndpoints = new Set();
                
                scripts.forEach(script => {
                    const text = script.textContent || script.innerText;
                    
                    // Look for API endpoint patterns
                    const apiPatterns = [
                        /['"](\/api\/[^'"]+)['"]/g,
                        /['"](https?:\/\/[^'"]+\/api\/[^'"]+)['"]/g,
                        /['"](\/v\d+\/[^'"]+)['"]/g,
                        /fetch\s*\(\s*['"]([^'"]+)['"]/g,
                        /axios\.\w+\s*\(\s*['"]([^'"]+)['"]/g
                    ];
                    
                    apiPatterns.forEach(pattern => {
                        let match;
                        while ((match = pattern.exec(text)) !== null) {
                            if (match[1]) {
                                apiEndpoints.add(match[1]);
                            }
                        }
                    });
                });
                
                return Array.from(apiEndpoints);
            }
        """
        
        try:
            discovered_endpoints = await page.evaluate(api_discovery_script)
            data.api_endpoints.extend(discovered_endpoints)
        except Exception as e:
            logger.error(f"Error discovering API endpoints: {e}")
            
    async def _extract_links_from_element(self, element) -> List[str]:
        """Extract links from an element."""
        try:
            links = await element.locator('a[href]').all()
            return [await link.get_attribute('href') for link in links]
        except:
            return []
            
    async def _extract_timestamp(self, element) -> Optional[str]:
        """Extract timestamp from an element."""
        try:
            # Look for time elements or date patterns
            time_element = await element.locator('time').first
            if time_element:
                return await time_element.get_attribute('datetime')
        except:
            pass
            
        # Look for date patterns in text
        try:
            text = await element.text_content()
            import re
            date_pattern = r'\d{4}-\d{2}-\d{2}'
            match = re.search(date_pattern, text)
            if match:
                return match.group()
        except:
            pass
            
        return None


class StealthCrawlingAgent:
    """
    Advanced stealth crawling agent with anti-bot protection bypass.
    
    Features:
    - Browser fingerprint randomization
    - Proxy rotation support
    - Human-like behavior simulation
    - Rate limiting and retry logic
    - Captcha detection and avoidance
    """
    
    def __init__(self, config: ScanConfig, stealth_config: StealthConfig = None):
        self.config = config
        self.stealth_config = stealth_config or StealthConfig()
        self.js_agent = JavaScriptIntelligenceAgent(config, stealth_config)
        self.crawl_results: List[CrawlResult] = []
        
    async def stealth_crawl_security_sources(self, 
                                           target_urls: List[str], 
                                           vulnerability_id: str) -> List[JavaScriptSecurityData]:
        """
        Perform stealth crawling of security sources with anti-detection.
        
        Args:
            target_urls: List of URLs to crawl
            vulnerability_id: Vulnerability identifier for context
            
        Returns:
            List of extracted security data
        """
        results = []
        
        console.log(f"[bold cyan][STEALTH_CRAWL] Starting stealth crawl for {vulnerability_id}[/bold cyan]")
        
        async with self.js_agent:
            for i, url in enumerate(target_urls):
                try:
                    # Human-like delay between requests
                    if i > 0:
                        delay = random.uniform(
                            self.stealth_config.request_delay_min,
                            self.stealth_config.request_delay_max
                        )
                        console.log(f"[dim][STEALTH_DELAY] Waiting {delay:.1f}s before next request[/dim]")
                        await asyncio.sleep(delay)
                        
                    # Research the site
                    data = await self.js_agent.research_javascript_heavy_site(url, vulnerability_id)
                    results.append(data)
                    
                    console.log(f"[green][STEALTH_SUCCESS] ({i+1}/{len(target_urls)}) {url}[/green]")
                    
                except Exception as e:
                    logger.error(f"Stealth crawl failed for {url}: {e}")
                    continue
                    
        console.log(f"[bold green][STEALTH_COMPLETE] Crawled {len(results)} sites successfully[/bold green]")
        return results
        
    async def bypass_common_protections(self, page: Page) -> bool:
        """
        Attempt to bypass common anti-bot protections.
        
        Returns:
            True if bypass was successful, False otherwise
        """
        try:
            # Check for common protection indicators
            protection_indicators = [
                'cloudflare', 'captcha', 'bot protection', 
                'please wait', 'checking your browser'
            ]
            
            page_content = await page.content()
            page_content_lower = page_content.lower()
            
            if any(indicator in page_content_lower for indicator in protection_indicators):
                console.log("[yellow][PROTECTION_DETECTED] Bot protection detected, attempting bypass[/yellow]")
                
                # Wait for potential automatic bypass
                await asyncio.sleep(random.uniform(3, 7))
                
                # Simulate human behavior
                await self._simulate_human_behavior(page)
                
                # Check if bypass was successful
                new_content = await page.content()
                if len(new_content) > len(page_content) * 1.2:  # Significant content increase
                    console.log("[green][BYPASS_SUCCESS] Protection bypass successful[/green]")
                    return True
                else:
                    console.log("[red][BYPASS_FAILED] Protection bypass failed[/red]")
                    return False
                    
            return True  # No protection detected
            
        except Exception as e:
            logger.error(f"Error during protection bypass: {e}")
            return False
            
    async def _simulate_human_behavior(self, page: Page):
        """Simulate human-like behavior on the page."""
        try:
            # Random mouse movements
            await page.mouse.move(
                random.randint(100, 800),
                random.randint(100, 600)
            )
            
            # Random scrolling
            scroll_distance = random.randint(100, 500)
            await page.evaluate(f"window.scrollBy(0, {scroll_distance})")
            
            await asyncio.sleep(random.uniform(0.5, 2.0))
            
            # Another scroll
            scroll_distance = random.randint(-200, 200)
            await page.evaluate(f"window.scrollBy(0, {scroll_distance})")
            
        except Exception as e:
            logger.error(f"Error simulating human behavior: {e}")


# Export main classes
__all__ = [
    'JavaScriptIntelligenceAgent', 
    'StealthCrawlingAgent', 
    'JavaScriptSecurityData', 
    'StealthConfig'
]