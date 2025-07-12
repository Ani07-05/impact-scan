import requests
from typing import List, Dict, Any, Optional
import re
from ..utils.schema import Finding, ScanConfig
from rich.console import Console
import time
import hashlib
import google.generativeai as genai

console = Console()

class StackOverflowAPI:
    """
    Enhanced wrapper for the Stack Overflow API to search for vulnerability fixes.
    Implements rate limiting, caching, and improved search strategies.
    """
    BASE_URL = "https://api.stackexchange.com/2.3"

    def __init__(self, api_key: Optional[str] = None):
        self.api_key = api_key
        self.headers = {
            "Accept": "application/json",
            "User-Agent": "Impact-Scan-Security-Tool/1.0"
        }
        self.rate_limit_delay = 0.1  # 100ms between requests
        self.last_request_time = 0
        self.cache = {}  # Simple in-memory cache
        self.max_cache_size = 100
        
    def _rate_limit(self):
        """Implement rate limiting to avoid hitting API limits."""
        current_time = time.time()
        time_since_last_request = current_time - self.last_request_time
        if time_since_last_request < self.rate_limit_delay:
            time.sleep(self.rate_limit_delay - time_since_last_request)
        self.last_request_time = time.time()
        
    def _get_cache_key(self, url: str, params: dict) -> str:
        """Generate a cache key for the request."""
        cache_data = f"{url}_{str(sorted(params.items()))}"
        return hashlib.md5(cache_data.encode()).hexdigest()
        
    def _make_request(self, url: str, params: dict) -> List[Dict[str, Any]]:
        """Make a cached API request with rate limiting."""
        cache_key = self._get_cache_key(url, params)
        
        # Check cache first
        if cache_key in self.cache:
            console.log("[dim]Cache hit for API request[/dim]")
            return self.cache[cache_key]
            
        # Rate limiting
        self._rate_limit()
        
        # Make the request
        try:
            response = requests.get(url, params=params, headers=self.headers, timeout=10)
            response.raise_for_status()
            
            data = response.json()
            items = data.get("items", [])
            
            # Cache the result
            if len(self.cache) >= self.max_cache_size:
                # Simple LRU: remove oldest entry
                oldest_key = next(iter(self.cache))
                del self.cache[oldest_key]
            
            self.cache[cache_key] = items
            return items
            
        except requests.RequestException as e:
            console.log(f"[bold red]Error making API request:[/bold red] {e}")
            return []
    
    def search_questions(self, query: str, site: str = "stackoverflow") -> List[Dict[str, Any]]:
        """
        Search for questions on Stack Overflow using the API.
        
        Args:
            query: The search query
            site: The site to search (default: stackoverflow)
            
        Returns:
            List of question objects from the API
        """
        url = f"{self.BASE_URL}/search/advanced"
        
        params = {
            "q": query,
            "site": site,
            "order": "desc",
            "sort": "relevance",
            "filter": "withbody",
            "pagesize": 10,
            "accepted": "True"  # Prefer questions with accepted answers
        }
        
        if self.api_key:
            params["key"] = self.api_key
            
        return self._make_request(url, params)
    
    def get_question_answers(self, question_id: int, site: str = "stackoverflow") -> List[Dict[str, Any]]:
        """
        Get answers for a specific question.
        
        Args:
            question_id: The ID of the question
            site: The site to search (default: stackoverflow)
            
        Returns:
            List of answer objects from the API
        """
        url = f"{self.BASE_URL}/questions/{question_id}/answers"
        
        params = {
            "site": site,
            "order": "desc",
            "sort": "votes",
            "filter": "withbody",
            "pagesize": 5
        }
        
        if self.api_key:
            params["key"] = self.api_key
            
        return self._make_request(url, params)

def extract_code_blocks(html_content: str) -> List[str]:
    """
    Extract code blocks from HTML content.
    
    Args:
        html_content: HTML content from Stack Overflow
        
    Returns:
        List of code block strings
    """
    from bs4 import BeautifulSoup
    
    soup = BeautifulSoup(html_content, 'html.parser')
    code_blocks = []
    
    # Find all code blocks
    for code_tag in soup.find_all(['code', 'pre']):
        code_text = code_tag.get_text().strip()
        if code_text and len(code_text) > 10:  # Filter out very short code snippets
            code_blocks.append(code_text)
    
    return code_blocks

class GeminiWebSearch:
    """
    Gemini-powered agentic web search for vulnerability fixes.
    Uses Google's Gemini API to analyze and provide vulnerability fixes.
    """
    
    def __init__(self, api_key: str, stackoverflow_api: StackOverflowAPI, rate_limit_delay: float = 2.0):
        if not api_key:
            raise ValueError("Gemini API key is required for web search")
        
        genai.configure(api_key=api_key)
        self.model = genai.GenerativeModel('gemini-1.5-flash')
        self.stackoverflow_api = stackoverflow_api
        self.request_count = 0
        self.last_request_time = 0
        self.rate_limit_delay = rate_limit_delay
        self.cache = {}  # Simple cache for similar vulnerabilities
        self.max_cache_size = 200
        
    def _rate_limit(self):
        """Enhanced rate limiting with progressive backoff for high-volume scans."""
        current_time = time.time()
        time_since_last_request = current_time - self.last_request_time
        
        # Progressive backoff - longer delays after more requests
        if self.request_count > 80:
            delay = 5.0  # 5 seconds after 80 requests
            console.log(f"[yellow]⏳ High request count ({self.request_count}), using 5s delay[/yellow]")
        elif self.request_count > 50:
            delay = 3.0  # 3 seconds after 50 requests
            console.log(f"[yellow]⏳ Medium request count ({self.request_count}), using 3s delay[/yellow]")
        else:
            delay = self.rate_limit_delay
            
        if time_since_last_request < delay:
            sleep_time = delay - time_since_last_request
            console.log(f"[dim]Rate limiting: sleeping for {sleep_time:.1f}s[/dim]")
            time.sleep(sleep_time)
            
        self.last_request_time = time.time()
        self.request_count += 1
        
    def _get_cache_key(self, finding: Finding) -> str:
        """Generate cache key based on vulnerability type, file, and specific code pattern."""
        # Include file path, line number, and code snippet hash for specificity
        code_hash = hashlib.md5(finding.code_snippet.encode()).hexdigest()[:8]
        key_components = [
            finding.vuln_id,
            finding.title.lower(),
            finding.source.value,
            str(finding.file_path),  # Include specific file
            str(finding.line_number),  # Include specific line
            code_hash  # Include code pattern
        ]
        return hashlib.md5("|".join(key_components).encode()).hexdigest()
        
    def _get_cached_fix(self, finding: Finding) -> Optional[Dict[str, Any]]:
        """Get cached fix for similar vulnerability."""
        cache_key = self._get_cache_key(finding)
        return self.cache.get(cache_key)
        
    def _cache_fix(self, finding: Finding, fix_data: Dict[str, Any]):
        """Cache fix data for future use."""
        cache_key = self._get_cache_key(finding)
        
        # Simple LRU cache management
        if len(self.cache) >= self.max_cache_size:
            # Remove oldest entry
            oldest_key = next(iter(self.cache))
            del self.cache[oldest_key]
            
        self.cache[cache_key] = fix_data
        
    def search_for_vulnerability_fix(self, finding: Finding) -> Dict[str, Any]:
        """
        Search for vulnerability fixes using Gemini AI with caching.
        
        Args:
            finding: The vulnerability finding to search for
            
        Returns:
            Dictionary containing fix information, code snippets, and citations
        """
        # Check cache first
        cached_fix = self._get_cached_fix(finding)
        if cached_fix:
            console.log(f"[green]📋 Using cached fix for {finding.vuln_id}[/green]")
            return cached_fix
            
        try:
            # Rate limit before making API call
            self._rate_limit()
            
            # Create a comprehensive search prompt
            prompt = self._create_search_prompt(finding)
            
            console.log(f"[blue]🤖 ({self.request_count}) Searching with Gemini AI for {finding.vuln_id}...[/blue]")
            
            # Generate response
            response = self.model.generate_content(
                prompt,
                generation_config=genai.types.GenerationConfig(
                    temperature=0.1,
                    max_output_tokens=4096,
                    top_p=0.8,
                )
            )
            
            if response.text:
                console.log(f"[green]✅ Gemini found potential fixes for {finding.vuln_id}[/green]")
                result = self._parse_gemini_response(response.text, finding)
                
                # Cache the result if successful
                if result.get('has_fix'):
                    self._cache_fix(finding, result)
                    
                return result
            else:
                console.log(f"[yellow]⚠️  Gemini returned empty response for {finding.vuln_id}[/yellow]")
                return {'has_fix': False}
                
        except Exception as e:
            console.log(f"[red]❌ Gemini search failed for {finding.vuln_id}: {e}[/red]")
            return {'has_fix': False}
    
    def _create_search_prompt(self, finding: Finding) -> str:
        """Create a comprehensive search prompt for Gemini."""
        
        # Determine vulnerability type for better search
        vuln_type = "unknown"
        if "sql" in finding.title.lower() or "injection" in finding.title.lower():
            vuln_type = "SQL injection"
        elif "xss" in finding.title.lower() or "cross-site" in finding.title.lower():
            vuln_type = "Cross-Site Scripting (XSS)"
        elif "hardcoded" in finding.title.lower():
            vuln_type = "hardcoded credentials/secrets"
        elif "path" in finding.title.lower() and "traversal" in finding.title.lower():
            vuln_type = "path traversal"
        elif "md5" in finding.title.lower() or "hash" in finding.title.lower():
            vuln_type = "weak cryptographic hash"
        elif "requests" in finding.title.lower() and "timeout" in finding.title.lower():
            vuln_type = "network request timeout vulnerability"
        elif "verify=false" in finding.title.lower() or "ssl" in finding.title.lower():
            vuln_type = "SSL certificate validation bypass"
        elif "yaml" in finding.title.lower() and "load" in finding.title.lower():
            vuln_type = "unsafe YAML deserialization"
        
        # Extract file extension for language detection
        file_ext = str(finding.file_path).split('.')[-1].lower() if '.' in str(finding.file_path) else ''
        language = "python"
        if file_ext == "js":
            language = "javascript"
        elif file_ext == "java":
            language = "java"
        elif file_ext == "php":
            language = "php"
        elif file_ext in ["cpp", "c"]:
            language = "c++"
        
        prompt = f"""You are a master-level cybersecurity researcher and developer. Your task is to provide a precise, secure, and well-supported fix for a vulnerability.

**Vulnerability Details:**
- **ID:** {finding.vuln_id}
- **Title:** {finding.title}
- **Type:** {vuln_type}
- **Severity:** {finding.severity.value}
- **File:** `{finding.file_path}:{finding.line_number}`
- **Language:** {language}

**Vulnerable Code Snippet:**
```{language}
{finding.code_snippet}
```

**Description:**
{finding.description}

**Your Task (Respond in Markdown):**

1.  **Vulnerability Analysis:**
    *   In 1-2 sentences, explain precisely why the provided code is vulnerable.

2.  **Secure Code Fix:**
    *   Provide a complete, drop-in replacement for the vulnerable code snippet.
    *   The code must be secure, correct, and maintain the original functionality.
    *   Use the following format, replacing `{language}` with the correct language identifier:
        ```diff
        --- a/{finding.file_path}
        +++ b/{finding.file_path}
        @@ ... @@
        - {finding.code_snippet}
        + [Your secure code here]
        ```

3.  **Justification and Citation:**
    *   In 1-2 sentences, explain *why* your proposed fix is secure.
    *   **Crucially, back up your explanation with at least one highly relevant, specific URL (e.g., from OWASP, a security blog, official documentation, or a high-quality Stack Overflow answer).**
    *   The citation must directly support your proposed fix for this *specific* vulnerability type.
"""
        return prompt
    
    def _parse_gemini_response(self, response_text: str, finding: Finding) -> Dict[str, Any]:
        """Parse Gemini's response to extract fixes and useful information."""
        
        # Extract code blocks using regex - look for specific patterns
        code_pattern = r'```(?:python|javascript|java|php|sql|bash|js|py|cpp|c|diff)\s*\n(.*?)```'
        code_blocks = re.findall(code_pattern, response_text, re.DOTALL | re.IGNORECASE)
        
        # Also try generic code blocks
        if not code_blocks:
            generic_pattern = r'```\s*\n?(.*?)```'
            code_blocks = re.findall(generic_pattern, response_text, re.DOTALL)
        
        # Extract potential URLs
        url_pattern = r'https?://[^\s<>"{}|\\^`\[\]]*'
        urls = re.findall(url_pattern, response_text)
        
        # Find the best code fix - look for a diff block
        best_fix = None
        if code_blocks:
            for block in code_blocks:
                if block.strip().startswith('--- a/'):
                    best_fix = f"```diff\n{block.strip()}\n```"
                    break
            # Fallback to longest code block if no diff found
            if not best_fix:
                best_fix = max(code_blocks, key=len)

        # Extract explanation and justification
        justification_match = re.search(r"## Justification and Citation\s*(.*?)\s*(?:##|$)", response_text, re.DOTALL | re.IGNORECASE)
        analysis_match = re.search(r"## Vulnerability Analysis\s*(.*?)\s*(?:##|$)", response_text, re.DOTALL | re.IGNORECASE)
        
        explanation = ""
        if analysis_match:
            explanation += f"**Vulnerability Analysis:**\n{analysis_match.group(1).strip()}\n\n"
        if justification_match:
            explanation += f"**Justification:**\n{justification_match.group(1).strip()}"

        # Extract citations from the dedicated section and the rest of the text
        citations = []
        citations_match = re.search(r"## Web Citations\s*(.*?)\s*(?:##|$)", response_text, re.DOTALL | re.IGNORECASE)
        if citations_match:
            # Extract URLs from the markdown list in the Web Citations section
            list_items = re.findall(r'-\s*(https?://[^\s]+)', citations_match.group(1))
            citations.extend(list_items)

        # Add any other URLs found in the response, avoiding duplicates
        for url in urls:
            if url not in citations:
                citations.append(url)

        return {
            'fix_explanation': explanation or response_text,
            'code_fix': best_fix,
            'all_code_blocks': code_blocks,
            'citations': citations[:4],  # Limit to 4 citations
            'has_fix': best_fix is not None and len(best_fix.strip()) > 10
        }

def search_with_gemini(finding: Finding, config: ScanConfig, so_api: StackOverflowAPI) -> bool:
    """
    Search for vulnerability fixes using Gemini AI.
    
    Args:
        finding: The vulnerability finding to search for
        config: Scan configuration
        so_api: An instance of the StackOverflowAPI
        
    Returns:
        True if a fix was found and applied, False otherwise
    """
    try:
        # Get Gemini API key
        gemini_key = config.api_keys.gemini
        if not gemini_key:
            console.log("[yellow]No Gemini API key found, skipping AI search[/yellow]")
            return False
        
        # Initialize Gemini web search with configured delay
        gemini_search = GeminiWebSearch(gemini_key, so_api, config.web_search_delay)
        
        # Search for fixes
        result = gemini_search.search_for_vulnerability_fix(finding)
        
        if result.get('has_fix'):
            # Apply the fix to the finding with better structure
            finding.web_fix = result['code_fix']
            finding.ai_explanation = result['fix_explanation']
            
            # Store structured web fix data
            if not hasattr(finding, 'metadata') or finding.metadata is None:
                finding.metadata = {}
            
            finding.metadata.update({
                'web_fix_explanation': result['fix_explanation'],
                'web_fix_code': result['code_fix'],
                'gemini_powered': True,
                'cached_result': result.get('from_cache', False),
                'additional_citations': result['citations'][1:] if len(result['citations']) > 1 else []
            })
            
            # Add primary citation
            if result['citations']:
                finding.citation = result['citations'][0]
            else:
                # If Gemini provides a fix but no citation, mark it for enhancement
                finding.citation = "NEEDS_WEB_ENHANCEMENT"
            
            console.log(f"[bold green]✅ Found specific Gemini-powered fix for {finding.vuln_id}[/bold green]")
            return True
        else:
            console.log(f"[yellow]No suitable fix found via Gemini for {finding.vuln_id}[/yellow]")
            return False
            
    except Exception as e:
        console.log(f"[bold red]Error during Gemini search for {finding.vuln_id}:[/bold red] {e}")
        return False

def search_for_vulnerability_fix(finding: Finding, config: ScanConfig):
    """
    Searches for a fix for a given vulnerability using a hybrid approach.
    It prioritizes a Gemini-based AI search for a tailored fix and explanation,
    then enhances it with the best available web and Stack Overflow citations.
    
    Args:
        finding: The vulnerability finding to search for.
        config: Scan configuration.
    """
    if not config.enable_web_search:
        return

    console.log(f"🔍 Searching for vulnerability fix for [bold]{finding.vuln_id}[/bold]...")

    # Initialize Stack Overflow API
    so_api = StackOverflowAPI(config.api_keys.stackoverflow)

    # --- Step 1: Get the primary fix and explanation from Gemini AI ---
    search_with_gemini(finding, config, so_api)

    # --- Step 2: Enhance the finding with the best possible citations ---
    console.log(f"🔗 Enhancing citations for [bold]{finding.vuln_id}[/bold]...")
    
    # Initialize metadata if it doesn't exist
    if not hasattr(finding, 'metadata') or finding.metadata is None:
        finding.metadata = {}
    if 'additional_citations' not in finding.metadata:
        finding.metadata['additional_citations'] = []

    # A. Prioritize finding a high-quality Stack Overflow link
    # best_so_url = find_best_stackoverflow_url(finding, so_api)
    # if best_so_url:
    #     console.log(f"[green]🎯 Found high-quality Stack Overflow URL: {best_so_url}[/green]")
    #     # Add to the top of the list to prioritize it
    #     if best_so_url not in finding.metadata['additional_citations']:
    #         finding.metadata['additional_citations'].insert(0, best_so_url)

    # B. Search other credible web sources for more context
    additional_urls = search_additional_sources(finding)
    if additional_urls:
        console.log(f"[green]🔗 Found {len(additional_urls)} additional web sources[/green]")
        for url in additional_urls:
            if url not in finding.metadata['additional_citations']:
                finding.metadata['additional_citations'].append(url)

    # --- Step 3: Set the primary citation from the collected sources ---
    # Use the original Gemini citation if it's a valid URL, otherwise pick the best from our search.
    if finding.citation and finding.citation.startswith("http"):
        pass  # Keep the specific citation from Gemini
    elif finding.metadata['additional_citations']:
        # Promote the best-found citation to be the primary one
        finding.citation = finding.metadata['additional_citations'].pop(0)
    else:
        # If no citations were found at all, clear any placeholders
        finding.citation = ""

    if not finding.web_fix:
        console.log(f"[yellow]⚠️  No suitable fix found for {finding.vuln_id}[/yellow]")


def find_best_stackoverflow_url(finding: Finding, so_api: StackOverflowAPI) -> Optional[str]:
    """
    Finds the best Stack Overflow URL for a given finding.
    
    Args:
        finding: The vulnerability finding.
        so_api: An initialized StackOverflowAPI instance.
        
    Returns:
        The best URL as a string, or None.
    """
    try:
        file_ext = str(finding.file_path).split('.')[-1].lower() if '.' in str(finding.file_path) else ''
        search_queries = [
            f"{finding.vuln_id} {file_ext} fix",
            f"{finding.title} secure coding {file_ext}",
            f"how to fix \"{finding.title}\" in {file_ext}",
        ]
        
        best_score = -1
        best_url = None
        
        for query in search_queries:
            questions = so_api.search_questions(query)
            for question in questions[:3]:  # Check top 3 questions per query
                question_score = question.get("score", 0)
                is_accepted = question.get("is_accepted", False)
                
                # Simple scoring: accepted answers with high score are best
                score = question_score + (50 if is_accepted else 0)
                
                if score > best_score:
                    best_score = score
                    best_url = question.get("link")
        
        return best_url
    except Exception as e:
        console.log(f"[bold red]Error during Stack Overflow search for {finding.vuln_id}:[/bold red] {e}")
        return None

def search_additional_sources(finding: Finding) -> List[str]:
    """
    Search for additional specific sources beyond Stack Overflow.
    Returns a list of relevant URLs from CVE databases, security blogs, etc.
    """
    sources = []
    
    try:
        # Search for CVE-specific information if vuln_id looks like a CVE
        if "cve-" in finding.vuln_id.lower():
            cve_id = finding.vuln_id.upper()
            sources.append(f"https://nvd.nist.gov/vuln/detail/{cve_id}")
            sources.append(f"https://cve.mitre.org/cgi-bin/cvename.cgi?name={cve_id}")
        
        # Add specific sources based on vulnerability type
        vuln_lower = finding.title.lower()
        
        if "sql injection" in vuln_lower or "sqli" in vuln_lower:
            sources.extend([
                "https://portswigger.net/web-security/sql-injection",
                "https://cheatsheetseries.owasp.org/cheatsheets/SQL_Injection_Prevention_Cheat_Sheet.html"
            ])
        elif "xss" in vuln_lower or "cross-site scripting" in vuln_lower:
            sources.extend([
                "https://portswigger.net/web-security/cross-site-scripting",
                "https://cheatsheetseries.owasp.org/cheatsheets/Cross_Site_Scripting_Prevention_Cheat_Sheet.html"
            ])
        elif "path traversal" in vuln_lower:
            sources.extend([
                "https://portswigger.net/web-security/file-path-traversal",
                "https://owasp.org/www-community/attacks/Path_Traversal"
            ])
        elif "hardcoded" in vuln_lower:
            sources.extend([
                "https://cheatsheetseries.owasp.org/cheatsheets/Secrets_Management_Cheat_Sheet.html",
                "https://cwe.mitre.org/data/definitions/798.html"
            ])
        elif "yaml" in vuln_lower and ("load" in vuln_lower or "unsafe" in vuln_lower):
            sources.extend([
                "https://pyyaml.org/wiki/PyYAMLDocumentation",
                "https://security.snyk.io/vuln/SNYK-PYTHON-PYYAML-42159",
                "https://blog.sentry.io/unsafe-yaml-loading/"
            ])
        elif "md5" in vuln_lower or "weak hash" in vuln_lower:
            sources.extend([
                "https://cheatsheetseries.owasp.org/cheatsheets/Password_Storage_Cheat_Sheet.html",
                "https://cwe.mitre.org/data/definitions/327.html"
            ])
        elif "ssl" in vuln_lower and "verify" in vuln_lower:
            sources.extend([
                "https://requests.readthedocs.io/en/latest/user/advanced/#ssl-cert-verification",
                "https://cheatsheetseries.owasp.org/cheatsheets/Transport_Layer_Protection_Cheat_Sheet.html"
            ])
        elif "timeout" not in finding.title.lower() and "request" in finding.title.lower():
             sources.extend([
                "https://requests.readthedocs.io/en/latest/user/quickstart/#timeouts",
                "https://cwe.mitre.org/data/definitions/400.html"
            ])
        
        # Limit to first 3 sources to avoid overwhelming the report
        return list(dict.fromkeys(sources))[:3]  # Remove duplicates and limit
        
    except Exception as e:
        console.log(f"[yellow]Warning: Could not search additional sources: {e}[/yellow]")
        return []

def process_findings_for_web_fixes(findings: List[Finding], config: ScanConfig):
    """
    Processes findings with advanced batching, prioritization, and rate limiting.
    
    Args:
        findings: List of vulnerability findings
        config: Scan configuration with enhanced web search settings
    """
    if not config.enable_web_search:
        return

    console.log(f"🚀 Processing {len(findings)} findings for web fixes using intelligent batching...")
    
    # Check available APIs
    gemini_available = bool(config.api_keys.gemini)
    so_available = bool(config.api_keys.stackoverflow)
    
    if gemini_available:
        console.log(f"[bold green]🤖 Gemini AI web search enabled (delay: {config.web_search_delay}s)[/bold green]")
    if so_available:
        console.log("[bold blue]📚 Stack Overflow API search enabled[/bold blue]")
    
    if not gemini_available and not so_available:
        console.log("[yellow]⚠️  No API keys found for web search - using basic search[/yellow]")
    
    # Prioritize findings by severity if enabled
    if config.prioritize_high_severity:
        console.log("[cyan]🎯 Prioritizing findings by severity (CRITICAL → HIGH → MEDIUM → LOW)[/cyan]")
        
        # Separate findings by severity
        severity_order = ['CRITICAL', 'HIGH', 'MEDIUM', 'LOW']
        prioritized_findings = []
        
        for severity in severity_order:
            severity_findings = [f for f in findings if f.severity.value.upper() == severity]
            if severity_findings:
                console.log(f"[dim]Found {len(severity_findings)} {severity} severity findings[/dim]")
                prioritized_findings.extend(severity_findings)
        
        # Add any remaining findings not in the standard severity levels
        remaining_findings = [f for f in findings if f not in prioritized_findings]
        prioritized_findings.extend(remaining_findings)
        
        findings = prioritized_findings
    
    # Apply limit and show statistics
    total_findings = len(findings)
    limited_findings = findings[:config.web_search_limit]
    
    if total_findings > config.web_search_limit:
        console.log(f"[yellow]⚠️  Limiting web search to {config.web_search_limit} out of {total_findings} findings[/yellow]")
        console.log(f"[dim]Skipping {total_findings - config.web_search_limit} findings to stay within limits[/dim]")
    
    console.log("[bold cyan]📊 Processing Strategy:[/bold cyan]")
    console.log(f"  • Total findings: {total_findings}")
    console.log(f"  • Processing limit: {config.web_search_limit}")
    console.log(f"  • Batch size: {config.web_search_batch_size}")
    console.log(f"  • Rate limit delay: {config.web_search_delay}s")
    console.log(f"  • Prioritize by severity: {config.prioritize_high_severity}")
    
    # Process findings in batches
    total_processed = 0
    successful_fixes = 0
    cached_hits = 0
    
    # Initialize global cache for deduplication across batches
    processed_cache = set()
    
    for batch_start in range(0, len(limited_findings), config.web_search_batch_size):
        batch_end = min(batch_start + config.web_search_batch_size, len(limited_findings))
        batch = limited_findings[batch_start:batch_end]
        batch_num = (batch_start // config.web_search_batch_size) + 1
        total_batches = (len(limited_findings) + config.web_search_batch_size - 1) // config.web_search_batch_size
        
        console.log(f"\n[bold magenta]🔄 Batch {batch_num}/{total_batches} ({len(batch)} findings)[/bold magenta]")
        
        batch_start_time = time.time()
        batch_successful = 0
        batch_cached = 0
        
        for i, finding in enumerate(batch, 1):
            # Simple deduplication based on vuln_id and title
            dedup_key = f"{finding.vuln_id}_{finding.title}"
            if dedup_key in processed_cache:
                console.log(f"[dim]({total_processed + i}) Skipping duplicate: {finding.vuln_id}[/dim]")
                continue
                
            processed_cache.add(dedup_key)
            
            console.log(f"[bold cyan]({total_processed + i}/{len(limited_findings)}) Processing:[/bold cyan] {finding.vuln_id} [{finding.severity.value.upper()}]")
            
            # Search for vulnerability fix
            search_for_vulnerability_fix(finding, config)
            
            # Track results
            if finding.web_fix:
                batch_successful += 1
                successful_fixes += 1
                
                # Check if it was a cache hit
                final_metadata = getattr(finding, 'metadata', {})
                if final_metadata.get('cached_result'):
                    batch_cached += 1
                    cached_hits += 1
                    
                console.log(f"[bold green]✅ Fix found for {finding.vuln_id}[/bold green]")
            else:
                console.log(f"[yellow]⚠️  No fix found for {finding.vuln_id}[/yellow]")
        
        batch_duration = time.time() - batch_start_time
        total_processed += len(batch)
        
        # Batch summary
        console.log(f"[dim]Batch {batch_num} complete in {batch_duration:.1f}s: {batch_successful}/{len(batch)} fixes found ({batch_cached} cached)[/dim]")
        
        # Inter-batch delay for rate limiting (except for the last batch)
        if batch_end < len(limited_findings):
            inter_batch_delay = max(5.0, config.web_search_delay * 2)  # Longer delay between batches
            console.log(f"[dim]⏸️  Waiting {inter_batch_delay}s before next batch...[/dim]")
            time.sleep(inter_batch_delay)
    
    # Final summary statistics
    console.log("\n[bold green]🎉 Web search complete![/bold green]")
    console.log("[bold cyan]📈 Final Results:[/bold cyan]")
    console.log(f"  • Total processed: {total_processed}/{total_findings}")
    console.log(f"  • Successful fixes: {successful_fixes} ({successful_fixes/total_processed*100:.1f}%)")
    console.log(f"  • Cache hits: {cached_hits} ({cached_hits/total_processed*100:.1f}%)")
    console.log(f"  • Actual API calls: {successful_fixes - cached_hits}")
    
    # Add findings with citations count
    cited_count = sum(1 for f in limited_findings if f.citation)
    console.log(f"  • Citations added: {cited_count}")
    
    # Show severity breakdown of successful fixes
    if successful_fixes > 0:
        console.log("[bold cyan]🎯 Fixes by Severity:[/bold cyan]")
        for severity in ['CRITICAL', 'HIGH', 'MEDIUM', 'LOW']:
            severity_fixes = sum(1 for f in limited_findings 
                               if f.web_fix and f.severity.value.upper() == severity)
            if severity_fixes > 0:
                console.log(f"  • {severity}: {severity_fixes} fixes")
    
    console.log("[bold green]✅ Ready to handle high-volume scans with intelligent rate limiting![/bold green]")
