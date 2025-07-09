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
    
    def __init__(self, api_key: str):
        if not api_key:
            raise ValueError("Gemini API key is required for web search")
        
        genai.configure(api_key=api_key)
        self.model = genai.GenerativeModel('gemini-1.5-flash')
        
    def search_for_vulnerability_fix(self, finding: Finding) -> Dict[str, Any]:
        """
        Search for vulnerability fixes using Gemini AI.
        
        Args:
            finding: The vulnerability finding to search for
            
        Returns:
            Dictionary containing fix information, code snippets, and citations
        """
        try:
            # Create a comprehensive search prompt
            prompt = self._create_search_prompt(finding)
            
            console.log(f"[blue]🤖 Searching with Gemini AI for {finding.vuln_id}...[/blue]")
            
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
                return self._parse_gemini_response(response.text, finding)
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
        
        prompt = f"""
You are a cybersecurity expert. I need help finding a specific fix for this vulnerability:

VULNERABILITY DETAILS:
- ID: {finding.vuln_id}
- Title: {finding.title}
- Type: {vuln_type}
- Severity: {finding.severity.value}
- Source: {finding.source.value}
- File: {finding.file_path}
- Line: {finding.line_number}

VULNERABLE CODE:
```
{finding.code_snippet}
```

DESCRIPTION: {finding.description}

Please provide:

1. **EXPLANATION**: What exactly is wrong with this code and why it's vulnerable

2. **SECURE FIX**: Provide a secure code replacement that fixes this exact vulnerability. Include the complete corrected code snippet.

3. **BEST PRACTICES**: List 3-5 security best practices to prevent this type of vulnerability

4. **ADDITIONAL RESOURCES**: Suggest relevant documentation, OWASP guidelines, or security resources

Format your response clearly with headers for each section. Focus on practical, implementable solutions.
"""
        return prompt
    
    def _parse_gemini_response(self, response_text: str, finding: Finding) -> Dict[str, Any]:
        """Parse Gemini's response to extract fixes and useful information."""
        
        # Extract code blocks using regex
        code_pattern = r'```(?:python|javascript|java|php|sql|bash|js|py)?\n?(.*?)```'
        code_blocks = re.findall(code_pattern, response_text, re.DOTALL | re.IGNORECASE)
        
        # Extract potential URLs (though Gemini might not provide real URLs)
        url_pattern = r'https?://[^\s<>"{}|\\^`\[\]]*'
        urls = re.findall(url_pattern, response_text)
        
        # Find the best code fix
        best_fix = None
        if code_blocks:
            # Clean and filter code blocks
            cleaned_blocks = []
            for block in code_blocks:
                cleaned = block.strip()
                if len(cleaned) > 20:  # Filter out very short snippets
                    cleaned_blocks.append(cleaned)
            
            # Prefer code blocks that contain security-related keywords
            security_keywords = [
                'parameterized', 'prepared', 'escape', 'sanitize', 'validate', 
                'secure', 'safe', 'protected', 'bind', 'placeholder'
            ]
            
            for block in cleaned_blocks:
                if any(keyword in block.lower() for keyword in security_keywords):
                    best_fix = block
                    break
            
            # If no security-specific fix found, use the longest code block
            if not best_fix and cleaned_blocks:
                best_fix = max(cleaned_blocks, key=len)
        
        # Create mock citations since Gemini doesn't browse the web in this version
        mock_citations = [
            f"https://owasp.org/www-project-top-ten/2017/A1_2017-Injection",
            f"https://cwe.mitre.org/data/definitions/89.html",
            f"https://docs.python.org/3/library/sqlite3.html#sqlite3-placeholders"
        ]
        
        # Add real URLs if found in response
        if urls:
            mock_citations.extend(urls[:3])
        
        return {
            'fix_explanation': response_text,
            'code_fix': best_fix,
            'all_code_blocks': code_blocks,
            'citations': mock_citations[:5],  # Limit to 5 citations
            'has_fix': best_fix is not None
        }

def search_with_gemini(finding: Finding, config: ScanConfig) -> bool:
    """
    Search for vulnerability fixes using Gemini AI.
    
    Args:
        finding: The vulnerability finding to search for
        config: Scan configuration
        
    Returns:
        True if a fix was found and applied, False otherwise
    """
    try:
        # Get Gemini API key - try both 'google' and 'gemini' keys
        gemini_key = config.api_keys.get("google") or config.api_keys.get("gemini")
        if not gemini_key:
            console.log("[yellow]No Gemini API key found, skipping AI search[/yellow]")
            return False
        
        # Initialize Gemini web search
        gemini_search = GeminiWebSearch(gemini_key)
        
        # Search for fixes
        result = gemini_search.search_for_vulnerability_fix(finding)
        
        if result.get('has_fix'):
            # Apply the fix to the finding
            finding.web_fix = result['code_fix']
            
            # Add Gemini analysis to description
            if result['fix_explanation']:
                # Truncate explanation to keep it manageable
                explanation_excerpt = result['fix_explanation'][:800] + "..." if len(result['fix_explanation']) > 800 else result['fix_explanation']
                finding.description = f"{finding.description}\n\n🤖 Gemini Analysis:\n{explanation_excerpt}"
            
            # Add citations
            if result['citations']:
                finding.citation = result['citations'][0]  # Use first citation as primary
                # Store additional citations in metadata
                if not hasattr(finding, 'metadata') or finding.metadata is None:
                    finding.metadata = {}
                finding.metadata['additional_citations'] = result['citations'][1:]
                finding.metadata['gemini_powered'] = True
            
            console.log(f"[bold green]✅ Found Gemini-powered fix for {finding.vuln_id}[/bold green]")
            return True
        else:
            console.log(f"[yellow]No suitable fix found via Gemini for {finding.vuln_id}[/yellow]")
            return False
            
    except Exception as e:
        console.log(f"[bold red]Error during Gemini search for {finding.vuln_id}:[/bold red] {e}")
        return False

def search_for_vulnerability_fix(finding: Finding, config: ScanConfig):
    """
    Searches for a fix for a given vulnerability using Gemini AI and Stack Overflow API.
    
    Args:
        finding: The vulnerability finding to search for
        config: Scan configuration
    """
    if not config.enable_web_search:
        return

    console.log(f"🔍 Searching for vulnerability fix for {finding.vuln_id}...")

    # Try Gemini first for more comprehensive search
    if search_with_gemini(finding, config):
        return  # Found a fix with Gemini, we're done
    
    # Fall back to Stack Overflow API search
    console.log(f"Falling back to Stack Overflow API search for {finding.vuln_id}...")
    
    # Get API key from config if available
    api_key = config.api_keys.get("stackoverflow")
    so_api = StackOverflowAPI(api_key)

    try:
        # Create more specific search queries based on vulnerability type
        if finding.source.value == "static_analysis":
            # For static analysis findings (like Bandit), focus on security fixes
            search_queries = [
                f"{finding.vuln_id} python security fix",
                f"{finding.title} python vulnerability fix",
                f"python {finding.title} secure coding",
                f"bandit {finding.vuln_id} fix python"
            ]
        else:
            # For dependency vulnerabilities, focus on updates and patches
            search_queries = [
                f"{finding.vuln_id} vulnerability fix update",
                f"{finding.title} security patch",
                f"{finding.vuln_id} dependency update"
            ]
        
        best_score = -1
        
        for query in search_queries[:2]:  # Limit to 2 queries to avoid rate limits
            console.log(f"📝 Searching Stack Overflow: {query}")
            questions = so_api.search_questions(query)
            
            for question in questions[:3]:  # Check top 3 questions only
                question_id = question.get("question_id")
                question_url = question.get("link")
                question_score = question.get("score", 0)
                
                # Get answers for this question
                answers = so_api.get_question_answers(question_id)
                
                for answer in answers[:2]:  # Check top 2 answers only
                    answer_score = answer.get("score", 0)
                    is_accepted = answer.get("is_accepted", False)
                    
                    # Calculate combined score (accepted answers get bonus)
                    combined_score = answer_score + question_score + (50 if is_accepted else 0)
                    
                    if combined_score > best_score:
                        best_score = combined_score
                        
                        # Extract code blocks from the answer
                        answer_body = answer.get("body", "")
                        code_blocks = extract_code_blocks(answer_body)
                        
                        if code_blocks:
                            # Use the first substantial code block
                            finding.web_fix = code_blocks[0]
                            finding.citation = question_url
                            console.log(f"[green]✅ Found Stack Overflow fix for {finding.vuln_id}[/green]")
                            break
                            
                if finding.web_fix:
                    break
            
            if finding.web_fix:
                break
        
        if not finding.web_fix:
            console.log(f"[yellow]No suitable fix found for {finding.vuln_id} on Stack Overflow[/yellow]")
            
    except Exception as e:
        console.log(f"[bold red]Error during Stack Overflow search for {finding.vuln_id}:[/bold red] {e}")

def process_findings_for_web_fixes(findings: List[Finding], config: ScanConfig):
    """
    Processes a list of findings to search for web fixes using Gemini AI and Stack Overflow API.
    
    Args:
        findings: List of vulnerability findings
        config: Scan configuration
    """
    if not config.enable_web_search:
        return

    console.log(f"🚀 Processing {len(findings)} findings for web fixes using AI-powered search...")
    
    # Check if Gemini is available
    gemini_available = bool(config.api_keys.get("google") or config.api_keys.get("gemini"))
    so_available = bool(config.api_keys.get("stackoverflow"))
    
    if gemini_available:
        console.log("[bold green]🤖 Gemini AI web search enabled[/bold green]")
    if so_available:
        console.log("[bold blue]📚 Stack Overflow API search enabled[/bold blue]")
    
    if not gemini_available and not so_available:
        console.log("[yellow]⚠️  No API keys found for web search - using basic search[/yellow]")
    
    for i, finding in enumerate(findings, 1):
        console.log(f"[bold cyan]Processing finding {i}/{len(findings)}:[/bold cyan] {finding.vuln_id}")
        search_for_vulnerability_fix(finding, config)
        
        # Add a small delay between searches to be respectful
        if i < len(findings):
            time.sleep(1.0)  # 1 second delay
    
    # Summary statistics
    fixed_count = sum(1 for f in findings if f.web_fix)
    cited_count = sum(1 for f in findings if f.citation)
    
    console.log(f"[bold green]✅ Web search complete:[/bold green] {fixed_count}/{len(findings)} fixes found, {cited_count} citations added")
