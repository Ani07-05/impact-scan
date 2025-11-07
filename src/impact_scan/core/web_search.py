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
        return hashlib.md5(cache_data.encode(), usedforsecurity=False).hexdigest()
        
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

    def build_search_query_from_finding(self, finding: Finding) -> str:
        """
        Build an optimized search query for Stack Overflow API from a Finding.

        Args:
            finding: The vulnerability finding

        Returns:
            Optimized search query string
        """
        # Extract language from file extension
        file_ext = str(finding.file_path).split('.')[-1].lower() if '.' in str(finding.file_path) else ''
        language_map = {
            'py': 'python',
            'js': 'javascript',
            'java': 'java',
            'php': 'php',
            'rb': 'ruby',
            'go': 'go',
            'rs': 'rust',
            'cpp': 'c++',
            'c': 'c',
            'ts': 'typescript'
        }
        language = language_map.get(file_ext, file_ext)

        # Map vulnerability types to search keywords
        # Check both title and description for better matching
        title_lower = finding.title.lower()
        desc_lower = finding.description.lower() if finding.description else ""
        combined = f"{title_lower} {desc_lower}"

        # Framework-specific vulnerabilities
        if 'flask' in combined and 'debug' in combined:
            vuln_keywords = 'Flask production deployment disable debug'
        elif 'django' in combined and 'debug' in combined:
            vuln_keywords = 'Django production settings debug false'
        elif ('flask' in combined or language == 'python') and 'secret' in combined and 'key' in combined:
            vuln_keywords = 'Flask secret key environment variable'
        elif 'flask' in combined and 'hardcoded' in combined:
            vuln_keywords = 'Flask configuration environment variables'
        # Generic security vulnerabilities
        elif 'sql injection' in combined or 'sqli' in combined:
            vuln_keywords = f'sql injection {language} prevent'
        elif 'xss' in combined or 'cross-site scripting' in combined:
            vuln_keywords = f'xss {language} prevent'
        elif 'hardcoded' in combined and 'password' in combined:
            vuln_keywords = f'password storage {language} secure'
        elif 'hardcoded' in combined and ('secret' in combined or 'key' in combined):
            vuln_keywords = f'{language} secret key environment variable'
        elif 'hardcoded' in combined:
            vuln_keywords = f'credentials storage {language} secure'
        elif 'path traversal' in combined:
            vuln_keywords = f'path traversal {language} prevent'
        elif 'yaml' in combined and 'load' in combined:
            vuln_keywords = f'yaml safe load {language}'
        elif 'md5' in combined or 'weak hash' in combined:
            vuln_keywords = f'password hash {language} secure'
        elif 'ssl' in combined and 'verify' in combined:
            vuln_keywords = f'ssl verify {language}'
        elif 'shell' in combined or 'command injection' in combined:
            vuln_keywords = f'command injection {language} prevent'
        else:
            # Use first 2-3 words from title + language
            words = title_lower.split()[:2]
            vuln_keywords = f"{' '.join(words)} {language}"

        # Return concise query (3-5 words for better API results)
        return vuln_keywords

    def extract_code_and_text_from_body(self, html_body: str) -> tuple[List[Dict[str, str]], str]:
        """
        Extract code blocks and explanation text from answer HTML body.

        Args:
            html_body: HTML body from Stack Overflow API response

        Returns:
            Tuple of (code_blocks, explanation_text)
            - code_blocks: List of dicts with 'language' and 'code' keys
            - explanation_text: Plain text explanation with code removed
        """
        from bs4 import BeautifulSoup

        soup = BeautifulSoup(html_body, 'html.parser')
        code_blocks = []

        # Extract code blocks with language detection
        for pre_tag in soup.find_all('pre'):
            code_tag = pre_tag.find('code')
            if not code_tag:
                continue

            code_text = code_tag.get_text().strip()
            if len(code_text) < 10:  # Skip very short snippets
                continue

            # Detect language from class attribute
            language = 'text'
            class_attr = code_tag.get('class', [])
            if isinstance(class_attr, list):
                for cls in class_attr:
                    if cls.startswith('language-') or cls.startswith('lang-'):
                        language = cls.split('-', 1)[1]
                        break
                    elif cls in ['python', 'javascript', 'java', 'php', 'ruby', 'go', 'rust', 'cpp', 'c']:
                        language = cls
                        break

            # Heuristic language detection if not found
            if language == 'text':
                language = self._detect_language_heuristic(code_text)

            code_blocks.append({
                'language': language,
                'code': code_text
            })

        # Extract explanation text (remove code blocks)
        explanation_soup = BeautifulSoup(html_body, 'html.parser')
        for pre in explanation_soup.find_all('pre'):
            pre.decompose()

        explanation = explanation_soup.get_text(separator=' ', strip=True)

        # Limit explanation length
        if len(explanation) > 500:
            explanation = explanation[:500] + "..."

        return code_blocks, explanation

    def _detect_language_heuristic(self, code: str) -> str:
        """Simple heuristic language detection for code snippets."""
        code_lower = code.lower()

        # Python indicators
        if 'def ' in code or 'import ' in code or 'elif ' in code or '__init__' in code:
            return 'python'

        # JavaScript indicators
        if 'function' in code or 'const ' in code or 'let ' in code or '=>' in code or 'var ' in code:
            return 'javascript'

        # Java indicators
        if 'public class' in code or 'private ' in code or 'System.out' in code:
            return 'java'

        # PHP indicators
        if '<?php' in code or '$_' in code:
            return 'php'

        # SQL indicators
        if 'select ' in code_lower or 'insert into' in code_lower or 'update ' in code_lower:
            return 'sql'

        return 'text'

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


def search_stackoverflow_via_api(
    finding: Finding,
    so_api: StackOverflowAPI,
    max_answers: int = 3
) -> List:
    """
    Search Stack Overflow using the official API instead of web scraping.

    This function provides a reliable, fast alternative to Google-based scraping by
    directly querying the Stack Exchange API.

    Args:
        finding: The vulnerability finding to search for
        so_api: StackOverflowAPI instance
        max_answers: Maximum number of answers to return (default: 3)

    Returns:
        List of StackOverflowAnswer objects (from stackoverflow_scraper module)
    """
    # Import StackOverflowAnswer from scraper module to reuse data structures
    from .stackoverflow_scraper import StackOverflowAnswer, CodeBlock

    console.log(f"[cyan][SO_API] Searching Stack Overflow API for {finding.vuln_id}...[/cyan]")

    # Build optimized search query
    query = so_api.build_search_query_from_finding(finding)
    console.log(f"[dim]API Query: {query}[/dim]")

    # Search for questions
    questions = so_api.search_questions(query)

    if not questions:
        console.log(f"[yellow][SO_API] No questions found for {finding.vuln_id}[/yellow]")
        return []

    console.log(f"[green][SO_API] Found {len(questions)} questions[/green]")

    all_answers = []

    # Process each question
    for i, question in enumerate(questions[:5], 1):  # Limit to top 5 questions
        try:
            question_id = question.get('question_id')
            question_title = question.get('title', 'Unknown Question')
            question_link = question.get('link', '')

            console.log(f"[dim]  ({i}) Processing question {question_id}: {question_title[:60]}...[/dim]")

            # Get answers for this question
            answers = so_api.get_question_answers(question_id)

            if not answers:
                continue

            # Process each answer
            for answer in answers[:3]:  # Top 3 answers per question
                try:
                    answer_id = answer.get('answer_id')
                    answer_body = answer.get('body', '')
                    votes = answer.get('score', 0)
                    is_accepted = answer.get('is_accepted', False)

                    # Extract code blocks and explanation from body
                    code_blocks_data, explanation = so_api.extract_code_and_text_from_body(answer_body)

                    # Skip answers without code
                    if not code_blocks_data:
                        continue

                    # Extract author info
                    owner = answer.get('owner', {})
                    author_name = owner.get('display_name', 'Unknown')
                    author_reputation = owner.get('reputation', 0)

                    # Extract creation date
                    creation_date = answer.get('creation_date', 0)
                    from datetime import datetime
                    post_date = datetime.fromtimestamp(creation_date).strftime('%Y-%m-%d') if creation_date else 'Unknown'

                    # Convert code blocks to CodeBlock objects
                    code_block_objects = [
                        CodeBlock(language=cb['language'], code=cb['code'])
                        for cb in code_blocks_data
                    ]

                    # Calculate score: votes + (accepted bonus) + (reputation factor)
                    score = float(votes) + (50.0 if is_accepted else 0.0) + (author_reputation / 1000.0)

                    # Build answer URL
                    answer_url = f"{question_link}#answer-{answer_id}" if '#' not in question_link else question_link

                    # Create StackOverflowAnswer object
                    so_answer = StackOverflowAnswer(
                        url=answer_url,
                        title=question_title,
                        question_id=str(question_id),
                        answer_id=str(answer_id),
                        votes=votes,
                        accepted=is_accepted,
                        author=author_name,
                        author_reputation=author_reputation,
                        post_date=post_date,
                        code_snippets=code_block_objects,
                        explanation=explanation,
                        comments=[],  # API doesn't easily provide comments, can be added later
                        score=score
                    )

                    all_answers.append(so_answer)

                except Exception as e:
                    console.log(f"[red]Error processing answer {answer.get('answer_id')}: {e}[/red]")
                    continue

        except Exception as e:
            console.log(f"[red]Error processing question {question.get('question_id')}: {e}[/red]")
            continue

    # Sort by score and limit to max_answers
    all_answers.sort(key=lambda x: x.score, reverse=True)
    top_answers = all_answers[:max_answers]

    if top_answers:
        console.log(f"[bold green][SO_API_SUCCESS] Found {len(top_answers)} Stack Overflow answers via API[/bold green]")
    else:
        console.log(f"[yellow][SO_API] No answers with code found for {finding.vuln_id}[/yellow]")

    return top_answers


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
            console.log(f"[yellow][RATE-LIMIT] High request count ({self.request_count}), using 5s delay[/yellow]")
        elif self.request_count > 50:
            delay = 3.0  # 3 seconds after 50 requests
            console.log(f"[yellow][RATE-LIMIT] Medium request count ({self.request_count}), using 3s delay[/yellow]")
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
        code_hash = hashlib.md5(finding.code_snippet.encode(), usedforsecurity=False).hexdigest()[:8]
        key_components = [
            finding.vuln_id,
            finding.title.lower(),
            finding.source.value,
            str(finding.file_path),  # Include specific file
            str(finding.line_number),  # Include specific line
            code_hash  # Include code pattern
        ]
        return hashlib.md5("|".join(key_components).encode(), usedforsecurity=False).hexdigest()
        
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
            console.log(f"[green][CACHE] Using cached fix for {finding.vuln_id}[/green]")
            return cached_fix
            
        try:
            # Rate limit before making API call
            self._rate_limit()
            
            # Create a comprehensive search prompt
            prompt = self._create_search_prompt(finding)
            
            console.log(f"[blue][AI] ({self.request_count}) Searching with Gemini AI for {finding.vuln_id}...[/blue]")
            
            # Generate response with proper asyncio handling
            try:
                response = self.model.generate_content(
                    prompt,
                    generation_config=genai.types.GenerationConfig(
                        temperature=0.1,
                        max_output_tokens=4096,
                        top_p=0.8,
                    )
                )
            except RuntimeError as e:
                if "no current event loop" in str(e).lower() or "asyncio" in str(e).lower():
                    # Handle asyncio issues by creating a new event loop
                    import asyncio
                    try:
                        # Try to get current loop, create one if none exists
                        asyncio.get_event_loop()
                    except RuntimeError:
                        # Create and set a new event loop for this thread
                        loop = asyncio.new_event_loop()
                        asyncio.set_event_loop(loop)
                    
                    # Retry the API call
                    response = self.model.generate_content(
                        prompt,
                        generation_config=genai.types.GenerationConfig(
                            temperature=0.1,
                            max_output_tokens=4096,
                            top_p=0.8,
                        )
                    )
                else:
                    raise
            
            if response.text:
                console.log(f"[green][SUCCESS] Gemini found potential fixes for {finding.vuln_id}[/green]")
                result = self._parse_gemini_response(response.text, finding)
                
                # Cache the result if successful
                if result.get('has_fix'):
                    self._cache_fix(finding, result)
                    
                return result
            else:
                console.log(f"[yellow][WARNING] Gemini returned empty response for {finding.vuln_id}[/yellow]")
                return {'has_fix': False}
                
        except Exception as e:
            console.log(f"[red][ERROR] Gemini search failed for {finding.vuln_id}: {e}[/red]")
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
            
            console.log(f"[bold green][SUCCESS] Found specific Gemini-powered fix for {finding.vuln_id}[/bold green]")
            return True
        else:
            console.log(f"[yellow]No suitable fix found via Gemini for {finding.vuln_id}[/yellow]")
            return False
            
    except Exception as e:
        console.log(f"[bold red]Error during Gemini search for {finding.vuln_id}:[/bold red] {e}")
        return False

def analyze_stackoverflow_with_gemini(finding: Finding, so_answers: List, config: ScanConfig) -> List[Dict[str, Any]]:
    """
    Analyze scraped Stack Overflow answers using Gemini AI.

    Args:
        finding: The vulnerability finding
        so_answers: List of StackOverflowAnswer objects from scraper
        config: Scan configuration

    Returns:
        List of analyzed Stack Overflow fixes with Gemini validation
    """
    if not config.api_keys.gemini:
        console.log("[yellow]No Gemini API key, skipping Stack Overflow analysis[/yellow]")
        return []

    console.log(f"[cyan][GEMINI_SO] Analyzing {len(so_answers)} Stack Overflow answers with Gemini AI...[/cyan]")

    try:
        import google.generativeai as genai
        genai.configure(api_key=config.api_keys.gemini)
        model = genai.GenerativeModel('gemini-1.5-flash')

        analyzed_fixes = []

        for i, so_answer in enumerate(so_answers, 1):
            try:
                # Build analysis prompt
                code_blocks_text = "\n\n".join([
                    f"```{block.language}\n{block.code}\n```"
                    for block in so_answer.code_snippets
                ])

                prompt = f"""You are a cybersecurity expert analyzing a Stack Overflow answer for security vulnerability fixes.

**Vulnerability Context:**
- ID: {finding.vuln_id}
- Title: {finding.title}
- Severity: {finding.severity.value}
- File: {finding.file_path}:{finding.line_number}

**Original Vulnerable Code:**
```
{finding.code_snippet}
```

**Stack Overflow Answer Details:**
- URL: {so_answer.url}
- Votes: {so_answer.votes} {"(✓ Accepted)" if so_answer.accepted else ""}
- Author: {so_answer.author} ({so_answer.author_reputation:,} reputation)
- Explanation: {so_answer.explanation}

**Proposed Fix Code from Stack Overflow:**
{code_blocks_text}

**Your Task:**
1. **Validate Security**: Is this Stack Overflow fix secure for the given vulnerability? Explain why or why not in 2-3 sentences.
2. **Applicability**: Does this fix apply to the specific vulnerable code shown? Rate: HIGH/MEDIUM/LOW and explain.
3. **Recommendations**: If needed, suggest any modifications to make the fix more secure or applicable.

Keep your response concise (under 200 words).
"""

                # Rate limit
                time.sleep(1.5)

                # Generate analysis
                response = model.generate_content(
                    prompt,
                    generation_config=genai.types.GenerationConfig(
                        temperature=0.2,
                        max_output_tokens=500,
                        top_p=0.8,
                    )
                )

                if response.text:
                    gemini_analysis = response.text.strip()
                    console.log(f"[green]({i}/{len(so_answers)}) Gemini analysis complete for answer {so_answer.answer_id}[/green]")

                    # Convert to dict with Gemini analysis
                    fix_dict = {
                        'url': so_answer.url,
                        'title': so_answer.title,
                        'question_id': so_answer.question_id,
                        'answer_id': so_answer.answer_id,
                        'votes': so_answer.votes,
                        'accepted': so_answer.accepted,
                        'author': so_answer.author,
                        'author_reputation': so_answer.author_reputation,
                        'post_date': so_answer.post_date,
                        'code_snippets': [{'language': cb.language, 'code': cb.code} for cb in so_answer.code_snippets],
                        'explanation': so_answer.explanation,
                        'comments': so_answer.comments,
                        'gemini_analysis': gemini_analysis,
                        'score': so_answer.score
                    }
                    analyzed_fixes.append(fix_dict)
                else:
                    console.log(f"[yellow]({i}/{len(so_answers)}) Gemini returned empty response[/yellow]")

            except Exception as e:
                console.log(f"[red]Error analyzing SO answer {so_answer.answer_id}: {e}[/red]")
                continue

        console.log(f"[bold green][GEMINI_SO_SUCCESS] Analyzed {len(analyzed_fixes)} Stack Overflow fixes[/bold green]")
        return analyzed_fixes

    except Exception as e:
        console.log(f"[bold red]Error in Gemini Stack Overflow analysis: {e}[/bold red]")
        return []


def _filter_relevant_so_answers(finding: Finding, so_answers: List) -> List:
    """
    Filter Stack Overflow answers for relevance to the vulnerability.

    Args:
        finding: The vulnerability finding
        so_answers: List of Stack Overflow answer objects

    Returns:
        Filtered list of relevant answers
    """
    if not so_answers:
        return []

    # Extract vulnerability keywords
    title_lower = finding.title.lower()
    desc_lower = finding.description.lower() if finding.description else ""
    vuln_id_lower = finding.vuln_id.lower() if finding.vuln_id else ""

    # Build relevance keywords from vulnerability
    relevance_keywords = set()

    # Framework/language keywords
    if 'flask' in title_lower or 'flask' in desc_lower:
        relevance_keywords.update(['flask', 'python', 'werkzeug'])
    if 'django' in title_lower or 'django' in desc_lower:
        relevance_keywords.update(['django', 'python'])
    if 'sql' in title_lower or 'sql' in desc_lower:
        relevance_keywords.update(['sql', 'injection', 'database', 'query', 'parameterized'])
    if 'debug' in title_lower or 'debug' in desc_lower:
        relevance_keywords.update(['debug', 'production', 'deployment', 'configuration'])
    if 'secret' in title_lower or 'secret' in desc_lower or 'hardcoded' in title_lower or 'hardcoded' in desc_lower:
        relevance_keywords.update(['secret', 'key', 'environment', 'variable', 'config', 'credential', 'password'])
    if 'xss' in title_lower or 'xss' in desc_lower:
        relevance_keywords.update(['xss', 'sanitize', 'escape', 'html'])

    # Irrelevant keywords to exclude
    exclude_keywords = ['gmail', 'google cloud', 'docker', 'kubernetes', 'cloud run', 'm1 mac', 'ios', 'android']

    relevant_answers = []

    for answer in so_answers:
        answer_title = answer.title.lower() if hasattr(answer, 'title') else ''
        answer_explanation = answer.explanation.lower() if hasattr(answer, 'explanation') else ''
        answer_text = f"{answer_title} {answer_explanation}"

        # Check if answer contains excluded keywords
        has_excluded = any(excluded in answer_text for excluded in exclude_keywords)
        if has_excluded:
            continue

        # Check if answer contains relevance keywords
        matches = sum(1 for keyword in relevance_keywords if keyword in answer_text)

        # Require at least 2 keyword matches for relevance
        if matches >= 2:
            relevant_answers.append(answer)

    return relevant_answers


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

    console.log(f"[SEARCH] Searching for vulnerability fix for [bold]{finding.vuln_id}[/bold]...")

    # Initialize Stack Overflow API
    so_api = StackOverflowAPI(config.api_keys.stackoverflow)

    # --- Step 1: Get the primary fix and explanation from Gemini AI ---
    search_with_gemini(finding, config, so_api)

    # --- Step 1.5: Enhance with Stack Overflow (API-first, scraper fallback) ---
    so_answers = []

    # Try API search first (fast, reliable)
    if config.api_keys.gemini:
        try:
            console.log(f"[SO_API] Trying Stack Overflow API for [bold]{finding.vuln_id}[/bold]...")
            so_answers = search_stackoverflow_via_api(finding, so_api, max_answers=config.stackoverflow_max_answers)

            if so_answers:
                console.log(f"[bold green][SO_API] API search successful - found {len(so_answers)} answers[/bold green]")
        except Exception as e:
            console.log(f"[yellow][SO_API] API search failed: {e}[/yellow]")
            so_answers = []

    # Fallback to scraper only if API returned nothing AND scraper is enabled
    if not so_answers and config.enable_stackoverflow_scraper and config.api_keys.gemini:
        console.log(f"[SO_SCRAPER] Falling back to web scraper for [bold]{finding.vuln_id}[/bold]...")

        try:
            # Import scraper (async)
            from .stackoverflow_scraper import StackOverflowScraper
            import asyncio

            # Create scraper with config
            so_scraper = StackOverflowScraper(
                scrape_delay=config.stackoverflow_scrape_delay,
                max_answers=config.stackoverflow_max_answers,
                include_comments=config.stackoverflow_include_comments
            )

            # Scrape Stack Overflow (async)
            try:
                so_answers = asyncio.run(so_scraper.search_and_scrape(finding))
            except RuntimeError as e:
                # Handle "no running event loop" error
                if "no running event loop" in str(e).lower() or "cannot be called from a running event loop" in str(e).lower():
                    # Already in async context, use existing loop
                    loop = asyncio.get_event_loop()
                    so_answers = loop.run_until_complete(so_scraper.search_and_scrape(finding))
                else:
                    raise

        except Exception as e:
            console.log(f"[red][SO_SCRAPER] Scraper failed: {e}[/red]")
            so_answers = []

    # Process Stack Overflow answers (from API or scraper)
    if so_answers:
        console.log(f"[green][SO_FOUND] Found {len(so_answers)} Stack Overflow answers[/green]")

        # Filter for relevance before processing
        relevant_answers = _filter_relevant_so_answers(finding, so_answers)

        if not relevant_answers:
            console.log(f"[yellow][SO_FILTER] All {len(so_answers)} Stack Overflow answers filtered as irrelevant[/yellow]")
            so_answers = []
        else:
            console.log(f"[green][SO_FILTER] {len(relevant_answers)}/{len(so_answers)} Stack Overflow answers passed relevance check[/green]")
            so_answers = relevant_answers

        # Try to analyze with Gemini AI (optional)
        analyzed_fixes = []
        if so_answers and config.api_keys.gemini:
            analyzed_fixes = analyze_stackoverflow_with_gemini(finding, so_answers, config)

        # If Gemini analysis succeeded, use those results
        if analyzed_fixes:
            so_data_to_use = analyzed_fixes
            console.log(f"[green][SO_GEMINI] Using {len(analyzed_fixes)} Gemini-analyzed Stack Overflow answers[/green]")
        elif so_answers:
            # Fallback: Include SO answers without Gemini analysis
            console.log(f"[yellow][SO_FALLBACK] Including Stack Overflow answers without AI analysis[/yellow]")
            so_data_to_use = [answer.to_dict() for answer in so_answers]
        else:
            so_data_to_use = []

        # Convert to StackOverflowFix objects and attach to finding
        from ..utils.schema import StackOverflowFix, CodeBlock

        so_fix_objects = []
        for fix in so_data_to_use:
            # Convert code snippets
            code_blocks = [CodeBlock(**cb) for cb in fix['code_snippets']]

            # Create StackOverflowFix object
            so_fix = StackOverflowFix(
                url=fix['url'],
                title=fix['title'],
                question_id=fix['question_id'],
                answer_id=fix['answer_id'],
                votes=fix['votes'],
                accepted=fix['accepted'],
                author=fix['author'],
                author_reputation=fix['author_reputation'],
                post_date=fix['post_date'],
                code_snippets=code_blocks,
                explanation=fix['explanation'],
                comments=fix['comments'],
                gemini_analysis=fix.get('gemini_analysis'),  # Will be None if no Gemini analysis
                score=fix['score']
            )
            so_fix_objects.append(so_fix)

        # Attach to finding
        finding.stackoverflow_fixes = so_fix_objects

        console.log(f"[bold green][SO_SUCCESS] Added {len(so_fix_objects)} Stack Overflow fixes to {finding.vuln_id}[/bold green]")

        # Add SO URLs to citations
        if not finding.citations:
            finding.citations = []
        for so_fix in so_fix_objects:
            if so_fix.url not in finding.citations:
                finding.citations.append(so_fix.url)
    else:
        console.log(f"[yellow][SO_WARNING] No Stack Overflow answers found for {finding.vuln_id}[/yellow]")

    # --- Step 2: Enhance the finding with the best possible citations ---
    console.log(f"[ENHANCE] Enhancing citations for [bold]{finding.vuln_id}[/bold]...")
    
    # Initialize metadata if it doesn't exist
    if not hasattr(finding, 'metadata') or finding.metadata is None:
        finding.metadata = {}
    if 'additional_citations' not in finding.metadata:
        finding.metadata['additional_citations'] = []

    # A. Prioritize finding a high-quality Stack Overflow link
    # best_so_url = find_best_stackoverflow_url(finding, so_api)
    # if best_so_url:
    #     console.log(f"[green][TARGET] Found high-quality Stack Overflow URL: {best_so_url}[/green]")
    #     # Add to the top of the list to prioritize it
    #     if best_so_url not in finding.metadata['additional_citations']:
    #         finding.metadata['additional_citations'].insert(0, best_so_url)

    # B. Search other credible web sources for more context
    additional_urls = search_additional_sources(finding)
    if additional_urls:
        console.log(f"[green][LINK] Found {len(additional_urls)} additional web sources[/green]")
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
        console.log(f"[yellow][WARNING] No suitable fix found for {finding.vuln_id}[/yellow]")


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

    console.log(f"[PROCESS] Processing {len(findings)} findings for web fixes using intelligent batching...")
    
    # Check available APIs
    gemini_available = bool(config.api_keys.gemini)
    so_available = bool(config.api_keys.stackoverflow)
    
    if gemini_available:
        console.log(f"[bold green][AI] Gemini AI web search enabled (delay: {config.web_search_delay}s)[/bold green]")
    if so_available:
        console.log("[bold blue][API] Stack Overflow API search enabled[/bold blue]")
    
    if not gemini_available and not so_available:
        console.log("[yellow][WARNING] No API keys found for web search - using basic search[/yellow]")
    
    # Prioritize findings by severity if enabled
    if config.prioritize_high_severity:
        console.log("[cyan][PRIORITY] Prioritizing findings by severity (CRITICAL -> HIGH -> MEDIUM -> LOW)[/cyan]")
        
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
        console.log(f"[yellow][LIMIT] Limiting web search to {config.web_search_limit} out of {total_findings} findings[/yellow]")
        console.log(f"[dim]Skipping {total_findings - config.web_search_limit} findings to stay within limits[/dim]")
    
    console.log("[bold cyan][STRATEGY] Processing Strategy:[/bold cyan]")
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
    processed_cache = {}  # Changed to dict to store findings

    for batch_start in range(0, len(limited_findings), config.web_search_batch_size):
        batch_end = min(batch_start + config.web_search_batch_size, len(limited_findings))
        batch = limited_findings[batch_start:batch_end]
        batch_num = (batch_start // config.web_search_batch_size) + 1
        total_batches = (len(limited_findings) + config.web_search_batch_size - 1) // config.web_search_batch_size

        console.log(f"\n[bold magenta][BATCH] Batch {batch_num}/{total_batches} ({len(batch)} findings)[/bold magenta]")

        batch_start_time = time.time()
        batch_successful = 0
        batch_cached = 0

        for i, finding in enumerate(batch, 1):
            # Simple deduplication based on vuln_id and title
            dedup_key = f"{finding.vuln_id}_{finding.title}"
            if dedup_key in processed_cache:
                console.log(f"[dim]({total_processed + i}) Copying citations from duplicate: {finding.vuln_id}[/dim]")
                # Copy SO citations from the first processed finding
                original_finding = processed_cache[dedup_key]
                if original_finding.stackoverflow_fixes:
                    finding.stackoverflow_fixes = original_finding.stackoverflow_fixes
                if original_finding.citations:
                    finding.citations = original_finding.citations.copy() if finding.citations else original_finding.citations
                continue

            processed_cache[dedup_key] = finding  # Store the finding for copying later
            
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
                    
                console.log(f"[bold green][SUCCESS] Fix found for {finding.vuln_id}[/bold green]")
            else:
                console.log(f"[yellow][WARNING] No fix found for {finding.vuln_id}[/yellow]")
        
        batch_duration = time.time() - batch_start_time
        total_processed += len(batch)
        
        # Batch summary
        console.log(f"[dim]Batch {batch_num} complete in {batch_duration:.1f}s: {batch_successful}/{len(batch)} fixes found ({batch_cached} cached)[/dim]")
        
        # Inter-batch delay for rate limiting (except for the last batch)
        if batch_end < len(limited_findings):
            inter_batch_delay = max(5.0, config.web_search_delay * 2)  # Longer delay between batches
            console.log(f"[dim][PAUSE] Waiting {inter_batch_delay}s before next batch...[/dim]")
            time.sleep(inter_batch_delay)
    
    # Final summary statistics
    console.log("\n[bold green][COMPLETE] Web search complete![/bold green]")
    console.log("[bold cyan][RESULTS] Final Results:[/bold cyan]")
    console.log(f"  • Total processed: {total_processed}/{total_findings}")
    console.log(f"  • Successful fixes: {successful_fixes} ({successful_fixes/total_processed*100:.1f}%)")
    console.log(f"  • Cache hits: {cached_hits} ({cached_hits/total_processed*100:.1f}%)")
    console.log(f"  • Actual API calls: {successful_fixes - cached_hits}")
    
    # Add findings with citations count
    cited_count = sum(1 for f in limited_findings if f.citation)
    console.log(f"  • Citations added: {cited_count}")
    
    # Show severity breakdown of successful fixes
    if successful_fixes > 0:
        console.log("[bold cyan][BREAKDOWN] Fixes by Severity:[/bold cyan]")
        for severity in ['CRITICAL', 'HIGH', 'MEDIUM', 'LOW']:
            severity_fixes = sum(1 for f in limited_findings 
                               if f.web_fix and f.severity.value.upper() == severity)
            if severity_fixes > 0:
                console.log(f"  • {severity}: {severity_fixes} fixes")
    
    console.log("[bold green][READY] Ready to handle high-volume scans with intelligent rate limiting![/bold green]")


def enhance_findings_with_web_search(findings_data: List[Dict[str, Any]], config: ScanConfig) -> List[Dict[str, Any]]:
    """
    Enhance findings with mandatory web search citations.
    
    This function ensures every security finding has authoritative web sources
    for better context and remediation guidance.
    
    Args:
        findings_data: List of finding dictionaries 
        config: Scan configuration with web search settings
        
    Returns:
        List of enhanced findings with citations
    """
    if not config.enable_web_search:
        console.log("[yellow]Web search disabled - skipping mandatory citations[/yellow]")
        return findings_data
    
    console.log(f"[MANDATORY] Enhancing {len(findings_data)} findings with mandatory web search citations...")
    
    # Initialize API
    so_api = StackOverflowAPI(api_key=config.api_keys.stackoverflow)
    enhanced_findings = []
    
    for i, finding_dict in enumerate(findings_data):
        try:
            # Convert dict to Finding object for web search compatibility
            from ..utils.schema import Severity, VulnSource
            from pathlib import Path
            
            finding = Finding(
                file_path=Path("unknown"),  # Placeholder path
                line_number=1,
                vuln_id=finding_dict.get("vuln_id", "unknown"),
                rule_id=finding_dict.get("rule_id", "unknown"), 
                title=finding_dict.get("title", "Unknown vulnerability"),
                severity=Severity(finding_dict.get("severity", "medium").lower()),
                source=VulnSource.STATIC_ANALYSIS,  # Default source
                code_snippet="",
                description=finding_dict.get("description", ""),
                citations=finding_dict.get("citations", []),
                web_fix=finding_dict.get("web_fix")
            )
            
            console.log(f"[CITE] ({i+1}/{len(findings_data)}) Searching citations for {finding.vuln_id}...")
            
            # Perform web search to get citations
            search_for_vulnerability_fix(finding, config)
            
            # Add additional authoritative sources
            additional_sources = search_additional_sources(finding)
            if additional_sources:
                existing_citations = finding.citations or []
                finding.citations = existing_citations + additional_sources
            
            # Update the original dict with enhanced data
            enhanced_dict = finding_dict.copy()
            enhanced_dict["citations"] = finding.citations or []
            enhanced_dict["web_fix"] = finding.web_fix
            
            citation_count = len(finding.citations) if finding.citations else 0
            console.log(f"[CITE] Found {citation_count} citations for {finding.vuln_id}")
            
            enhanced_findings.append(enhanced_dict)
            
        except Exception as e:
            console.log(f"[red]Error enhancing finding {i+1}: {e}[/red]")
            enhanced_findings.append(finding_dict)  # Return original if enhancement fails
    
    total_citations = sum(len(f.get("citations", [])) for f in enhanced_findings)
    console.log(f"[MANDATORY] ✅ Enhanced findings with {total_citations} total mandatory citations")
    
    return enhanced_findings


def validate_mandatory_citations(findings: List[Dict[str, Any]]) -> Dict[str, Any]:
    """
    Validate that all findings have the required web search citations.
    
    Returns validation report with citation compliance metrics.
    """
    if not findings:
        return {"compliant": True, "total": 0, "with_citations": 0, "compliance_rate": 1.0}
    
    findings_with_citations = 0
    total_citations = 0
    
    for finding in findings:
        citations = finding.get("citations", [])
        web_fix = finding.get("web_fix")
        
        if citations or web_fix:
            findings_with_citations += 1
            total_citations += len(citations) if citations else 0
    
    compliance_rate = findings_with_citations / len(findings)
    
    return {
        "compliant": compliance_rate == 1.0,
        "total": len(findings),
        "with_citations": findings_with_citations,
        "without_citations": len(findings) - findings_with_citations,
        "total_citations": total_citations,
        "compliance_rate": compliance_rate,
        "status": "✅ COMPLIANT" if compliance_rate == 1.0 else f"⚠️  NON-COMPLIANT ({compliance_rate:.1%})"
    }


# Modern Web Intelligence Integration
async def enhanced_vulnerability_research(findings: List[Finding], config: ScanConfig) -> List[Finding]:
    """
    Enhanced vulnerability research using the modern OSS Security Intelligence Platform.
    
    This function integrates the new 2025 web crawling capabilities with the existing
    web search functionality, providing comprehensive security intelligence.
    
    Args:
        findings: List of vulnerability findings to enhance
        config: Scan configuration
        
    Returns:
        List of enhanced findings with comprehensive intelligence
    """
    if not config.enable_web_search:
        console.log("[yellow]Enhanced web research disabled[/yellow]")
        return findings
        
    console.log(f"[bold cyan][ENHANCED_RESEARCH] Starting OSS Security Intelligence for {len(findings)} findings[/bold cyan]")
    
    try:
        # Import the new comprehensive security crawler
        from .comprehensive_security_crawler import ComprehensiveSecurityCrawler
        
        # Initialize the OSS Security Intelligence Platform
        async with ComprehensiveSecurityCrawler(config) as crawler:
            enhanced_findings = []
            
            for finding in findings:
                try:
                    console.log(f"[bold blue][OSS_INTEL] Researching {finding.vuln_id}...[/bold blue]")
                    
                    # Get comprehensive intelligence report
                    intelligence_report = await crawler.comprehensive_vulnerability_research(finding)
                    
                    # Enhance the finding with intelligence data
                    enhanced_finding = _enhance_finding_with_intelligence(finding, intelligence_report)
                    enhanced_findings.append(enhanced_finding)
                    
                    console.log(f"[bold green][OSS_SUCCESS] Enhanced {finding.vuln_id} - "
                               f"Confidence: {intelligence_report.confidence_score:.1%}, "
                               f"Sources: {len(intelligence_report.static_intelligence.sources)}[/bold green]")
                    
                except Exception as e:
                    console.log(f"[red]Error enhancing {finding.vuln_id}: {e}[/red]")
                    enhanced_findings.append(finding)  # Return original if enhancement fails
                    
            console.log(f"[bold green][ENHANCED_COMPLETE] OSS Security Intelligence complete for {len(enhanced_findings)} findings[/bold green]")
            return enhanced_findings
            
    except ImportError as e:
        console.log(f"[yellow]Modern web intelligence not available: {e}[/yellow]")
        console.log("[dim]Falling back to legacy web search...[/dim]")
        
        # Fallback to existing web search functionality
        for finding in findings:
            search_for_vulnerability_fix(finding, config)
            
        return findings
        
    except Exception as e:
        console.log(f"[red]Error in enhanced research: {e}[/red]")
        console.log("[dim]Falling back to legacy web search...[/dim]")
        
        # Fallback to existing web search functionality
        for finding in findings:
            search_for_vulnerability_fix(finding, config)
            
        return findings


def _enhance_finding_with_intelligence(finding: Finding, intelligence_report) -> Finding:
    """
    Enhance a Finding object with comprehensive intelligence data.
    
    Args:
        finding: Original finding
        intelligence_report: SecurityIntelligenceReport from OSS platform
        
    Returns:
        Enhanced Finding object
    """
    # Create enhanced finding copy
    enhanced_finding = Finding(
        file_path=finding.file_path,
        line_number=finding.line_number,
        vuln_id=finding.vuln_id,
        rule_id=finding.rule_id,
        title=finding.title,
        severity=finding.severity,
        source=finding.source,
        code_snippet=finding.code_snippet,
        description=finding.description,
        fix_suggestion=finding.fix_suggestion,
        web_fix=finding.web_fix,
        ai_fix=finding.ai_fix,
        ai_explanation=finding.ai_explanation,
        citations=finding.citations or [],
        citation=finding.citation,
        metadata=finding.metadata or {}
    )
    
    # Enhance with static intelligence
    static_intel = intelligence_report.static_intelligence
    
    # Add comprehensive citations
    enhanced_finding.citations.extend(static_intel.citations)
    
    # Enhance web fix with intelligence synthesis
    if not enhanced_finding.web_fix and static_intel.patches:
        patch_info = static_intel.patches[0]  # Use first patch
        enhanced_finding.web_fix = f"Patch available: {patch_info.get('content', '')[:200]}..."
        
    # Add enhanced metadata
    enhanced_finding.metadata.update({
        'oss_intelligence': {
            'confidence_score': intelligence_report.confidence_score,
            'completeness_score': intelligence_report.completeness_score,
            'sources_analyzed': len(static_intel.sources),
            'exploits_found': len(static_intel.exploits),
            'patches_found': len(static_intel.patches),
            'poc_examples': len(intelligence_report.poc_examples),
            'threat_level': intelligence_report.threat_landscape.get('risk_level', 'unknown'),
            'intelligence_timestamp': intelligence_report.timestamp.isoformat()
        },
        'actionable_insights': intelligence_report.actionable_insights[:3],  # Top 3 insights
        'risk_assessment': intelligence_report.risk_assessment,
        'enhanced_by': 'OSS_Security_Intelligence_Platform_2025'
    })
    
    # Enhance AI explanation with intelligence insights
    if intelligence_report.actionable_insights:
        insights_text = " ".join(intelligence_report.actionable_insights[:2])
        if enhanced_finding.ai_explanation:
            enhanced_finding.ai_explanation += f"\n\nOSS Intelligence Insights: {insights_text}"
        else:
            enhanced_finding.ai_explanation = f"OSS Intelligence Insights: {insights_text}"
            
    return enhanced_finding


# Legacy function compatibility wrapper
async def enhanced_web_search_findings(findings: List[Finding], config: ScanConfig) -> List[Finding]:
    """
    Compatibility wrapper for enhanced web search functionality.
    
    This function provides a smooth transition between legacy and modern web intelligence.
    """
    return await enhanced_vulnerability_research(findings, config)


# Export new functions
__all__ = [
    'StackOverflowAPI', 'GeminiWebSearch', 'search_for_vulnerability_fix',
    'enhance_findings_with_web_search', 'enhanced_vulnerability_research',
    'enhanced_web_search_findings'
]
