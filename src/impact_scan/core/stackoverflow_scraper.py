"""
Stack Overflow web scraper for extracting security vulnerability fixes.

This module provides hybrid scraping:
- Primary: Parse.bot API (fast, cost-effective ~$0.001/request)
- Fallback: Playwright browser automation (slower but reliable)

Auto-selection logic chooses the best method based on availability and failure rates.
"""

import asyncio
import hashlib
import random
import re
import time
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Dict, List, Optional

import httpx
from bs4 import BeautifulSoup
from rich.console import Console

try:
    from playwright.async_api import Browser, async_playwright
    from playwright.async_api import TimeoutError as PlaywrightTimeoutError
    PLAYWRIGHT_AVAILABLE = True
except ImportError:
    PLAYWRIGHT_AVAILABLE = False
    Browser = None
    async_playwright = None
    PlaywrightTimeoutError = TimeoutError

from ..utils.schema import Finding, StackOverflowFix, CodeBlock as SchemaCodeBlock
from ..utils.rate_limiter import AdaptiveRateLimiter
from ..utils.persistent_cache import PersistentCache

console = Console()


@dataclass
class CodeBlock:
    """Represents a code block extracted from Stack Overflow."""

    language: str
    code: str

    def to_dict(self) -> Dict[str, str]:
        return {"language": self.language, "code": self.code}


@dataclass
class StackOverflowAnswer:
    """Represents a scraped Stack Overflow answer with metadata."""

    url: str
    title: str
    question_id: str
    answer_id: str
    votes: int
    accepted: bool
    author: str
    author_reputation: int
    post_date: str
    code_snippets: List[CodeBlock]
    explanation: str
    comments: List[str]
    score: float

    def to_dict(self) -> Dict[str, Any]:
        """Convert to dictionary for JSON serialization."""
        return {
            "url": self.url,
            "title": self.title,
            "question_id": self.question_id,
            "answer_id": self.answer_id,
            "votes": self.votes,
            "accepted": self.accepted,
            "author": self.author,
            "author_reputation": self.author_reputation,
            "post_date": self.post_date,
            "code_snippets": [block.to_dict() for block in self.code_snippets],
            "explanation": self.explanation,
            "comments": self.comments,
            "score": self.score,
        }

    def get_citation_apa(self) -> str:
        """Generate APA format citation."""
        year = (
            self.post_date.split("-")[0]
            if "-" in self.post_date
            else self.post_date[:4]
        )
        return f"{self.author}. ({year}). {self.title}. Stack Overflow. {self.url}"

    def get_citation_mla(self) -> str:
        """Generate MLA format citation."""
        return f'{self.author}. "{self.title}." Stack Overflow, {self.post_date}, {self.url}.'

    def get_citation_chicago(self) -> str:
        """Generate Chicago format citation."""
        return f'{self.author}. "{self.title}." Stack Overflow. {self.post_date}. {self.url}.'


class StackOverflowContentExtractor:
    """Extracts and parses content from Stack Overflow HTML pages."""

    @staticmethod
    def extract_answer_data(html: str, url: str) -> List[StackOverflowAnswer]:
        """
        Extract answer data from Stack Overflow HTML.

        Args:
            html: Raw HTML content from Stack Overflow page
            url: The Stack Overflow URL being parsed

        Returns:
            List of StackOverflowAnswer objects, sorted by score (highest first)
        """
        soup = BeautifulSoup(html, "html.parser")
        answers = []

        # Extract question title
        title_elem = soup.find("h1", {"itemprop": "name"}) or soup.find(
            "a", {"class": "question-hyperlink"}
        )
        question_title = (
            title_elem.get_text().strip() if title_elem else "Unknown Question"
        )

        # Extract question ID from URL
        question_id_match = re.search(r"/questions/(\d+)/", url)
        question_id = question_id_match.group(1) if question_id_match else "unknown"

        # Find all answer divs
        answer_divs = soup.find_all("div", {"class": "answer"})

        for answer_div in answer_divs:
            try:
                answer_data = StackOverflowContentExtractor._parse_answer(
                    answer_div, question_title, question_id, url
                )
                if (
                    answer_data and answer_data.code_snippets
                ):  # Only include answers with code
                    answers.append(answer_data)
            except Exception as e:
                console.log(f"[yellow]Warning: Failed to parse answer: {e}[/yellow]")
                continue

        # Sort by score (highest first)
        answers.sort(key=lambda x: x.score, reverse=True)

        return answers

    @staticmethod
    def _parse_answer(
        answer_div, question_title: str, question_id: str, base_url: str
    ) -> Optional[StackOverflowAnswer]:
        """Parse a single answer div into StackOverflowAnswer object."""
        try:
            # Extract answer ID
            answer_id = answer_div.get("data-answerid", "unknown")

            # Extract votes
            vote_elem = answer_div.find(
                "div", {"class": "js-vote-count"}
            ) or answer_div.find("span", {"itemprop": "upvoteCount"})
            votes = 0
            if vote_elem:
                vote_text = vote_elem.get_text().strip()
                try:
                    votes = int(vote_text)
                except (ValueError, TypeError):
                    votes = 0

            # Check if accepted
            accepted = (
                answer_div.find("div", {"class": "accepted-answer"}) is not None
                or answer_div.find("svg", {"class": "fc-green-500"}) is not None
            )

            # Extract author info
            author_elem = answer_div.find(
                "div", {"class": "user-details"}
            ) or answer_div.find("a", {"class": "user-link"})
            author = "Unknown"
            author_reputation = 0

            if author_elem:
                author_link = author_elem.find("a")
                if author_link:
                    author = author_link.get_text().strip()

                # Extract reputation
                rep_elem = author_elem.find("span", {"class": "reputation-score"})
                if rep_elem:
                    rep_text = rep_elem.get("title", rep_elem.get_text())
                    # Parse reputation (e.g., "12.3k" or "12,345")
                    rep_text = rep_text.replace(",", "").replace("k", "000").strip()
                    try:
                        author_reputation = int(float(rep_text))
                    except (ValueError, TypeError):
                        author_reputation = 0

            # Extract post date
            time_elem = answer_div.find(
                "time", {"itemprop": "dateCreated"}
            ) or answer_div.find("span", {"class": "relativetime"})
            post_date = (
                time_elem.get("datetime", time_elem.get_text())
                if time_elem
                else "Unknown"
            )

            # Extract answer content
            answer_content = answer_div.find(
                "div", {"class": "s-prose"}
            ) or answer_div.find("div", {"class": "answercell"})
            if not answer_content:
                return None

            # Extract code blocks with language detection
            code_snippets = StackOverflowContentExtractor._extract_code_blocks(
                answer_content
            )

            # Extract explanation text (remove code blocks)
            explanation_soup = BeautifulSoup(str(answer_content), "html.parser")
            for code_elem in explanation_soup.find_all(["pre", "code"]):
                code_elem.decompose()
            explanation = explanation_soup.get_text(separator=" ", strip=True)

            # Limit explanation length
            if len(explanation) > 500:
                explanation = explanation[:500] + "..."

            # Extract comments (top 3 only)
            comments = []
            comment_div = answer_div.find(
                "div", {"class": "comments"}
            ) or answer_div.find("ul", {"class": "comments-list"})
            if comment_div:
                comment_elems = comment_div.find_all("li", {"class": "comment"})[:3]
                for comment_elem in comment_elems:
                    comment_text_elem = comment_elem.find(
                        "span", {"class": "comment-copy"}
                    )
                    if comment_text_elem:
                        comment_text = comment_text_elem.get_text().strip()
                        if len(comment_text) > 150:
                            comment_text = comment_text[:150] + "..."
                        comments.append(comment_text)

            # Calculate score: votes + (accepted bonus) + (reputation factor)
            score = (
                float(votes)
                + (50.0 if accepted else 0.0)
                + (author_reputation / 1000.0)
            )

            # Build answer URL
            answer_url = (
                f"{base_url}#answer-{answer_id}" if "#" not in base_url else base_url
            )

            return StackOverflowAnswer(
                url=answer_url,
                title=question_title,
                question_id=question_id,
                answer_id=answer_id,
                votes=votes,
                accepted=accepted,
                author=author,
                author_reputation=author_reputation,
                post_date=post_date,
                code_snippets=code_snippets,
                explanation=explanation,
                comments=comments,
                score=score,
            )

        except Exception as e:
            console.log(f"[red]Error parsing answer: {e}[/red]")
            return None

    @staticmethod
    def _extract_code_blocks(content_div) -> List[CodeBlock]:
        """Extract code blocks with language detection."""
        code_blocks = []

        # Find all pre > code elements
        pre_elements = content_div.find_all("pre")

        for pre in pre_elements:
            code_elem = pre.find("code")
            if not code_elem:
                continue

            # Extract code text
            code_text = code_elem.get_text().strip()
            if len(code_text) < 10:  # Skip very short snippets
                continue

            # Detect language from class attribute
            language = "text"
            class_attr = code_elem.get("class", [])
            if isinstance(class_attr, list):
                for cls in class_attr:
                    if cls.startswith("language-") or cls.startswith("lang-"):
                        language = cls.split("-", 1)[1]
                        break
                    elif cls in [
                        "python",
                        "javascript",
                        "java",
                        "cpp",
                        "c",
                        "php",
                        "ruby",
                        "go",
                        "rust",
                    ]:
                        language = cls
                        break

            # Heuristic language detection if not found
            if language == "text":
                language = StackOverflowContentExtractor._detect_language(code_text)

            code_blocks.append(CodeBlock(language=language, code=code_text))

        return code_blocks

    @staticmethod
    def _detect_language(code: str) -> str:
        """Simple heuristic language detection."""
        code_lower = code.lower()

        # Python indicators
        if "def " in code or "import " in code or "elif " in code or "__init__" in code:
            return "python"

        # JavaScript indicators
        if "function" in code or "const " in code or "let " in code or "=>" in code:
            return "javascript"

        # Java indicators
        if "public class" in code or "private " in code or "System.out" in code:
            return "java"

        # PHP indicators
        if "<?php" in code or "$_" in code:
            return "php"

        # SQL indicators
        if (
            "select " in code_lower
            or "insert into" in code_lower
            or "update " in code_lower
        ):
            return "sql"

        return "text"


class StackOverflowScraper:
    """
    Web scraper for Stack Overflow using Playwright.

    Searches Google for Stack Overflow questions related to security vulnerabilities,
    scrapes answer pages, and extracts code fixes with metadata.
    """

    def __init__(
        self,
        scrape_delay: float = 4.0,
        max_answers: int = 3,
        include_comments: bool = True,
        enable_persistent_cache: bool = True,
    ):
        """
        Initialize the Stack Overflow scraper.

        Args:
            scrape_delay: Delay in seconds between requests (default: 4.0)
            max_answers: Maximum number of answers to return (default: 3)
            include_comments: Whether to include comments (default: True)
            enable_persistent_cache: Enable persistent SQLite cache (default: True)
        """
        self.max_answers = max_answers
        self.include_comments = include_comments

        # Initialize adaptive rate limiter (token bucket + exponential backoff + circuit breaker)
        requests_per_minute = 60.0 / scrape_delay if scrape_delay > 0 else 10.0
        self.rate_limiter = AdaptiveRateLimiter(
            requests_per_minute=requests_per_minute,
            max_burst=3,
            initial_backoff=1.0,
            max_backoff=60.0,
            backoff_multiplier=2.0,
            circuit_breaker_threshold=3,
            circuit_breaker_timeout=300.0,  # 5 minutes
        )

        # Initialize persistent cache
        self.enable_persistent_cache = enable_persistent_cache
        if enable_persistent_cache:
            self.persistent_cache = PersistentCache(
                cache_dir=Path.home() / ".impact_scan" / "cache",
                db_name="stackoverflow_cache.db",
                default_ttl=86400,  # 24 hours
            )
        else:
            self.persistent_cache = None

        # In-memory cache as fallback
        self.cache: Dict[str, List[StackOverflowAnswer]] = {}
        self.max_cache_size = 100

        self.user_agents = [
            "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/121.0.0.0 Safari/537.36",
            "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/121.0.0.0 Safari/537.36",
            "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/121.0.0.0 Safari/537.36",
        ]

    async def _rate_limit(self):
        """
        Implement advanced rate limiting with token bucket and circuit breaker.

        Returns:
            True if request can proceed, False if circuit breaker is open
        """
        return await self.rate_limiter.acquire()

    def _get_cache_key(self, finding: Finding) -> str:
        """Generate cache key for a finding."""
        key_components = [finding.vuln_id, finding.title, str(finding.file_path)]
        return hashlib.md5(
            "|".join(key_components).encode(), usedforsecurity=False
        ).hexdigest()

    def _get_cached_answers(
        self, finding: Finding
    ) -> Optional[List[StackOverflowAnswer]]:
        """Get cached answers for a finding (checks persistent cache first, then in-memory)."""
        cache_key_data = {
            "vuln_id": finding.vuln_id,
            "title": finding.title,
            "file_path": str(finding.file_path),
        }

        # Try persistent cache first
        if self.persistent_cache:
            cached_data = self.persistent_cache.get(cache_key_data)
            if cached_data:
                # Deserialize from dict back to StackOverflowAnswer objects
                answers = []
                for answer_dict in cached_data:
                    try:
                        code_snippets = [
                            CodeBlock(language=cb["language"], code=cb["code"])
                            for cb in answer_dict.get("code_snippets", [])
                        ]
                        answer = StackOverflowAnswer(
                            url=answer_dict["url"],
                            title=answer_dict["title"],
                            question_id=answer_dict["question_id"],
                            answer_id=answer_dict["answer_id"],
                            votes=answer_dict["votes"],
                            accepted=answer_dict["accepted"],
                            author=answer_dict["author"],
                            author_reputation=answer_dict["author_reputation"],
                            post_date=answer_dict["post_date"],
                            code_snippets=code_snippets,
                            explanation=answer_dict["explanation"],
                            comments=answer_dict.get("comments", []),
                            score=answer_dict["score"],
                        )
                        answers.append(answer)
                    except (KeyError, TypeError) as e:
                        console.log(f"[yellow]Warning: Failed to deserialize cached answer: {e}[/yellow]")
                        continue

                if answers:
                    console.log(
                        f"[green][PERSISTENT CACHE HIT] Using cached Stack Overflow answers for {finding.vuln_id}[/green]"
                    )
                    return answers

        # Fallback to in-memory cache
        cache_key = self._get_cache_key(finding)
        if cache_key in self.cache:
            console.log(
                f"[green][MEMORY CACHE HIT] Using cached Stack Overflow answers for {finding.vuln_id}[/green]"
            )
            return self.cache[cache_key]

        return None

    def _cache_answers(self, finding: Finding, answers: List[StackOverflowAnswer]):
        """Cache answers for a finding (both persistent and in-memory)."""
        # Store in persistent cache
        if self.persistent_cache:
            cache_key_data = {
                "vuln_id": finding.vuln_id,
                "title": finding.title,
                "file_path": str(finding.file_path),
            }
            # Serialize answers to dicts
            serialized_answers = [answer.to_dict() for answer in answers]
            self.persistent_cache.set(cache_key_data, serialized_answers)

        # Also store in memory cache for faster access during this session
        cache_key = self._get_cache_key(finding)

        # Simple LRU: remove oldest if at capacity
        if len(self.cache) >= self.max_cache_size:
            oldest_key = next(iter(self.cache))
            del self.cache[oldest_key]

        self.cache[cache_key] = answers

    async def search_and_scrape(self, finding: Finding) -> List[StackOverflowAnswer]:
        """
        Search Google for Stack Overflow answers and scrape the content.

        Args:
            finding: The vulnerability finding to search for

        Returns:
            List of StackOverflowAnswer objects, sorted by score
        """
        # Check cache first
        cached = self._get_cached_answers(finding)
        if cached:
            return cached

        console.log(
            f"[cyan][SO_SCRAPER] Searching Stack Overflow for {finding.vuln_id}...[/cyan]"
        )

        try:
            # Build search query
            query = self._build_search_query(finding)
            console.log(f"[dim]Search query: {query}[/dim]")

            # Step 1: Search Stack Overflow directly (no browser needed!)
            so_urls = await self._search_stackoverflow_direct(query)

            if not so_urls:
                console.log(
                    f"[yellow]No Stack Overflow URLs found for {finding.vuln_id}[/yellow]"
                )
                return []

            console.log(f"[green]Found {len(so_urls)} Stack Overflow URLs[/green]")

            # Step 2: Scrape those URLs with Playwright
            async with async_playwright() as p:
                browser = await p.chromium.launch(headless=True)
                try:
                    # Scrape each URL
                    all_answers = []
                    for url in so_urls[:5]:  # Limit to top 5 URLs
                        # Apply rate limiting (token bucket + circuit breaker)
                        if not await self._rate_limit():
                            console.log("[yellow]Circuit breaker open - stopping scrape[/yellow]")
                            break

                        answers = await self._scrape_stackoverflow_page(browser, url)
                        all_answers.extend(answers)

                        # Record success for rate limiter
                        if answers:
                            self.rate_limiter.record_success()

                    # Sort by score and limit
                    all_answers.sort(key=lambda x: x.score, reverse=True)
                    top_answers = all_answers[: self.max_answers]

                    # Cache results
                    if top_answers:
                        self._cache_answers(finding, top_answers)
                        console.log(
                            f"[bold green][SO_SUCCESS] Found {len(top_answers)} Stack Overflow answers for {finding.vuln_id}[/bold green]"
                        )

                    return top_answers

                finally:
                    await browser.close()

        except Exception as e:
            console.log(
                f"[bold red][SO_ERROR] Scraping failed for {finding.vuln_id}: {e}[/bold red]"
            )
            return []

    def _extract_code_keywords(self, code_snippet: str) -> List[str]:
        """
        Extract relevant keywords from vulnerable code snippet.
        Focus on libraries, functions, and security-relevant terms.
        """
        keywords = []
        code_lower = code_snippet.lower()

        # Check for multi-word function patterns FIRST (before single word extraction)
        # These are high-priority security-relevant functions
        multi_word_funcs = [
            "render_template_string",
            "render_template",
            "execute_script",
            "pickle.loads",
            "pickle.load",
            "yaml.load",
            "yaml.unsafe_load",
            "os.system",
            "subprocess.call",
            "subprocess.run",
            "subprocess.popen",
            "eval",
            "exec",
            "compile",
            "__import__",
        ]

        for func in multi_word_funcs:
            if func in code_lower:
                # Extract the key part (e.g., "render_template_string" or "pickle loads")
                keywords.append(func.replace(".", " ").replace("_", " "))

        # Common security-relevant libraries and modules
        libs = [
            "urllib3",
            "requests",
            "flask",
            "django",
            "sqlalchemy",
            "pymongo",
            "pickle",
            "yaml",
            "xml",
            "subprocess",
            "jwt",
            "crypto",
            "ssl",
            "hashlib",
            "pandas",
            "numpy",
            "tensorflow",
            "jinja2",
            "psycopg2",
            "mysql",
            "sqlite3",
            "redis",
            "boto3",
            "paramiko",
            "lxml",
            "etree",
            "beautifulsoup",
            "scrapy",
        ]

        for lib in libs:
            if lib in code_lower and lib not in " ".join(keywords):
                keywords.append(lib)

        # Extract import statements (e.g., "import requests", "from flask import")
        import_matches = re.findall(r"\b(?:import|from)\s+(\w+)", code_snippet)
        for imp in import_matches[:3]:
            if imp not in " ".join(keywords):
                keywords.append(imp)

        # Extract single-word function calls (e.g., "execute(", "query(", "cursor(")
        func_matches = re.findall(r"\b(\w+)\s*\(", code_snippet)
        # Filter to security-relevant functions
        security_funcs = [
            f
            for f in func_matches
            if f
            in [
                "execute",
                "query",
                "cursor",
                "connect",
                "open",
                "send",
                "load",
                "loads",
                "decode",
                "deserialize",
                "format",
                "render",
            ]
        ]
        for func in security_funcs[:2]:
            if func not in " ".join(keywords):
                keywords.append(func)

        # Remove duplicates while preserving order
        seen = set()
        unique_keywords = []
        for k in keywords:
            k_clean = k.strip()
            if k_clean not in seen and len(k_clean) > 2:  # Ignore very short terms
                seen.add(k_clean)
                unique_keywords.append(k_clean)

        return unique_keywords[:5]  # Limit to top 5 most relevant

    def _build_search_query(self, finding: Finding) -> str:
        """
        Build contextual search query using:
        1. Vulnerability type from title
        2. Key terms from actual vulnerable code
        3. Programming language

        Example: "urllib3 ssl certificate verification python stack overflow"
        This ensures Stack Overflow answers are directly relevant to fixing the specific vulnerable code!
        """
        # Extract language from file extension
        file_ext = (
            str(finding.file_path).split(".")[-1].lower()
            if "." in str(finding.file_path)
            else ""
        )
        language_map = {
            "py": "python",
            "js": "javascript",
            "ts": "typescript",
            "java": "java",
            "php": "php",
            "rb": "ruby",
            "go": "go",
            "rs": "rust",
            "cpp": "c++",
            "c": "c",
            "cs": "c#",
            "sql": "sql",
        }
        language = language_map.get(file_ext, file_ext or "python")

        # Extract vulnerability name from title (NOT CVE number!)
        title_lower = finding.title.lower()

        # Remove common prefixes/CVE IDs to get clean vulnerability name
        vuln_name = title_lower
        vuln_name = re.sub(r"\bcve-\d{4}-\d+\b", "", vuln_name)  # Remove CVE IDs
        vuln_name = re.sub(r"\bcwe-\d+\b", "", vuln_name)  # Remove CWE IDs
        vuln_name = re.sub(
            r"^(python|java|javascript|php|ruby)\s+", "", vuln_name
        )  # Remove language prefix
        vuln_name = vuln_name.strip()

        # Simplify to key vulnerability type
        if "sql injection" in vuln_name or "sqli" in vuln_name:
            vuln_name = "sql injection"
        elif "cross-site scripting" in vuln_name or "xss" in vuln_name:
            vuln_name = "xss cross site scripting"
        elif "path traversal" in vuln_name or "directory traversal" in vuln_name:
            vuln_name = "path traversal"
        elif "command injection" in vuln_name or "os command" in vuln_name:
            vuln_name = "command injection"
        elif "xxe" in vuln_name or "xml external" in vuln_name:
            vuln_name = "xxe xml external entity"
        elif "csrf" in vuln_name or "cross-site request" in vuln_name:
            vuln_name = "csrf protection"
        elif "hardcoded" in vuln_name and (
            "password" in vuln_name or "secret" in vuln_name or "key" in vuln_name
        ):
            vuln_name = "hardcoded credentials"
        elif "insecure deserialization" in vuln_name or "pickle" in vuln_name:
            vuln_name = "insecure deserialization"
        elif "weak" in vuln_name and (
            "hash" in vuln_name or "md5" in vuln_name or "sha1" in vuln_name
        ):
            vuln_name = "weak password hashing"
        elif "ssl" in vuln_name or "tls" in vuln_name or "certificate" in vuln_name:
            vuln_name = "ssl certificate verification"

        # NEW: Extract keywords from actual vulnerable code!
        code_keywords = self._extract_code_keywords(finding.code_snippet)

        # Build query: <top_keywords> <vuln_name> <language>
        # Keep it short to avoid DuckDuckGo issues - limit to 2 keywords max
        if code_keywords:
            # Take only top 2 most relevant keywords to keep query short
            top_keywords = " ".join(code_keywords[:2])
            query = f"{top_keywords} {vuln_name} {language}"
        else:
            # Fallback if no keywords extracted
            query = f"{vuln_name} {language}"

        return query

    async def _search_stackoverflow_direct(self, query: str) -> List[str]:
        """
        Search using DuckDuckGo - no rate limits, no authentication needed.
        Uses proper delays and random user agents to avoid bot detection.
        """
        try:
            # Add small delay to avoid rapid-fire requests (DDG's anti-bot measure)
            await asyncio.sleep(random.uniform(1.0, 2.0))

            # Use DuckDuckGo HTML search (bot-friendly)
            search_url = "https://html.duckduckgo.com/html/"

            # Add site:stackoverflow.com to limit results
            search_query = f"site:stackoverflow.com {query}"

            # Rotate user agents to appear more human-like
            user_agent = random.choice(self.user_agents)

            async with httpx.AsyncClient(timeout=20.0, follow_redirects=True) as client:
                headers = {
                    "User-Agent": user_agent,
                    "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8",
                    "Accept-Language": "en-US,en;q=0.9",
                    "Accept-Encoding": "gzip, deflate, br",
                    "DNT": "1",
                    "Connection": "keep-alive",
                    "Upgrade-Insecure-Requests": "1",
                }

                # DuckDuckGo uses POST with form data
                data = {"q": search_query, "b": "", "kl": "us-en"}

                console.log(f"[dim]Searching via DuckDuckGo: {search_query}[/dim]")
                response = await client.post(search_url, data=data, headers=headers)

                # Handle rate limiting
                if response.status_code == 429:
                    retry_after = response.headers.get("Retry-After")
                    console.log(f"[yellow]DuckDuckGo rate limit (429) - Retry-After: {retry_after}[/yellow]")
                    await self.rate_limiter.record_rate_limit(retry_after_header=retry_after)
                    return []

                if response.status_code != 200:
                    console.log(
                        f"[yellow]DuckDuckGo returned {response.status_code} (might be temporary rate limiting)[/yellow]"
                    )

                    # If we get 202, DDG is processing - wait and parse anyway
                    if response.status_code == 202:
                        console.log("[dim]Attempting to parse 202 response...[/dim]")
                    else:
                        self.rate_limiter.record_failure()
                        return []

                # Parse HTML to extract Stack Overflow URLs
                soup = BeautifulSoup(response.text, "html.parser")

                # Find all result links
                urls = []
                result_links = soup.find_all("a", {"class": "result__a"})

                for link in result_links[:10]:  # Top 10 results
                    href = link.get("href", "")

                    # DuckDuckGo wraps URLs, extract the actual SO URL
                    if "stackoverflow.com/questions/" in href:
                        # Clean up the URL
                        base_url = href.split("#")[0].split("?")[0]
                        if base_url not in urls:
                            urls.append(base_url)

                if urls:
                    console.log(
                        f"[green]Found {len(urls)} SO questions via DuckDuckGo[/green]"
                    )
                    return urls
                else:
                    console.log(
                        "[yellow]No SO URLs found via DDG - trying direct SO search...[/yellow]"
                    )
                    # Fallback: Use Stack Overflow's internal search
                    return await self._search_stackoverflow_internal(query)

        except Exception as e:
            console.log(
                f"[yellow]DDG search failed: {e} - trying direct SO search...[/yellow]"
            )
            return await self._search_stackoverflow_internal(query)

    async def _search_stackoverflow_internal(self, query: str) -> List[str]:
        """
        Fallback: Search Stack Overflow directly using their search page.
        This bypasses external search engines entirely!
        """
        try:
            # Stack Overflow's search endpoint
            search_url = "https://stackoverflow.com/search"
            params = {
                "q": query,
                "tab": "Votes",  # Sort by votes for quality answers
            }

            async with httpx.AsyncClient(timeout=15.0, follow_redirects=True) as client:
                headers = {
                    "User-Agent": random.choice(self.user_agents),
                    "Accept": "text/html,application/xhtml+xml",
                }

                console.log(
                    f"[dim]Searching directly on stackoverflow.com: {query}[/dim]"
                )
                response = await client.get(search_url, params=params, headers=headers)

                # Handle rate limiting
                if response.status_code == 429:
                    retry_after = response.headers.get("Retry-After")
                    console.log(f"[yellow]Stack Overflow rate limit (429) - Retry-After: {retry_after}[/yellow]")
                    await self.rate_limiter.record_rate_limit(retry_after_header=retry_after)
                    raise Exception("429: Rate limit exceeded")

                if response.status_code != 200:
                    console.log(
                        f"[yellow]SO search returned {response.status_code}[/yellow]"
                    )
                    self.rate_limiter.record_failure()
                    return []

                # Parse search results
                soup = BeautifulSoup(response.text, "html.parser")

                # Find question links in search results
                urls = []
                question_links = soup.find_all("a", {"class": "s-link"})

                for link in question_links[:10]:
                    href = link.get("href", "")
                    if href.startswith("/questions/"):
                        full_url = f"https://stackoverflow.com{href}"
                        # Remove query params
                        base_url = full_url.split("?")[0].split("#")[0]
                        if base_url not in urls:
                            urls.append(base_url)

                if urls:
                    console.log(
                        f"[green]Found {len(urls)} SO questions via direct search[/green]"
                    )
                else:
                    console.log("[yellow]No results from SO direct search[/yellow]")

                return urls

        except Exception as e:
            console.log(f"[red]SO direct search failed: {e}[/red]")
            return []

    async def _scrape_stackoverflow_page(
        self, browser: Browser, url: str
    ) -> List[StackOverflowAnswer]:
        """Scrape a Stack Overflow question page."""
        page = await browser.new_page(
            user_agent=self.user_agents[1], viewport={"width": 1920, "height": 1080}
        )

        try:
            console.log(f"[dim]Scraping: {url}[/dim]")

            # Navigate to Stack Overflow page
            await page.goto(url, wait_until="networkidle", timeout=30000)

            # Wait for content
            await page.wait_for_selector(".answer", timeout=10000)

            # Get HTML
            html = await page.content()

            # Extract answer data
            answers = StackOverflowContentExtractor.extract_answer_data(html, url)

            console.log(f"[green]Extracted {len(answers)} answers from {url}[/green]")

            return answers

        except PlaywrightTimeoutError:
            console.log(f"[yellow]Timeout scraping {url}[/yellow]")
            return []
        except Exception as e:
            console.log(f"[red]Error scraping {url}: {e}[/red]")
            return []
        finally:
            await page.close()


class HybridStackOverflowScraper:
    """
    Hybrid Stack Overflow scraper with intelligent fallback.

    Strategy:
    1. Parse.bot API (primary): Fast, cheap, API-based scraping
    2. Playwright (fallback): Browser automation when Parse.bot fails
    3. Auto-selection: Chooses method based on failure rates
    """

    def __init__(
        self,
        parsebot_api_key: Optional[str] = None,
        scrape_delay: float = 4.0,
        max_answers: int = 3,
        method: str = "auto",
        enable_persistent_cache: bool = True,
    ):
        """
        Initialize hybrid scraper.

        Args:
            parsebot_api_key: Parse.bot API key (optional)
            scrape_delay: Delay between requests for Playwright
            max_answers: Maximum answers to return
            method: 'parsebot', 'playwright', or 'auto'
            enable_persistent_cache: Enable persistent SQLite cache (default: True)
        """
        self.parsebot_api_key = parsebot_api_key
        self.scrape_delay = scrape_delay
        self.max_answers = max_answers
        self.method = method
        self.enable_persistent_cache = enable_persistent_cache

        # Statistics
        self.stats = {
            "parsebot_requests": 0,
            "parsebot_successes": 0,
            "parsebot_failures": 0,
            "playwright_requests": 0,
            "playwright_successes": 0,
            "playwright_failures": 0,
            "cache_hits": 0,
        }

        # Initialize clients lazily
        self._parsebot_client = None
        self._playwright_scraper = None

        # Initialize persistent cache
        if enable_persistent_cache:
            self.persistent_cache = PersistentCache(
                cache_dir=Path.home() / ".impact_scan" / "cache",
                db_name="stackoverflow_cache.db",
                default_ttl=86400,  # 24 hours
            )
        else:
            self.persistent_cache = None

        # In-memory cache as fallback
        self.cache: Dict[str, List[StackOverflowAnswer]] = {}

    async def _get_parsebot_client(self):
        """Lazy initialize Parse.bot client"""
        if self._parsebot_client is None and self.parsebot_api_key:
            try:
                from .parsebot_client import ParseBotClient

                cache_dir = Path.home() / ".impact_scan" / "parsebot_cache"
                self._parsebot_client = ParseBotClient(
                    api_key=self.parsebot_api_key,
                    cache_dir=cache_dir,
                    enable_cache=True,
                )
            except ImportError:
                console.log(
                    "[yellow]Parse.bot client not available, using Playwright[/yellow]"
                )
        return self._parsebot_client

    def _get_playwright_scraper(self) -> StackOverflowScraper:
        """Lazy initialize Playwright scraper"""
        if self._playwright_scraper is None:
            self._playwright_scraper = StackOverflowScraper(
                scrape_delay=self.scrape_delay,
                max_answers=self.max_answers,
                enable_persistent_cache=self.enable_persistent_cache
            )
        return self._playwright_scraper

    def _get_cache_key(self, finding: Finding) -> str:
        """Generate cache key for a finding"""
        key_components = [finding.vuln_id, finding.title, str(finding.file_path)]
        return hashlib.md5(
            "|".join(key_components).encode(), usedforsecurity=False
        ).hexdigest()

    def _should_use_parsebot(self) -> bool:
        """Decide whether to use Parse.bot based on method and failure rates"""
        if not self.parsebot_api_key:
            return False

        if self.method == "playwright":
            return False

        if self.method == "parsebot":
            return True

        # Auto mode: use Parse.bot unless failure rate is high
        if self.stats["parsebot_requests"] < 5:
            return True  # Try Parse.bot initially

        failure_rate = self.stats["parsebot_failures"] / self.stats["parsebot_requests"]
        return failure_rate < 0.5  # Fallback to Playwright if >50% failure rate

    async def search_and_scrape(self, finding: Finding) -> List[StackOverflowAnswer]:
        """
        Search and scrape Stack Overflow using best available method.

        Args:
            finding: Vulnerability finding to search for

        Returns:
            List of StackOverflowAnswer objects
        """
        # Check persistent cache first
        if self.persistent_cache:
            cache_key_data = {
                "vuln_id": finding.vuln_id,
                "title": finding.title,
                "file_path": str(finding.file_path),
            }
            cached_data = self.persistent_cache.get(cache_key_data)
            if cached_data:
                # Deserialize from dict back to StackOverflowAnswer objects
                answers = []
                for answer_dict in cached_data:
                    try:
                        code_snippets = [
                            CodeBlock(language=cb["language"], code=cb["code"])
                            for cb in answer_dict.get("code_snippets", [])
                        ]
                        answer = StackOverflowAnswer(
                            url=answer_dict["url"],
                            title=answer_dict["title"],
                            question_id=answer_dict["question_id"],
                            answer_id=answer_dict["answer_id"],
                            votes=answer_dict["votes"],
                            accepted=answer_dict["accepted"],
                            author=answer_dict["author"],
                            author_reputation=answer_dict["author_reputation"],
                            post_date=answer_dict["post_date"],
                            code_snippets=code_snippets,
                            explanation=answer_dict["explanation"],
                            comments=answer_dict.get("comments", []),
                            score=answer_dict["score"],
                        )
                        answers.append(answer)
                    except (KeyError, TypeError) as e:
                        console.log(f"[yellow]Warning: Failed to deserialize cached answer: {e}[/yellow]")
                        continue

                if answers:
                    self.stats["cache_hits"] += 1
                    console.log(
                        f"[green][PERSISTENT CACHE HIT] Using cached answers for {finding.vuln_id}[/green]"
                    )
                    return answers

        # Check in-memory cache
        cache_key = self._get_cache_key(finding)
        if cache_key in self.cache:
            self.stats["cache_hits"] += 1
            console.log(
                f"[green][MEMORY CACHE HIT] Using cached answers for {finding.vuln_id}[/green]"
            )
            return self.cache[cache_key]

        # Try Parse.bot first if available
        if self._should_use_parsebot():
            console.log(
                "[cyan][PARSEBOT] Searching Stack Overflow via Parse.bot API...[/cyan]"
            )
            answers = await self._scrape_with_parsebot(finding)

            if answers:
                self.stats["parsebot_successes"] += 1

                # Cache in persistent storage
                if self.persistent_cache:
                    cache_key_data = {
                        "vuln_id": finding.vuln_id,
                        "title": finding.title,
                        "file_path": str(finding.file_path),
                    }
                    serialized_answers = [answer.to_dict() for answer in answers]
                    self.persistent_cache.set(cache_key_data, serialized_answers)

                # Cache in memory
                self.cache[cache_key] = answers

                console.log(
                    f"[bold green][PARSEBOT SUCCESS] Found {len(answers)} answers[/bold green]"
                )
                return answers
            else:
                self.stats["parsebot_failures"] += 1
                console.log(
                    "[yellow][PARSEBOT] Failed, falling back to Playwright...[/yellow]"
                )

        # Fallback to Playwright
        console.log(
            "[cyan][PLAYWRIGHT] Searching Stack Overflow via browser automation...[/cyan]"
        )
        self.stats["playwright_requests"] += 1

        scraper = self._get_playwright_scraper()
        answers = await scraper.search_and_scrape(finding)

        if answers:
            self.stats["playwright_successes"] += 1
            self.cache[cache_key] = answers
            console.log(
                f"[bold green][PLAYWRIGHT SUCCESS] Found {len(answers)} answers[/bold green]"
            )
        else:
            self.stats["playwright_failures"] += 1
            console.log("[yellow][PLAYWRIGHT] No answers found[/yellow]")

        return answers

    async def _scrape_with_parsebot(
        self, finding: Finding
    ) -> List[StackOverflowAnswer]:
        """Scrape using Parse.bot API"""
        self.stats["parsebot_requests"] += 1

        try:
            client = await self._get_parsebot_client()
            if not client:
                return []

            # Build search query (reuse existing logic)
            playwright_scraper = self._get_playwright_scraper()
            query = playwright_scraper._build_search_query(finding)

            # Search Stack Overflow
            questions = await client.search_stackoverflow(
                query, max_results=self.max_answers
            )

            if not questions:
                return []

            # Convert Parse.bot format to StackOverflowAnswer format
            answers = []
            for question in questions:
                for pb_answer in question.answers:
                    # Parse code blocks from HTML
                    code_snippets = StackOverflowContentExtractor._extract_code_blocks(
                        BeautifulSoup(pb_answer.body_html, "html.parser")
                    )

                    if not code_snippets:  # Skip answers without code
                        continue

                    # Convert to StackOverflowAnswer
                    answer = StackOverflowAnswer(
                        url=question.url,
                        title=question.title,
                        question_id=question.question_id,
                        answer_id=pb_answer.answer_id,
                        votes=pb_answer.votes,
                        accepted=pb_answer.is_accepted,
                        author=pb_answer.author,
                        author_reputation=0,  # Not provided by Parse.bot
                        post_date=pb_answer.created_date,
                        code_snippets=code_snippets,
                        explanation=pb_answer.body_text[:500],
                        comments=[],  # Parse.bot doesn't extract comments
                        score=float(pb_answer.votes)
                        + (50.0 if pb_answer.is_accepted else 0.0),
                    )
                    answers.append(answer)

            # Sort by score and limit
            answers.sort(key=lambda x: x.score, reverse=True)
            return answers[: self.max_answers]

        except Exception as e:
            console.log(f"[red]Parse.bot error: {e}[/red]")
            return []

    def get_stats(self) -> Dict[str, Any]:
        """Get scraping statistics"""
        total_requests = (
            self.stats["parsebot_requests"] + self.stats["playwright_requests"]
        )

        return {
            "total_requests": total_requests,
            "cache_hits": self.stats["cache_hits"],
            "parsebot_requests": self.stats["parsebot_requests"],
            "parsebot_success_rate": (
                self.stats["parsebot_successes"] / self.stats["parsebot_requests"]
                if self.stats["parsebot_requests"] > 0
                else 0
            ),
            "playwright_requests": self.stats["playwright_requests"],
            "playwright_success_rate": (
                self.stats["playwright_successes"] / self.stats["playwright_requests"]
                if self.stats["playwright_requests"] > 0
                else 0
            ),
            "estimated_cost_usd": self.stats["parsebot_successes"] * 0.001,
        }

    async def close(self):
        """Close clients"""
        if self._parsebot_client:
            await self._parsebot_client.close()


# Convenience function for synchronous usage
def scrape_stackoverflow_sync(
    finding: Finding, scrape_delay: float = 4.0, max_answers: int = 3
) -> List[StackOverflowAnswer]:
    """Synchronous wrapper for Stack Overflow scraping."""
    scraper = StackOverflowScraper(scrape_delay=scrape_delay, max_answers=max_answers)
    return asyncio.run(scraper.search_and_scrape(finding))


def search_and_scrape_solutions(
    finding: Finding, max_results: int = 3, scrape_delay: float = 4.0
) -> List[StackOverflowFix]:
    """
    Search and scrape Stack Overflow for solutions to a vulnerability.

    This is the main entry point used by entrypoint.py to enrich findings
    with Stack Overflow solutions.

    Args:
        finding: The vulnerability finding to search for
        max_results: Maximum number of answers to return (default: 3)
        scrape_delay: Delay between requests in seconds (default: 4.0)

    Returns:
        List of StackOverflowFix objects
    """
    try:
        # Use hybrid scraper for best results (Parse.bot + Playwright fallback)
        scraper = HybridStackOverflowScraper(
            max_answers=max_results,
            scrape_delay=scrape_delay,
            method="auto",  # Auto-select best method
        )

        # Run async scraper
        answers = asyncio.run(scraper.search_and_scrape(finding))

        if not answers:
            return []

        # Convert StackOverflowAnswer objects to StackOverflowFix model objects
        fixes = []
        for answer in answers:
            # Convert CodeBlock objects to schema CodeBlock objects
            code_blocks = [
                SchemaCodeBlock(language=cb.language, code=cb.code)
                for cb in answer.code_snippets
            ]

            fix = StackOverflowFix(
                url=answer.url,
                title=answer.title,
                question_id=answer.question_id,
                answer_id=answer.answer_id,
                votes=answer.votes,
                accepted=answer.accepted,
                author=answer.author,
                author_reputation=answer.author_reputation,
                post_date=answer.post_date,
                code_snippets=code_blocks,
                explanation=answer.explanation,
                comments=answer.comments,
                score=answer.score,
                gemini_analysis=None  # Can be added later by AI validator
            )
            fixes.append(fix)

        console.log(
            f"[bold green]Successfully found {len(fixes)} Stack Overflow solutions[/bold green]"
        )
        return fixes

    except Exception as e:
        console.log(f"[red]Error in search_and_scrape_solutions: {e}[/red]")
        import traceback
        traceback.print_exc()
        return []
