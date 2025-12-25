"""
Parse.bot API Client for Web Scraping
Replaces Playwright with fast, cost-effective API scraping
~$0.001 per request, 10-100x faster than browser automation
"""

import asyncio
import hashlib
import json
import time
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Dict, List, Optional

import httpx
from rich.console import Console

console = Console()

# Parse.bot API configuration
PARSEBOT_API_BASE = "https://api.parse.bot/v1"
DEFAULT_TIMEOUT = 30.0

# Pricing: Free tier = 100 calls/month, Hobby = $30/1000 calls, Developer = $150/5000 calls
# Effective cost: ~$0.03 per call (Hobby tier) or $0.03 per call (Developer tier)


@dataclass
class StackOverflowAnswer:
    """Parsed Stack Overflow answer data"""

    answer_id: str
    votes: int
    is_accepted: bool
    body_html: str
    body_text: str
    author: str
    created_date: str
    last_edited: Optional[str] = None


@dataclass
class StackOverflowQuestion:
    """Parsed Stack Overflow question with answers"""

    question_id: str
    title: str
    url: str
    votes: int
    views: int
    tags: List[str]
    body_html: str
    body_text: str
    answers: List[StackOverflowAnswer] = field(default_factory=list)
    accepted_answer_id: Optional[str] = None


@dataclass
class ParseBotStats:
    """Usage statistics for cost tracking"""

    total_requests: int = 0
    successful_requests: int = 0
    failed_requests: int = 0
    cache_hits: int = 0
    total_cost_usd: float = 0.0

    def record_request(self, success: bool, cached: bool = False):
        """Record a request"""
        self.total_requests += 1
        if cached:
            self.cache_hits += 1
        elif success:
            self.successful_requests += 1
            # Hobby tier: $30/1000 calls = $0.03 per call
            # Developer tier: $150/5000 calls = $0.03 per call
            self.total_cost_usd += 0.03  # $0.03 per request (average)
        else:
            self.failed_requests += 1


class ParseBotClient:
    """
    Client for Parse.bot AI-powered web scraping API.

    Parse.bot creates custom scrapers on-demand using AI to reverse-engineer websites.
    Provides fast, browserless scraping of Stack Overflow pages.

    Pricing: ~$0.03 per API call (Hobby/Developer tier)
    Speed: 10-50x faster than Playwright browser automation
    """

    def __init__(
        self, api_key: str, cache_dir: Optional[Path] = None, enable_cache: bool = True
    ):
        self.api_key = api_key
        self.cache_dir = cache_dir
        self.enable_cache = enable_cache

        if self.enable_cache and self.cache_dir:
            self.cache_dir.mkdir(parents=True, exist_ok=True)

        # HTTP client
        self.http_client: Optional[httpx.AsyncClient] = None

        # Statistics
        self.stats = ParseBotStats()

    async def _get_client(self) -> httpx.AsyncClient:
        """Lazy initialize HTTP client"""
        if self.http_client is None:
            self.http_client = httpx.AsyncClient(
                timeout=DEFAULT_TIMEOUT,
                limits=httpx.Limits(max_keepalive_connections=5),
                headers={
                    "Authorization": f"Bearer {self.api_key}",
                    "Content-Type": "application/json",
                },
            )
        return self.http_client

    def _get_cache_path(self, url: str) -> Path:
        """Get cache file path for URL"""
        url_hash = hashlib.sha256(url.encode()).hexdigest()
        return self.cache_dir / f"parsebot_{url_hash}.json"

    async def _check_cache(self, url: str, max_age_hours: int = 168) -> Optional[Dict]:
        """Check if cached response exists and is fresh"""
        if not self.enable_cache or not self.cache_dir:
            return None

        cache_path = self._get_cache_path(url)

        if not cache_path.exists():
            return None

        # Check age
        file_age = time.time() - cache_path.stat().st_mtime
        max_age_seconds = max_age_hours * 3600

        if file_age > max_age_seconds:
            return None

        try:
            with open(cache_path, "r", encoding="utf-8") as f:
                cached_data = json.load(f)
                console.log(f"[dim]Cache hit for {url[:60]}...[/dim]")
                self.stats.record_request(success=True, cached=True)
                return cached_data
        except Exception as e:
            console.log(f"[yellow]Cache read error: {e}[/yellow]")
            return None

    async def _save_cache(self, url: str, data: Dict):
        """Save response to cache"""
        if not self.enable_cache or not self.cache_dir:
            return

        cache_path = self._get_cache_path(url)

        try:
            with open(cache_path, "w", encoding="utf-8") as f:
                json.dump(data, f, indent=2, ensure_ascii=False)
        except Exception as e:
            console.log(f"[yellow]Cache write error: {e}[/yellow]")

    async def search_google(
        self, query: str, num_results: int = 5, site: Optional[str] = None
    ) -> List[Dict[str, str]]:
        """
        Search Google for relevant pages.
        Returns list of {title, url, snippet}.
        """
        # Check cache first
        cache_key = f"google_{query}_{num_results}_{site}"
        cached = await self._check_cache(cache_key, max_age_hours=24)

        if cached:
            return cached.get("results", [])

        # Build search query
        search_query = query
        if site:
            search_query = f"{query} site:{site}"

        client = await self._get_client()

        try:
            # Note: This is a placeholder - Parse.bot may use a different endpoint
            # In production, check Parse.bot documentation for correct API
            response = await client.post(
                f"{PARSEBOT_API_BASE}/search",
                json={"query": search_query, "num_results": num_results},
            )

            if response.status_code == 200:
                data = response.json()
                results = data.get("results", [])

                await self._save_cache(cache_key, {"results": results})
                self.stats.record_request(success=True)

                return results
            else:
                console.log(
                    f"[yellow]Google search failed: {response.status_code}[/yellow]"
                )
                self.stats.record_request(success=False)
                return []

        except Exception as e:
            console.log(f"[red]Error searching Google: {e}[/red]")
            self.stats.record_request(success=False)
            return []

    async def scrape_stackoverflow_page(
        self, url: str
    ) -> Optional[StackOverflowQuestion]:
        """
        Scrape a Stack Overflow question page.
        Returns structured question with answers.
        """
        # Check cache
        cached = await self._check_cache(url, max_age_hours=168)  # 7 days

        if cached:
            return self._parse_stackoverflow_response(cached)

        client = await self._get_client()

        try:
            console.log(f"[cyan]Scraping {url[:60]}... via Parse.bot[/cyan]")

            # Parse.bot scraping request
            response = await client.post(
                f"{PARSEBOT_API_BASE}/scrape",
                json={
                    "url": url,
                    "extract": {
                        "question": {
                            "selector": ".question",
                            "fields": {
                                "title": {
                                    "selector": ".question-hyperlink",
                                    "type": "text",
                                },
                                "votes": {"selector": ".js-vote-count", "type": "text"},
                                "views": {"selector": ".js-view-count", "type": "text"},
                                "body": {"selector": ".s-prose", "type": "html"},
                                "tags": {
                                    "selector": ".post-tag",
                                    "type": "text",
                                    "multiple": True,
                                },
                            },
                        },
                        "answers": {
                            "selector": ".answer",
                            "multiple": True,
                            "fields": {
                                "answer_id": {
                                    "selector": "[data-answerid]",
                                    "attribute": "data-answerid",
                                },
                                "votes": {"selector": ".js-vote-count", "type": "text"},
                                "is_accepted": {
                                    "selector": ".accepted-answer-indicator",
                                    "exists": True,
                                },
                                "body": {"selector": ".s-prose", "type": "html"},
                                "author": {
                                    "selector": ".user-details a",
                                    "type": "text",
                                },
                                "date": {
                                    "selector": ".user-action-time",
                                    "type": "text",
                                },
                            },
                        },
                    },
                },
            )

            if response.status_code == 200:
                data = response.json()

                # Save to cache
                await self._save_cache(url, data)
                self.stats.record_request(success=True)

                return self._parse_stackoverflow_response(data)
            else:
                console.log(
                    f"[yellow]Parse.bot scraping failed: {response.status_code}[/yellow]"
                )
                self.stats.record_request(success=False)
                return None

        except Exception as e:
            console.log(f"[red]Error scraping Stack Overflow: {e}[/red]")
            self.stats.record_request(success=False)
            return None

    def _parse_stackoverflow_response(
        self, data: Dict
    ) -> Optional[StackOverflowQuestion]:
        """Parse Parse.bot response into StackOverflowQuestion"""
        try:
            question_data = data.get("question", {})
            answers_data = data.get("answers", [])

            # Extract question ID from URL or data
            question_id = data.get("question_id", "unknown")

            # Parse question
            question = StackOverflowQuestion(
                question_id=question_id,
                title=question_data.get("title", "Unknown"),
                url=data.get("url", ""),
                votes=self._parse_int(question_data.get("votes", "0")),
                views=self._parse_int(question_data.get("views", "0")),
                tags=question_data.get("tags", []),
                body_html=question_data.get("body", ""),
                body_text=self._html_to_text(question_data.get("body", "")),
            )

            # Parse answers
            for answer_data in answers_data:
                answer = StackOverflowAnswer(
                    answer_id=answer_data.get("answer_id", "unknown"),
                    votes=self._parse_int(answer_data.get("votes", "0")),
                    is_accepted=answer_data.get("is_accepted", False),
                    body_html=answer_data.get("body", ""),
                    body_text=self._html_to_text(answer_data.get("body", "")),
                    author=answer_data.get("author", "Anonymous"),
                    created_date=answer_data.get("date", ""),
                    last_edited=answer_data.get("edited_date"),
                )
                question.answers.append(answer)

                if answer.is_accepted:
                    question.accepted_answer_id = answer.answer_id

            return question

        except Exception as e:
            console.log(f"[red]Error parsing Stack Overflow response: {e}[/red]")
            return None

    def _parse_int(self, value: str) -> int:
        """Parse integer from string (handles '1.2k' format)"""
        if not value:
            return 0

        try:
            # Remove commas
            value = value.replace(",", "")

            # Handle k/m suffixes
            if "k" in value.lower():
                return int(float(value.lower().replace("k", "")) * 1000)
            elif "m" in value.lower():
                return int(float(value.lower().replace("m", "")) * 1000000)
            else:
                return int(value)
        except:
            return 0

    def _html_to_text(self, html: str) -> str:
        """Convert HTML to plain text (basic implementation)"""
        if not html:
            return ""

        # Remove script/style tags
        import re

        html = re.sub(r"<script[^>]*>.*?</script>", "", html, flags=re.DOTALL)
        html = re.sub(r"<style[^>]*>.*?</style>", "", html, flags=re.DOTALL)

        # Remove HTML tags
        html = re.sub(r"<[^>]+>", "", html)

        # Decode HTML entities
        html = html.replace("&lt;", "<").replace("&gt;", ">").replace("&amp;", "&")
        html = html.replace("&quot;", '"').replace("&#39;", "'")

        # Clean whitespace
        html = re.sub(r"\s+", " ", html).strip()

        return html

    async def search_stackoverflow(
        self, query: str, max_results: int = 3
    ) -> List[StackOverflowQuestion]:
        """
        Search Stack Overflow and scrape top results.
        Returns list of questions with answers.
        """
        # Search Google for SO questions
        search_results = await self.search_google(
            query=query, num_results=max_results, site="stackoverflow.com"
        )

        if not search_results:
            return []

        # Scrape each result
        questions = []
        for result in search_results:
            url = result.get("url", "")
            if "stackoverflow.com/questions/" in url:
                question = await self.scrape_stackoverflow_page(url)
                if question:
                    questions.append(question)

                # Rate limiting
                await asyncio.sleep(0.5)

        return questions

    def get_stats(self) -> Dict[str, Any]:
        """Get usage statistics"""
        return {
            "total_requests": self.stats.total_requests,
            "successful_requests": self.stats.successful_requests,
            "failed_requests": self.stats.failed_requests,
            "cache_hits": self.stats.cache_hits,
            "cache_hit_rate": (
                self.stats.cache_hits / self.stats.total_requests
                if self.stats.total_requests > 0
                else 0
            ),
            "total_cost_usd": round(self.stats.total_cost_usd, 4),
            "avg_cost_per_request": (
                self.stats.total_cost_usd / self.stats.successful_requests
                if self.stats.successful_requests > 0
                else 0
            ),
        }

    async def close(self):
        """Close HTTP client"""
        if self.http_client:
            await self.http_client.aclose()
            self.http_client = None
