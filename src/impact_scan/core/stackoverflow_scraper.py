"""
Stack Overflow web scraper for extracting security vulnerability fixes.

This module uses Playwright to scrape Stack Overflow answers via Google search,
extracts code snippets and explanations, and prepares content for Gemini AI analysis.
"""
import asyncio
import hashlib
import re
import time
from dataclasses import dataclass
from typing import List, Optional, Dict, Any
from pathlib import Path

from bs4 import BeautifulSoup
from playwright.async_api import async_playwright, Browser, Page, TimeoutError as PlaywrightTimeoutError
from rich.console import Console

from ..utils.schema import Finding

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
            "score": self.score
        }


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
        soup = BeautifulSoup(html, 'html.parser')
        answers = []

        # Extract question title
        title_elem = soup.find('h1', {'itemprop': 'name'}) or soup.find('a', {'class': 'question-hyperlink'})
        question_title = title_elem.get_text().strip() if title_elem else "Unknown Question"

        # Extract question ID from URL
        question_id_match = re.search(r'/questions/(\d+)/', url)
        question_id = question_id_match.group(1) if question_id_match else "unknown"

        # Find all answer divs
        answer_divs = soup.find_all('div', {'class': 'answer'})

        for answer_div in answer_divs:
            try:
                answer_data = StackOverflowContentExtractor._parse_answer(
                    answer_div, question_title, question_id, url
                )
                if answer_data and answer_data.code_snippets:  # Only include answers with code
                    answers.append(answer_data)
            except Exception as e:
                console.log(f"[yellow]Warning: Failed to parse answer: {e}[/yellow]")
                continue

        # Sort by score (highest first)
        answers.sort(key=lambda x: x.score, reverse=True)

        return answers

    @staticmethod
    def _parse_answer(answer_div, question_title: str, question_id: str, base_url: str) -> Optional[StackOverflowAnswer]:
        """Parse a single answer div into StackOverflowAnswer object."""
        try:
            # Extract answer ID
            answer_id = answer_div.get('data-answerid', 'unknown')

            # Extract votes
            vote_elem = answer_div.find('div', {'class': 'js-vote-count'}) or answer_div.find('span', {'itemprop': 'upvoteCount'})
            votes = 0
            if vote_elem:
                vote_text = vote_elem.get_text().strip()
                try:
                    votes = int(vote_text)
                except (ValueError, TypeError):
                    votes = 0

            # Check if accepted
            accepted = answer_div.find('div', {'class': 'accepted-answer'}) is not None or \
                      answer_div.find('svg', {'class': 'fc-green-500'}) is not None

            # Extract author info
            author_elem = answer_div.find('div', {'class': 'user-details'}) or answer_div.find('a', {'class': 'user-link'})
            author = "Unknown"
            author_reputation = 0

            if author_elem:
                author_link = author_elem.find('a')
                if author_link:
                    author = author_link.get_text().strip()

                # Extract reputation
                rep_elem = author_elem.find('span', {'class': 'reputation-score'})
                if rep_elem:
                    rep_text = rep_elem.get('title', rep_elem.get_text())
                    # Parse reputation (e.g., "12.3k" or "12,345")
                    rep_text = rep_text.replace(',', '').replace('k', '000').strip()
                    try:
                        author_reputation = int(float(rep_text))
                    except (ValueError, TypeError):
                        author_reputation = 0

            # Extract post date
            time_elem = answer_div.find('time', {'itemprop': 'dateCreated'}) or answer_div.find('span', {'class': 'relativetime'})
            post_date = time_elem.get('datetime', time_elem.get_text()) if time_elem else "Unknown"

            # Extract answer content
            answer_content = answer_div.find('div', {'class': 's-prose'}) or answer_div.find('div', {'class': 'answercell'})
            if not answer_content:
                return None

            # Extract code blocks with language detection
            code_snippets = StackOverflowContentExtractor._extract_code_blocks(answer_content)

            # Extract explanation text (remove code blocks)
            explanation_soup = BeautifulSoup(str(answer_content), 'html.parser')
            for code_elem in explanation_soup.find_all(['pre', 'code']):
                code_elem.decompose()
            explanation = explanation_soup.get_text(separator=' ', strip=True)

            # Limit explanation length
            if len(explanation) > 500:
                explanation = explanation[:500] + "..."

            # Extract comments (top 3 only)
            comments = []
            comment_div = answer_div.find('div', {'class': 'comments'}) or answer_div.find('ul', {'class': 'comments-list'})
            if comment_div:
                comment_elems = comment_div.find_all('li', {'class': 'comment'})[:3]
                for comment_elem in comment_elems:
                    comment_text_elem = comment_elem.find('span', {'class': 'comment-copy'})
                    if comment_text_elem:
                        comment_text = comment_text_elem.get_text().strip()
                        if len(comment_text) > 150:
                            comment_text = comment_text[:150] + "..."
                        comments.append(comment_text)

            # Calculate score: votes + (accepted bonus) + (reputation factor)
            score = float(votes) + (50.0 if accepted else 0.0) + (author_reputation / 1000.0)

            # Build answer URL
            answer_url = f"{base_url}#answer-{answer_id}" if '#' not in base_url else base_url

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
                score=score
            )

        except Exception as e:
            console.log(f"[red]Error parsing answer: {e}[/red]")
            return None

    @staticmethod
    def _extract_code_blocks(content_div) -> List[CodeBlock]:
        """Extract code blocks with language detection."""
        code_blocks = []

        # Find all pre > code elements
        pre_elements = content_div.find_all('pre')

        for pre in pre_elements:
            code_elem = pre.find('code')
            if not code_elem:
                continue

            # Extract code text
            code_text = code_elem.get_text().strip()
            if len(code_text) < 10:  # Skip very short snippets
                continue

            # Detect language from class attribute
            language = "text"
            class_attr = code_elem.get('class', [])
            if isinstance(class_attr, list):
                for cls in class_attr:
                    if cls.startswith('language-') or cls.startswith('lang-'):
                        language = cls.split('-', 1)[1]
                        break
                    elif cls in ['python', 'javascript', 'java', 'cpp', 'c', 'php', 'ruby', 'go', 'rust']:
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
        if 'def ' in code or 'import ' in code or 'elif ' in code or '__init__' in code:
            return 'python'

        # JavaScript indicators
        if 'function' in code or 'const ' in code or 'let ' in code or '=>' in code:
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


class StackOverflowScraper:
    """
    Web scraper for Stack Overflow using Playwright.

    Searches Google for Stack Overflow questions related to security vulnerabilities,
    scrapes answer pages, and extracts code fixes with metadata.
    """

    def __init__(self, scrape_delay: float = 4.0, max_answers: int = 3, include_comments: bool = True):
        """
        Initialize the Stack Overflow scraper.

        Args:
            scrape_delay: Delay in seconds between requests (default: 4.0)
            max_answers: Maximum number of answers to return (default: 3)
            include_comments: Whether to include comments (default: True)
        """
        self.scrape_delay = scrape_delay
        self.max_answers = max_answers
        self.include_comments = include_comments
        self.cache: Dict[str, List[StackOverflowAnswer]] = {}
        self.max_cache_size = 100
        self.last_request_time = 0
        self.user_agents = [
            'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/121.0.0.0 Safari/537.36',
            'Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/121.0.0.0 Safari/537.36',
            'Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/121.0.0.0 Safari/537.36',
        ]

    def _rate_limit(self):
        """Implement rate limiting between requests."""
        current_time = time.time()
        time_since_last = current_time - self.last_request_time

        if time_since_last < self.scrape_delay:
            sleep_time = self.scrape_delay - time_since_last
            console.log(f"[dim]Rate limiting: sleeping {sleep_time:.1f}s[/dim]")
            time.sleep(sleep_time)

        self.last_request_time = time.time()

    def _get_cache_key(self, finding: Finding) -> str:
        """Generate cache key for a finding."""
        key_components = [finding.vuln_id, finding.title, str(finding.file_path)]
        return hashlib.md5("|".join(key_components).encode(), usedforsecurity=False).hexdigest()

    def _get_cached_answers(self, finding: Finding) -> Optional[List[StackOverflowAnswer]]:
        """Get cached answers for a finding."""
        cache_key = self._get_cache_key(finding)
        return self.cache.get(cache_key)

    def _cache_answers(self, finding: Finding, answers: List[StackOverflowAnswer]):
        """Cache answers for a finding."""
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
            console.log(f"[green][CACHE] Using cached Stack Overflow answers for {finding.vuln_id}[/green]")
            return cached

        console.log(f"[cyan][SO_SCRAPER] Searching Stack Overflow for {finding.vuln_id}...[/cyan]")

        try:
            # Build search query
            query = self._build_search_query(finding)
            console.log(f"[dim]Search query: {query}[/dim]")

            # Search and scrape
            async with async_playwright() as p:
                browser = await p.chromium.launch(headless=True)
                try:
                    # Get Stack Overflow URLs from Google search
                    so_urls = await self._search_google_for_stackoverflow(browser, query)

                    if not so_urls:
                        console.log(f"[yellow]No Stack Overflow URLs found for {finding.vuln_id}[/yellow]")
                        return []

                    console.log(f"[green]Found {len(so_urls)} Stack Overflow URLs[/green]")

                    # Scrape each URL
                    all_answers = []
                    for url in so_urls[:5]:  # Limit to top 5 URLs
                        self._rate_limit()
                        answers = await self._scrape_stackoverflow_page(browser, url)
                        all_answers.extend(answers)

                    # Sort by score and limit
                    all_answers.sort(key=lambda x: x.score, reverse=True)
                    top_answers = all_answers[:self.max_answers]

                    # Cache results
                    if top_answers:
                        self._cache_answers(finding, top_answers)
                        console.log(f"[bold green][SO_SUCCESS] Found {len(top_answers)} Stack Overflow answers for {finding.vuln_id}[/bold green]")

                    return top_answers

                finally:
                    await browser.close()

        except Exception as e:
            console.log(f"[bold red][SO_ERROR] Scraping failed for {finding.vuln_id}: {e}[/bold red]")
            return []

    def _build_search_query(self, finding: Finding) -> str:
        """Build Google search query for Stack Overflow."""
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
            'c': 'c'
        }
        language = language_map.get(file_ext, file_ext)

        # Simplify vulnerability title for better search results
        # Check both title and description for better matching
        title_lower = finding.title.lower()
        desc_lower = finding.description.lower() if finding.description else ""
        combined = f"{title_lower} {desc_lower}"

        # Extract key vulnerability type - Framework-specific first
        if 'flask' in combined and 'debug' in combined:
            vuln_type = 'Flask production deployment disable debug'
        elif 'django' in combined and 'debug' in combined:
            vuln_type = 'Django production settings debug false'
        elif ('flask' in combined or language == 'python') and 'secret' in combined and 'key' in combined:
            vuln_type = 'Flask secret key environment variable'
        elif 'flask' in combined and 'hardcoded' in combined:
            vuln_type = 'Flask configuration environment variables'
        # Generic vulnerabilities
        elif 'sql injection' in combined or 'sqli' in combined:
            vuln_type = 'sql injection prevention'
        elif 'xss' in combined or 'cross-site scripting' in combined:
            vuln_type = 'xss prevention'
        elif 'hardcoded' in combined and ('secret' in combined or 'key' in combined):
            vuln_type = f'{language} secret key environment variable'
        elif 'hardcoded' in combined:
            vuln_type = 'hardcoded credentials fix'
        elif 'path traversal' in combined:
            vuln_type = 'path traversal prevention'
        elif 'yaml' in combined and 'load' in combined:
            vuln_type = 'safe yaml loading'
        elif 'md5' in combined or 'weak hash' in combined:
            vuln_type = 'secure password hashing'
        else:
            # Use first 3 words from title
            words = title_lower.split()[:3]
            vuln_type = ' '.join(words)

        # Build query
        query = f"site:stackoverflow.com {vuln_type} {language} secure"
        return query

    async def _search_google_for_stackoverflow(self, browser: Browser, query: str) -> List[str]:
        """Search Google and extract Stack Overflow URLs."""
        page = await browser.new_page(
            user_agent=self.user_agents[0],
            viewport={'width': 1920, 'height': 1080}
        )

        try:
            # Navigate to Google search
            search_url = f"https://www.google.com/search?q={query.replace(' ', '+')}"
            await page.goto(search_url, wait_until='domcontentloaded', timeout=30000)

            # Wait for results - try multiple selectors as Google changes layout
            try:
                await page.wait_for_selector('div#search', timeout=5000)
            except:
                try:
                    await page.wait_for_selector('div#rso', timeout=5000)
                except:
                    await page.wait_for_selector('body', timeout=5000)  # Fallback

            # Extract Stack Overflow URLs
            links = await page.query_selector_all('a[href*="stackoverflow.com/questions/"]')

            urls = []
            for link in links:
                href = await link.get_attribute('href')
                if href and '/questions/' in href:
                    # Clean URL (remove Google redirect)
                    if href.startswith('/url?q='):
                        href = href.split('/url?q=')[1].split('&')[0]

                    # Normalize URL
                    if 'stackoverflow.com/questions/' in href:
                        urls.append(href)

            # Remove duplicates while preserving order
            seen = set()
            unique_urls = []
            for url in urls:
                # Normalize to question URL (remove answer anchors for deduplication)
                base_url = url.split('#')[0]
                if base_url not in seen:
                    seen.add(base_url)
                    unique_urls.append(base_url)

            return unique_urls

        except Exception as e:
            console.log(f"[red]Google search failed: {e}[/red]")
            return []
        finally:
            await page.close()

    async def _scrape_stackoverflow_page(self, browser: Browser, url: str) -> List[StackOverflowAnswer]:
        """Scrape a Stack Overflow question page."""
        page = await browser.new_page(
            user_agent=self.user_agents[1],
            viewport={'width': 1920, 'height': 1080}
        )

        try:
            console.log(f"[dim]Scraping: {url}[/dim]")

            # Navigate to Stack Overflow page
            await page.goto(url, wait_until='networkidle', timeout=30000)

            # Wait for content
            await page.wait_for_selector('.answer', timeout=10000)

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


# Convenience function for synchronous usage
def scrape_stackoverflow_sync(finding: Finding, scrape_delay: float = 4.0, max_answers: int = 3) -> List[StackOverflowAnswer]:
    """Synchronous wrapper for Stack Overflow scraping."""
    scraper = StackOverflowScraper(scrape_delay=scrape_delay, max_answers=max_answers)
    return asyncio.run(scraper.search_and_scrape(finding))
