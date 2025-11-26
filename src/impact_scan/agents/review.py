"""
AIReviewAgent - AI-Powered Deep Code Review

Uses Claude/GPT-4 to detect logical flaws, business logic errors,
race conditions, and complex vulnerabilities that pattern matching misses.
"""

import ast
import logging
import os
from pathlib import Path
from typing import Any, Dict, List, Union

from ..utils.schema import Finding, Severity, VulnSource
from .base import AgentResult, MultiModelAgent

logger = logging.getLogger(__name__)


class AIReviewAgent(MultiModelAgent):
    """
    AI-powered code review for logical flaws and business logic

    Detects:
    - Race conditions (TOCTOU)
    - Business logic bypass
    - Integer overflow
    - State machine errors
    - Authorization logic flaws
    - Complex dataflow issues

    Uses context-aware analysis with full file understanding
    """

    def __init__(self, config, **kwargs):
        super().__init__(
            name="review",
            config=config,
            primary_model="groq",  # Groq: Fast, free, explicit reasoning
            **kwargs,
        )
        self.context_window = kwargs.get("context_window", 5)  # Related files to read
        self.focus_areas = kwargs.get(
            "focus_areas",
            ["race_conditions", "business_logic", "authorization", "state_management"],
        )
        self.groq_model = kwargs.get(
            "groq_model", "openai/gpt-oss-20b"
        )  # Best for reasoning

    async def _execute_internal(
        self, target: Union[str, Path], context: Dict[str, Any], result: AgentResult
    ) -> None:
        """Execute AI-powered code review"""

        print("[REVIEW] Starting AI-powered code review...")

        target_path = Path(target).resolve()
        if not target_path.exists():
            raise FileNotFoundError(f"Target not found: {target_path}")

        # Phase 1: Gather context (related files, imports, dependencies)
        print("[REVIEW] Gathering code context...")
        code_context = await self._gather_context(target_path)

        # Phase 2: Identify high-risk areas
        print("[REVIEW] Identifying high-risk code patterns...")
        risk_areas = self._identify_risk_areas(target_path, code_context)

        # Phase 3: AI deep review of risk areas
        print(f"[REVIEW] Performing AI review on {len(risk_areas)} risk areas...")
        findings = await self._ai_deep_review(risk_areas, code_context)

        # Add findings to result
        for finding in findings:
            result.findings.append(finding)

        # Compile statistics
        result.data["total_logical_flaws"] = len(findings)
        result.data["risk_areas_analyzed"] = len(risk_areas)
        result.data["ai_provider"] = self.primary_model
        result.data["by_severity"] = {
            "HIGH": len([f for f in findings if f.severity == Severity.HIGH]),
            "MEDIUM": len([f for f in findings if f.severity == Severity.MEDIUM]),
            "LOW": len([f for f in findings if f.severity == Severity.LOW]),
        }
        result.data["by_category"] = self._categorize_by_flaw_type(findings)

        print(f"[REVIEW] Found {len(findings)} logical flaws")

    async def _gather_context(self, target_path: Path) -> Dict[str, Any]:
        """Gather comprehensive context for AI review"""
        context = {
            "target_files": [],
            "imports": set(),
            "related_files": [],
            "frameworks": set(),
            "patterns": [],
        }

        # Collect target files
        if target_path.is_file():
            files = [target_path]
        else:
            files = list(target_path.rglob("*.py"))[:20]  # Limit for performance

        for file_path in files:
            try:
                content = file_path.read_text(encoding="utf-8")

                # Parse imports
                try:
                    tree = ast.parse(content)
                    for node in ast.walk(tree):
                        if isinstance(node, ast.Import):
                            for alias in node.names:
                                context["imports"].add(alias.name)
                        elif isinstance(node, ast.ImportFrom):
                            if node.module:
                                context["imports"].add(node.module)
                except:
                    pass

                # Detect frameworks
                if "flask" in content.lower():
                    context["frameworks"].add("Flask")
                if "django" in content.lower():
                    context["frameworks"].add("Django")
                if "fastapi" in content.lower():
                    context["frameworks"].add("FastAPI")

                context["target_files"].append(
                    {
                        "path": file_path,
                        "content": content,
                        "loc": len(content.split("\n")),
                    }
                )

            except Exception as e:
                logger.debug(f"Error reading {file_path}: {e}")

        return context

    def _identify_risk_areas(
        self, target_path: Path, context: Dict[str, Any]
    ) -> List[Dict[str, Any]]:
        """Identify high-risk code areas for AI review"""
        risk_areas = []

        for file_info in context["target_files"]:
            content = file_info["content"]
            file_path = file_info["path"]

            # Pattern 1: Race condition indicators
            if (
                "threading" in content
                or "multiprocessing" in content
                or "async" in content
            ):
                if "lock" not in content.lower() and "semaphore" not in content.lower():
                    risk_areas.append(
                        {
                            "type": "race_condition",
                            "file": file_path,
                            "reason": "Concurrent code without explicit synchronization",
                            "content": content,
                            "priority": "HIGH",
                        }
                    )

            # Pattern 2: Financial/payment logic
            if any(
                keyword in content.lower()
                for keyword in [
                    "price",
                    "payment",
                    "balance",
                    "withdraw",
                    "deposit",
                    "charge",
                ]
            ):
                risk_areas.append(
                    {
                        "type": "business_logic",
                        "file": file_path,
                        "reason": "Financial logic detected - potential for logic bypass",
                        "content": content,
                        "priority": "HIGH",
                    }
                )

            # Pattern 3: Authorization checks
            if (
                "current_user" in content
                or "is_authenticated" in content
                or "has_permission" in content
            ):
                if "bypass" in content.lower() or "skip" in content.lower():
                    risk_areas.append(
                        {
                            "type": "authorization",
                            "file": file_path,
                            "reason": "Authorization code with potential bypass",
                            "content": content,
                            "priority": "HIGH",
                        }
                    )

            # Pattern 4: State transitions
            if content.count("state") > 3 or "status" in content:
                risk_areas.append(
                    {
                        "type": "state_management",
                        "file": file_path,
                        "reason": "State machine logic - check for invalid transitions",
                        "content": content,
                        "priority": "MEDIUM",
                    }
                )

            # Pattern 5: Time-based logic (TOCTOU)
            if ("check" in content and "use" in content) or "time.sleep" in content:
                risk_areas.append(
                    {
                        "type": "toctou",
                        "file": file_path,
                        "reason": "Time-of-check/time-of-use pattern detected",
                        "content": content,
                        "priority": "HIGH",
                    }
                )

        # Sort by priority
        risk_areas.sort(key=lambda x: 0 if x["priority"] == "HIGH" else 1)

        return risk_areas[:10]  # Limit to top 10 for cost/performance

    async def _ai_deep_review(
        self, risk_areas: List[Dict[str, Any]], context: Dict[str, Any]
    ) -> List[Finding]:
        """Perform AI-powered deep review"""
        findings = []

        for area in risk_areas:
            try:
                # Build AI prompt with context
                prompt = self._build_review_prompt(area, context)

                # Call AI for analysis
                response = await self._call_ai_model(prompt)

                # Parse response into findings
                area_findings = self._parse_ai_response(response, area)
                findings.extend(area_findings)

            except Exception as e:
                logger.error(f"AI review failed for {area['file']}: {e}")
                continue

        return findings

    def _build_review_prompt(
        self, risk_area: Dict[str, Any], context: Dict[str, Any]
    ) -> str:
        """Build detailed prompt for AI review"""

        flaw_type = risk_area["type"]
        frameworks = (
            ", ".join(context["frameworks"]) if context["frameworks"] else "None"
        )

        prompt = f"""You are an expert security code reviewer analyzing code for logical flaws and business logic vulnerabilities.

**Context:**
- File: {risk_area["file"].name}
- Frameworks: {frameworks}
- Risk Type: {flaw_type}
- Reason: {risk_area["reason"]}

**Code to Review:**
```python
{risk_area["content"][:2000]}  # Truncated for token limits
```

**Your Task:**
Analyze this code for **{flaw_type}** vulnerabilities. Focus on:

1. **Race Conditions**: Check-then-act patterns, unprotected shared state, TOCTOU
2. **Business Logic**: Logic bypass, insufficient validation, edge cases
3. **Authorization**: Missing checks, inconsistent enforcement, privilege escalation
4. **State Management**: Invalid transitions, concurrent modification

**Output Format (JSON):**
{{
    "has_issue": true/false,
    "issue_type": "race_condition|business_logic|authorization|state_management",
    "severity": "HIGH|MEDIUM|LOW",
    "title": "Brief description",
    "description": "Detailed explanation with reasoning",
    "line_number": 0,
    "proof_of_concept": "How to exploit",
    "recommendation": "How to fix",
    "reasoning_trace": ["Step 1", "Step 2", ...]
}}

Be precise. Only report REAL vulnerabilities with clear exploitation paths.
"""
        return prompt

    async def _call_ai_model(self, prompt: str) -> str:
        """Call AI model for analysis (Groq primary, Anthropic fallback)"""
        try:
            # Primary: Groq (fast, free, explicit reasoning)
            from groq import AsyncGroq

            # Get API key from config dict or environment
            groq_key = os.environ.get("GROQ_API_KEY")
            if hasattr(self.config, "groq_api_key"):
                groq_key = self.config.groq_api_key or groq_key

            client = AsyncGroq(api_key=groq_key, timeout=120.0)

            response = await client.chat.completions.create(
                model=self.groq_model,
                messages=[{"role": "user", "content": prompt}],
                max_tokens=2000,
                temperature=0,  # Deterministic for code review
                reasoning_effort="high",  # Explicit reasoning chains
            )

            return response.choices[0].message.content

        except Exception as groq_error:
            logger.warning(
                f"Groq call failed ({groq_error}), falling back to Anthropic"
            )

            # Fallback: Anthropic Claude
            try:
                from anthropic import AsyncAnthropic

                # Get API key from environment or config
                anthropic_key = os.environ.get("ANTHROPIC_API_KEY")
                if hasattr(self.config, "anthropic_api_key"):
                    anthropic_key = self.config.anthropic_api_key or anthropic_key

                client = AsyncAnthropic(api_key=anthropic_key)

                response = await client.messages.create(
                    model="claude-3-5-sonnet-20241022",
                    max_tokens=2000,
                    temperature=0,
                    messages=[{"role": "user", "content": prompt}],
                )

                return response.content[0].text

            except Exception as anthropic_error:
                logger.error(
                    f"Both AI providers failed: Groq={groq_error}, Anthropic={anthropic_error}"
                )
                return '{"has_issue": false}'

    def _parse_ai_response(
        self, response: str, risk_area: Dict[str, Any]
    ) -> List[Finding]:
        """Parse AI response into Finding objects"""
        findings = []

        try:
            import json

            # Extract JSON from response
            if "```json" in response:
                json_str = response.split("```json")[1].split("```")[0]
            elif "```" in response:
                json_str = response.split("```")[1].split("```")[0]
            else:
                json_str = response

            data = json.loads(json_str.strip())

            if not data.get("has_issue", False):
                return findings

            # Map severity
            severity_map = {
                "HIGH": Severity.HIGH,
                "MEDIUM": Severity.MEDIUM,
                "LOW": Severity.LOW,
            }

            finding = Finding(
                vuln_id=f"ai-review-{data['issue_type']}-{risk_area['file'].name}",
                rule_id=f"ai-{data['issue_type']}",
                title=data.get("title", "Logical Flaw Detected"),
                description=f"{data.get('description', 'No description')}\n\n"
                f"**Proof of Concept:**\n{data.get('proof_of_concept', 'N/A')}\n\n"
                f"**Recommendation:**\n{data.get('recommendation', 'N/A')}\n\n"
                f"**AI Reasoning:**\n"
                + "\n".join(
                    f"{i + 1}. {step}"
                    for i, step in enumerate(data.get("reasoning_trace", []))
                ),
                severity=severity_map.get(
                    data.get("severity", "MEDIUM"), Severity.MEDIUM
                ),
                source=VulnSource.AI_DETECTION,
                file_path=risk_area["file"],
                line_number=data.get("line_number", 1),
                code_snippet=risk_area["content"][:500],  # First 500 chars for context
                metadata={
                    "flaw_type": data.get("issue_type"),
                    "ai_model": "claude-3-5-sonnet",
                    "reasoning_trace": data.get("reasoning_trace", []),
                    "confidence": "HIGH",
                },
            )

            findings.append(finding)

        except Exception as e:
            logger.error(f"Failed to parse AI response: {e}")
            logger.debug(f"Response was: {response[:500]}")

        return findings

    def _categorize_by_flaw_type(self, findings: List[Finding]) -> Dict[str, int]:
        """Categorize findings by logical flaw type"""
        categories = {}
        for finding in findings:
            flaw_type = finding.metadata.get("flaw_type", "other")
            categories[flaw_type] = categories.get(flaw_type, 0) + 1
        return categories
