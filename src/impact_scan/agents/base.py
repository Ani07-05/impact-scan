"""
Base Agent Architecture for Multi-Agent Security Platform
Enhanced with mandatory web search citations for all security findings.
"""

import asyncio
import logging
import shutil
import sys
import time
import uuid
from abc import ABC, abstractmethod
from dataclasses import dataclass, field
from datetime import datetime
from enum import Enum
from pathlib import Path
from typing import Any, Callable, Dict, List, Optional, Union

from ..utils.schema import Finding, ScanConfig

logger = logging.getLogger(__name__)


class AgentStatus(Enum):
    """Agent execution status"""

    IDLE = "idle"
    RUNNING = "running"
    COMPLETED = "completed"
    FAILED = "failed"
    PAUSED = "paused"


@dataclass
class AgentResult:
    """Result from agent execution with mandatory web search citations"""

    agent_id: str = "unknown"
    agent_name: str = "unknown"
    status: AgentStatus = AgentStatus.IDLE
    data: Dict[str, Any] = field(default_factory=dict)
    findings: List[Finding] = field(default_factory=list)
    citations_count: int = 0
    web_search_performed: bool = False
    execution_time: float = 0.0
    error_message: Optional[str] = None
    timestamp: datetime = field(default_factory=datetime.now)

    @property
    def success(self) -> bool:
        return self.status == AgentStatus.COMPLETED

    @property
    def failed(self) -> bool:
        return self.status == AgentStatus.FAILED

    @property
    def has_mandatory_citations(self) -> bool:
        """Check if all findings have required web search citations"""
        if not self.findings:
            return True  # No findings, no citations required

        findings_with_citations = sum(
            1 for finding in self.findings if finding.citations or finding.web_fix
        )

        return findings_with_citations == len(self.findings)


class Agent(ABC):
    """
    Base class for all security agents in the multi-agent platform.

    Each agent is a specialized AI-powered tool that performs specific
    security testing tasks (reconnaissance, vulnerability detection,
    exploitation, compliance checking, etc.)
    """

    def __init__(
        self,
        name: str,
        config: ScanConfig,
        tools: Optional[List[str]] = None,
        dependencies: Optional[List[str]] = None,
        max_concurrent_tasks: int = 5,
    ):
        self.agent_id = str(uuid.uuid4())[:8]
        self.name = name
        self.config = config
        self.tools = tools or []
        self.dependencies = dependencies or []
        self.max_concurrent_tasks = max_concurrent_tasks

        self.status = AgentStatus.IDLE
        self.results: List[AgentResult] = []
        self.current_task = None
        self.start_time = None
        self.callbacks: List[Callable] = []

    def add_callback(self, callback: Callable[[AgentResult], None]):
        """Add callback to be called when agent completes"""
        self.callbacks.append(callback)

    def _notify_callbacks(self, result: AgentResult):
        """Notify all registered callbacks"""
        for callback in self.callbacks:
            try:
                callback(result)
            except Exception as e:
                logger.error(f"Callback error: {e}")

    async def execute(
        self, target: Union[str, Path], context: Dict[str, Any] = None
    ) -> AgentResult:
        """
        Execute the agent's main functionality.

        Args:
            target: The target to analyze (path, URL, etc.)
            context: Additional context from other agents

        Returns:
            AgentResult with findings and execution data
        """
        self.status = AgentStatus.RUNNING
        self.start_time = time.time()
        context = context or {}

        result = AgentResult(
            agent_id=self.agent_id, agent_name=self.name, status=AgentStatus.RUNNING
        )

        try:
            # Validate dependencies
            await self._check_dependencies()

            # Execute agent-specific logic
            await self._execute_internal(target, context, result)

            # Mandatory web search for citations if findings exist
            if result.findings and self.config.enable_web_search:
                await self._enhance_with_web_search(result)
                result.web_search_performed = True

            # Validate mandatory citations
            if result.findings and not result.has_mandatory_citations:
                logging.warning(
                    f"[{self.name}] Some findings lack web search citations. "
                    f"Citations found: {result.citations_count}/{len(result.findings)}"
                )

            result.status = AgentStatus.COMPLETED
            result.execution_time = time.time() - self.start_time

        except Exception as e:
            result.status = AgentStatus.FAILED
            result.error_message = str(e)
            result.execution_time = time.time() - self.start_time

        finally:
            self.status = result.status
            self.results.append(result)
            self._notify_callbacks(result)

        return result

    @abstractmethod
    async def _execute_internal(
        self, target: Union[str, Path], context: Dict[str, Any], result: AgentResult
    ) -> None:
        """
        Internal execution logic specific to each agent.
        Must be implemented by subclasses.
        """
        pass

    async def _check_dependencies(self):
        """Check if required tools/dependencies are available"""
        logger.info(f"Checking dependencies for agent, tools: {self.tools}")
        for tool in self.tools:
            available = await self._is_tool_available(tool)
            logger.info(f"Tool '{tool}' available: {available}")
            if not available:
                raise RuntimeError(f"Required tool '{tool}' not available")

    async def _is_tool_available(self, tool: str) -> bool:
        """Check if a specific tool is available"""
        import sys as _sys
        _sys.stderr.write(f"[DEBUG] _is_tool_available called for tool: {tool}\n")
        _sys.stderr.flush()

        # Special case for ripgrep - check for bundled version
        if tool == "ripgrep" or tool == "rg":
            frozen = getattr(sys, 'frozen', False)
            has_meipass = hasattr(sys, '_MEIPASS')
            _sys.stderr.write(f"[DEBUG] sys.frozen={frozen}, has _MEIPASS={has_meipass}\n")
            _sys.stderr.flush()

            # Check for bundled ripgrep directly (avoid import issues)
            if frozen and has_meipass:
                # Running as PyInstaller bundle
                bundle_dir = Path(sys._MEIPASS)
                rg_name = 'rg.exe' if sys.platform == 'win32' else 'rg'
                bundled_rg = bundle_dir / 'impact_scan_tools' / rg_name

                logger.info(f"Agent checking for bundled ripgrep at: {bundled_rg}")
                exists = bundled_rg.exists()
                logger.info(f"Bundled ripgrep exists: {exists}")

                if exists:
                    logger.info(f"Agent found bundled ripgrep: {bundled_rg}")
                    return True
                else:
                    logger.warning(f"Bundled ripgrep not found at expected location: {bundled_rg}")
                    # Try alternative location
                    bundled_rg_alt = bundle_dir / rg_name
                    if bundled_rg_alt.exists():
                        logger.info(f"Agent found bundled ripgrep at alt location: {bundled_rg_alt}")
                        return True
            else:
                logger.info("Not running as frozen executable, skipping bundled ripgrep check")

            # Fall back to system ripgrep
            logger.info("Checking system ripgrep with shutil.which")
            has_rg = shutil.which("rg") is not None
            logger.info(f"shutil.which('rg') returned: {has_rg}")
            if not has_rg:
                logger.error("Ripgrep not found - neither bundled nor in system PATH")
            return has_rg

        return shutil.which(tool) is not None

    async def _enhance_with_web_search(self, result: AgentResult) -> None:
        """
        Enhance findings with mandatory web search citations.
        Web search module is currently deprecated/experimental.
        """
        logger.debug(f"[{self.name}] Web search enhancement skipped (module not available)")
        return

    def get_capabilities(self) -> Dict[str, Any]:
        """Return agent capabilities and metadata"""
        return {
            "agent_id": self.agent_id,
            "name": self.name,
            "tools": self.tools,
            "dependencies": self.dependencies,
            "max_concurrent_tasks": self.max_concurrent_tasks,
            "status": self.status.value,
            "description": self.__doc__ or "No description available",
        }

    def pause(self):
        """Pause agent execution"""
        self.status = AgentStatus.PAUSED

    def resume(self):
        """Resume agent execution"""
        if self.status == AgentStatus.PAUSED:
            self.status = AgentStatus.RUNNING

    def reset(self):
        """Reset agent to initial state"""
        self.status = AgentStatus.IDLE
        self.results.clear()
        self.current_task = None
        self.start_time = None


class MultiModelAgent(Agent):
    """
    Enhanced agent that can use multiple AI models for different tasks.
    Inspired by CAI's multi-model approach.
    """

    def __init__(
        self,
        name: str,
        config: ScanConfig,
        primary_model: str = "auto",
        fallback_models: Optional[List[str]] = None,
        **kwargs,
    ):
        super().__init__(name, config, **kwargs)
        self.primary_model = primary_model
        self.fallback_models = fallback_models or ["openai", "anthropic", "gemini"]
        self.model_performance = {}

    async def _get_ai_analysis(
        self, prompt: str, context: Dict[str, Any] = None, preferred_model: str = None
    ) -> str:
        """
        Get AI analysis using the best available model.
        Includes automatic fallback and performance tracking.
        """
        models_to_try = [preferred_model or self.primary_model] + self.fallback_models
        models_to_try = [m for m in models_to_try if m and m != "auto"]

        if self.primary_model == "auto":
            models_to_try = self._get_best_model_order()

        for model in models_to_try:
            try:
                start_time = time.time()
                result = await self._call_ai_model(model, prompt, context)

                # Track performance
                execution_time = time.time() - start_time
                self.model_performance[model] = self.model_performance.get(model, [])
                self.model_performance[model].append(execution_time)

                return result

            except Exception as e:
                logger.warning(f"Model {model} failed: {e}")
                continue

        raise RuntimeError("All AI models failed")

    def _get_best_model_order(self) -> List[str]:
        """Get models ordered by performance"""
        if not self.model_performance:
            return ["anthropic", "openai", "gemini"]  # Default order

        # Sort by average performance (lower is better)
        sorted_models = sorted(
            self.model_performance.items(), key=lambda x: sum(x[1]) / len(x[1])
        )

        return [model for model, _ in sorted_models] + ["anthropic", "openai", "gemini"]

    async def _call_ai_model(
        self, model: str, prompt: str, context: Dict[str, Any] = None
    ) -> str:
        """
        Call specific AI model. To be implemented by subclasses or
        integrated with existing AI calling logic.
        """
        # This will integrate with the existing fix_ai.py logic
        from ..core.fix_ai import get_ai_response

        # Convert model name to provider format
        model_map = {"anthropic": "anthropic", "openai": "openai", "gemini": "gemini"}

        provider = model_map.get(model)
        if not provider:
            raise ValueError(f"Unknown model: {model}")

        # Use existing AI response logic
        response = await asyncio.to_thread(
            get_ai_response, prompt, self.config, provider
        )

        return response or ""
