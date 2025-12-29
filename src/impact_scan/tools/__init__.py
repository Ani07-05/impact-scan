"""
Tool infrastructure for Impact-Scan.

Provides observable, callable tools that agents can invoke with standardized
interfaces and logging.
"""

from abc import ABC, abstractmethod
from typing import Any, Dict, Optional
from dataclasses import dataclass
import logging
import time


@dataclass
class ToolResult:
    """Standardized tool execution result"""
    success: bool
    data: Any
    metadata: Dict[str, Any]
    error: Optional[str] = None


class BaseTool(ABC):
    """
    Base class for all tools in Impact-Scan.

    Tools provide observable, callable interfaces for scanning operations.
    Each tool logs its execution with [TOOL CALL] prefix for transparency.
    """

    def __init__(self, name: str):
        """
        Initialize tool with name.

        Args:
            name: Tool identifier (e.g., "ripgrep", "ai_validator")
        """
        self.name = name
        self.logger = logging.getLogger(f"impact_scan.tools.{name}")

    def execute(self, **kwargs) -> ToolResult:
        """
        Execute tool with observable logging.

        This method wraps _execute_internal() to provide:
        - Standardized logging with [TOOL CALL] prefix
        - Error handling and graceful degradation
        - Execution metadata (duration, etc.)

        Args:
            **kwargs: Tool-specific parameters

        Returns:
            ToolResult with success status, data, and metadata
        """
        self.logger.info(f"[TOOL CALL] {self.name} - Starting execution")
        start_time = time.time()

        try:
            result = self._execute_internal(**kwargs)
            duration = time.time() - start_time

            self.logger.info(f"[TOOL CALL] {self.name} - Completed successfully ({duration:.2f}s)")

            metadata = self._get_metadata()
            metadata['duration_seconds'] = duration

            return ToolResult(
                success=True,
                data=result,
                metadata=metadata,
                error=None
            )
        except Exception as e:
            duration = time.time() - start_time
            self.logger.error(f"[TOOL CALL] {self.name} - Failed: {str(e)} ({duration:.2f}s)")

            return ToolResult(
                success=False,
                data=None,
                metadata={'duration_seconds': duration, 'tool': self.name},
                error=str(e)
            )

    @abstractmethod
    def _execute_internal(self, **kwargs) -> Any:
        """
        Tool-specific implementation.

        Subclasses must implement this method to provide tool functionality.

        Args:
            **kwargs: Tool-specific parameters

        Returns:
            Tool-specific result data

        Raises:
            Exception: If tool execution fails
        """
        pass

    def _get_metadata(self) -> Dict[str, Any]:
        """
        Get tool execution metadata.

        Override this method to provide additional metadata like version,
        configuration, etc.

        Returns:
            Dict with metadata (at minimum: tool name)
        """
        return {"tool": self.name}


__all__ = ['BaseTool', 'ToolResult']
