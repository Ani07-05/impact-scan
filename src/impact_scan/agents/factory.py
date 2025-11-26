"""
Agent Factory System - Inspired by CAI's Dynamic Agent Creation

Provides dynamic agent discovery, creation, and management for specialized
security testing agents. Enables runtime agent instantiation with flexible
configuration and automatic tool detection.
"""

import importlib
import inspect
import os
import pkgutil
from pathlib import Path
from typing import Any, Callable, Dict, List, Optional, Type

from ..utils.schema import ScanConfig
from .base import Agent, MultiModelAgent


class AgentFactory:
    """
    Dynamic agent factory inspired by CAI's agent creation patterns.

    Handles discovery, registration, and instantiation of security agents
    with flexible configuration and automatic dependency management.
    """

    def __init__(self):
        self._agent_classes: Dict[str, Type[Agent]] = {}
        self._agent_factories: Dict[str, Callable] = {}
        self._agent_metadata: Dict[str, Dict[str, Any]] = {}

    def register_agent_class(self, name: str, agent_class: Type[Agent]):
        """Register an agent class for factory creation"""
        if not issubclass(agent_class, Agent):
            raise ValueError(f"Agent class {agent_class} must inherit from Agent")

        self._agent_classes[name] = agent_class

        # Extract agent status metadata
        status = getattr(agent_class, "_status", "stable")
        experimental = getattr(agent_class, "_experimental", False)
        planned_version = getattr(agent_class, "_planned_version", None)

        self._agent_metadata[name] = {
            "class": agent_class.__name__,
            "module": agent_class.__module__,
            "description": agent_class.__doc__ or "No description available",
            "tools": getattr(agent_class, "required_tools", []),
            "dependencies": getattr(agent_class, "dependencies", []),
            "status": status,  # stable, experimental, disabled
            "experimental": experimental,
            "planned_version": planned_version,
        }

    def register_agent_factory(self, name: str, factory_func: Callable):
        """Register a custom factory function for complex agent creation"""
        self._agent_factories[name] = factory_func

    def create_agent(
        self,
        agent_type: str,
        config: ScanConfig,
        name: Optional[str] = None,
        model_override: Optional[str] = None,
        tools_override: Optional[List[str]] = None,
        **kwargs,
    ) -> Agent:
        """
        Create an agent instance with flexible configuration.

        Args:
            agent_type: Type of agent to create (registered name)
            config: Scan configuration
            name: Custom agent name (defaults to agent_type)
            model_override: Override default AI model
            tools_override: Override default tools list
            **kwargs: Additional configuration for agent

        Returns:
            Configured agent instance
        """
        agent_name = name or agent_type

        # Try custom factory first
        if agent_type in self._agent_factories:
            return self._agent_factories[agent_type](
                name=agent_name,
                config=config,
                model_override=model_override,
                tools_override=tools_override,
                **kwargs,
            )

        # Use registered class
        if agent_type not in self._agent_classes:
            available = ", ".join(self._agent_classes.keys())
            raise ValueError(
                f"Unknown agent type '{agent_type}'. Available: {available}"
            )

        agent_class = self._agent_classes[agent_type]

        # Prepare agent parameters
        agent_params = {"name": agent_name, "config": config, **kwargs}

        # Add tools if specified
        if tools_override is not None:
            agent_params["tools"] = tools_override
        elif hasattr(agent_class, "default_tools"):
            agent_params["tools"] = agent_class.default_tools

        # Handle model override for MultiModelAgent subclasses
        if model_override and issubclass(agent_class, MultiModelAgent):
            agent_params["primary_model"] = model_override

        return agent_class(**agent_params)

    def discover_agents(
        self, package_path: str = "impact_scan.agents", include_disabled: bool = False
    ) -> int:
        """
        Automatically discover and register agent classes from package.

        Args:
            package_path: Python package path to scan for agents
            include_disabled: Whether to include disabled/experimental agents (default: False)

        Returns:
            Number of agents discovered and registered
        """
        discovered = 0
        skipped = 0

        try:
            # Import the package
            package = importlib.import_module(package_path)
            package_dir = Path(package.__file__).parent

            # Scan all Python files in the package
            for module_info in pkgutil.iter_modules([str(package_dir)]):
                if module_info.name.startswith("_") or module_info.name in [
                    "factory",
                    "base",
                ]:
                    continue

                try:
                    module_name = f"{package_path}.{module_info.name}"
                    module = importlib.import_module(module_name)

                    # Find agent classes in the module
                    for name, obj in inspect.getmembers(module, inspect.isclass):
                        if (
                            issubclass(obj, Agent)
                            and obj != Agent
                            and obj != MultiModelAgent
                            and obj.__module__ == module_name
                        ):
                            # Check if agent is disabled
                            status = getattr(obj, "_status", "stable")

                            # Skip disabled agents unless explicitly included
                            if status == "disabled" and not include_disabled:
                                skipped += 1
                                print(
                                    f"[FACTORY] Skipped disabled agent: {name} (use --experimental to enable)"
                                )
                                continue

                            # Use class name without 'Agent' suffix as type name
                            agent_type = (
                                name.lower().replace("agent", "")
                                if name.endswith("Agent")
                                else name.lower()
                            )

                            self.register_agent_class(agent_type, obj)
                            discovered += 1

                            status_badge = (
                                f"[{status.upper()}]" if status != "stable" else ""
                            )
                            print(
                                f"[FACTORY] Discovered agent: {agent_type} ({obj.__name__}) {status_badge}"
                            )

                except Exception as e:
                    print(f"[FACTORY] Failed to import {module_info.name}: {e}")
                    continue

        except Exception as e:
            print(f"[FACTORY] Failed to discover agents: {e}")

        if skipped > 0:
            print(
                f"[FACTORY] {skipped} disabled agents skipped (total discovered: {discovered})"
            )

        return discovered

    def get_available_agents(
        self, include_disabled: bool = False
    ) -> Dict[str, Dict[str, Any]]:
        """
        Get metadata about all available agent types

        Args:
            include_disabled: Whether to include disabled agents in the list

        Returns:
            Dictionary of agent metadata filtered by status
        """
        if include_disabled:
            return self._agent_metadata.copy()

        # Filter out disabled agents
        return {
            name: metadata
            for name, metadata in self._agent_metadata.items()
            if metadata.get("status") != "disabled"
        }

    def create_generic_agent_factory(self, agent_class: Type[Agent]) -> Callable:
        """
        Create a generic factory function for an agent class.
        Inspired by CAI's create_generic_agent_factory pattern.
        """

        def factory(
            name: str,
            config: ScanConfig,
            model_override: Optional[str] = None,
            tools_override: Optional[List[str]] = None,
            **kwargs,
        ) -> Agent:
            return self.create_agent(
                agent_type=agent_class.__name__.lower().replace("agent", ""),
                config=config,
                name=name,
                model_override=model_override,
                tools_override=tools_override,
                **kwargs,
            )

        return factory

    def get_model_name_for_agent(
        self, agent_type: str, model_override: Optional[str] = None
    ) -> str:
        """
        Get the appropriate model name for an agent type.
        Follows CAI's model selection priority:
        1. Explicit override
        2. Agent-specific env var
        3. Global env var
        4. Default fallback
        """
        # 1. Explicit override
        if model_override:
            return model_override

        # 2. Agent-specific environment variable
        agent_env_var = f"CAI_MODEL_{agent_type.upper()}"
        if agent_env_var in os.environ:
            return os.environ[agent_env_var]

        # 3. Global environment variable
        if "CAI_MODEL" in os.environ:
            return os.environ["CAI_MODEL"]

        # 4. Default fallback based on agent type
        defaults = {
            "static": "gemini",  # Fast for code analysis
            "dependency": "openai",  # Good for structured data
            "fix": "anthropic",  # Best for code generation
            "compliance": "gemini",  # Fast for policy checking
        }

        return defaults.get(agent_type, "anthropic")


# Global factory instance
_factory = AgentFactory()


# Convenience functions
def create_agent(agent_type: str, config: ScanConfig, **kwargs) -> Agent:
    """Create an agent using the global factory"""
    return _factory.create_agent(agent_type, config, **kwargs)


def register_agent(name: str, agent_class: Type[Agent]):
    """Register an agent class with the global factory"""
    _factory.register_agent_class(name, agent_class)


def discover_agents(
    package_path: str = "impact_scan.agents", include_disabled: bool = False
) -> int:
    """Discover and register agents from a package"""
    return _factory.discover_agents(package_path, include_disabled)


def get_available_agents(include_disabled: bool = False) -> Dict[str, Dict[str, Any]]:
    """Get all available agent types"""
    return _factory.get_available_agents(include_disabled)


def get_factory() -> AgentFactory:
    """Get the global factory instance"""
    return _factory
