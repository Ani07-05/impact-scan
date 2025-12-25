"""
Agent Orchestrator - The brain of the multi-agent security platform
Coordinates multiple specialized security agents for comprehensive testing.
"""

import asyncio
import time
from dataclasses import dataclass, field
from enum import Enum
from pathlib import Path
from typing import Any, Callable, Dict, List, Optional, Set, Union

from .base import Agent, AgentResult, AgentStatus


class OrchestrationStrategy(Enum):
    """Different orchestration strategies"""

    SEQUENTIAL = "sequential"  # Run agents one by one
    PARALLEL = "parallel"  # Run all agents simultaneously
    PIPELINE = "pipeline"  # Output of one feeds into next
    ADAPTIVE = "adaptive"  # AI decides the execution order


@dataclass
class AgentDependency:
    """Defines dependencies between agents"""

    agent_name: str
    depends_on: List[str] = field(default_factory=list)
    requires_data: List[str] = field(default_factory=list)
    priority: int = 1  # Higher priority runs first


@dataclass
class OrchestrationPlan:
    """Execution plan for agent orchestration"""

    strategy: OrchestrationStrategy
    agents: List[str]
    dependencies: List[AgentDependency] = field(default_factory=list)
    max_parallel: int = 5
    timeout: int = 3600  # 1 hour default timeout


class AgentOrchestrator:
    """
    Orchestrates multiple security agents for comprehensive security testing.

    This is the core of our revolutionary multi-agent platform - it coordinates
    specialized agents to work together like a cybersecurity dream team.
    """

    def __init__(self):
        self.agents: Dict[str, Agent] = {}
        self.results: Dict[str, AgentResult] = {}
        self.execution_graph: Dict[str, Set[str]] = {}
        self.callbacks: List[Callable] = []
        self.current_plan: Optional[OrchestrationPlan] = None

        # Performance tracking
        self.total_execution_time = 0.0
        self.agent_performance: Dict[str, List[float]] = {}

    def register_agent(self, agent: Agent):
        """Register a security agent with the orchestrator"""
        self.agents[agent.name] = agent
        self.agent_performance[agent.name] = []

        # Add callback to track agent completion
        agent.add_callback(self._on_agent_complete)

    def unregister_agent(self, agent_name: str):
        """Remove an agent from orchestrator"""
        if agent_name in self.agents:
            del self.agents[agent_name]
            del self.agent_performance[agent_name]

    def add_callback(self, callback: Callable[[Dict[str, AgentResult]], None]):
        """Add callback for orchestration completion"""
        self.callbacks.append(callback)

    def _on_agent_complete(self, result: AgentResult):
        """Handle individual agent completion"""
        self.results[result.agent_name] = result
        self.agent_performance[result.agent_name].append(result.execution_time)

        # Notify callbacks about agent completion
        for callback in self.callbacks:
            try:
                callback({result.agent_name: result})
            except Exception as e:
                print(f"Orchestrator callback error: {e}")

    async def execute_comprehensive_scan(
        self,
        target: Union[str, Path],
        strategy: OrchestrationStrategy = OrchestrationStrategy.ADAPTIVE,
        include_agents: Optional[List[str]] = None,
        context: Dict[str, Any] = None,
    ) -> Dict[str, AgentResult]:
        """
        Execute a comprehensive security scan using multiple agents.

        This is the main entry point for our revolutionary security testing.
        """
        start_time = time.time()
        context = context or {}

        # Determine which agents to run
        agents_to_run = include_agents or list(self.agents.keys())
        agents_to_run = [name for name in agents_to_run if name in self.agents]

        if not agents_to_run:
            raise ValueError("No valid agents specified for execution")

        # Create orchestration plan
        plan = await self._create_execution_plan(
            agents_to_run, strategy, target, context
        )
        self.current_plan = plan

        # Execute based on strategy
        if strategy == OrchestrationStrategy.SEQUENTIAL:
            results = await self._execute_sequential(target, plan, context)
        elif strategy == OrchestrationStrategy.PARALLEL:
            results = await self._execute_parallel(target, plan, context)
        elif strategy == OrchestrationStrategy.PIPELINE:
            results = await self._execute_pipeline(target, plan, context)
        elif strategy == OrchestrationStrategy.ADAPTIVE:
            results = await self._execute_adaptive(target, plan, context)
        else:
            raise ValueError(f"Unknown orchestration strategy: {strategy}")

        self.total_execution_time = time.time() - start_time
        self.results.update(results)

        return results

    async def _create_execution_plan(
        self,
        agent_names: List[str],
        strategy: OrchestrationStrategy,
        target: Union[str, Path],
        context: Dict[str, Any],
    ) -> OrchestrationPlan:
        """Create an intelligent execution plan"""

        # Define intelligent dependencies based on security testing workflow
        dependencies = [
            # Reconnaissance should run first - provides attack surface
            AgentDependency("recon", depends_on=[], priority=10),
            # Vulnerability detection needs recon data
            AgentDependency(
                "vuln",
                depends_on=["recon"],
                requires_data=["endpoints", "services"],
                priority=9,
            ),
            # Code quality analysis can run in parallel with vuln scanning
            AgentDependency("quality", depends_on=[], priority=8),
            # AI review runs after vuln + quality for full context
            AgentDependency(
                "review",
                depends_on=["vuln", "quality"],
                requires_data=["vulnerabilities", "quality_issues"],
                priority=7,
            ),
            # Exploitation needs vulnerabilities
            AgentDependency(
                "exploit",
                depends_on=["vuln"],
                requires_data=["vulnerabilities"],
                priority=6,
            ),
            # Compliance can run in parallel with vuln scanning
            AgentDependency("compliance", depends_on=["recon"], priority=5),
            # Fix generation should run after all detection agents
            AgentDependency(
                "fix",
                depends_on=["vuln", "quality", "review"],
                requires_data=["vulnerabilities"],
                priority=4,
            ),
        ]

        # Filter dependencies for only registered agents
        active_deps = [dep for dep in dependencies if dep.agent_name in agent_names]

        return OrchestrationPlan(
            strategy=strategy,
            agents=agent_names,
            dependencies=active_deps,
            max_parallel=min(5, len(agent_names)),
        )

    async def _execute_sequential(
        self, target: Union[str, Path], plan: OrchestrationPlan, context: Dict[str, Any]
    ) -> Dict[str, AgentResult]:
        """Execute agents sequentially in priority order"""
        results = {}

        # Sort agents by priority
        sorted_agents = self._sort_agents_by_priority(plan)

        for agent_name in sorted_agents:
            if agent_name in self.agents:
                agent = self.agents[agent_name]
                print(f"[ORCHESTRATOR] Executing {agent_name} agent...")

                # Build context from previous results
                agent_context = self._build_agent_context(agent_name, results, context)

                result = await agent.execute(target, agent_context)
                results[agent_name] = result

                print(f"[ORCHESTRATOR] {agent_name} completed: {result.status.value}")

                # Stop on critical failure (can be made configurable)
                if result.failed and agent_name in ["recon"]:  # Critical agents
                    print(
                        f"[ORCHESTRATOR] Critical agent {agent_name} failed, stopping execution"
                    )
                    break

        return results

    async def _execute_parallel(
        self, target: Union[str, Path], plan: OrchestrationPlan, context: Dict[str, Any]
    ) -> Dict[str, AgentResult]:
        """Execute all agents in parallel with proper concurrency"""
        print(f"[ORCHESTRATOR] Executing {len(plan.agents)} agents in parallel...")

        # Create tasks for all agents
        tasks = {}
        for agent_name in plan.agents:
            if agent_name in self.agents:
                agent = self.agents[agent_name]
                agent_context = self._build_agent_context(agent_name, {}, context)
                task = asyncio.create_task(
                    agent.execute(target, agent_context), name=f"agent_{agent_name}"
                )
                tasks[agent_name] = task

        # Wait for all agents with gather for true parallelism
        results = {}
        completed = await asyncio.gather(*tasks.values(), return_exceptions=True)

        for agent_name, result in zip(tasks.keys(), completed):
            if isinstance(result, Exception):
                print(f"[ORCHESTRATOR] {agent_name} FAILED: {result}")
                # Create failed result
                from .base import AgentStatus

                results[agent_name] = AgentResult(
                    agent_id=f"orchestrator-{agent_name}",
                    agent_name=agent_name,
                    status=AgentStatus.FAILED,
                    error_message=str(result),
                )
            else:
                results[agent_name] = result
                print(f"[ORCHESTRATOR] {agent_name} OK ({result.execution_time:.1f}s)")

        return results

    async def _execute_pipeline(
        self, target: Union[str, Path], plan: OrchestrationPlan, context: Dict[str, Any]
    ) -> Dict[str, AgentResult]:
        """Execute agents in pipeline mode - output of one feeds into next"""
        results = {}
        sorted_agents = self._sort_agents_by_dependencies(plan)

        for agent_name in sorted_agents:
            if agent_name in self.agents:
                agent = self.agents[agent_name]

                # Build rich context from all previous results
                agent_context = self._build_agent_context(agent_name, results, context)

                print(
                    f"[PIPELINE] Executing {agent_name} with context from {list(results.keys())}"
                )

                result = await agent.execute(target, agent_context)
                results[agent_name] = result

                # Pipeline can continue even on non-critical failures
                status_msg = (
                    "SUCCESS" if result.success else f"FAILED: {result.error_message}"
                )
                print(f"[PIPELINE] {agent_name}: {status_msg}")

        return results

    async def _execute_adaptive(
        self, target: Union[str, Path], plan: OrchestrationPlan, context: Dict[str, Any]
    ) -> Dict[str, AgentResult]:
        """
        Adaptive execution - AI decides the optimal execution strategy
        based on target characteristics and agent capabilities.
        """
        # For now, use intelligent pipeline as adaptive strategy
        # Future: Use AI to decide execution order based on target analysis

        print("[ADAPTIVE] Analyzing target and selecting optimal strategy...")

        # Quick target analysis to determine strategy
        target_path = Path(target) if isinstance(target, str) else target

        if target_path.exists() and target_path.is_dir():
            # For codebases, use pipeline approach
            return await self._execute_pipeline(target, plan, context)
        else:
            # For URLs/network targets, use parallel approach
            return await self._execute_parallel(target, plan, context)

    def _sort_agents_by_priority(self, plan: OrchestrationPlan) -> List[str]:
        """Sort agents by priority (higher priority first)"""
        priority_map = {dep.agent_name: dep.priority for dep in plan.dependencies}

        return sorted(
            plan.agents, key=lambda name: priority_map.get(name, 0), reverse=True
        )

    def _sort_agents_by_dependencies(self, plan: OrchestrationPlan) -> List[str]:
        """Sort agents by dependency order (dependencies first)"""
        # Topological sort based on dependencies
        deps_map = {dep.agent_name: dep.depends_on for dep in plan.dependencies}

        result = []
        visited = set()

        def visit(agent: str):
            if agent in visited:
                return
            visited.add(agent)

            for dep in deps_map.get(agent, []):
                if dep in plan.agents:
                    visit(dep)

            if agent not in result:
                result.append(agent)

        for agent in plan.agents:
            visit(agent)

        return result

    def _build_agent_context(
        self,
        agent_name: str,
        previous_results: Dict[str, AgentResult],
        base_context: Dict[str, Any],
    ) -> Dict[str, Any]:
        """Build context for an agent from previous results and base context"""

        context = base_context.copy()
        context["previous_results"] = previous_results

        # Add specific data from dependencies if plan is available
        if self.current_plan:
            for dep in self.current_plan.dependencies:
                if dep.agent_name == agent_name:
                    for required_data in dep.requires_data:
                        # Extract required data from dependent agents
                        for dep_agent in dep.depends_on:
                            if dep_agent in previous_results:
                                result_data = previous_results[dep_agent].data
                                if required_data in result_data:
                                    context[required_data] = result_data[required_data]

        return context

    def get_orchestration_summary(self) -> Dict[str, Any]:
        """Get summary of orchestration performance and results"""
        return {
            "total_execution_time": self.total_execution_time,
            "agents_executed": list(self.results.keys()),
            "successful_agents": [
                name for name, result in self.results.items() if result.success
            ],
            "failed_agents": [
                name for name, result in self.results.items() if result.failed
            ],
            "total_findings": sum(
                len(result.findings) for result in self.results.values()
            ),
            "agent_performance": {
                name: {
                    "avg_execution_time": sum(times) / len(times) if times else 0,
                    "executions": len(times),
                }
                for name, times in self.agent_performance.items()
            },
        }

    def reset(self):
        """Reset orchestrator state"""
        self.results.clear()
        self.execution_graph.clear()
        self.current_plan = None
        self.total_execution_time = 0.0

        # Reset all agents
        for agent in self.agents.values():
            agent.reset()
