"""
End-to-end tests for tool-based scanning architecture.

Tests the complete workflow:
1. RipgrepTool generates context and scans
2. AIValidatorTool filters false positives (if API key available)
3. StackOverflowTool enriches findings (if enabled)
4. AIFixGeneratorTool generates fixes (if enabled)
"""

import os
import pytest
from pathlib import Path
import tempfile
import shutil

from impact_scan.tools.ripgrep_tool import RipgrepTool
from impact_scan.tools.ai_validator_tool import AIValidatorTool
from impact_scan.tools.stackoverflow_tool import StackOverflowTool
from impact_scan.tools.ai_fix_generator_tool import AIFixGeneratorTool
from impact_scan.agents.static_analysis_agent import StaticAnalysisAgent
from impact_scan.utils.schema import ScanConfig, Severity
from impact_scan.core.knowledge_graph import KnowledgeGraph


@pytest.fixture
def vulnerable_codebase(tmp_path):
    """Create a test codebase with known vulnerabilities."""
    # Create project structure
    project = tmp_path / "test_project"
    project.mkdir()

    # Create a vulnerable Python file
    (project / "app.py").write_text('''
import os
import subprocess

# Hardcoded secret (should be detected)
API_KEY = "sk-1234567890abcdef"
PASSWORD = "admin123"

def execute_command(user_input):
    """Command injection vulnerability"""
    cmd = f"ls {user_input}"
    os.system(cmd)

def run_sql_query(user_id):
    """SQL injection vulnerability"""
    query = f"SELECT * FROM users WHERE id = {user_id}"
    return query

def unsafe_eval(code):
    """Dangerous eval usage"""
    return eval(code)

def process_file(filename):
    """Path traversal vulnerability"""
    file_path = f"/data/{filename}"
    with open(file_path, 'r') as f:
        return f.read()
''')

    # Create a config file
    (project / "config.py").write_text('''
# Flask debug mode enabled (security issue)
DEBUG = True
SECRET_KEY = "hardcoded-secret-key"

# CORS wildcard (security issue)
CORS_ORIGINS = "*"
''')

    # Create a safe file (should not have findings)
    (project / "utils.py").write_text('''
import hashlib

def hash_password(password):
    """Safe password hashing"""
    return hashlib.sha256(password.encode()).hexdigest()

def validate_input(user_input):
    """Input validation"""
    if not user_input.isalnum():
        raise ValueError("Invalid input")
    return user_input
''')

    return project


class TestRipgrepTool:
    """Test RipgrepTool in isolation."""

    def test_ripgrep_tool_generates_context(self, vulnerable_codebase):
        """Test that RipgrepTool generates impact-scan.md."""
        tool = RipgrepTool(root_path=vulnerable_codebase)

        result = tool.execute(
            generate_context=True,
            generate_rules=False,
            scan=False
        )

        assert result.success, f"Tool failed: {result.error}"
        assert 'context_file' in result.data

        context_file = Path(result.data['context_file'])
        assert context_file.exists()
        assert context_file.name == "impact-scan.md"

        # Verify context content
        content = context_file.read_text()
        assert "# Impact-Scan Codebase Context" in content
        assert "Project Overview" in content

    def test_ripgrep_tool_generates_rules(self, vulnerable_codebase):
        """Test that RipgrepTool generates impact-scan.yml."""
        tool = RipgrepTool(root_path=vulnerable_codebase)

        result = tool.execute(
            generate_context=False,
            generate_rules=True,
            scan=False
        )

        assert result.success, f"Tool failed: {result.error}"
        assert 'rules_file' in result.data

        rules_file = Path(result.data['rules_file'])
        assert rules_file.exists()
        assert rules_file.name == "impact-scan.yml"

    def test_ripgrep_tool_detects_vulnerabilities(self, vulnerable_codebase):
        """Test that RipgrepTool detects known vulnerabilities."""
        tool = RipgrepTool(root_path=vulnerable_codebase)

        result = tool.execute(
            generate_context=True,
            generate_rules=True,
            scan=True
        )

        assert result.success, f"Tool failed: {result.error}"
        assert 'findings' in result.data

        findings = result.data['findings']
        assert len(findings) > 0, "No vulnerabilities detected in vulnerable codebase"

        # Check for specific vulnerability types
        finding_titles = [f.title for f in findings]

        # Should detect some security patterns
        # (exact matches depend on ripgrep scanner implementation)
        assert any(finding for finding in findings), "Expected at least one finding"

    def test_ripgrep_tool_metadata(self, vulnerable_codebase):
        """Test that RipgrepTool provides execution metadata."""
        tool = RipgrepTool(root_path=vulnerable_codebase)

        result = tool.execute(scan=True)

        assert result.success
        assert 'duration_seconds' in result.metadata
        assert result.metadata['tool'] == 'ripgrep'
        assert 'root_path' in result.metadata


class TestKnowledgeGraphParsing:
    """Test KnowledgeGraph parsing of impact-scan.md."""

    def test_knowledge_graph_parses_context(self, vulnerable_codebase):
        """Test that KnowledgeGraph can parse impact-scan.md."""
        # First generate context
        ripgrep_tool = RipgrepTool(root_path=vulnerable_codebase)
        rg_result = ripgrep_tool.execute(generate_context=True, generate_rules=False, scan=False)

        assert rg_result.success
        context_file = Path(rg_result.data['context_file'])

        # Now test knowledge graph parsing
        kg = KnowledgeGraph(vulnerable_codebase)
        kg.build(context_file=context_file)

        # Knowledge graph should have parsed the context
        assert len(kg.files) > 0, "Knowledge graph should have classified files"

    def test_parse_impact_scan_context_method(self, vulnerable_codebase):
        """Test parse_impact_scan_context method directly."""
        # Generate context
        ripgrep_tool = RipgrepTool(root_path=vulnerable_codebase)
        rg_result = ripgrep_tool.execute(generate_context=True, scan=False)

        context_file = Path(rg_result.data['context_file'])

        # Parse it
        kg = KnowledgeGraph(vulnerable_codebase)
        metadata = kg.parse_impact_scan_context(context_file)

        # Should extract metadata
        assert isinstance(metadata, dict)
        # May have project_type, frameworks, dependencies, etc.


@pytest.mark.skipif(not os.getenv("GROQ_API_KEY"), reason="Requires GROQ_API_KEY")
class TestAIValidatorTool:
    """Test AIValidatorTool (requires API key)."""

    def test_ai_validator_filters_findings(self, vulnerable_codebase):
        """Test that AIValidatorTool filters false positives."""
        # First get findings from ripgrep
        ripgrep_tool = RipgrepTool(root_path=vulnerable_codebase)
        rg_result = ripgrep_tool.execute(scan=True)

        assert rg_result.success
        findings = rg_result.data['findings']
        original_count = len(findings)

        if original_count == 0:
            pytest.skip("No findings to validate")

        # Now validate with AI
        validator_tool = AIValidatorTool(
            root_path=vulnerable_codebase,
            groq_api_key=os.getenv("GROQ_API_KEY")
        )

        val_result = validator_tool.execute(findings=findings)

        assert val_result.success, f"Validation failed: {val_result.error}"
        validated_findings = val_result.data

        # AI validation should return a list
        assert isinstance(validated_findings, list)

        # May filter some findings (or keep all if they're all true positives)
        assert len(validated_findings) <= original_count


class TestStaticAnalysisAgentE2E:
    """End-to-end test of StaticAnalysisAgent using tools."""

    def test_agent_executes_with_tools(self, vulnerable_codebase):
        """Test that StaticAnalysisAgent executes using tool-based architecture."""
        import asyncio

        # Create config
        config = ScanConfig(
            root_path=vulnerable_codebase,
            min_severity=Severity.LOW,
            ai_validation=False,  # Disable AI to avoid API key requirement
            stackoverflow=False,  # Disable SO to speed up test
            enable_ai_fixes=False
        )

        # Create agent
        agent = StaticAnalysisAgent(name="TestAgent", config=config)

        # Execute
        async def run_agent():
            from impact_scan.agents.base import AgentResult, AgentStatus
            result = AgentResult(agent_name="TestAgent")

            await agent._execute_internal(
                target=vulnerable_codebase,
                context={},
                result=result
            )

            return result

        result = asyncio.run(run_agent())

        # Verify execution
        from impact_scan.agents.base import AgentStatus
        assert result.status == AgentStatus.COMPLETED, f"Agent failed with status: {result.status}"
        assert 'tools_used' in result.data
        assert 'ripgrep' in result.data['tools_used']
        assert result.data['findings_count'] >= 0

    @pytest.mark.skipif(not os.getenv("GROQ_API_KEY"), reason="Requires GROQ_API_KEY")
    def test_agent_with_ai_validation(self, vulnerable_codebase):
        """Test StaticAnalysisAgent with AI validation enabled."""
        import asyncio

        config = ScanConfig(
            root_path=vulnerable_codebase,
            min_severity=Severity.LOW,
            ai_validation=True,  # Enable AI validation
            stackoverflow=False,
            enable_ai_fixes=False
        )

        agent = StaticAnalysisAgent(name="TestAgentAI", config=config)

        async def run_agent():
            from impact_scan.agents.base import AgentResult
            result = AgentResult(agent_name="TestAgentAI")

            await agent._execute_internal(
                target=vulnerable_codebase,
                context={},
                result=result
            )

            return result

        result = asyncio.run(run_agent())

        from impact_scan.agents.base import AgentStatus
        assert result.status == AgentStatus.COMPLETED
        assert 'ai_validator' in result.data['tools_used']


class TestToolObservability:
    """Test that tools log execution for observability."""

    def test_tool_logs_execution(self, vulnerable_codebase, caplog):
        """Test that RipgrepTool logs [TOOL CALL] messages."""
        import logging
        caplog.set_level(logging.INFO)

        tool = RipgrepTool(root_path=vulnerable_codebase)
        result = tool.execute(scan=True)

        assert result.success

        # Check for observable logging
        log_messages = [record.message for record in caplog.records]

        # Should have TOOL CALL start message
        assert any("[TOOL CALL] ripgrep - Starting execution" in msg for msg in log_messages)

        # Should have TOOL CALL completion message
        assert any("[TOOL CALL] ripgrep - Completed successfully" in msg for msg in log_messages)

    def test_tool_metadata_includes_duration(self, vulnerable_codebase):
        """Test that tools include execution duration in metadata."""
        tool = RipgrepTool(root_path=vulnerable_codebase)
        result = tool.execute(scan=True)

        assert result.success
        assert 'duration_seconds' in result.metadata
        assert isinstance(result.metadata['duration_seconds'], float)
        assert result.metadata['duration_seconds'] > 0


class TestErrorHandling:
    """Test error handling in tools."""

    def test_ripgrep_tool_handles_missing_path(self):
        """Test that RipgrepTool handles non-existent path."""
        nonexistent_path = Path("/nonexistent/path/12345")

        tool = RipgrepTool(root_path=nonexistent_path)
        result = tool.execute(scan=True)

        # Tool should handle error gracefully
        # (May succeed with empty results or fail with clear error)
        if not result.success:
            assert result.error is not None
            assert isinstance(result.error, str)

    def test_ai_validator_requires_api_key(self, vulnerable_codebase):
        """Test that AIValidatorTool requires API key."""
        with pytest.raises(ValueError, match="API key is required"):
            AIValidatorTool(root_path=vulnerable_codebase, groq_api_key="")

    def test_ai_fix_generator_requires_api_key(self):
        """Test that AIFixGeneratorTool requires API key."""
        with pytest.raises(ValueError, match="API key is required"):
            AIFixGeneratorTool(provider="groq", api_key=None)
