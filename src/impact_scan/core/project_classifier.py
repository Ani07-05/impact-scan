"""
AI-Powered Project Classifier - Intelligent project type detection.

Replaces brittle file-pattern-based entry point detection with AI analysis of:
- README files
- Package manifests (package.json, Cargo.toml, pyproject.toml, go.mod)
- Directory structure
- Build configs

Classifies projects as:
- Web applications (Flask, Django, FastAPI, Express, Next.js, React)
- Libraries/packages (fpdf2, requests, lodash)
- CLI tools
- Desktop applications
- System services
- Mixed/monorepo

This allows intelligent Semgrep rule selection:
- Web apps → CORS, session, XSS, CSRF rules
- Libraries → Skip web-specific rules, focus on API security
- Rust → unsafe blocks, memory safety
- Go → goroutine safety, SQL injection
"""

import json
import logging
from dataclasses import dataclass
from pathlib import Path
from typing import Dict, List, Optional

from ..utils import schema
from . import fix_ai

logger = logging.getLogger(__name__)


@dataclass
class ProjectContext:
    """
    Rich context about a project determined by AI analysis.

    Attributes:
        project_type: Primary type (web_app, library, cli, desktop, service)
        frameworks: Detected frameworks (Flask, React, Next.js, etc.)
        languages: Programming languages used (Python, JavaScript, Rust, etc.)
        is_library: True if this is a library/package, not an application
        is_web_app: True if this is a web application
        description: AI-generated project description
        security_context: Security-relevant characteristics
    """
    project_type: str  # web_app, library, cli, desktop, service, mixed
    frameworks: List[str]
    languages: List[str]
    is_library: bool
    is_web_app: bool
    description: str
    security_context: Dict[str, bool]  # e.g., {"handles_http": True, "stores_secrets": True}


class ProjectClassifier:
    """
    Uses AI to understand project type and context from README and manifest files.
    """

    _CLASSIFICATION_PROMPT = """<role>You are a software architect specializing in codebase analysis and project classification.</role>

<task>Analyze this project and classify its type, frameworks, and security context.</task>

<project_info>
Root Directory: {root_path}

README Content (first 3000 chars):
{readme_content}

Package Manifests:
{manifest_content}

Directory Structure:
{directory_structure}
</project_info>

<classification_framework>
Analyze the project and determine:

1. **Primary Project Type**:
   - web_app: Web application (Flask, Django, Express, Next.js, Rails)
   - library: Reusable library/package (fpdf2, requests, lodash, React library)
   - cli: Command-line tool
   - desktop: Desktop application (Electron, Qt, Tkinter)
   - service: System service/daemon/microservice
   - mixed: Monorepo or multiple types

2. **Frameworks**: List all detected frameworks (Flask, Django, React, Next.js, FastAPI, Express, etc.)

3. **Languages**: All programming languages used (Python, JavaScript, TypeScript, Rust, Go, etc.)

4. **Security Context**: Answer these questions:
   - handles_http: Does it handle HTTP requests directly? (web server, API)
   - handles_auth: Does it implement authentication/authorization?
   - stores_secrets: Does it manage API keys, passwords, tokens?
   - processes_user_input: Does it accept untrusted user input?
   - generates_html: Does it generate HTML output? (XSS relevant)
   - uses_database: Does it interact with databases? (SQL injection relevant)
   - is_frontend: Is it a frontend/browser application? (CSP, XSS relevant)

5. **Description**: One-sentence description of what the project does
</classification_framework>

<output_format>
Return ONLY a JSON object (no markdown, no code blocks):
{{
  "project_type": "web_app|library|cli|desktop|service|mixed",
  "frameworks": ["framework1", "framework2"],
  "languages": ["Python", "JavaScript"],
  "description": "Brief description",
  "security_context": {{
    "handles_http": true|false,
    "handles_auth": true|false,
    "stores_secrets": true|false,
    "processes_user_input": true|false,
    "generates_html": true|false,
    "uses_database": true|false,
    "is_frontend": true|false
  }}
}}
</output_format>

<examples>
Example 1 - fpdf2 (PDF library):
{{
  "project_type": "library",
  "frameworks": [],
  "languages": ["Python"],
  "description": "Python library for PDF generation",
  "security_context": {{
    "handles_http": false,
    "handles_auth": false,
    "stores_secrets": false,
    "processes_user_input": true,
    "generates_html": false,
    "uses_database": false,
    "is_frontend": false
  }}
}}

Example 2 - Flask web app:
{{
  "project_type": "web_app",
  "frameworks": ["Flask"],
  "languages": ["Python"],
  "description": "Flask web application with user authentication",
  "security_context": {{
    "handles_http": true,
    "handles_auth": true,
    "stores_secrets": true,
    "processes_user_input": true,
    "generates_html": true,
    "uses_database": true,
    "is_frontend": false
  }}
}}

Example 3 - Next.js app:
{{
  "project_type": "web_app",
  "frameworks": ["Next.js", "React"],
  "languages": ["TypeScript", "JavaScript"],
  "description": "Next.js web application with React frontend",
  "security_context": {{
    "handles_http": true,
    "handles_auth": true,
    "stores_secrets": true,
    "processes_user_input": true,
    "generates_html": true,
    "uses_database": false,
    "is_frontend": true
  }}
}}
</examples>

<constraints>
- Be conservative: If unclear, default to web_app (safer to over-scan)
- Check README and package.json/pyproject.toml for clues
- Look for keywords: "library", "package", "framework", "API", "server", "frontend"
- Libraries typically have install instructions, not deployment instructions
</constraints>"""

    def __init__(
        self,
        ai_provider: Optional[fix_ai.AIFixProvider] = None,
        api_keys: Optional[schema.APIKeys] = None
    ):
        """
        Initialize project classifier.

        Args:
            ai_provider: Optional AI provider. If None, auto-detects from api_keys.
            api_keys: API keys for AI providers (needed if ai_provider is None).
        """
        self.ai_provider = ai_provider
        self.api_keys = api_keys

    def classify(self, root_path: Path) -> Optional[ProjectContext]:
        """
        Classify project type using AI analysis of README and manifests.

        Args:
            root_path: Root directory of the project

        Returns:
            ProjectContext with classification results, or None if AI unavailable
        """
        try:
            # Gather project context
            readme_content = self._read_readme(root_path)
            manifest_content = self._read_manifests(root_path)
            directory_structure = self._get_directory_structure(root_path)

            if not readme_content and not manifest_content:
                logger.warning("No README or manifest files found, skipping AI classification")
                return None

            # Initialize AI provider if needed
            if not self.ai_provider:
                if not self.api_keys:
                    logger.warning("No API keys provided for AI classification")
                    return None

                try:
                    self.ai_provider = fix_ai.auto_detect_provider(self.api_keys)
                    if not self.ai_provider:
                        logger.warning("No AI provider API key found")
                        return None
                except Exception as e:
                    logger.warning(f"AI provider not available: {e}")
                    return None

            # Build prompt
            prompt = self._CLASSIFICATION_PROMPT.format(
                root_path=root_path,
                readme_content=readme_content or "(No README found)",
                manifest_content=manifest_content or "(No manifest files found)",
                directory_structure=directory_structure
            )

            # Get AI classification
            logger.info("Analyzing project with AI...")
            response = self.ai_provider.generate_content(prompt)

            # Parse response
            context = self._parse_response(response)

            if context:
                logger.info(f"Project classified as: {context.project_type}")
                logger.info(f"Frameworks: {', '.join(context.frameworks) if context.frameworks else 'None'}")
                logger.info(f"Description: {context.description}")

            return context

        except Exception as e:
            logger.error(f"Project classification failed: {e}")
            return None

    def _read_readme(self, root_path: Path) -> Optional[str]:
        """Read README file (any common variant)."""
        readme_variants = [
            "README.md", "README.MD", "README.txt", "README.rst",
            "README", "readme.md", "Readme.md"
        ]

        for variant in readme_variants:
            readme_path = root_path / variant
            if readme_path.is_file():
                try:
                    content = readme_path.read_text(encoding="utf-8", errors="ignore")
                    # Limit to first 3000 chars to avoid token overflow
                    return content[:3000]
                except Exception as e:
                    logger.debug(f"Could not read {readme_path}: {e}")

        return None

    def _read_manifests(self, root_path: Path) -> Optional[str]:
        """Read package manifest files."""
        manifests = {
            "package.json": "Node.js",
            "pyproject.toml": "Python",
            "Cargo.toml": "Rust",
            "go.mod": "Go",
            "pom.xml": "Java (Maven)",
            "build.gradle": "Java (Gradle)",
            "Gemfile": "Ruby",
            "composer.json": "PHP",
        }

        manifest_contents = []

        for filename, language in manifests.items():
            manifest_path = root_path / filename
            if manifest_path.is_file():
                try:
                    content = manifest_path.read_text(encoding="utf-8", errors="ignore")
                    # Limit each manifest to 1000 chars
                    manifest_contents.append(f"=== {filename} ({language}) ===\n{content[:1000]}\n")
                except Exception as e:
                    logger.debug(f"Could not read {manifest_path}: {e}")

        return "\n".join(manifest_contents) if manifest_contents else None

    def _get_directory_structure(self, root_path: Path, max_depth: int = 2) -> str:
        """Get basic directory structure (top-level dirs)."""
        try:
            dirs = []
            for item in root_path.iterdir():
                if item.is_dir() and not item.name.startswith("."):
                    dirs.append(item.name)

            return "Top-level directories: " + ", ".join(sorted(dirs)[:20])
        except Exception as e:
            logger.debug(f"Could not read directory structure: {e}")
            return "(Could not read directory structure)"

    def _parse_response(self, response: str) -> Optional[ProjectContext]:
        """Parse AI response into ProjectContext."""
        try:
            # Clean response (remove markdown code fences if present)
            cleaned = response.strip()
            if cleaned.startswith("```"):
                cleaned = "\n".join(cleaned.split("\n")[1:-1])

            data = json.loads(cleaned)

            # Validate required fields
            project_type = data.get("project_type", "web_app")
            frameworks = data.get("frameworks", [])
            languages = data.get("languages", [])
            description = data.get("description", "Unknown project")
            security_context = data.get("security_context", {})

            # Derive helper flags
            is_library = project_type == "library"
            is_web_app = project_type == "web_app" or security_context.get("handles_http", False)

            return ProjectContext(
                project_type=project_type,
                frameworks=frameworks,
                languages=languages,
                is_library=is_library,
                is_web_app=is_web_app,
                description=description,
                security_context=security_context
            )

        except json.JSONDecodeError as e:
            logger.error(f"Failed to parse AI classification response: {e}")
            logger.debug(f"Response was: {response[:500]}")
            return None
        except Exception as e:
            logger.error(f"Unexpected error parsing classification: {e}")
            return None


def classify_project(
    root_path: Path,
    ai_provider: Optional[fix_ai.AIFixProvider] = None,
    api_keys: Optional[schema.APIKeys] = None
) -> Optional[ProjectContext]:
    """
    Convenience function to classify a project.

    Args:
        root_path: Root directory of the project
        ai_provider: Optional AI provider
        api_keys: API keys for AI providers (needed if ai_provider is None)

    Returns:
        ProjectContext or None if classification fails
    """
    classifier = ProjectClassifier(ai_provider, api_keys)
    return classifier.classify(root_path)
