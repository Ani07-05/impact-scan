"""
ReconAgent - Attack Surface Discovery Agent
Revolutionary reconnaissance agent for comprehensive attack surface mapping.
"""

import re
from pathlib import Path
from typing import Any, Dict, Set, Union

from .base import AgentResult, MultiModelAgent


class ReconAgent(MultiModelAgent):
    """
    Advanced reconnaissance agent for attack surface discovery.

    This agent goes beyond traditional scanners to provide comprehensive
    attack surface mapping using AI-enhanced analysis.

    Capabilities:
    - Framework and technology detection
    - Endpoint discovery and mapping
    - Service enumeration
    - Configuration analysis
    - Security header assessment
    - Attack vector identification
    """

    def __init__(self, config, **kwargs):
        super().__init__(
            name="recon",
            config=config,
            tools=["find", "grep", "curl", "nmap"],
            **kwargs,
        )
        self.discovered_endpoints = set()
        self.detected_frameworks = set()
        self.services = {}
        self.attack_vectors = []

    async def _execute_internal(
        self, target: Union[str, Path], context: Dict[str, Any], result: AgentResult
    ) -> None:
        """Execute comprehensive reconnaissance"""

        target_path = Path(target) if isinstance(target, str) else target

        print(f"[RECON] Starting attack surface discovery for {target_path}")

        # Phase 1: Framework Detection
        await self._detect_frameworks(target_path, result)

        # Phase 2: Endpoint Discovery
        await self._discover_endpoints(target_path, result)

        # Phase 3: Configuration Analysis
        await self._analyze_configuration(target_path, result)

        # Phase 4: Service Enumeration (if network target)
        if self._is_network_target(str(target)):
            await self._enumerate_services(str(target), result)

        # Phase 5: AI-Enhanced Analysis
        await self._ai_enhanced_analysis(target_path, result)

        # Compile final results
        self._compile_results(result)

        print(
            f"[RECON] Discovered {len(self.discovered_endpoints)} endpoints, "
            f"{len(self.detected_frameworks)} frameworks, "
            f"{len(self.attack_vectors)} attack vectors"
        )

    async def _detect_frameworks(self, target_path: Path, result: AgentResult):
        """Detect web frameworks and technologies"""
        print("[RECON] Detecting frameworks and technologies...")

        framework_signatures = {
            # Python frameworks
            "flask": ["app.py", "run.py", "from flask import", "Flask(__name__)"],
            "django": [
                "manage.py",
                "settings.py",
                "from django.conf import",
                "DJANGO_SETTINGS_MODULE",
            ],
            "fastapi": ["from fastapi import", "FastAPI()", "app = FastAPI"],
            # JavaScript frameworks
            "nextjs": ["next.config.js", "pages/", "_app.js", "getServerSideProps"],
            "react": ["package.json", "src/App.js", "react", "ReactDOM.render"],
            "vue": ["vue.config.js", ".vue", "new Vue(", "createApp"],
            "nuxt": ["nuxt.config.js", "pages/", "asyncData"],
            # Node.js
            "express": ["express", "app.listen", "app.get", "app.post"],
            "koa": ["const Koa = require", "new Koa()"],
            # PHP frameworks
            "laravel": ["artisan", "composer.json", "Laravel", "Illuminate\\"],
            "symfony": ["symfony", "src/Controller", "Symfony\\"],
            "wordpress": ["wp-config.php", "wp-content", "WordPress"],
            # Java frameworks
            "spring": ["pom.xml", "@SpringBootApplication", "spring-boot"],
            "struts": ["struts.xml", "struts2"],
            # .NET
            "dotnet": [".csproj", "Program.cs", "Startup.cs", "using Microsoft"],
            # Ruby
            "rails": ["Gemfile", "config/routes.rb", "Rails.application"],
            # Go
            "gin": ["gin.Default()", "gin.Engine"],
            "echo": ["echo.New()", "labstack/echo"],
            # Database
            "mysql": ["mysql", "3306"],
            "postgresql": ["postgresql", "postgres", "5432"],
            "mongodb": ["mongodb", "mongo", "27017"],
            "redis": ["redis", "6379"],
            # Web servers
            "nginx": ["nginx.conf", "server {"],
            "apache": ["httpd.conf", ".htaccess", "apache"],
            # Container tech
            "docker": ["Dockerfile", "docker-compose", ".dockerignore"],
            "kubernetes": ["deployment.yaml", "service.yaml", "k8s"],
        }

        detected = {}

        if target_path.exists() and target_path.is_dir():
            # File-based detection for local directories
            for framework, signatures in framework_signatures.items():
                confidence = 0
                evidence = []

                for signature in signatures:
                    if self._search_for_signature(target_path, signature):
                        confidence += 1
                        evidence.append(signature)

                if confidence > 0:
                    detected[framework] = {
                        "confidence": min(confidence / len(signatures), 1.0),
                        "evidence": evidence,
                    }
                    self.detected_frameworks.add(framework)

        result.data["frameworks"] = detected
        result.findings.extend(
            [
                {
                    "type": "framework_detection",
                    "framework": framework,
                    "confidence": info["confidence"],
                    "evidence": info["evidence"],
                    "severity": "info",
                }
                for framework, info in detected.items()
            ]
        )

    def _search_for_signature(self, target_path: Path, signature: str) -> bool:
        """Search for framework signatures in codebase"""
        try:
            # File existence check
            if not signature.startswith(("from ", "import ", "const ", "using ", "@")):
                file_path = target_path / signature
                if file_path.exists():
                    return True

                # Directory check
                if (target_path / signature).is_dir():
                    return True

            # Content-based search for code patterns
            for file_path in target_path.rglob("*.py"):  # Start with Python
                try:
                    content = file_path.read_text(encoding="utf-8", errors="ignore")
                    if signature in content:
                        return True
                except:
                    continue

            for file_path in target_path.rglob("*.js"):  # JavaScript
                try:
                    content = file_path.read_text(encoding="utf-8", errors="ignore")
                    if signature in content:
                        return True
                except:
                    continue

            # Add more file types as needed

        except Exception:
            pass

        return False

    async def _discover_endpoints(self, target_path: Path, result: AgentResult):
        """Discover API endpoints and routes"""
        print("[RECON] Discovering endpoints and routes...")

        endpoints = set()

        if target_path.exists() and target_path.is_dir():
            # Python Flask/Django endpoints
            endpoints.update(await self._find_python_endpoints(target_path))

            # JavaScript/Node.js endpoints
            endpoints.update(await self._find_js_endpoints(target_path))

            # Configuration-based endpoints
            endpoints.update(await self._find_config_endpoints(target_path))

        self.discovered_endpoints.update(endpoints)

        result.data["endpoints"] = list(endpoints)
        result.findings.extend(
            [
                {
                    "type": "endpoint_discovery",
                    "endpoint": endpoint,
                    "method": "auto-detected",
                    "severity": "info",
                }
                for endpoint in endpoints
            ]
        )

    async def _find_python_endpoints(self, target_path: Path) -> Set[str]:
        """Find Python web framework endpoints"""
        endpoints = set()

        # Flask routes
        flask_patterns = [
            r"@app\.route\(['\"]([^'\"]+)['\"]",
            r"@blueprint\.route\(['\"]([^'\"]+)['\"]",
            r"add_url_rule\(['\"]([^'\"]+)['\"]",
        ]

        # Django URLs
        django_patterns = [
            r"path\(['\"]([^'\"]+)['\"]",
            r"url\(r['\"][^'\"]*\^?([^'\"$]+)",
            r"re_path\(r['\"]([^'\"]+)['\"]",
        ]

        for py_file in target_path.rglob("*.py"):
            try:
                content = py_file.read_text(encoding="utf-8", errors="ignore")

                # Search for Flask routes
                for pattern in flask_patterns:
                    matches = re.findall(pattern, content)
                    endpoints.update(matches)

                # Search for Django URLs
                for pattern in django_patterns:
                    matches = re.findall(pattern, content)
                    endpoints.update(matches)

            except Exception:
                continue

        return endpoints

    async def _find_js_endpoints(self, target_path: Path) -> Set[str]:
        """Find JavaScript/Node.js endpoints"""
        endpoints = set()

        # Express.js, Next.js API routes
        js_patterns = [
            r"app\.get\(['\"]([^'\"]+)['\"]",
            r"app\.post\(['\"]([^'\"]+)['\"]",
            r"app\.put\(['\"]([^'\"]+)['\"]",
            r"app\.delete\(['\"]([^'\"]+)['\"]",
            r"router\.get\(['\"]([^'\"]+)['\"]",
            r"router\.post\(['\"]([^'\"]+)['\"]",
            # Next.js API routes from file structure
        ]

        for js_file in target_path.rglob("*.js"):
            try:
                content = js_file.read_text(encoding="utf-8", errors="ignore")

                for pattern in js_patterns:
                    matches = re.findall(pattern, content)
                    endpoints.update(matches)

            except Exception:
                continue

        # Next.js API routes from file structure
        api_dir = target_path / "pages" / "api"
        if api_dir.exists():
            for api_file in api_dir.rglob("*.js"):
                # Convert file path to API route
                relative_path = api_file.relative_to(api_dir)
                route = "/" + str(relative_path).replace("\\", "/").replace(".js", "")
                endpoints.add(f"/api{route}")

        return endpoints

    async def _find_config_endpoints(self, target_path: Path) -> Set[str]:
        """Find endpoints from configuration files"""
        endpoints = set()

        # OpenAPI/Swagger specs
        for spec_file in target_path.rglob("*.yaml"):
            if (
                "swagger" in spec_file.name.lower()
                or "openapi" in spec_file.name.lower()
            ):
                try:
                    content = spec_file.read_text(encoding="utf-8", errors="ignore")
                    # Simple path extraction - can be enhanced
                    path_matches = re.findall(r"^\s*(/[^:]+):", content, re.MULTILINE)
                    endpoints.update(path_matches)
                except Exception:
                    continue

        return endpoints

    async def _analyze_configuration(self, target_path: Path, result: AgentResult):
        """Analyze configuration files for security insights"""
        print("[RECON] Analyzing configuration files...")

        config_findings = []
        sensitive_patterns = {
            "api_key": r"(api[_-]?key|apikey)\s*[=:]\s*['\"]?([^'\"\\s]+)",
            "password": r"(password|pwd|passwd)\s*[=:]\s*['\"]?([^'\"\\s]+)",
            "secret": r"(secret|token)\s*[=:]\s*['\"]?([^'\"\\s]+)",
            "database_url": r"(database[_-]?url|db[_-]?url)\s*[=:]\s*['\"]?([^'\"\\s]+)",
            "jwt_secret": r"(jwt[_-]?secret|jwtSecret)\s*[=:]\s*['\"]?([^'\"\\s]+)",
        }

        config_files = (
            list(target_path.rglob("*.env"))
            + list(target_path.rglob("config.*"))
            + list(target_path.rglob("settings.*"))
            + list(target_path.rglob(".env*"))
        )

        for config_file in config_files:
            try:
                content = config_file.read_text(encoding="utf-8", errors="ignore")

                for pattern_name, pattern in sensitive_patterns.items():
                    matches = re.findall(pattern, content, re.IGNORECASE)
                    for match in matches:
                        config_findings.append(
                            {
                                "type": "sensitive_config",
                                "pattern": pattern_name,
                                "file": str(config_file.relative_to(target_path)),
                                "severity": "high"
                                if pattern_name in ["password", "secret", "api_key"]
                                else "medium",
                            }
                        )

            except Exception:
                continue

        result.data["configuration_analysis"] = config_findings
        result.findings.extend(config_findings)

    def _is_network_target(self, target: str) -> bool:
        """Check if target is a network address"""
        import socket

        # Simple check for IP or hostname
        try:
            socket.gethostbyname(
                target.replace("http://", "").replace("https://", "").split("/")[0]
            )
            return True
        except:
            return False

    async def _enumerate_services(self, target: str, result: AgentResult):
        """Enumerate network services"""
        print(f"[RECON] Enumerating services for {target}")

        # Basic service enumeration - can be expanded
        services = {}

        # Common ports to check
        common_ports = [
            21,
            22,
            23,
            25,
            53,
            80,
            110,
            143,
            443,
            993,
            995,
            3389,
            5432,
            3306,
            27017,
        ]

        # This is a simplified version - in production would use more sophisticated tools
        for port in common_ports[:5]:  # Limit for demo
            try:
                import socket

                sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                sock.settimeout(1)
                host = (
                    target.replace("http://", "").replace("https://", "").split("/")[0]
                )
                result_code = sock.connect_ex((host, port))
                sock.close()

                if result_code == 0:
                    services[port] = {
                        "status": "open",
                        "service": self._guess_service(port),
                    }

            except Exception:
                continue

        self.services = services
        result.data["services"] = services

        if services:
            result.findings.append(
                {"type": "open_services", "services": services, "severity": "info"}
            )

    def _guess_service(self, port: int) -> str:
        """Guess service based on port"""
        port_services = {
            21: "FTP",
            22: "SSH",
            23: "Telnet",
            25: "SMTP",
            53: "DNS",
            80: "HTTP",
            110: "POP3",
            143: "IMAP",
            443: "HTTPS",
            993: "IMAPS",
            995: "POP3S",
            3389: "RDP",
            5432: "PostgreSQL",
            3306: "MySQL",
            27017: "MongoDB",
        }
        return port_services.get(port, "Unknown")

    async def _ai_enhanced_analysis(self, target_path: Path, result: AgentResult):
        """Use AI to enhance reconnaissance findings"""
        print("[RECON] Performing AI-enhanced analysis...")

        # Build context for AI analysis
        context = {
            "frameworks": list(self.detected_frameworks),
            "endpoints": list(self.discovered_endpoints)[:10],  # Limit for prompt
            "services": self.services,
            "target_type": "directory" if target_path.is_dir() else "file",
        }

        prompt = f"""
Analyze this reconnaissance data for security implications:

Detected Frameworks: {context["frameworks"]}
Discovered Endpoints: {context["endpoints"]}
Open Services: {list(context["services"].keys())}

Provide:
1. Potential attack vectors based on the technology stack
2. Security concerns specific to detected frameworks
3. Recommended security testing focus areas
4. Risk assessment (High/Medium/Low) with reasoning

Format as JSON with keys: attack_vectors, security_concerns, testing_focus, risk_assessment
"""

        try:
            ai_response = await self._get_ai_analysis(prompt, context)

            # Parse AI response (with error handling)
            try:
                import json

                ai_analysis = json.loads(ai_response)

                result.data["ai_analysis"] = ai_analysis

                # Convert AI insights to findings
                if "attack_vectors" in ai_analysis:
                    for vector in ai_analysis["attack_vectors"]:
                        self.attack_vectors.append(vector)
                        result.findings.append(
                            {
                                "type": "ai_attack_vector",
                                "vector": vector,
                                "source": "ai_analysis",
                                "severity": "medium",
                            }
                        )

            except json.JSONDecodeError:
                # If JSON parsing fails, store as text
                result.data["ai_analysis"] = {"raw_response": ai_response}

        except Exception as e:
            print(f"[RECON] AI analysis failed: {e}")
            result.data["ai_analysis_error"] = str(e)

    def _compile_results(self, result: AgentResult):
        """Compile final reconnaissance results"""

        summary = {
            "frameworks_detected": len(self.detected_frameworks),
            "endpoints_discovered": len(self.discovered_endpoints),
            "services_found": len(self.services),
            "attack_vectors_identified": len(self.attack_vectors),
            "total_findings": len(result.findings),
        }

        result.data["summary"] = summary
        result.data["frameworks"] = list(self.detected_frameworks)
        result.data["endpoints"] = list(self.discovered_endpoints)
        result.data["services"] = self.services
        result.data["attack_vectors"] = self.attack_vectors

        # Create high-level finding
        result.findings.append(
            {
                "type": "reconnaissance_summary",
                "summary": summary,
                "severity": "info",
                "description": f"Reconnaissance completed: {summary['frameworks_detected']} frameworks, "
                f"{summary['endpoints_discovered']} endpoints, {summary['services_found']} services detected",
            }
        )
