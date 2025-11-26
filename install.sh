#!/bin/bash
# Impact-Scan Installation Script for Linux/macOS
# Automatically installs Impact-Scan with all dependencies

set -e

echo "======================================"
echo "Impact-Scan Installation Script"
echo "======================================"
echo ""

# Color codes
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
NC='\033[0m' # No Color

# Detect OS
OS="$(uname -s)"
case "${OS}" in
    Linux*)     MACHINE=Linux;;
    Darwin*)    MACHINE=Mac;;
    *)          MACHINE="UNKNOWN:${OS}"
esac

echo "Detected OS: ${MACHINE}"
echo ""

# Check Python version
echo "Checking Python installation..."
if ! command -v python3 &> /dev/null; then
    echo -e "${RED}Error: Python 3 is not installed${NC}"
    echo "Please install Python 3.9 or higher from https://www.python.org/"
    exit 1
fi

PYTHON_VERSION=$(python3 --version | cut -d' ' -f2)
echo -e "${GREEN}Found Python ${PYTHON_VERSION}${NC}"

# Check if Python version is 3.9+
REQUIRED_VERSION="3.9"
if ! python3 -c "import sys; exit(0 if sys.version_info >= (3, 9) else 1)"; then
    echo -e "${RED}Error: Python 3.9 or higher is required${NC}"
    echo "Current version: ${PYTHON_VERSION}"
    exit 1
fi

echo ""
echo "Choose installation method:"
echo "1) Poetry (recommended for development)"
echo "2) pip (simple installation)"
echo "3) Docker (containerized)"
read -p "Enter choice [1-3]: " choice

case $choice in
    1)
        echo ""
        echo "Installing with Poetry..."

        # Check if Poetry is installed
        if ! command -v poetry &> /dev/null; then
            echo "Poetry not found. Installing Poetry..."
            curl -sSL https://install.python-poetry.org | python3 -

            # Add Poetry to PATH
            export PATH="$HOME/.local/bin:$PATH"

            echo -e "${GREEN}Poetry installed successfully${NC}"
        else
            echo -e "${GREEN}Poetry is already installed${NC}"
        fi

        # Install dependencies
        echo "Installing Impact-Scan dependencies..."
        poetry install --all-extras

        echo ""
        echo -e "${GREEN}Installation complete!${NC}"
        echo ""
        echo "To use Impact-Scan:"
        echo "  poetry run impact-scan --help"
        echo "  poetry run impact-scan scan <path>"
        echo "  poetry run impact-scan web"
        echo ""
        echo "Or activate the virtual environment:"
        echo "  poetry shell"
        echo "  impact-scan --help"
        ;;

    2)
        echo ""
        echo "Installing with pip..."

        # Create virtual environment
        echo "Creating virtual environment..."
        python3 -m venv venv

        # Activate virtual environment
        source venv/bin/activate

        # Upgrade pip
        pip install --upgrade pip

        # Install Impact-Scan
        echo "Installing Impact-Scan..."
        pip install -e .[all]

        # Install external tools
        echo "Installing external security tools..."
        pip install semgrep pip-audit safety

        echo ""
        echo -e "${GREEN}Installation complete!${NC}"
        echo ""
        echo "To use Impact-Scan:"
        echo "  source venv/bin/activate"
        echo "  impact-scan --help"
        echo "  impact-scan scan <path>"
        echo "  impact-scan web"
        echo ""
        echo "Virtual environment created in: ./venv"
        ;;

    3)
        echo ""
        echo "Installing with Docker..."

        # Check if Docker is installed
        if ! command -v docker &> /dev/null; then
            echo -e "${RED}Error: Docker is not installed${NC}"
            echo "Please install Docker from https://www.docker.com/"
            exit 1
        fi

        echo "Building Docker image..."
        docker build -t impact-scan:latest .

        echo ""
        echo -e "${GREEN}Docker installation complete!${NC}"
        echo ""
        echo "To use Impact-Scan with Docker:"
        echo "  docker run -v \$(pwd):/workspace impact-scan scan /workspace"
        echo "  docker run -p 5000:5000 -v \$(pwd):/workspace impact-scan web"
        echo ""
        echo "Or use docker-compose:"
        echo "  docker-compose run scan"
        echo "  docker-compose up web"
        ;;

    *)
        echo -e "${RED}Invalid choice${NC}"
        exit 1
        ;;
esac

echo ""
echo "Optional: Configure API keys for AI-powered features"
echo "Set environment variables:"
echo "  export GROQ_API_KEY='your-key-here'        # Recommended (fastest + free tier)"
echo "  export GOOGLE_API_KEY='your-key-here'      # Gemini (cheapest)"
echo "  export OPENAI_API_KEY='your-key-here'      # GPT models"
echo "  export ANTHROPIC_API_KEY='your-key-here'   # Claude models"
echo ""
echo "Verify installation:"
echo "  impact-scan --version"
echo "  impact-scan doctor  # Health check"
echo ""
echo -e "${GREEN}Installation script completed successfully!${NC}"
