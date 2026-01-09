.PHONY: help install install-python install-frontend build-frontend dev test lint format clean ci check-uv check-node

# Configuration
FRONTEND_DIR := semgrepai/web/frontend
PYTHON := uv run python
PYTEST := uv run pytest
RUFF := uv run ruff
BLACK := uv run black
MYPY := uv run mypy

# Colors for output
GREEN := \033[0;32m
YELLOW := \033[0;33m
RED := \033[0;31m
NC := \033[0m

help:
	@echo "SemgrepAI Development Commands"
	@echo "==============================="
	@echo ""
	@echo "Setup:"
	@echo "  make install          - Install Python + Frontend (single command)"
	@echo "  make install-python   - Install Python dependencies only"
	@echo "  make install-frontend - Install and build frontend"
	@echo ""
	@echo "Development:"
	@echo "  make dev              - Start web server (development mode)"
	@echo "  make build-frontend   - Build frontend for production"
	@echo ""
	@echo "Quality:"
	@echo "  make test             - Run all tests"
	@echo "  make test-unit        - Run unit tests only (fast, no API calls)"
	@echo "  make test-e2e         - Run E2E tests (slow, real LLM calls)"
	@echo "  make lint             - Run linters (Python + Frontend)"
	@echo "  make format           - Format code (Python + Frontend)"
	@echo ""
	@echo "Utilities:"
	@echo "  make clean            - Remove build artifacts"
	@echo "  make ci               - Run CI pipeline locally"
	@echo ""

# Main install target
install: check-uv check-node install-python install-frontend
	@echo "$(GREEN)Installation complete!$(NC)"
	@echo ""
	@echo "Activate the virtual environment:"
	@echo "  source .venv/bin/activate"
	@echo ""
	@echo "Start the server:"
	@echo "  semgrepai server"

# Install Python dependencies
install-python: check-uv
	@echo "$(YELLOW)Installing Python dependencies...$(NC)"
	uv sync --all-extras
	@echo "$(GREEN)Python dependencies installed$(NC)"

# Install and build frontend
install-frontend: check-node
	@echo "$(YELLOW)Installing frontend dependencies...$(NC)"
	cd $(FRONTEND_DIR) && npm ci
	@echo "$(YELLOW)Building frontend...$(NC)"
	cd $(FRONTEND_DIR) && npm run build
	@echo "$(GREEN)Frontend built$(NC)"

# Build frontend only
build-frontend: check-node
	@echo "$(YELLOW)Building frontend...$(NC)"
	cd $(FRONTEND_DIR) && npm run build

# Development server
dev: check-uv
	@echo "$(YELLOW)Starting development server...$(NC)"
	$(PYTHON) -m semgrepai.cli server

# Run all tests
test: check-uv
	@echo "$(YELLOW)Running tests...$(NC)"
	$(PYTEST) tests/ -v --cov=semgrepai --cov-report=term-missing

# Run unit tests only (fast, no external deps)
test-unit: check-uv
	@echo "$(YELLOW)Running unit tests...$(NC)"
	$(PYTEST) tests/unit -v -m "unit"

# Run integration tests
test-integration: check-uv
	@echo "$(YELLOW)Running integration tests...$(NC)"
	$(PYTEST) tests/integration -v -m "integration"

# Run E2E tests (slow, costs money)
test-e2e: check-uv
	@echo "$(YELLOW)Running E2E tests (this will make real LLM API calls)...$(NC)"
	$(PYTEST) tests/e2e -v -m "e2e"

# Lint all code
lint: check-uv
	@echo "$(YELLOW)Linting Python...$(NC)"
	$(RUFF) check semgrepai/
	$(MYPY) semgrepai/ || true
	@if [ -f "$(FRONTEND_DIR)/package.json" ]; then \
		echo "$(YELLOW)Linting Frontend...$(NC)"; \
		cd $(FRONTEND_DIR) && npm run lint || true; \
	fi

# Format all code
format: check-uv
	@echo "$(YELLOW)Formatting Python...$(NC)"
	$(BLACK) semgrepai/ tests/
	$(RUFF) check --fix semgrepai/ tests/

# Clean build artifacts
clean:
	@echo "$(YELLOW)Cleaning build artifacts...$(NC)"
	rm -rf dist/ build/ *.egg-info .pytest_cache .coverage htmlcov .mypy_cache .ruff_cache
	rm -rf $(FRONTEND_DIR)/dist
	find . -type d -name __pycache__ -exec rm -rf {} + 2>/dev/null || true
	@echo "$(GREEN)Clean complete$(NC)"

# Deep clean (includes node_modules and venv)
clean-all: clean
	@echo "$(YELLOW)Deep cleaning...$(NC)"
	rm -rf .venv $(FRONTEND_DIR)/node_modules
	@echo "$(GREEN)Deep clean complete$(NC)"

# CI pipeline
ci: check-uv check-node
	@echo "$(YELLOW)Running CI pipeline...$(NC)"
	@echo ""
	@echo "Step 1: Install dependencies"
	@make install
	@echo ""
	@echo "Step 2: Lint"
	@make lint
	@echo ""
	@echo "Step 3: Test (unit tests only for CI)"
	@make test-unit
	@echo ""
	@echo "$(GREEN)CI pipeline complete$(NC)"

# Lock dependencies
lock: check-uv
	@echo "$(YELLOW)Locking dependencies...$(NC)"
	uv lock
	@echo "$(GREEN)Dependencies locked$(NC)"

# Check UV is installed
check-uv:
	@command -v uv >/dev/null 2>&1 || { \
		echo "$(RED)ERROR: uv is not installed.$(NC)"; \
		echo ""; \
		echo "Install with:"; \
		echo "  curl -LsSf https://astral.sh/uv/install.sh | sh"; \
		echo ""; \
		echo "Or visit: https://docs.astral.sh/uv/getting-started/installation/"; \
		exit 1; \
	}

# Check Node.js is installed
check-node:
	@command -v npm >/dev/null 2>&1 || { \
		echo "$(RED)ERROR: Node.js/npm is not installed.$(NC)"; \
		echo ""; \
		echo "Install from: https://nodejs.org/"; \
		exit 1; \
	}
