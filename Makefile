.PHONY: install dev test clean help

# Default target
.DEFAULT_GOAL := help

install: ## Install dependencies using uv and yarn
	@echo "Installing backend dependencies..."
	@uv pip install -r pyproject.toml
	@echo "Installing frontend dependencies..."
	@cd frontend && yarn install

dev: ## Run the application in development mode (backend + frontend)
	@echo "Starting development servers..."
	@# Trap SIGINT to kill child processes on Ctrl+C
	@trap 'kill 0' SIGINT; \
	uv run uvicorn app:app --host 0.0.0.0 --port 8000 & \
	cd frontend && yarn dev --port 5173 & \
	wait

test: ## Run backend tests
	@uv run pytest

lint: ## Run linting (ruff for backend, eslint for frontend)
	@echo "Linting backend..."
	@uv run ruff check .
	@echo "Linting frontend..."
	@cd frontend && yarn lint || echo "Add 'lint' script to package.json first"

format: ## Format code (ruff for backend, prettier for frontend)
	@echo "Formatting backend..."
	@uv run ruff format .
	@echo "Formatting frontend..."
	@cd frontend && npx prettier --write "src/**/*.{ts,tsx,css}"

docker-up: ## Start Docker Compose services
	@docker-compose up -d --build

docker-down: ## Stop Docker Compose services
	@docker-compose down

clean: ## Remove build artifacts and temporary files
	@rm -rf .venv
	@rm -rf frontend/node_modules
	@find . -type d -name "__pycache__" -exec rm -rf {} +

help: ## Show this help message
	@grep -E '^[a-zA-Z_-]+:.*?## .*$$' $(MAKEFILE_LIST) | sort | awk 'BEGIN {FS = ":.*?## "}; {printf "\033[36m%-15s\033[0m %s\n", $$1, $$2}'
