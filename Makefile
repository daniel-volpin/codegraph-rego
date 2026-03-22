.PHONY: install backend-dev dev test lint format neo4j-up neo4j-down docker-up docker-down clean help

# Default target
.DEFAULT_GOAL := help

install: ## Install dependencies using uv and yarn
	@chmod +x scripts/setup_benchmark_env.sh
	@./scripts/setup_benchmark_env.sh
	@echo "Installing frontend dependencies..."
	@cd frontend && yarn install

backend-dev: ## Start Neo4j via Docker Compose and run the backend locally
	@./scripts/start_backend_dev.sh

dev: ## Run the application in development mode (backend + frontend)
	@echo "Starting development servers..."
	@backend_pid=''; frontend_pid=''; \
	trap 'status=$$?; trap - INT TERM EXIT; if [ -n "$$backend_pid" ]; then kill "$$backend_pid" 2>/dev/null || true; fi; if [ -n "$$frontend_pid" ]; then kill "$$frontend_pid" 2>/dev/null || true; fi; wait "$$backend_pid" 2>/dev/null || true; wait "$$frontend_pid" 2>/dev/null || true; exit $$status' INT TERM EXIT; \
	./scripts/start_backend_dev.sh & backend_pid=$$!; \
	cd frontend && yarn dev --port 5173 & frontend_pid=$$!; \
	while kill -0 "$$backend_pid" 2>/dev/null && kill -0 "$$frontend_pid" 2>/dev/null; do \
		sleep 1; \
	done; \
	backend_status=0; frontend_status=0; backend_exited=0; frontend_exited=0; \
	if ! kill -0 "$$backend_pid" 2>/dev/null; then backend_exited=1; wait "$$backend_pid" || backend_status=$$?; fi; \
	if ! kill -0 "$$frontend_pid" 2>/dev/null; then frontend_exited=1; wait "$$frontend_pid" || frontend_status=$$?; fi; \
	if [ "$$backend_exited" -eq 1 ]; then \
		if [ "$$backend_status" -eq 0 ]; then backend_status=1; fi; \
		echo "Backend development process exited with status $$backend_status." >&2; \
		exit "$$backend_status"; \
	fi; \
	if [ "$$frontend_exited" -eq 1 ]; then \
		if [ "$$frontend_status" -eq 0 ]; then frontend_status=1; fi; \
		echo "Frontend development process exited with status $$frontend_status." >&2; \
		exit "$$frontend_status"; \
	fi

test: ## Run backend tests
	@uv run python -m pytest -q

policy-check: ## Validate OPA/Rego policies
	@opa check --strict policy/
	@opa fmt -w policy/

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

neo4j-up: ## Start the local Neo4j dependency only
	@./scripts/dev_container.sh compose up -d neo4j

neo4j-down: ## Stop the local Neo4j dependency
	@./scripts/dev_container.sh compose stop neo4j

docker-up: ## Start Docker Compose services
	@./scripts/dev_container.sh compose up -d --build

docker-down: ## Stop Docker Compose services
	@./scripts/dev_container.sh compose down

clean: ## Remove build artifacts and temporary files
	@echo "Removing Python caches..."
	@find . -type d -name "__pycache__" -prune -exec rm -rf {} +
	@echo "Removing pytest caches..."
	@find . -type d -name ".pytest_cache" -prune -exec rm -rf {} +

help: ## Show this help message
	@grep -E '^[a-zA-Z_-]+:.*?## .*$$' $(MAKEFILE_LIST) | sort | awk 'BEGIN {FS = ":.*?## "}; {printf "\033[36m%-15s\033[0m %s\n", $$1, $$2}'
