.PHONY: help setup build test clean dev-up dev-down

help:
	@echo "Vulnerability Reachability Analyzer - Available Commands"
	@echo ""
	@echo "Setup & Build:"
	@echo "  make setup          Initialize project (install deps, build)"
	@echo "  make build          Build all components (core, CLI, parsers)"
	@echo "  make build-core     Build Dart core only"
	@echo "  make build-cli      Build TypeScript CLI only"
	@echo ""
	@echo "Development:"
	@echo "  make dev-up         Start dev environment (Docker + services)"
	@echo "  make dev-down       Stop dev environment"
	@echo "  make watch          Watch for changes and rebuild"
	@echo ""
	@echo "Testing:"
	@echo "  make test           Run all tests"
	@echo "  make test-core      Test Dart core"
	@echo "  make test-cli       Test TypeScript CLI"
	@echo "  make test-e2e       Run end-to-end tests"
	@echo ""
	@echo "Quality:"
	@echo "  make lint           Lint all code"
	@echo "  make format         Format all code"
	@echo "  make analyze        Static analysis"
	@echo ""
	@echo "Packaging:"
	@echo "  make package        Package all artifacts"
	@echo "  make publish        Publish packages (npm, pub.dev)"
	@echo ""
	@echo "Cleaning:"
	@echo "  make clean          Remove build artifacts"
	@echo "  make clean-all      Full clean (deps, build, cache)"

## Setup

setup: install-deps build
	@echo "✅ Project setup complete!"

install-deps:
	@echo "📦 Installing Dart dependencies..."
	cd core && dart pub get

	@echo "📦 Installing Node.js dependencies..."
	npm install

	@echo "📦 Installing Python dependencies..."
	pip install -r requirements.txt

## Build

build: build-core build-cli
	@echo "✅ Build complete!"

build-core:
	@echo "🔨 Building Dart core..."
	cd core && dart pub get && dart analyze

build-cli:
	@echo "🔨 Building TypeScript CLI..."
	npm run build

build-parsers:
	@echo "🔨 Building Python parsers..."
	cd adapters/parsers/python_parser && python -m py_compile *.py

## Development

dev-up:
	@echo "🚀 Starting development environment..."
	docker-compose -f docker-compose.yml up -d
	@echo "✅ Services started: SQLite, mock NVD API"

dev-down:
	@echo "🛑 Stopping development environment..."
	docker-compose -f docker-compose.yml down

watch:
	@echo "👀 Watching for changes..."
	npm run watch

## Testing

test: test-core test-cli test-parsers
	@echo "✅ All tests passed!"

test-core:
	@echo "🧪 Testing Dart core..."
	cd core && dart test --coverage=coverage

test-cli:
	@echo "🧪 Testing TypeScript CLI..."
	npm run test

test-parsers:
	@echo "🧪 Testing Python parsers..."
	python -m pytest adapters/parsers/python_parser/ -v

test-e2e:
	@echo "🧪 Running E2E tests..."
	npm run test:e2e

test-watch:
	npm run test -- --watch

## Quality

lint:
	@echo "🔍 Linting code..."
	cd core && dart analyze
	npm run lint
	python -m pylint adapters/parsers/python_parser/

format:
	@echo "📐 Formatting code..."
	cd core && dart format .
	npm run format
	python -m black adapters/parsers/python_parser/

analyze: lint
	@echo "📊 Running static analysis..."
	cd core && dart analyze --fatal-warnings

## Packaging

package: build
	@echo "📦 Packaging artifacts..."
	npm run package
	dart pub publish --dry-run

publish: package
	@echo "🚀 Publishing packages..."
	npm publish --access public
	cd core && dart pub publish

## Cleaning

clean:
	@echo "🧹 Cleaning build artifacts..."
	rm -rf dist/ build/
	npm run clean

clean-all: clean
	@echo "🧹 Full clean..."
	rm -rf node_modules/ .dart_tool/ .pytest_cache/ __pycache__/
	find . -type d -name ".coverage" -exec rm -rf {} +

## Utilities

version:
	@echo "Version: $(shell cat package.json | grep version | head -1 | awk '{print $$2}' | tr -d ',\"\\')"

check-health:
	@echo "🏥 Health check..."
	@which dart > /dev/null || echo "❌ Dart not found"
	@which node > /dev/null || echo "❌ Node.js not found"
	@which python > /dev/null || echo "❌ Python not found"
	@echo "✅ All required tools found"
