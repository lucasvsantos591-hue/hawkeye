#!/bin/bash

# VRA Quick Start Script

set -e

echo "🚀 Vulnerability Reachability Analyzer - Quick Start"
echo "======================================================"
echo ""

# Check dependencies
echo "📋 Checking dependencies..."

if ! command -v dart &> /dev/null; then
    echo "❌ Dart not found. Install from https://dart.dev/get-dart"
    exit 1
fi

if ! command -v node &> /dev/null; then
    echo "❌ Node.js not found. Install from https://nodejs.org"
    exit 1
fi

if ! command -v python3 &> /dev/null; then
    echo "❌ Python 3 not found. Install from https://python.org"
    exit 1
fi

echo "✅ All dependencies found!"
echo ""

# Install dependencies
echo "📦 Installing dependencies..."
echo ""

echo "  → Dart dependencies..."
cd core
dart pub get
cd ..

echo "  → Node.js dependencies..."
npm install

echo "  → Python dependencies..."
pip install -r requirements.txt

echo ""
echo "✅ Dependencies installed successfully!"
echo ""

# Build
echo "🔨 Building project..."
npm run build

echo ""
echo "✅ Build complete!"
echo ""

# Summary
echo "======================================================"
echo "🎉 VRA is ready to use!"
echo ""
echo "Quick commands:"
echo "  npm run dev       - Watch mode for development"
echo "  make test         - Run all tests"
echo "  make dev-up       - Start dev services (Docker)"
echo "  vra analyze       - Analyze a project"
echo ""
echo "📚 Full documentation: PROJECT_STRUCTURE.md"
echo "🌐 VS Code:          code ."
echo ""
