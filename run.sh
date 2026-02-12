#!/bin/bash

echo "═══════════════════════════════════════════════════════════"
echo "  SecVault v3.0 — Setup & Run Script"
echo "═══════════════════════════════════════════════════════════"
echo ""

# Check Python
if ! command -v python3 &> /dev/null; then
    echo "❌ Python 3 not found. Please install Python 3.8+"
    exit 1
fi

echo "✓ Python 3 found"

# Install dependencies
echo ""
echo "📦 Installing dependencies..."
pip install -q flask 2>/dev/null || pip3 install -q flask 2>/dev/null

if [ $? -ne 0 ]; then
    echo "❌ Failed to install Flask. Try manually: pip install flask"
    exit 1
fi

echo "✓ Flask installed"

# Check structure
echo ""
echo "📁 Checking file structure..."
if [ ! -f "server/server.py" ]; then
    echo "❌ server/server.py not found!"
    exit 1
fi

if [ ! -d "static/js" ]; then
    echo "❌ static/js directory not found!"
    exit 1
fi

if [ ! -d "templates" ]; then
    echo "❌ templates directory not found!"
    exit 1
fi

echo "✓ All files present"

# Run server
echo ""
echo "═══════════════════════════════════════════════════════════"
echo "  🚀 Starting SecVault v3.0"
echo "═══════════════════════════════════════════════════════════"
echo ""
echo "  Open in browser:"
echo "  → http://127.0.0.1:5000"
echo ""
echo "  Press Ctrl+C to stop"
echo ""
echo "═══════════════════════════════════════════════════════════"
echo ""

cd server
python3 server.py
