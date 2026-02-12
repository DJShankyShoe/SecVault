@echo off
REM ========================================
REM SecVault v3.0 - Windows Start Script
REM ========================================

echo.
echo ========================================
echo   SecVault v3.0 - Secure File Sharing
echo ========================================
echo.

REM Check if Python is installed
python --version >nul 2>&1
if errorlevel 1 (
    echo [ERROR] Python is not installed or not in PATH
    echo.
    echo Please install Python 3.8 or higher from:
    echo https://www.python.org/downloads/
    echo.
    echo Make sure to check "Add Python to PATH" during installation
    pause
    exit /b 1
)

echo [OK] Python found
python --version
echo.

REM Check if we're in the correct directory
if not exist "server\server.py" (
    echo [ERROR] server\server.py not found
    echo.
    echo Please run this script from the secvault_v3_modular directory
    pause
    exit /b 1
)

echo [OK] Project structure verified
echo.

REM Install dependencies
echo Installing dependencies...
echo.
pip install -r requirements.txt
if errorlevel 1 (
    echo.
    echo [ERROR] Failed to install dependencies
    pause
    exit /b 1
)

echo.
echo [OK] Dependencies installed
echo.
echo ========================================
echo   Starting SecVault Server
echo ========================================
echo.
echo Server will run on: http://127.0.0.1:5000
echo.
echo Press Ctrl+C to stop the server
echo.
echo ========================================
echo.

REM Change to server directory and run
cd server
python server.py

REM If server exits, pause to see any error messages
echo.
echo.
echo Server stopped.
pause
