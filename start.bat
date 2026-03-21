@echo off
title 1337APP - AI Security Agent
color 0A
echo.
echo   ██╗██████╗ ██████╗ ███████╗ █████╗ ██████╗ ██████╗
echo   ██║╚════██╗╚════██╗╚════██║██╔══██╗██╔══██╗██╔══██╗
echo   ██║ █████╔╝ █████╔╝    ██╔╝███████║██████╔╝██████╔╝
echo   ██║ ╚═══██╗ ╚═══██╗   ██╔╝ ██╔══██║██╔═══╝ ██╔═══╝
echo   ██║██████╔╝██████╔╝   ██║  ██║  ██║██║     ██║
echo   ╚═╝╚═════╝ ╚═════╝    ╚═╝  ╚═╝  ╚═╝╚═╝     ╚═╝
echo.
echo   AI Security Analysis Agent
echo   ============================
echo.

cd /d "%~dp0"

echo [1/4] Installing backend dependencies...
pip install -r backend\requirements.txt -q 2>nul
echo [OK] Backend dependencies ready.
echo.

echo [2/4] Installing frontend dependencies...
cd frontend
call npm install --silent 2>nul
echo [OK] Frontend dependencies ready.
echo.

echo [3/4] Building frontend...
call npm run build --silent 2>nul
echo [OK] Frontend built.
echo.
cd /d "%~dp0"

echo [4/4] Starting backend on http://localhost:8000 ...
start /b "" python -m uvicorn backend.main:app --host 127.0.0.1 --port 8000 >nul 2>&1

timeout /t 3 /nobreak >nul

echo.
echo ============================================
echo   1337APP is running!
echo   Open: http://localhost:8000
echo   Press any key to stop...
echo ============================================
echo.

start http://localhost:8000

pause >nul

taskkill /f /im python.exe /fi "WINDOWTITLE eq *uvicorn*" >nul 2>&1
echo [*] Stopped.
