@echo off
setlocal

REM This file lives in "bat files", so move to the project root first.
cd /d "%~dp0.."

echo ============================================
echo  AI-IDS Capture Demo Helper
echo ============================================
echo.
echo This window starts Docker Redis + Dashboard.
echo Dashboard URL: http://localhost:5000
echo.
echo After Docker is ready, open a NEW PowerShell window as Administrator
echo and run:
echo.
echo   cd %CD%
echo   .\start-capture.ps1
echo.
echo Keep both windows open during the demo.
echo.
echo To generate benign web traffic later, run this in a third PowerShell window:
echo.
echo   1..20 ^| ForEach-Object { Invoke-WebRequest https://example.com -TimeoutSec 10 ^| Out-Null }
echo.
echo Evidence appears in:
echo   backend\evidence\alerts.jsonl
echo   backend\evidence\threat-*.png
echo.
echo Starting Docker now...
echo.

docker compose up

echo.
echo ============================================
echo  Docker stopped. Press any key to close.
echo ============================================
pause >nul
