@echo off
REM STEP 4 - open the dashboard (uses IDS_API_TOKEN from .env if set).
cd /d "%~dp0.."
where pwsh >nul 2>nul && (set PS=pwsh) || (set PS=powershell)
%PS% -NoProfile -ExecutionPolicy Bypass -File "%CD%\open-dashboard.ps1"
