@echo off
REM Run the backend test suite (no Docker needed).
cd /d "%~dp0..\backend"
python -m pytest tests -q
pause
