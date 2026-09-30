@echo off
cd /d "%~dp0..\backend"

echo Starting Python backend on port 5000...
python main.py

pause