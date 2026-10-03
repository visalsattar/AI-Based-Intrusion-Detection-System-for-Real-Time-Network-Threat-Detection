@echo off
REM Stop Redis + dashboard containers. Close the capture window with Ctrl+C.
cd /d "%~dp0.."
docker compose down
pause
