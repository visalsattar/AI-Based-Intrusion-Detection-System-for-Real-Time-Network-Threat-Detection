@echo off
REM start.bat -- double-click this to build and run the entire stack
REM (Redis + Backend + the built-in React frontend) with one click.
REM No need to ever run "npm start" or "npm run build" manually --
REM the frontend is compiled inside the Docker image automatically.

cd /d "%~dp0"

echo ============================================
echo  AI-IDS Command Center - Starting Stack
echo ============================================
echo.
echo Building images and starting Redis + Backend...
echo (First run takes a few minutes - installs npm packages,
echo  builds the React app, and installs Python dependencies.)
echo.

docker-compose up --build

echo.
echo ============================================
echo  Stack stopped. Press any key to close.
echo ============================================
pause >nul
