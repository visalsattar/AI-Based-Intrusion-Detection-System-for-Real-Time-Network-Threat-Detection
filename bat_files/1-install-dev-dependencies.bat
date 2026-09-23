@echo off
setlocal
cd /d "%~dp0"

echo Installing backend Python dependencies...
python -m pip install -r backend\requirements.txt
if errorlevel 1 (
    echo Backend dependency installation failed.
    pause
    exit /b 1
)

echo.
echo Installing frontend npm dependencies...
cd /d "%~dp0frontend"
npm install
if errorlevel 1 (
    echo Frontend dependency installation failed.
    pause
    exit /b 1
)

cd /d "%~dp0"
echo.
echo Backend and frontend dependencies installed successfully.
pause
