@echo off
REM STEP 3 - start live packet capture (needs step 2 running, Npcap installed).
REM It asks for Administrator permission by itself.
cd /d "%~dp0.."
echo Which Random Forest model?
echo   1 = default CICIDS2017 DDoS model (recommended for the flood demo)
echo   2 = multiday_v2 (multi-class: also PortScan etc.)
set /p M=Choose 1 or 2 [1]: 
set RF=
if "%M%"=="2" set RF=-RfDir multiday_v2
where pwsh >nul 2>nul && (set PS=pwsh) || (set PS=powershell)
%PS% -NoProfile -ExecutionPolicy Bypass -File "%CD%\start-capture.ps1" %RF%
echo A new Administrator window runs the capture. Keep it open during the demo.
pause
