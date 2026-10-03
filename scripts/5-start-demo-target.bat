@echo off
REM STEP 5 - start the port 8080 target that the phone will flood. Keep this window open.
cd /d "%~dp0.."
echo Laptop IP addresses (use the Wi-Fi/Ethernet one on the same network as the phone):
ipconfig | findstr /i "IPv4"
echo.
echo If Windows Firewall asks, click Allow (Private networks).
python demo\listener_8080.py
pause
