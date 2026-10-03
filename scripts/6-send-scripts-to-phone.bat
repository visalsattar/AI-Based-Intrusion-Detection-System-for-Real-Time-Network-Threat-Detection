@echo off
REM STEP 6 (optional, once) - lets the phone download lab_flood.py / lab_benign.py.
cd /d "%~dp0..\demo"
ipconfig | findstr /i "IPv4"
echo.
echo In Termux on the phone run (replace LAPTOP-IP):
echo   python -c "import urllib.request as u;[u.urlretrieve(f\"http://LAPTOP-IP:8081/{f}\",f) for f in (\"lab_flood.py\",\"lab_benign.py\")]"
echo.
echo Then the attack:   python lab_flood.py LAPTOP-IP --seconds 60 --rate 220
echo Normal traffic:    python lab_benign.py LAPTOP-IP --seconds 60
echo Close this window when the phone has the files.
python -m http.server 8081
pause
