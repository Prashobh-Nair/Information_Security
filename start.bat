@echo off
cd /d "%~dp0"
title NetSecure - Exercise 12 Server

echo ====================================================================
echo   NetSecure: Real Hardware Telemetry ^& Wireshark Sniffer Lab
echo ====================================================================
echo.

:: 1. Free port 5000 if an old background process is holding it
for /f "tokens=5" %%a in ('netstat -aon ^| findstr /r ":5000.*LISTENING"') do (
    echo [Info] Freeing busy port 5000 (Process ID %%a)...
    taskkill /f /pid %%a >nul 2>&1
)

:: 2. Auto-detect current active Wi-Fi / LAN IP dynamically
set "LOCAL_IP=localhost"
for /f %%i in ('python -c "import socket; s=socket.socket(socket.AF_INET,socket.SOCK_DGRAM); s.connect(('8.8.8.8',80)); print(s.getsockname()[0]); s.close()" 2^>nul') do (
    set "LOCAL_IP=%%i"
)

echo [Status] NetSecure Server is starting...
echo.
echo   - Access on this Laptop:     http://localhost:5000
echo   - Access on Phone / Laptop B: http://%LOCAL_IP%:5000
echo.
echo ====================================================================
echo.

:: 3. Open browser after 2 seconds so server is fully bound
start "" cmd /c "timeout /t 2 /nobreak >nul && start http://localhost:5000"

:: 4. Start Uvicorn Server
python -m uvicorn backend.app:app --host 0.0.0.0 --port 5000

echo.
echo Server stopped.
pause
