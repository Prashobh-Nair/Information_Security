@echo off
title NetSecure - Exercise 12 Server
echo ==============================================================
echo  NetSecure: Real Hardware Telemetry & Wireshark Sniffer Lab
echo  Bound to: http://192.168.1.6:5000  ^|  http://localhost:5000
echo ==============================================================
start http://192.168.1.6:5000
python -m uvicorn backend.app:app --host 0.0.0.0 --port 5000 --reload
pause
