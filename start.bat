@echo off
cd /d "%~dp0"
title NetSecure - Exercise 12 Server
python run.py
if errorlevel 1 pause
