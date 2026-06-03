@echo off
for /f "tokens=2" %%a in ('tasklist ^| findstr /i mosquitto.exe') do taskkill /PID %%a /F
