@echo off
setlocal
if not exist "mqtt\data" mkdir "mqtt\data"
if not exist "mqtt\log" mkdir "mqtt\log"
mosquitto -c mqtt\mosquitto.conf -v
endlocal
