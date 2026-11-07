@echo off
REM Starts the Marty status dashboard on this PC, by hand. Normally you do not
REM need this: the "Marty Services" scheduled task supervises it and restarts it
REM within seconds if it dies. It listens on 127.0.0.1:8765 only; phones reach it
REM over the tailnet at https://{{TAILNET_HOST}} (tailscale serve). It is
REM not reachable from the home WiFi by IP, and must never be port-forwarded.

cd /d "%~dp0"
echo Starting Marty dashboard...
python server.py
pause
