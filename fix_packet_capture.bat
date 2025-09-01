@echo off
echo ========================================
echo DoS/DDoS Attack Detector - Packet Capture Fix
echo ========================================
echo.
echo This script will fix packet capture issues on Windows.
echo.
echo IMPORTANT: You must run this as Administrator!
echo.
echo To run as Administrator:
echo 1. Right-click on this batch file
echo 2. Select "Run as Administrator"
echo.
echo If you're not running as Administrator, this will fail.
echo.
pause

echo.
echo Checking if running as Administrator...
net session >nul 2>&1
if %errorLevel% == 0 (
    echo [OK] Running as Administrator
    echo.
    echo Starting packet capture fix...
    python fix_packet_capture.py
) else (
    echo [ERROR] Not running as Administrator!
    echo.
    echo Please:
    echo 1. Right-click on this batch file
    echo 2. Select "Run as Administrator"
    echo 3. Run it again
    echo.
    pause
    exit /b 1
)

echo.
echo Fix script completed!
echo.
pause
