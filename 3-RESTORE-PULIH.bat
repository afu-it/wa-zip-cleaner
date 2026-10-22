@echo off
cd /d "%~dp0"
net session >nul 2>&1 || (powershell -NoProfile -Command "Start-Process -FilePath '%~f0' -Verb RunAs" & exit /b)
echo Tampal laluan manifest.json (contoh C:\WAZipQuarantine\20261022-210000\manifest.json)
echo Paste the path to manifest.json
set /p M=^> 
powershell -NoProfile -ExecutionPolicy Bypass -File "%~dp0wa-zip-cleaner.ps1" -Restore -Manifest "%M%"
pause
