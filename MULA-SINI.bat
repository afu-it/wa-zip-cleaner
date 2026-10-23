@echo off
title WA-ZIP Cleaner - Imbas & Bersih
cd /d "%~dp0"

REM Minta kebenaran admin (auto)
net session >nul 2>&1 || (powershell -NoProfile -Command "Start-Process -FilePath '%~f0' -Verb RunAs" & exit /b)

cls
echo ============================================================
echo    WA-ZIP CLEANER  -  satu klik je
echo ============================================================
echo.
echo  Langkah 1: IMBAS komputer (boleh ambil 2-10 minit)
echo  Jangan tutup tetingkap ni. Tunggu je.
echo.
powershell -NoProfile -ExecutionPolicy Bypass -File "%~dp0wa-zip-cleaner.ps1"
set SCANRESULT=%errorlevel%

echo.
if "%SCANRESULT%"=="0" (
  echo ============================================================
  echo   BERSIH! Tiada malware dijumpai. Komputer anda selamat.
  echo ============================================================
  echo.
  pause
  exit /b
)

echo ============================================================
echo   BAHAYA DIJUMPAI di atas.
echo ============================================================
echo.
echo  Nak saya bersihkan sekarang?
echo  (fail jahat akan dialih ke C:\WAZipQuarantine, bukan dipadam terus)
echo.
set /p ANS=  Taip  Y  dan tekan Enter untuk BERSIHKAN (atau tutup tetingkap untuk batal):

if /i not "%ANS%"=="Y" (
  echo.
  echo  Dibatalkan. Tiada apa diubah.
  pause
  exit /b
)

echo.
echo  Langkah 2: MEMBERSIHKAN...
echo.
powershell -NoProfile -ExecutionPolicy Bypass -File "%~dp0wa-zip-cleaner.ps1" -Fix

echo.
echo ============================================================
echo   SIAP MEMBERSIH.
echo ============================================================
echo.
echo  PENTING, buat ni sekarang:
echo    1. RESTART komputer (matikan dan hidupkan semula).
echo    2. Lepas hidup balik, double-click fail MULA-SINI.bat ni
echo       SEKALI LAGI, sampai keluar perkataan BERSIH.
echo    3. Dari TELEFON: WhatsApp ^> Peranti dipaut ^> Log keluar semua.
echo    4. Tukar kata laluan bank online dan emel.
echo.
pause
