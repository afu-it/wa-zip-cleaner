# WA-ZIP Cleaner

Pengimbas & pembersih percuma untuk PC Windows yang terbuka fail **"Click here to view....zip"** dari WhatsApp.
Free scanner & cleaner for Windows PCs that opened the WhatsApp **"Click here to view....zip"** file.

> Mac, iPhone dan Android **tidak** terjejas. Fail ini hanya berfungsi di Windows.
> Mac, iPhone and Android are **not** affected. This file only works on Windows.

**Bukti & analisis penuh (screenshot VirusTotal + Triage):** [docs/REPORT.md](docs/REPORT.md)

---

## Bahasa Melayu

### Saya kena ke?
Anda mungkin kena jika:
- Anda terima fail `.zip` dalam WhatsApp (selalunya dari kawan yang akaunnya dah dicuri), dan
- anda **buka** fail itu di komputer Windows (selalunya muncul "pendrive" baru bila didouble-click).

### Cara guna (5 minit)
1. Tekan butang hijau **Code** > **Download ZIP** di atas, kemudian extract (Extract All).
2. Double-click **`1-SCAN-IMBAS.bat`**. Tekan **Yes** bila Windows minta kebenaran.
3. Tunggu 2–10 minit. Keputusan:
   - **BERSIH**: tiada apa perlu dibuat.
   - **HIGH / bahaya**: teruskan ke langkah 4.
4. Double-click **`2-CLEAN-BERSIH.bat`**. Fail jahat akan dialih ke `C:\WAZipQuarantine` (tidak dipadam terus).
5. **Restart PC**, kemudian jalankan `1-SCAN-IMBAS.bat` sekali lagi sehingga keluar BERSIH.

### Selepas bersih, WAJIB buat ni (dari telefon atau PC lain)
1. WhatsApp telefon > **Peranti dipaut** > **Log keluar semua peranti**.
2. Tukar kata laluan **bank online** dan **emel**.
3. Beritahu kawan-kawan: jangan buka fail .zip yang dihantar dari nombor anda.

### Kalau tersalah buang
Double-click `3-RESTORE-PULIH.bat` dan tampal laluan `manifest.json` yang dipaparkan semasa membersih.

### Had alat ini
- Malware ini memasang **driver yang mematikan antivirus**. Kalau alat ini jumpa driver tersebut, cara paling selamat ialah **backup data dan pasang semula Windows**.
- Alat ini mengesan versi yang kami bedah (Oktober 2026). Versi baru mungkin berbeza.

---

## English

### Am I affected?
Possibly, if you received a `.zip` file on WhatsApp (often from a friend whose account was hijacked) **and opened it on a Windows PC** (a new "drive" usually appears).

### How to use (5 minutes)
1. Click the green **Code** button > **Download ZIP**, then Extract All.
2. Double-click **`1-SCAN-IMBAS.bat`** and click **Yes** on the Windows prompt.
3. Wait 2–10 minutes. **CLEAN** means nothing to do. **HIGH** means continue.
4. Double-click **`2-CLEAN-BERSIH.bat`**. Malicious items are moved to `C:\WAZipQuarantine` (not deleted outright).
5. **Restart the PC** and scan again until it says CLEAN.

### After cleaning (from another device)
1. WhatsApp on your phone > **Linked devices** > **Log out from all devices**.
2. Change your **online banking** and **email** passwords.
3. Warn your contacts not to open ZIP files sent from your number.

### Undo
Run `3-RESTORE-PULIH.bat` and paste the `manifest.json` path printed during cleaning.

### Limits
- The malware installs **antivirus-killing drivers**. If they are found, the safest option is to **back up your data and reinstall Windows**.
- Detection covers the variant analysed in October 2026. New variants may differ.

---

## What it checks

| # | Check | Examples |
|---|---|---|
| 1 | Running processes | `rundll32 ... ,_vmclientcore@16`, fake `rime.dll` loaded outside Program Files |
| 2 | Mounted virtual disks | `Click here to view*.vhd` |
| 3 | Registry | `HKCU\Console\0`, `HKCU\Console\1`, `Console\IpDate`, `IpDates_info` |
| 4 | Drivers / services | `ZyArk`, `ardrv` outside OPSWAT folder |
| 5 | Auto-start | Run keys, scheduled tasks, Startup folder |
| 6 | Files | known SHA-256 hashes, lure names, fake `dd_vcredist_x86_*_vcRuntimeMinimum_x86.exe`, script files disguised as statements |
| 7 | Related campaign | ManageEngine UEMS agent from the WhatsApp VBS campaign (warning only) |

Advanced:
```powershell
powershell -ExecutionPolicy Bypass -File .\wa-zip-cleaner.ps1          # scan only
powershell -ExecutionPolicy Bypass -File .\wa-zip-cleaner.ps1 -Fix     # quarantine
powershell -ExecutionPolicy Bypass -File .\wa-zip-cleaner.ps1 -Restore -Manifest <path>
```
Exit codes: `0` clean, `1` findings, `2` error.

Technical details and indicators: [IOCS.md](IOCS.md).

## License
MIT. No warranty. Use at your own risk.
