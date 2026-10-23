# WA-ZIP Cleaner

Terbuka fail `Click here to view....zip` dari WhatsApp kat komputer Windows? Alat percuma ni periksa komputer awak dan buang malware tu kalau ada.

Telefon (Android, iPhone) dan Mac tak kena. Malware ni cuma jalan kat Windows.

## Cara bersihkan (1 arahan)

1. Tekan kekunci **Windows + X**, pilih **Terminal (Admin)** atau **Windows PowerShell (Admin)**. Tekan **Yes**.
2. Salin baris di bawah, tampal dalam tetingkap tu, tekan **Enter**:

```powershell
[Net.ServicePointManager]::SecurityProtocol="Tls12"; $p="$env:TEMP\waz.ps1"; iwr https://raw.githubusercontent.com/afu-it/wa-zip-cleaner/main/wa-zip-cleaner.ps1 -OutFile $p; powershell -ExecutionPolicy Bypass -File $p; if ($LASTEXITCODE -eq 1 -and (Read-Host "Taip Y dan Enter untuk bersihkan") -eq "Y") { powershell -ExecutionPolicy Bypass -File $p -Fix }
```

3. Tunggu 2 hingga 10 minit. Jangan tutup tetingkap.
   - Keluar **BERSIH**: komputer awak selamat. Siap.
   - Keluar **BAHAYA**: taip `Y`, tekan Enter. Fail jahat dialih ke folder `C:\WAZipQuarantine`, tak dipadam terus.

## Lepas bersihkan, buat 3 benda ni

1. Dari telefon: WhatsApp > **Peranti dipaut** (Linked devices) > log keluar semua.
2. Tukar kata laluan bank online dan emel.
3. Restart komputer, pastu jalankan arahan tadi sekali lagi sampai keluar **BERSIH**.

Tak perlu format Windows. Format cuma perlu kalau alat ni beritahu ia jumpa driver yang matikan antivirus.

---

Bahagian di bawah untuk yang nak tahu lebih. Tekan tajuk untuk buka.

<details>
<summary><b>Tak reti guna arahan? Cara download dan klik</b></summary>

1. Kat atas page ni, tekan butang hijau **Code** > **Download ZIP**.
2. Buka folder Downloads. Klik kanan fail zip tu > **Extract All** > **Extract**.
3. Dalam folder tu, double-click **`MULA-SINI.bat`**.
   - Windows minta kebenaran: tekan **Yes**.
   - Keluar "Windows protected your PC": tekan **More info** > **Run anyway**.
4. Tunggu 2 hingga 10 minit. Kalau keluar **BAHAYA**, taip `Y` dan tekan Enter.
5. Buat 3 benda dalam bahagian "Lepas bersihkan" di atas. Lepas restart, double-click `MULA-SINI.bat` sekali lagi.

</details>

<details>
<summary><b>Cara manual guna PowerShell (dari folder yang dah download)</b></summary>

1. Download dan extract alat ni (langkah 1 dan 2 dalam bahagian download di atas).
2. Buka PowerShell sebagai Admin: **Windows + X** > **Terminal (Admin)**.
3. Taip `cd ` (ada jarak), seret folder tu masuk tetingkap, tekan Enter. Contoh:
   ```powershell
   cd "C:\Users\Ali\Downloads\wa-zip-cleaner"
   ```
4. Imbas sahaja, tak ubah apa-apa:
   ```powershell
   powershell -ExecutionPolicy Bypass -File .\wa-zip-cleaner.ps1
   ```
5. Kalau keluar **BAHAYA**, bersihkan:
   ```powershell
   powershell -ExecutionPolicy Bypass -File .\wa-zip-cleaner.ps1 -Fix
   ```

Nak pulihkan fail yang dah dialih (kalau tersalah buang):
```powershell
powershell -ExecutionPolicy Bypass -File .\wa-zip-cleaner.ps1 -Restore -Manifest "C:\WAZipQuarantine\<tarikh>\manifest.json"
```
Lokasi `manifest.json` dipaparkan masa membersih.

Kod keluar: `0` bersih, `1` ada jumpa, `2` ralat.

</details>

<details>
<summary><b>Guna Claude, ChatGPT atau Copilot untuk pandu awak</b></summary>

Salin teks ni dan tampal dalam apps AI awak:

```text
Saya rasa komputer Windows saya terkena malware WhatsApp "Click here to view.zip"
(jenis Winos 4.0 / Silver Fox / ValleyRAT). Saya bukan orang IT.

Ada alat pembersih percuma di: https://github.com/afu-it/wa-zip-cleaner

Tolong pandu saya satu langkah pada satu masa, guna bahasa mudah, untuk:
1. Jalankan alat tu di Windows dengan cara paling senang.
2. Faham keputusan BERSIH dan BAHAYA.
3. Bersihkan kalau ada jumpa.
4. Apa saya kena buat lepas tu (WhatsApp linked devices, tukar kata laluan).

Jangan suruh saya format Windows dulu. Tanya satu soalan pada satu masa kalau perlu.
```

</details>

<details>
<summary><b>Macam mana saya boleh terkena?</b></summary>

Biasanya begini:

1. Kawan hantar fail `Click here to view....zip` dalam WhatsApp. Selalunya akaun kawan tu dah kena curi, sebab tu nampak betul.
2. Awak buka fail tu kat komputer Windows. Ia muncul macam satu pendrive baru.
3. Dalam tu ada program sah (KafanInputService) yang ditipu untuk muat fail jahat `rime.dll`. Sebab programnya sah, antivirus biarkan.
4. Malware sorok diri dalam registry (`Console\0`) dan jalan terus dari memori, tanpa fail.
5. Ia pasang driver yang matikan antivirus (ZyArk/Baidu, ardrv/OPSWAT).
6. Ia pasang servis Windows palsu (`hidserv.dll`) supaya hidup semula setiap kali komputer dibuka, dan cuba hubungi server penggodam.

Kalau dibiarkan, penggodam boleh curi kata laluan, matikan antivirus, dan kawal komputer awak dari jauh.

Nama malware: Winos 4.0 / Silver Fox / ValleyRAT.

</details>

<details>
<summary><b>Betul ke ni malware? (bukti)</b></summary>

Kami hantar sampel sebenar ke dua perkhidmatan keselamatan:

| VirusTotal: 18 antivirus tanda bahaya | Hatching Triage: skor 10/10 |
|---|---|
| ![VirusTotal](docs/screenshots/virustotal-detection.png) | ![Triage](docs/screenshots/triage-overview.png) |

- VirusTotal: 18 daripada 71 antivirus tanda malicious. Padan peraturan *WinosStager*, dikaitkan dengan kempen "CleverSoar".
- Hatching Triage (dijalankan dalam Windows sebenar): skor 10/10, dikenal pasti sebagai ValleyRAT.

Laporan penuh: [docs/REPORT.md](docs/REPORT.md). Laporan Triage: [tria.ge/261023-f44nwacc45](https://tria.ge/261023-f44nwacc45)

</details>

<details>
<summary><b>Macam mana kami kaji malware ni</b></summary>

1. Buka kandungan zip dalam Linux tanpa menjalankannya, dan kenal pasti setiap fail jahat.
2. Jangkitkan Windows 11 dalam komputer maya yang terasing, pastu jalankan alat ni. Ia kesan dan buang jangkitan yang sedang hidup tanpa kacau fail biasa.
3. Bedah fail jahat guna Ghidra: cara penyulitan (RC4), kunci driver, dan cara ia bersembunyi.
4. Cuba paksa ia dedah alamat server penggodam guna emulasi, Wine+FEX dan sandbox Triage. Semua tanpa sambungan internet sebenar.
5. Sahkan dengan VirusTotal dan Triage.

Setiap pengesanan ada ujian automatik yang jalan atas Windows Server 2022 dan 2025 setiap kali kod berubah.

</details>

<details>
<summary><b>Had alat ni</b></summary>

- Alamat server penggodam belum dapat. Ia tersorok dalam bahagian bersulit yang cuma terbuka masa malware hidup, dan sandbox pun tak dedahkannya. Kemungkinan server tu dah ditutup. Kalau awak ada sampel dari kempen yang sama dan servernya masih hidup, sila hantar.
- Alat ni kenal versi yang kami bedah (Oktober 2026). Versi baru mungkin berbeza sikit, jadi kami tambah pengesanan umum (contohnya fail Hidden+System di tempat pelik) untuk tangkap varian baru.
- Kalau alat ni jumpa driver yang matikan antivirus, cara paling selamat ialah backup data dan install semula Windows. Alat ni akan beritahu.
- Ini bukan antivirus penuh. Ia khusus untuk kempen malware WhatsApp ni sahaja. Untuk imbasan menyeluruh, guna Kaspersky atau Malwarebytes.

</details>

<details>
<summary><b>Apa yang alat ni periksa</b></summary>

| # | Periksa | Contoh |
|---|---|---|
| 1 | Program sedang jalan | `rundll32 ...,_vmclientcore@16`, `rime.dll` palsu di luar Program Files |
| 2 | Cakera maya (VHD) | `Click here to view*.vhd` |
| 3 | Registry | `Console\0` (nama nilai 32-hex), `Console\IpDate`, `IpDates_info`, `Magisk`, `FaCai2024` |
| 4 | Driver dan servis | `ZyArk`, `ardrv`; servis yang lancar skrip dari folder pengguna |
| 5 | Auto-start | kunci Run (termasuk yang tunjuk ke fail Hidden+System), task berjadual, folder Startup |
| 6 | Fail | hash SHA-256 dikenali, nama umpan, `hidserv.dll` di luar System32, fail Hidden+System, pemasang Visual C++ palsu |
| 7 | Alat kawalan jauh berkaitan | agen ManageEngine UEMS dari kempen VBS WhatsApp (amaran sahaja) |

Butiran teknikal: [IOCS.md](IOCS.md), [docs/iocs.csv](docs/iocs.csv). Peraturan YARA: [winos4-whatsapp.yar](winos4-whatsapp.yar)

</details>

<details>
<summary><b>Nak tolong?</b></summary>

Projek ni percuma dan terbuka. Developer, vibecoder dan orang cybersecurity Malaysia dijemput menyumbang.

- Jumpa varian baru? Buka [Issue](https://github.com/afu-it/wa-zip-cleaner/issues) dengan hash atau pautan VirusTotal/Triage. Jangan upload fail malware terus.
- Reti coding? Tambah pengesanan dalam `wa-zip-cleaner.ps1` atau peraturan dalam `winos4-whatsapp.yar`, pastu buka Pull Request. Pastikan ujian automatik lulus.
- Reti menulis atau design? Baiki panduan ni, terjemah, atau buat poster amaran.
- Orang cybersecurity? Semak analisis dalam [docs/REPORT.md](docs/REPORT.md), atau kongsi IOC ke MalwareBazaar/ThreatFox.

</details>

<details>
<summary><b>English</b></summary>

Free scanner and cleaner for Windows PCs that opened the WhatsApp `Click here to view*.zip` malware (Winos 4.0 / Silver Fox / ValleyRAT). Phones and Macs are not affected.

Press **Windows + X**, open **Terminal (Admin)**, paste the command from the top of this page, and press Enter. If it reports a threat, type `Y` to quarantine it.

Or download the repo, extract it, and double-click `MULA-SINI.bat`.

Manual:
```powershell
powershell -ExecutionPolicy Bypass -File .\wa-zip-cleaner.ps1        # scan
powershell -ExecutionPolicy Bypass -File .\wa-zip-cleaner.ps1 -Fix   # quarantine
```

After cleaning: log out of WhatsApp linked devices, change bank and email passwords, restart, and scan again. Full analysis: [docs/REPORT.md](docs/REPORT.md).

</details>

## Lesen

MIT. Tiada jaminan. Guna atas risiko sendiri.
