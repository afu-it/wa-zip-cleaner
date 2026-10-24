# WA-ZIP Cleaner

Ada orang hantar fail zip kat WhatsApp (contoh `Click here to view....zip`, `Notice.zip`, `PDF_C2841_20260911100446.zip`, `20261019-MYS2026Y1019E51AC.zip` atau `101.zip`), dan anda terbuka kat laptop atau PC Windows? Relax. Tool free ni akan scan PC anda, dan kalau ada malware tu, dia buang terus.

Kalau anda buka kat phone (Android, iPhone) atau Mac, takpe, anda selamat. Malware ni cuma kacau Windows je.

Tapi hati-hati: kalau phone anda auto save fail tu ke **Google Drive** (atau cloud lain), dan PC anda sync dengan Drive yang sama, fail tu akan masuk PC. Kalau ada sesiapa double-click kat PC, terus kena.

## Betul ke ni malware?

Betul, ini bukan kami agak-agak je. Kami dah upload fail tu ke dua website yang memang kerja dia check malware. Dua-dua cakap bahaya:

| VirusTotal: 18 antivirus detect malicious | Hatching Triage: score 10/10 |
|---|---|
| ![VirusTotal](docs/screenshots/virustotal-detection.png) | ![Triage](docs/screenshots/triage-overview.png) |

Malware ni nama dia **ValleyRAT** (ada orang panggil Winos 4.0 atau Silver Fox). Kalau dah masuk PC, hacker boleh curi password anda, off antivirus anda, dan control PC anda dari jauh macam dia duduk depan PC anda.

## Langkah 1: Full scan Windows Defender

Defender memang dah ada dalam Windows, tak payah download apa-apa.

1. Tekan **Start**, taip `Windows Security`, buka.
2. Pilih **Virus & threat protection** > **Scan options** > **Full scan** > **Scan now**.
3. Tunggu. Ambil masa lebih kurang 30 minit sampai 2 jam. Kalau Defender jumpa apa-apa, tekan **Remove** atau **Quarantine**.

## Langkah 2: Scan dengan tool ni (copy paste 1 line je)

Defender tak semestinya tangkap malware ni, sebab dia guna program yang sah untuk tipu antivirus. Versi Oktober siap suruh Defender abaikan dia, jadi scan nampak bersih padahal tak. Tool ni cari kesan malware WhatsApp ni secara khusus, termasuk arahan yang suruh Defender abaikan dia, dan buang arahan tu.

> **Hati-hati:** ada hacker yang suruh mangsa copy paste arahan dalam PowerShell untuk pasang malware. Jangan copy paste arahan dari orang yang anda tak kenal. Arahan bawah ni cuma ambil fail dari GitHub rasmi projek ni, dan code dia terbuka untuk sesiapa semak. Kalau ragu-ragu, tunjuk page ni kat orang IT yang anda percaya dan minta dia buat untuk anda.

1. Tekan **Windows + X** serentak kat keyboard. Satu menu keluar. Pilih **Terminal (Admin)** atau **Windows PowerShell (Admin)**. Kalau dia tanya, tekan **Yes**.
2. Satu tetingkap hitam/biru keluar. Copy line ni, paste dalam tetingkap tu (klik kanan dalam tetingkap = paste), lepas tu tekan **Enter**:

```powershell
[Net.ServicePointManager]::SecurityProtocol="Tls12"; $p="$env:TEMP\waz.ps1"; iwr https://raw.githubusercontent.com/afu-it/wa-zip-cleaner/main/wa-zip-cleaner.ps1 -OutFile $p; powershell -ExecutionPolicy Bypass -File $p; if ($LASTEXITCODE -eq 1 -and (Read-Host "Taip Y dan Enter untuk bersihkan") -eq "Y") { powershell -ExecutionPolicy Bypass -File $p -Fix }
```

3. Tunggu dalam 2 sampai 10 minit. Jangan tutup tetingkap tu.
   - Keluar **BERSIH**: tool ni tak jumpa kesan malware yang dia kenal.
   - Kalau dia jumpa **ManageEngine** (program remote yang hacker pasang), dia akan tanya. Kalau office anda tak pernah pasang, taip `BUANG` dan Enter, tool akan buang dia walaupun dia minta PIN. Kalau office anda yang pasang, tekan Enter je, tool tak sentuh.
   - Keluar **BAHAYA**: taip `Y`, tekan Enter. Tool ni akan buang malware tu. Fail jahat tu dia pindah ke folder quarantine (`C:\WAZipQuarantine`), bukan delete terus, so kalau tersalah buang boleh restore balik.

**BERSIH tak bermaksud PC confirm selamat.** Hacker boleh tukar malware ni bila-bila masa, dan tool ni cuma kenal versi yang kami dah bedah. Kalau anda memang dah buka fail tu kat PC, tetap buat langkah tukar password kat bawah, dan kalau ragu-ragu, minta orang IT periksa.

## Kalau dah terbuka fail tu kat PC, buat benda ni juga

Malware ni boleh duduk diam dalam PC berminggu-minggu sambil curi data. Jadi walaupun tool ni keluar BERSIH atau dah buang dia, anggap password anda dah bocor.

Guna **phone**, bukan PC yang kena tu:

1. WhatsApp > **Linked devices** > log out semua. Ni supaya hacker tak boleh guna WhatsApp anda untuk hantar fail jahat ke kawan-kawan.
2. Tukar password **semua akaun yang pernah login atau save password dalam Chrome atau Edge** kat PC tu. Mula dengan online banking, email, Google, Microsoft dan Facebook.
3. Dalam setiap akaun tu, log out semua device lain, dan on **2FA** (kod pengesahan dari phone).
4. Kalau ada info bank dalam PC tu, call bank dan minta dia orang pantau akaun anda.

Lepas tu, untuk PC:

1. Restart PC, lepas tu buat Langkah 2 sekali lagi sampai keluar **BERSIH**.
2. Kalau tool ni bagi amaran **ManageEngine** (dan office anda tak pernah pasang), atau dia jumpa **driver** yang off antivirus, cara paling selamat: backup fail penting je (dokumen, gambar), pastu **format dan install semula Windows**. Kalau tak reti, bawa ke kedai komputer dan bagitau PC ni kena malware dengan remote access.
3. Masa backup, jangan copy fail `.exe`, `.zip`, `.dll`, `.bat`, `.vhd` atau `.vhdx`. Copy fail yang anda kenal je.

Kalau anda tak pernah buka fail tu kat PC, dan tool ni keluar **BERSIH**, tak payah buat semua ni.

---

Bawah ni info tambahan. Klik tajuk untuk buka.

<details>
<summary><b>Macam mana nak kenal fail jahat ni (sebelum terbuka)</b></summary>

Nama fail selalu bertukar. Antara yang dah orang jumpa: `Click here to view....zip`, `Notice.zip` (dalam dia ada `Notice.vhd`), `PDF_C2841_20260911100446.zip` dan `DOC_7748_20260924152821.zip`, `PDF_EXZ12S_20261022110417.zip`, `20261019.MYS2026Y1019A7F2E.zip` (huruf dan nombor pelik campur tarikh), `101.zip`, fail `.vbs` macam `Work Snapshot.vbs`, dan fail yang nama dia macam penyata akaun, invoice, resit, purchase order, gaji, claim, LHDN atau KWSP. Ada juga yang buat-buat datang dari agensi kerajaan. Bulan Oktober ada mesej macam ni: *"Kindly forward the attached Statement of Account to your Finance Manager for review. Please open it on a computer"*. Kalau orang suruh buka kat komputer, itu tanda bahaya.

Jadi jangan hafal nama. Kenal dari perangai dia:

1. Fail yang anda tak tunggu pun, selalunya `.zip`.
2. Ada pesanan pendek suruh buka **kat komputer**. Invoice atau penyata yang betul boleh je buka kat phone.
3. Datang dari kawan atau group yang anda kenal. Sebab WhatsApp diorang dah kena hack.
4. Kalau dah terbuka kat PC, Windows mungkin tanya "Do you want to open this file?" untuk fail `.vhd`. Tekan **Cancel**.

Kalau ragu-ragu, call orang yang hantar tu dan tanya betul ke dia hantar. Dokumen urusan patut datang guna email atau sistem rasmi, dan anda boleh minta macam tu.

Bank OCBC dan UOB pun dah bagi amaran: jangan buka fail `.vbs`, `.zip`, `.msi` atau `.exe` yang datang dari WhatsApp.

**Tip: off auto-download dalam WhatsApp.** Kalau auto-download off, fail tak masuk phone sendiri, jadi dia tak sampai ke Google Drive dan PC anda. Caranya: WhatsApp > **Settings** > **Storage and data** > **Media auto-download**, pastu tutup semua (mobile data, Wi-Fi, roaming).

</details>

<details>
<summary><b>Takut nak taip-taip? Cara download dan double-click je</b></summary>

1. Kat atas page ni, tekan butang hijau **Code**, pastu **Download ZIP**.
2. Buka folder **Downloads**. Klik kanan fail zip tadi > **Extract All** > **Extract**.
3. Dalam folder yang keluar, double-click fail **`MULA-SINI.bat`**.
   - Windows tanya boleh ke tak: tekan **Yes**.
   - Kalau keluar "Windows protected your PC": tekan **More info**, pastu **Run anyway**. Ni normal.
4. Tunggu 2 sampai 10 minit. Kalau keluar **BAHAYA**, taip `Y` dan tekan Enter.
5. Buat semua benda dalam "Kalau dah terbuka fail tu kat PC" kat atas. Lepas restart, double-click `MULA-SINI.bat` sekali lagi.

</details>

<details>
<summary><b>Macam mana boleh kena?</b></summary>

Biasanya jadi macam ni:

1. Kawan anda hantar fail zip tu kat WhatsApp. Sebenarnya WhatsApp kawan anda tu yang dah kena hack, sebab tu nampak macam betul.
2. Anda buka kat PC Windows. Dia keluar macam ada satu pendrive baru masuk.
3. Dalam tu ada satu program yang nampak legit. Program tu kena tipu untuk jalankan malware. Sebab nampak legit, antivirus pun tak perasan.
4. Malware tu sorok dalam registry Windows, bukan dalam fail biasa. So susah nak jumpa kalau cari sendiri.
5. Dia off antivirus anda.
6. Dia set supaya setiap kali PC hidup, dia hidup sekali. Lepas tu dia cuba contact server hacker.

</details>

<details>
<summary><b>Nak suruh AI (ChatGPT, Claude, Copilot) tolong ajar?</b></summary>

Copy semua ayat ni, paste dalam ChatGPT, Claude atau Copilot:

```text
Saya rasa PC Windows saya terkena malware WhatsApp "Click here to view.zip"
(jenis Winos 4.0 / Silver Fox / ValleyRAT). Saya tak pandai IT.

Ada tool free untuk buang malware ni: https://github.com/afu-it/wa-zip-cleaner

Tolong ajar saya satu langkah satu masa, guna bahasa senang, untuk:
1. Jalankan tool tu kat Windows dengan cara paling senang.
2. Faham apa maksud BERSIH dan BAHAYA.
3. Buang malware kalau ada.
4. Apa saya kena buat lepas tu (WhatsApp Linked devices, tukar password).

Jangan suruh saya format Windows dulu. Tanya satu soalan satu masa kalau perlu.
```

</details>

<details>
<summary><b>Apa yang tool ni tak boleh buat</b></summary>

- Ni bukan antivirus penuh. Dia cuma cari malware WhatsApp yang ni je. Kalau nak full scan, guna Windows Defender, Kaspersky atau Malwarebytes.
- Tool ni detect jenis fail **VHD** (yang kami kaji) dan jenis fail **VBS** (Kaspersky lapor kat Malaysia bulan Jun). Ada satu lagi jenis guna **shortcut (`.lnk`)**, nama dia SORVEPOTEL, yang Trend Micro jumpa kat Brazil. Belum ada bukti jenis ni tersebar kat Malaysia, dan tool ni tak detect jenis tu. Sebab tu buat juga full scan Windows Defender.
- Dia kenal versi malware yang kami jumpa bulan Oktober 2026. Kalau hacker ubah sikit, kami dah tambah detection yang lebih umum, tapi tak boleh janji 100%.
- Ada mangsa lain yang jumpa program curi data nama `888.exe` dalam kempen yang sama. Program ni ambil password Chrome, Edge dan sesi WhatsApp. Tool ni belum detect `888.exe`. Sebab tu kalau keluar BAHAYA, tukar semua password walaupun tool ni dah bersihkan.
- ManageEngine yang hacker pasang tak boleh di-uninstall cara biasa, sebab dia minta PIN yang cuma hacker ada. Tool ni boleh paksa buang dia (program, servis, task, folder dan entri Apps), tapi cuma lepas anda taip `BUANG`, sebab ada office yang memang guna ManageEngine. Semua yang dibuang ada backup. Buang ManageEngine tak bermaksud PC dah bersih, jadi tetap fikir untuk format.
- Kami belum jumpa alamat server hacker tu. Mungkin server tu dah mati.

</details>

<details>
<summary><b>Macam mana kami check malware ni</b></summary>

1. Buka fail zip tu dalam komputer berasingan, tanpa jalankan malware tu.
2. Sengaja jangkitkan satu Windows 11 dalam VM (komputer dalam komputer, tak sambung internet), pastu jalankan tool ni. Dia berjaya buang malware tu, dan fail biasa tak terusik.
3. Reverse-engineer malware tu untuk faham macam mana dia sorok diri.
4. Upload ke VirusTotal dan Triage untuk pihak lain sahkan.

Setiap kali code tool ni berubah, ada test automatik yang jalan kat Windows untuk pastikan dia masih jalan elok.

Report penuh: [docs/REPORT.md](docs/REPORT.md). Report Triage: [tria.ge/261023-f44nwacc45](https://tria.ge/261023-f44nwacc45)

</details>

<details>
<summary><b>Untuk orang IT: cara manual, restore, apa yang di-check</b></summary>

Buka PowerShell as Admin, `cd` ke folder repo, then:

```powershell
powershell -ExecutionPolicy Bypass -File .\wa-zip-cleaner.ps1        # scan je
powershell -ExecutionPolicy Bypass -File .\wa-zip-cleaner.ps1 -Fix   # quarantine
powershell -ExecutionPolicy Bypass -File .\wa-zip-cleaner.ps1 -RemoveManageEngine   # paksa buang ManageEngine tanpa tanya
powershell -ExecutionPolicy Bypass -File .\wa-zip-cleaner.ps1 -Restore -Manifest "C:\WAZipQuarantine\<tarikh>\manifest.json"
```

Path `manifest.json` keluar masa `-Fix`. Exit code: `0` bersih, `1` ada jumpa, `2` error.

Ada 2 versi Silver Fox yang tool ni kenal.

Versi 1 (kami bedah): VHD dalam zip, KafanInputService (signed) sideload `rime.dll`, payload dalam registry `Console\0` jalan fileless, BYOVD driver (ZyArk/Baidu, ardrv/OPSWAT), persistence guna servis palsu `hidserv.dll`.

Versi 2 ([Pelagos Intel](https://research.pelagos-intel.com/silverfox-in-the-desktop)): IMG dalam zip, KuGou `active_desktop_launcher.exe` (signed) load `active_desktop_render_x64.dll`, staging dalam `%APPDATA%\Microsoft\Update\`, Run value `MicrosoftUpdate`, C2 `134.122.155.135:443`.

| # | Check | Contoh |
|---|---|---|
| 1 | Process | `rundll32 ...,_vmclientcore@16`, `rime.dll` palsu luar Program Files |
| 2 | VHD | `Click here to view*.vhd` |
| 3 | Registry | `Console\0` (value name 32-hex), `Console\IpDate`, `IpDates_info`, `Magisk`, `FaCai2024` |
| 4 | Driver / servis | `ZyArk`, `ardrv`; servis yang launch script interpreter dari user folder |
| 5 | Autostart & Defender | Run keys (termasuk yang point ke fail Hidden+System, dan `MicrosoftUpdate` ke `%APPDATA%\Microsoft\Update\`), scheduled task (termasuk task hidden yang jalankan `Add-MpPreference`), Startup folder; pengecualian Defender untuk `svchost.exe`, `QtsUpdater.exe` dan program sistem lain |
| 6 | Fail | SHA-256 dikenali, nama umpan (`Click here to view*`, `Notice*.vhd`, `PDF_XXXXXX_<tarikh>`, `<tarikh>-MYS2026Y...`), payload `eneio64.dat` / `plcc3a.dat`, fail `.vhd`/`.vhdx` lain dalam user folder (warning, kecuali WSL), `hidserv.dll` luar System32, fail Hidden+System, installer Visual C++ palsu |
| 7 | RMM berkaitan | agent ManageEngine UEMS dari kempen VBS WhatsApp (warning; force remove bila user taip `BUANG` atau guna `-RemoveManageEngine`) |

IOC: [IOCS.md](IOCS.md), [docs/iocs.csv](docs/iocs.csv). YARA: [winos4-whatsapp.yar](winos4-whatsapp.yar). Tests jalan kat Windows Server 2022 dan 2025.

</details>

<details>
<summary><b>Nak tolong?</b></summary>

Projek ni free dan open source. Sesiapa pun boleh tolong: developer, vibecoder, orang cybersecurity Malaysia.

- Jumpa versi baru malware ni? Buka [Issue](https://github.com/afu-it/wa-zip-cleaner/issues), bagi hash atau link VirusTotal/Triage. Jangan upload fail malware terus.
- Reti code? Tambah detection dalam `wa-zip-cleaner.ps1` atau rule dalam `winos4-whatsapp.yar`, buka Pull Request. Pastikan test lulus.
- Reti tulis atau design? Tolong baiki panduan ni, translate, atau buat poster amaran.
- Orang security? Semak [docs/REPORT.md](docs/REPORT.md), atau share IOC ke MalwareBazaar/ThreatFox.

</details>

<details>
<summary><b>English</b></summary>

Free scanner and cleaner for Windows PCs that opened a WhatsApp ZIP lure such as `Click here to view*.zip`, `Notice.zip`, `PDF_EXZ12S_20261022110417.zip` or `20261019-MYS2026Y1019E51AC.zip` (ValleyRAT / Winos 4.0 / Silver Fox). Phones and Macs are not affected, but a phone that auto-saves to a cloud drive synced to a PC can still deliver the file to that PC.

This tool covers the VHD and VBS variants. It does not detect the shortcut (`.lnk`) variant known as SORVEPOTEL, which Trend Micro reported in Brazil (no confirmed Malaysian cases yet), so also run a Windows Defender full scan.

The October 2026 wave tells Windows Defender to ignore `svchost.exe` and `QtsUpdater.exe`, so a Defender scan can look clean; this tool finds and removes those exclusions. First run a Windows Defender full scan. Then press **Windows + X**, open **Terminal (Admin)**, paste the command from the top of this page, and press Enter. If it finds something, type `Y` to quarantine it. Only paste commands from sources you trust; if unsure, ask an IT person you trust to run it. A clean result does not prove the PC is safe, since the malware can change.

Or download the repo, extract it, and double-click `MULA-SINI.bat`.

If anything is found: from your phone, log out of WhatsApp Linked devices, change every password saved in or typed into Chrome/Edge on that PC, sign out other sessions and turn on 2FA. If the tool warns about ManageEngine or an antivirus-killing driver, back up your documents and reinstall Windows. Another victim of this campaign found a data stealer (`888.exe`) that this tool does not detect yet. Full analysis: [docs/REPORT.md](docs/REPORT.md).

</details>

## Lesen

MIT. Free, tapi takde jaminan. Guna atas risiko sendiri.
