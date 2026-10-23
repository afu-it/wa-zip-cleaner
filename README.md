# WA-ZIP Cleaner

**Terlanjur buka / tekan fail `.zip` pelik dari WhatsApp kat komputer Windows? Jangan panik.**
Alat **percuma** ni akan check komputer awak dan bersihkan kalau ada malware tu.

> 📱 **Mac, iPhone, Android TAK kena.** Malware ni cuma jalan kat **Windows** sahaja. Kalau awak buka kat telefon, awak selamat.

Pengimbas & pembersih untuk PC Windows yang terbuka fail **"Click here to view....zip"** dari WhatsApp (kempen malware *Winos 4.0 / Silver Fox / ValleyRAT*).

---

## 😨 Apa yang jadi kat saya?

Awak mungkin kena kalau:
- Awak dapat fail `.zip` dalam WhatsApp — **selalunya dari kawan yang akaun dia dah kena curi** (jadi nampak macam betul), dan
- awak **buka / double-click** fail tu kat **komputer Windows** — biasanya muncul macam satu "pendrive" baru.

Kalau dah terbuka, malware ni boleh **curi password, matikan antivirus, dan kawal komputer awak dari jauh**. Lagi cepat bersih lagi bagus. Alat ni tolong awak buat tu.

---

## 🔬 Ni betul ke? (Bukti)

Kami bukan main teka. Kami hantar malware sebenar ni ke dua perkhidmatan keselamatan terkenal dunia — dua-dua sahkan ia **memang berbahaya**:

| VirusTotal — 18 antivirus tanda bahaya | Hatching Triage — skor penuh 10/10 |
|---|---|
| ![VirusTotal](docs/screenshots/virustotal-detection.png) | ![Triage](docs/screenshots/triage-overview.png) |

- **VirusTotal:** 18/71 antivirus tanda malicious; padan peraturan *WinosStager*; dikaitkan dengan kempen **"CleverSoar"**.
- **Hatching Triage** (jalankan dalam Windows betul): skor **10/10**, dikenal pasti sebagai **ValleyRAT** (Silver Fox / Winos 4.0).

📄 Laporan penuh + semua gambar: **[docs/REPORT.md](docs/REPORT.md)** · Laporan Triage awam: [tria.ge/261023-f44nwacc45](https://tria.ge/261023-f44nwacc45)

---

## 🟢 CARA PALING SENANG (sesiapa pun boleh, tak perlu pandai IT)

**1. Download alat ni.** Tekan butang hijau **`< > Code`** kat atas page ni → **Download ZIP**.

**2. Buka (extract) fail zip tu.** Pergi folder *Downloads*, klik kanan fail yang baru turun → **Extract All** → **Extract**.

**3. Double-click fail `MULA-SINI.bat`** dalam folder tu.
- Windows tanya nak bagi kebenaran? Tekan **Yes**. (Normal, jangan takut.)
- Kalau keluar "Windows protected your PC" → tekan **More info** → **Run anyway**.

**4. Tunggu je.** Tetingkap hitam akan imbas komputer, ambil masa **2–10 minit**. Jangan tutup, pergi minum air dulu. 😄

**5. Baca apa dia cakap:**
- **BERSIH** → alhamdulillah, takde apa. Habis.
- **BAHAYA** → dia tanya nak bersihkan tak. **Taip `Y`, tekan Enter.** Dia bersihkan sendiri.

**6. Lepas bersih — WAJIB buat (guna TELEFON / komputer lain):**
- WhatsApp telefon → **Peranti dipaut (Linked devices)** → **Log keluar semua**.
- Tukar password **bank online** dan **email**.
- **Restart** komputer, pastu double-click `MULA-SINI.bat` sekali lagi sampai keluar **BERSIH**.

Itu je. Satu fail, satu klik.

---

## 💻 Cara guna PowerShell (kalau awak suka taip sendiri / `MULA-SINI.bat` tak jalan)

Sama hasil, cuma guna arahan. Ikut step by step:

**1. Download + extract** alat ni (macam langkah 1–2 di atas). Ingat folder tu kat mana (contoh: `C:\Users\Ali\Downloads\wa-zip-cleaner`).

**2. Buka PowerShell sebagai Admin.**
Tekan butang **Start** → taip `powershell` → klik kanan **Windows PowerShell** → **Run as administrator** → **Yes**.

**3. Pergi ke folder alat tu.** Taip `cd ` (ada space), pastu **seret folder tu masuk tetingkap** (path akan muncul sendiri), tekan Enter. Contoh:
```powershell
cd "C:\Users\Ali\Downloads\wa-zip-cleaner"
```

**4. IMBAS (scan je, tak ubah apa-apa):**
```powershell
powershell -ExecutionPolicy Bypass -File .\wa-zip-cleaner.ps1
```
Tunggu 2–10 minit. Kalau **BERSIH** → habis. Kalau **BAHAYA** → pergi langkah 5.

**5. BERSIHKAN (alih fail jahat ke kuarantin, bukan padam terus):**
```powershell
powershell -ExecutionPolicy Bypass -File .\wa-zip-cleaner.ps1 -Fix
```

**6. Restart komputer, pastu ulang langkah 4** sampai keluar **BERSIH**.

**Kalau tersalah buang** dan nak pulihkan balik:
```powershell
powershell -ExecutionPolicy Bypass -File .\wa-zip-cleaner.ps1 -Restore -Manifest "C:\WAZipQuarantine\<tarikh>\manifest.json"
```
(Path `manifest.json` tu dipaparkan masa membersih tadi.)

> Kod keluar (untuk yang teknikal): `0` = bersih, `1` = ada jumpa, `2` = ralat.

---

## 🕵️ Apa sebenarnya malware ni buat?

Ringkasnya, dari mula sampai habis:

1. **Umpan:** awak dapat fail `Click here to view*.zip` dalam WhatsApp.
2. Dalam zip ada fail **VHD** — bila buka, Windows pasang ia jadi "pendrive" baru.
3. Dalam tu ada program **bertandatangan sah** (KafanInputService) yang **ditipu** untuk muatkan fail jahat `rime.dll` — sebab programnya sah, **antivirus percaya**.
4. Ia sorok badan sebenar dalam **registry** (`Console\0`) dan jalankan terus dari ingatan — **tanpa fail**, susah dikesan antivirus.
5. Ia pasang **driver yang matikan antivirus** (ZyArk/Baidu, ardrv/OPSWAT).
6. Ia **kekal hidup** (servis Windows palsu `hidserv.dll` + auto-start) dan cuba hubungi server penggodam.

Jenis: **Winos 4.0 / Silver Fox / ValleyRAT** — alat kawalan jauh (RAT) yang makin banyak serang pengguna Malaysia lewat WhatsApp.

---

## 🧪 Macam mana kami jumpa & kaji malware ni?

Supaya awak percaya alat ni bukan main taip je — ni yang kami buat:

1. **Bedah dalam makmal selamat (Linux/Kali):** buka kandungan zip tanpa menjalankannya, kenal pasti setiap fail jahat + cara ia sembunyi.
2. **Uji atas Windows 11 betul (dalam komputer maya terasing):** sengaja jangkitkan, pastu jalankan alat kami — sahkan ia kesan & buang **jangkitan hidup sebenar** tanpa kacau fail biasa.
3. **Reverse-engineer** fail jahat (Ghidra): dapat cara penyulitan (RC4), kunci driver, dan mekanisme ia bersembunyi.
4. **Cuba paksa ia dedah server penggodam** guna beberapa cara (emulasi, Wine+FEX, sandbox awan Triage) — semua dalam persekitaran terasing tanpa internet sebenar.
5. **Sahkan dengan pihak ketiga:** VirusTotal + Triage (gambar di atas).

Setiap pengesanan dalam alat ni ada **ujian automatik** yang jalan atas Windows bersih (Windows Server 2022 & 2025) setiap kali kod berubah.

---

## 🚧 Apa kami BELUM mampu buat (jujur)

- **Alamat server penggodam (C2) belum dapat.** Alamat tu tersembunyi dalam bahagian tersulit yang cuma terbuka masa malware betul-betul "hidup". Walaupun guna sandbox profesional (Windows Intel sebenar), ia tetap tak dedah — besar kemungkinan **server tu dah mati/ditutup**. Kalau sesiapa ada sampel kempen sama yang server masih hidup, PR sangat dialu-alukan.
- **Alat ni kenal versi yang kami bedah (Oktober 2026).** Versi baru mungkin sikit berbeza — sebab tu kami tambah pengesanan *generik* (contoh: fail Tersembunyi+Sistem di tempat pelik) supaya varian baru pun tertangkap.
- **Driver pembunuh antivirus:** kalau dijumpai, cara paling selamat tetap **backup data & install semula Windows**. Alat ni akan bagitau.

---

## 🤝 Nak tolong? (Jemputan untuk komuniti Malaysia)

Repo ni **terbuka untuk semua** — developer, vibecoder, penggiat cybersecurity Malaysia. Mari kita jaga rakyat sama-sama. 🇲🇾

Macam mana nak sumbang:
- **Jumpa varian baru / sampel kempen ni?** Buka [Issue](https://github.com/afu-it/wa-zip-cleaner/issues) atau hantar hash/IOC. (Jangan upload malware mentah terus — bagi hash atau pautan VirusTotal/Triage je.)
- **Pandai coding?** Tambah pengesanan baru dalam `wa-zip-cleaner.ps1`, atau peraturan dalam `winos4-whatsapp.yar`, pastu buka **Pull Request**. Ada ujian automatik — pastikan ia hijau.
- **Pandai menulis / design?** Tolong perbaiki panduan ni, terjemah, atau buat poster amaran untuk orang ramai.
- **Cybersecurity pro?** Tolong sahkan/perbaiki analisis dalam [docs/REPORT.md](docs/REPORT.md), atau kongsi IOC ke feed komuniti (MalwareBazaar/ThreatFox).

Setiap sumbangan, kecil atau besar, membantu lindungi lebih ramai mangsa. Terima kasih. 🙏

---

## ℹ️ Tentang projek ni (About)

**WA-ZIP Cleaner** ialah projek **komuniti, percuma, sumber terbuka (MIT)** — dibuat selepas satu kempen malware WhatsApp sebenar yang sasarkan rakyat Malaysia (fail "Click here to view*.zip").

**Kenapa ia wujud:** ramai mangsa bukan orang IT. Bila dah terbuka fail tu, diorang tak tahu nak buat apa, dan alat profesional selalunya mahal atau susah. Jadi kami buat satu alat **ringkas, percuma, boleh guna sendiri** — plus analisis terbuka supaya komuniti keselamatan boleh sama-sama kesan & blok kempen ni.

**Apa ia BUKAN:**
- Bukan untuk dijual — percuma selamanya.
- Bukan antivirus penuh — ia alat khusus untuk kempen malware WhatsApp ni sahaja.
- Bukan sulap — setiap pengesanan datang dari analisis sebenar (lihat [docs/REPORT.md](docs/REPORT.md)) dan ada ujian automatik.

**Dibuat oleh & untuk komuniti Malaysia** — developer, vibecoder, dan penggiat cybersecurity. Kalau ia tolong walau seorang mangsa, berbaloi. 🇲🇾

---

## 🔎 Apa alat ni semak (7 bahagian)

| # | Semak | Contoh |
|---|---|---|
| 1 | Program sedang jalan | `rundll32 ...,_vmclientcore@16`, `rime.dll` palsu di luar Program Files |
| 2 | Cakera maya (VHD) | `Click here to view*.vhd` |
| 3 | Registry | `Console\0` (nama nilai 32-hex), `Console\IpDate`, `IpDates_info`, `Magisk`, `FaCai2024` |
| 4 | Driver / servis | `ZyArk`, `ardrv`; servis yang lancar penterjemah skrip dari folder pengguna |
| 5 | Auto-start | kunci Run (termasuk yang tunjuk ke fail Tersembunyi+Sistem), task berjadual, folder Startup |
| 6 | Fail | hash SHA-256 dikenali, nama umpan, `hidserv.dll` di luar System32, fail Tersembunyi+Sistem, pemasang Visual C++ palsu |
| 7 | Alat kawalan jauh berkaitan | agen ManageEngine UEMS dari kempen VBS WhatsApp (amaran sahaja) |

Butiran teknikal & IOC: **[IOCS.md](IOCS.md)** · **[docs/iocs.csv](docs/iocs.csv)** · Peraturan YARA: **[winos4-whatsapp.yar](winos4-whatsapp.yar)**

---

## English (short)

Free scanner/cleaner for Windows PCs that opened the WhatsApp **"Click here to view*.zip"** malware (Winos 4.0 / Silver Fox / ValleyRAT). **Mac, iPhone, Android are not affected.**

**Easiest:** download (green **Code → Download ZIP**), extract, double-click **`MULA-SINI.bat`**, click **Yes**, wait, and type **`Y`** to clean if something is found.

**PowerShell:** open PowerShell as Admin, `cd` into the folder, then:
```powershell
powershell -ExecutionPolicy Bypass -File .\wa-zip-cleaner.ps1        # scan
powershell -ExecutionPolicy Bypass -File .\wa-zip-cleaner.ps1 -Fix   # quarantine
```
After cleaning: log out WhatsApp linked devices, change bank/email passwords, restart, rescan. Full analysis: [docs/REPORT.md](docs/REPORT.md). Contributions from the Malaysian dev/security community are very welcome — see the Contribute section above.

## License
MIT. No warranty. Use at your own risk.
