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

## References
- eSentire, Winos4.0 online module staging component: https://www.esentire.com/blog/winos4-0-online-module-staging-component-used-in-cleversoar-campaign
- The Star, 29 Sep 2026: https://www.thestar.com.my/tech/tech-news/2026/09/29/malaysians-report-being-targeted-by-malware-file-sent-through-whatsapp
