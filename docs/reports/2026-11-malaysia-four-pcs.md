# Case Report: Four Malaysian PCs Cleaned, 5 November 2026

**Campaign:** WhatsApp lures that end with the attacker's own ManageEngine agent, the IP-guard spy agent, DLL sideloading and remote-control programs.

**Scope:** four Windows PCs (A, B, C, D) in Malaysia. Each owner gave permission, and all four were cleaned remotely on 5 November 2026 with [`wa-zip-cleaner.ps1`](../../wa-zip-cleaner.ps1) (versions 2026.11.05.14 to .21).

**Privacy:** this report has no owner names, PC names, user names, phone numbers, company names or home-network addresses. Evidence came from the tool's scan logs, Windows event logs, registry and folder listings, and `Get-FileHash`. No malware samples were collected or uploaded. VirusTotal was used for hash lookups only.

All times are Malaysia time (UTC+8).

---

## Summary

| PC | What was found | How it was removed | Result |
|---|---|---|---|
| A | Attacker's ManageEngine agent (Oct 9), then the IP-guard spy agent pushed through it (Oct 12) | Tool -Fix, then Safe Mode auto | Clean, no reinstall. Documents open normally. |
| B | ManageEngine installer kit hidden in a Defender-excluded folder; signed `Toolkit.exe` sideloading `unityplayer.dll`, started by a fake `WindowsUpdateSync` task | Tool -Fix | Clean |
| C | Fake `FilmoraTray` loading `libvlc.dll` from the Filmora folder; hidden-command Start Menu shortcut; two lure ZIPs; UltraViewer | Tool -Fix (twice, with a restart) | Clean |
| D | IP-guard spy agent talking to `137.220.205.162` | Tool -Fix, then Safe Mode auto (a first attempt failed, see below) | Clean, no reinstall |

All four PCs were infected and then reached a clean scan without reinstalling Windows. On two of them the attacker had a full commercial monitoring suite (IP-guard): screen recording, keylogging, email capture, browser history and SSL/SSH capture.

---

## PC A: ManageEngine, then IP-guard

**Timeline** (from System event 7045, MsiInstaller events and file times):

| When | What |
|---|---|
| 2026-10-09 16:39:58 | `UEMSAgent.msi` installed from `C:\Windows\Temp`. ManageEngine Endpoint Central (UEMS) agent 10.0.50.W, server `27.124.41.218`, server name `WIN-NIK9N0SF4IH`, ports 8383 (HTTPS) and 8443 (remote control) |
| 2026-10-09 16:40-16:47 | ManageEngine agent, remote-control, EDR and anti-ransomware services and drivers installed (`MEARWService`, `MEARWFltDriver`, `DCFAFilter`) |
| 2026-10-12 08:05-08:18 | ManageEngine drops the IP-guard / OCular agent (TEC Solutions). First drivers at 08:10:34; service "Windows Helper Service" (`.Winhlpsvr` -> `winrdgv3.exe`) at 08:13:06; then about 12 kernel drivers. IP-guard server `27.124.41.182` (same /24) |
| 2026-10-12 to 11-04 | Attacker's ManageEngine "Prohibited Software" policy runs `dcuninstallsw.exe` again and again |
| 2026-11-05 | Online removal fails (see "How IP-guard fights back"). Safe Mode removal succeeds: 215 files moved, services disabled and deleted, 0 HIGH on the next scan |

The lure ZIP that started this was not found on the PC.

**What IP-guard collects** (folder `C:\Windows\SysWOW64\Ocular`): `Screen`, `Mails`, `BroHistory`, `Winscap` (SSL/SSH capture) and `TSafeDoc` (document encryption). Treat everything typed or viewed on the PC since 12 October as stolen.

---

## PC B: hidden ManageEngine kit and Toolkit.exe sideload

- Two folders were Windows Defender exclusions: `%LOCALAPPDATA%\Microsoft\Windows\Caches\<random name>` and `%LOCALAPPDATA%\Toolkit`.
- `Caches\<random name>` held the ManageEngine installer kit. Its `DCAgentServerInfo.json` points at `156.234.7.51:8383`, server name `WIN-QMO1HP9BSRQ`, agent 11.3.2400.33.W. VirusTotal: 0 detections, owner Yancy Limited (HK).
- `Toolkit.exe` is a validly signed Gaggle Studios program (VirusTotal 0/75). It is only a host: it loads `unityplayer.dll` from its own folder. Neither `unityplayer.dll` nor the `UX64` file next to it is on VirusTotal.
- A root scheduled task named `WindowsUpdateSync` started `Toolkit.exe` from `AppData\Local`, and it was running.

---

## PC C: fake FilmoraTray, worm-style shortcut, UltraViewer

First scan: 10 HIGH findings.
- A program named `FilmoraTray` was running and loading a fake `libvlc.dll` from the Wondershare Filmora folder. This is DLL sideloading, the same pattern MyCERT MA-1493 describes for VLC.
- A Start Menu shortcut named like a real program ("V-Ray Swarm UI") ran a hidden command. The tool's check for SORVEPOTEL-style shortcuts flagged it. SORVEPOTEL is a WhatsApp worm that sends the lure to every contact.
- Two lure ZIPs from WhatsApp: one in Downloads, and one on the Desktop named as a construction-industry certificate.
- Six WhatsApp Web sessions in Chrome. The tool logs these out, and the owner was told to log out all linked devices from the phone.
- UltraViewer was installed. The owner did not recognise it.

After the first -Fix, `FilmoraTray` came back with a new process ID, so something restarted it. After a second -Fix and a restart it did not come back. UltraViewer was then removed (program, service, folder and Apps entry). The final scan was clean.

**Tool change:** UltraViewer is now always HIGH and always removed. MyCERT MA-1493 links UltraViewer to this campaign, and the attacker installs it for remote access. AnyDesk and TeamViewer stay warnings, because owners often install those themselves.

---

## PC D: IP-guard that survived the first Safe Mode pass

- The IP-guard agent `wrdlv4.exe` ("OCular Agent", 6 processes) was connecting to `137.220.205.162`. That address was already on the tool's attacker list from an earlier Triage sweep (ManageEngine agent server, port 8383). Malwarebytes on the PC blocked the connection while we were working.
- **First Safe Mode pass (tool .18), 16:42-16:46, failed.** The tool deleted IP-guard's Safe Mode entries and then waited 3 seconds before restarting. In those 3 seconds IP-guard registered itself again. In Safe Mode its programs (`winrdgv3.exe`, `systecv3.exe`, `winwdgsvr.exe`) were still running, so moving them failed with "Access denied", and its services were still enabled (`.Winhlpsvr Start=2`, `TsdEncrypt Start=0`). Most of its drivers were moved out anyway.
- **Second attempt (tool .19 and later) succeeded:** the tool keeps deleting the Safe Mode entries until the PC actually restarts, and in Safe Mode it stops the agent's processes, disables its services, deletes them, and only then moves its files. The PC started normally and the next scan was clean.

---

## How IP-guard fights back (A and D)

1. While Windows runs, it puts back changed service start values within seconds.
2. It re-adds its service `.Winhlpsvr` under `HKLM\SYSTEM\CurrentControlSet\Control\SafeBoot\Minimal` and `\Network`, so it also runs in Safe Mode.
3. It reinstalls its driver `THlpDrv` and other files at the next boot (seen on PC A, 15:17-15:22 on 5 Nov).
4. Its driver `THlpDrv64.sys` is the LOLDrivers-listed vulnerable `thelper.sys`.

What works, and what the tool now does by itself (`-Fix` then the Safe Mode auto run):
1. Block the IP-guard server in the firewall.
2. Unbind its network filters (`TNFCAP`, `tpacket7`) in normal Windows.
3. Delete its two Safe Mode entries and restart **at the same moment**, deleting them again and again until Windows shuts down.
4. In Safe Mode: stop its processes, set `Start=4` on its services, delete the services, then move the files to quarantine.
5. If anything is still locked, do one more Safe Mode round (at most 2). If that still fails, write `BUANG.bat` for the Windows recovery Command Prompt.

---

## Attacker infrastructure

| Address | Role | Seen on | Source |
|---|---|---|---|
| `27.124.41.218` | ManageEngine UEMS server (`WIN-NIK9N0SF4IH`), ports 8383 and 8443 | A | Agent registry (`DCServerIPAddress`); still answering on 5 Nov |
| `27.124.41.182` | IP-guard server, port 8237 | A | `OAgent.ini` `SIP=B6297C1B` |
| `156.234.7.51` | ManageEngine UEMS server (`WIN-QMO1HP9BSRQ`), port 8383 | B | `DCAgentServerInfo.json`; VirusTotal owner Yancy Limited (HK) |
| `137.220.205.162` | IP-guard agent connection target (also a ManageEngine server on 8383 in Triage) | D | Malwarebytes block on the PC; Triage sweep |

All four addresses are in the tool's attacker list (`$C2Ips`) and in [`docs/iocs.csv`](../iocs.csv).

## IP-guard binaries from PC A (signed, abused)

All are signed by Guangzhou TEC Solutions / T.E.C Solutions. VirusTotal detections range from 0 to 9 of 75 engines. They are a legitimate commercial product used as spyware, so antivirus programs often stay quiet.

| SHA-256 | Size | File |
|---|---|---|
| `7db962200026c0afa923f559d2155a2a27b7a026553c9ca24e3dee1ec81e395d` | 370552 | `wrdlv4.exe` |
| `cc4bb641aab59aca9fb15c49ff9fa88341e73ca6d6ff6a048ef67b0088f386343` | 242128 | `wrdlv4.exe` (32-bit) |
| `43987d8ebb0a9d8c4e6143615f128978639b79e734a0e3640473a932c4a9a400` | 2089440 | `winrdgv3.exe` |
| `26379f9e9f0fcf33b7294f266a9f39930b5f68c4d90bfa6bc95535fb6f6c942a` | 2707936 | `systecv3.exe` |
| `58355065384894d72b71258694cea27fb7fb21c6135a1639d8e1b9f9955e2969` | 222248 | `winwdgsvr.exe` |
| `9d8e4527063366c11a3aa65d4b48f51bc68042d5e3a9d34c022ce6118228f843` | 2445792 | `winwdgv3.dll` |
| `acb15186d5854eeea1d21adc9442719e378e1569b69692809ce352548d61bd66` | 16490976 | `winoav3.dll` |
| `a97184a5c92191dba005589f062b84b93fd9b5b27e32e448e9fb8044fbe19096` | 840168 | `SDGuarder.exe` |
| `9853c175c470ca668fab1c84496fe236d115cf008a70229a5c3ab5c6829dea8f` | 2537344 | `windevctrl64.exe` |
| `eff2ebf2133896f563c72340cc1f792359dea76d29822d9b0709b854bc76ae58` | 2965976 | `Agt3Tool.exe` |
| `7e783b0a0ff4710306bb3bca29296cf962ae77abc81245a99f12a9039158226f` | 69632 | `THlpDrv64.sys` |
| `e7eca2fd1ea5a1b0410e825474a18e96356218388f1bb6663be1f6afd61c9891` | 843128 | `TSDDrv64.sys` |
| `ca3d49677334aefcb816aeed98ed226836b95f0bf43fc237b3dff5e2e2a7a8c4` | 1126032 | `TsdEncrypt.sys` |
| `406dd376779e5dcd8601bc6063af2efe05bb1821c28a1c378d50de46434123a2` | 63528 | `tfsfltdrv.sys` |
| `69fdbf94ea89c22d198ceebc292ec0354cf8fcbc5f8123a9ecf441e2dbf76432` | 101328 | `TIjtdrv64.sys` |
| `2e9e2a9441e14ff55cc37e4a0f541dd313ce99a24e106fe21d13b56a6fa53f5a` | 31576 | `TNullFilter.sys` |
| `f11f1107aafa7f49787472ab3f9deb8b93ea515ca2d9d729337af61da94b3b31` | 249176 | `TVDisk.sys` |

ManageEngine files from PC A (genuine Zoho binaries, attacker-run server): `dcagentservice.exe` `23fa8f503da68dd5724b136f9f401ab747db352e5edd8e2c277bf7426f774773` (1290552), `MEARWFltDriver.sys` `8f65278ad59e2c88707b9ec4e61819c06aac61c109845200f6e09f3297acbe2b` (148408).

---

## Lessons

1. **Antivirus misses this.** Every remote-control and spy program here is a genuine signed product. Detections were 0 to 9 of 75. The tool finds them by where they sit, who signed them, and which server they talk to.
2. **"Remove it" is not enough for IP-guard.** It defends itself online and re-registers in Safe Mode within seconds. The Safe Mode entry has to be deleted at the moment of restart.
3. **Restarts matter.** A deleted service stays listed until the next boot, and FilmoraTray on PC C only stayed gone after a restart.
4. **Commands sent by WhatsApp break.** WhatsApp formatting removes `_`, so `$_` becomes `$.`. Commands for victims now avoid underscores (`$PSItem` instead of `$_`).
5. **Victims need one simple choice.** The force-removal menu now offers only one option, "Safe Mode auto", with "do not touch anything; type your Windows password when asked".

## What owners should do after cleaning

1. On the phone: WhatsApp > Linked devices > log out of all.
2. Change bank, email and Google passwords from the phone, and turn on two-step verification.
3. On PCs that had IP-guard: treat everything typed or viewed since the infection as stolen, including passwords, email and documents.
4. Tell contacts not to open ZIP files sent from the infected account recently.

## Limits

- No samples were collected, so we did not unpack payloads. Hashes come from `Get-FileHash` on the victim PCs. Two of them, `unityplayer.dll` and `UX64` from PC B, are not on VirusTotal, and their sizes were not recorded.
- The lure ZIP for PC A was not found. For PC C the lure ZIP was quarantined but not hashed for this report.
- What restarted `FilmoraTray` on PC C was not identified before it stopped coming back.

## References

- MyCERT MA-1491 and MA-1493 (ManageEngine abuse, UltraViewer and sideloading lures).
- LOLDrivers, `thelper.sys`: https://www.loldrivers.io
- LOLRMM: https://lolrmm.io
- Trend Micro, SORVEPOTEL / Water Saci (Oct 2025): https://www.trendmicro.com/en_gb/research/25/j/self-propagating-malware-spreads-via-whatsapp.html
- Full indicator list: [`IOCS.md`](../../IOCS.md), [`docs/iocs.csv`](../iocs.csv)
