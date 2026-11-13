# Extra coverage: hash matching, loaded fake rime.dll, ardrv/OPSWAT, ManageEngine,
# locked files, and the double-click .bat launchers. Harmless stand-ins only.
# -Part 1|2|3|4 runs a quarter of the checks (each part plants what it needs and cleans up);
# 0 (the default) runs everything in one go.
param([ValidateSet(0, 1, 2, 3, 4)][int]$Part = 0)
$ErrorActionPreference = 'Continue'
$root = Split-Path -Parent $PSScriptRoot
$tool = Join-Path $root 'wa-zip-cleaner.ps1'
$q = 'C:\WAZipQuarantineExtra'
$fail = 0
$env:WAZIP_NO_PROMPT = '1'
# Never reboot the runner into Safe Mode: the tool writes its decision here instead.
$safeDry = "$env:TEMP\waz-safeauto.txt"
# Runners can ship with UAC off; switched off it is now always HIGH, so start every check from the Windows default.
$uacK = 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System'
Set-ItemProperty -LiteralPath $uacK -Name ConsentPromptBehaviorAdmin -Value 5 -Type DWord; Set-ItemProperty -LiteralPath $uacK -Name EnableLUA -Value 1 -Type DWord
$env:WAZIP_TEST_SAFEAUTO_DRY = $safeDry
$env:WAZIP_TIMING = '1'
Get-MpComputerStatus -ErrorAction SilentlyContinue | Format-List RealTimeProtectionEnabled, AMRunningMode, OnAccessProtectionEnabled
$progress = "$env:TEMP\waz-progress.txt"
function Note($m) { Add-Content -LiteralPath $progress -Value ('{0} {1}' -f (Get-Date -Format 'HH:mm:ss'), $m) -ErrorAction SilentlyContinue }
function Check($ok, $msg) {
  if ($ok) { Write-Host "PASS $msg" -ForegroundColor Green; Note "PASS $msg" } else { Write-Host "FAIL $msg" -ForegroundColor Red; $script:fail++; Note "FAIL $msg" }
}
function Scan($report, [switch]$Fix, [switch]$RemoveME, [string]$Owner, [string]$Out, [string]$Root = $q) {
  $a = @('-NoProfile', '-ExecutionPolicy', 'Bypass', '-File', $tool, '-QuarantineRoot', $Root, '-ReportPath', $report)
  if ($Fix) { $a += '-Fix' }
  if ($RemoveME) { $a += '-RemoveManageEngine' }
  if ($Owner) { $a += '-Owner', $Owner }
  $os = Get-CimInstance Win32_OperatingSystem -ErrorAction SilentlyContinue
  $dc = Get-CimInstance Win32_LogicalDisk -Filter "DeviceID='C:'" -ErrorAction SilentlyContinue
  $np = @(Get-Process -ErrorAction SilentlyContinue).Count
  Note ("scan start $(Split-Path $report -Leaf) $(if ($Fix) { '-Fix' }) | C: free {0:N0} MB | RAM free {1:N0} MB | {2} processes" -f ($dc.FreeSpace / 1MB), ($os.FreePhysicalMemory / 1KB), $np)
  $t0 = Get-Date; Write-Host "--- scan start $($t0.ToString('HH:mm:ss')) $(Split-Path $report -Leaf) $($a[6..($a.Count-1)] -join ' ')" -ForegroundColor DarkCyan
  if ($Out) { & powershell @a 2>&1 | Tee-Object -FilePath $Out | Out-Host } else { & powershell @a | Out-Host }
  Note "scan end $([int]((Get-Date) - $t0).TotalSeconds) s"
  Write-Host "--- scan end after $([int]((Get-Date) - $t0).TotalSeconds) s" -ForegroundColor DarkCyan
  $code = $LASTEXITCODE
  $items = @()
  if (Test-Path $report) { $parsed = Get-Content -Raw $report | ConvertFrom-Json; $items = @($parsed | ForEach-Object { $_ }) }
  @{ Code = $code; All = $items }
}
function Has($r, $kind, $sev, $targetRx, $detailRx = '.') {
  [bool]($r.All | Where-Object { $_.Kind -eq $kind -and $_.Severity -eq $sev -and $_.Target -match $targetRx -and $_.Detail -match $detailRx })
}
$dl = Join-Path $env:USERPROFILE 'Downloads'
New-Item -ItemType Directory -Force -Path $dl | Out-Null

function Start-Encoded($script) {
  $enc = [Convert]::ToBase64String([Text.Encoding]::Unicode.GetBytes($script))
  Start-Process powershell -ArgumentList '-NoProfile', '-EncodedCommand', $enc -WindowStyle Hidden -PassThru
}
function InPart($n) { $Part -eq 0 -or $Part -eq $n }
if ($Part) { Write-Host "Running part $Part of 4" -ForegroundColor Cyan }
Add-Type -AssemblyName System.IO.Compression.FileSystem
# A real zip holding the named entries, so the tool can look inside it.
function New-TestZip($path, [string[]]$entries) {
  Remove-Item -LiteralPath $path -Force -ErrorAction SilentlyContinue
  $z = [IO.Compression.ZipFile]::Open($path, 'Create')
  foreach ($e in $entries) { $w = New-Object IO.StreamWriter($z.CreateEntry($e).Open()); $w.Write('dummy'); $w.Close() }
  $z.Dispose()
}

if (InPart 1) {
Write-Host '=== Plant ===' -ForegroundColor Cyan
# A. Hash matching via test IOC file (random bytes, not malware)
$hd = 'C:\Users\Public\HashTest'
New-Item -ItemType Directory -Force -Path $hd, 'C:\ProgramData\OPSWAT' | Out-Null
$bad = New-Object byte[] 5003; (New-Object Random 1).NextBytes($bad); [IO.File]::WriteAllBytes("$hd\invoice-copy.dat", $bad)
$leg = New-Object byte[] 3007; (New-Object Random 2).NextBytes($leg)
[IO.File]::WriteAllBytes("$hd\helper.exe", $leg)
[IO.File]::WriteAllBytes('C:\ProgramData\OPSWAT\helper.exe', $leg)
$iocs = @(
  @{ Sha = (Get-FileHash "$hd\invoice-copy.dat").Hash; Size = 5003; Name = 'TEST-BAD' }
  @{ Sha = (Get-FileHash "$hd\helper.exe").Hash; Size = 3007; Name = 'TEST-LEGIT'; Vendor = 'OPSWAT' }
)
$iocs | ConvertTo-Json | Out-File -Encoding UTF8 "$env:TEMP\test-iocs.json"
$env:WAZIP_TEST_IOCS = "$env:TEMP\test-iocs.json"

# B. A process that has loaded a DLL named rime.dll from outside Program Files
$rd = 'C:\Users\Public\RimeTest'
New-Item -ItemType Directory -Force -Path $rd | Out-Null
Copy-Item "$env:SystemRoot\System32\version.dll" "$rd\rime.dll"
$loader = @"
Add-Type -Name K -Namespace W -MemberDefinition '[DllImport("kernel32.dll", CharSet=CharSet.Unicode)] public static extern IntPtr LoadLibrary(string p);'
[W.K]::LoadLibrary('$rd\rime.dll') | Out-Null
Start-Sleep 900
"@
$rimeHost = Start-Encoded $loader

# C. Driver services and a ManageEngine agent look-alike (never started)
Set-Content "$env:SystemRoot\System32\drivers\ardrv.sys" 'dummy'
& sc.exe create ardrv type= kernel start= demand binPath= "System32\drivers\ardrv.sys" | Out-Null
& sc.exe create OpswatLegitTest type= kernel start= demand binPath= "C:\Program Files\OPSWAT\ardrv.sys" | Out-Null
& sc.exe create MEUemsTest start= demand DisplayName= "ManageEngine UEMS - Agent" binPath= "$env:SystemRoot\System32\svchost.exe" | Out-Null

# D. Lure file held open by a running process (stands in for malware resisting removal)
$locked = "$dl\Click here to view7.zip"
Set-Content "$dl\Reconciliation Invoice.zip" 'dummy'
Set-Content "$dl\Rekonsiliasi Akun.zip" 'dummy'
# MicroPoint chain under another ProgramData name, with its driver loaded from a .dat file (opt-in report, Nov 2026).
$vlDir = "$env:ProgramData\WazVirtualLinux"
New-Item -ItemType Directory -Force -Path $vlDir | Out-Null
Set-Content "$vlDir\WinCombo.exe" 'dummy'; Set-Content "$vlDir\Security_Module.dat" 'dummy'
& sc.exe create WazMsDriver type= kernel start= demand binPath= "$vlDir\Security_Module.dat" | Out-Null
# A VHD Explorer unpacked from a ZIP that was opened directly.
$vhdUnzip = "$env:TEMP\3f2bdc19-2690-456d-b323-37b01a256dc4_Waz Test Lure.zip.dc4"
New-Item -ItemType Directory -Force -Path $vhdUnzip | Out-Null
Set-Content "$vhdUnzip\Waz Test Lure.vhd" 'dummy'
# Same, in the <guid>_<name>.zip.<name>.zip\ shape that two clean-ups left behind as a warning (opt-in report, Nov 2026).
$vhdUnzip2 = "$env:TEMP\7b5e9327-c899-44e6-8733-29c21c690ee0_WazMys.zip.WazMys.zip"
New-Item -ItemType Directory -Force -Path $vhdUnzip2 | Out-Null
Set-Content "$vhdUnzip2\WazMys.vhd" 'dummy'
# Hidden+System payload DLL in Temp from the same report.
$hsDll = "$env:TEMP\hs_rt32_wazt0001.dll"
Set-Content $hsDll 'dummy'
(Get-Item -LiteralPath $hsDll -Force).Attributes = 'Hidden, System'
# Developer files whose names contain a lure word must stay untouched (false positives from an opt-in report, Nov 2026).
$devNpm = "$env:APPDATA\npm\node_modules\wazfake\lib"; $devDoc = "$env:USERPROFILE\Documents\WazDev"
New-Item -ItemType Directory -Force -Path $devNpm, $devDoc | Out-Null
Set-Content "$devNpm\checkProjectBilling.js" 'module.exports = function () { return 1 }'
Set-Content "$devDoc\build_salary_deck.js" 'console.log("deck")'
Set-Content "$devDoc\WorkflowsStepFailedResponse.js" 'export {}'
Set-Content "$dl\Invoice Nov 2026.js" 'var s = new ActiveXObject("WScript.Shell");'
# Defender caught the image inside a lure ZIP while Explorer unpacked it; the ZIP stays in a subfolder of Downloads.
New-Item -ItemType Directory -Force -Path "$dl\wa" | Out-Null
Set-Content "$dl\wa\Account Summary 0411.zip" 'dummy'
$env:WAZIP_TEST_DEFDET = "Trojan:Win32/Malgent|file:_$env:TEMP\cca655ea-b3ee-49d8-bac2-64ce8eeda700_Account Summary 0411.zip.700\4.img"
Set-Content $locked 'dummy'
$lock = "`$f=[IO.File]::Open('$locked','Open','Read','None'); Start-Sleep 3600"
$locker = Start-Encoded $lock
# Wait until the fake rime.dll is really loaded before scanning.
for ($i = 0; $i -lt 30; $i++) {
  $loaded = try { (Get-Process -Id $rimeHost.Id).Modules | Where-Object ModuleName -eq 'rime.dll' } catch { $null }
  if ($loaded) { break }
  Start-Sleep 1
}
Check ([bool]$loaded) 'test setup: fake rime.dll loaded in host process'

# E. Renamed VHD lures, a generic VHD, and a WSL disk that must be ignored
Set-Content "$dl\Notice.vhd" 'dummy'
Set-Content "$dl\Other.vhdx" 'dummy'
$wsl = Join-Path $env:LOCALAPPDATA 'Packages\CanonicalGroupLimited.Test\LocalState'
New-Item -ItemType Directory -Force -Path $wsl | Out-Null
Set-Content "$wsl\ext4.vhdx" 'dummy'

# F. A process holding a TCP connection to a "known C2" (an odd loopback address, never the real one)
$env:WAZIP_TEST_C2 = '127.77.0.1'
$srv = Start-Encoded "`$l=[Net.Sockets.TcpListener]::new([Net.IPAddress]::Parse('127.77.0.1'),47123); `$l.Start(); `$c=`$l.AcceptTcpClient(); Start-Sleep 3600"
Start-Sleep 2
$cli = Start-Encoded "`$t=[Net.Sockets.TcpClient]::new(); `$t.Connect('127.77.0.1',47123); Start-Sleep 3600"
for ($i = 0; $i -lt 20; $i++) {
  if (Get-NetTCPConnection -RemoteAddress 127.77.0.1 -ErrorAction SilentlyContinue) { break }
  Start-Sleep 1
}

# G. Windows Defender told to skip a program and the fake Microsoft\Update folder (October 2026 wave)
$stageDir = "$env:APPDATA\Microsoft\Update"
$defOk = $false
try {
  Add-MpPreference -ExclusionProcess 'QtsUpdater.exe' -ErrorAction Stop
  Add-MpPreference -ExclusionPath $stageDir -ErrorAction Stop
  # Victim report 2026-10-28: wscript.exe excluded together with the whole user folder.
  Add-MpPreference -ExclusionProcess 'wscript.exe' -ErrorAction Stop
  Add-MpPreference -ExclusionPath 'C:\Users\WazExclTest' -ErrorAction Stop
  $defOk = @((Get-MpPreference).ExclusionProcess) -contains 'QtsUpdater.exe'
} catch { Write-Host "Defender not available: $($_.Exception.Message)" }

# H. LOLDrivers matches (random bytes listed in a test copy of the list), a remote-control
# program service, and the Microsoft driver blocklist switched off. Nothing is loaded or started.
$drvDir = "$env:SystemRoot\System32\drivers"
$mal = New-Object byte[] 4099; (New-Object Random 3).NextBytes($mal); [IO.File]::WriteAllBytes("$drvDir\wazlolm.sys", $mal)
$vul = New-Object byte[] 4101; (New-Object Random 4).NextBytes($vul); [IO.File]::WriteAllBytes("$drvDir\wazlolv.sys", $vul)
& sc.exe create WazLolMal type= kernel start= demand binPath= "System32\drivers\wazlolm.sys" | Out-Null
& sc.exe create WazLolVuln type= kernel start= demand binPath= "\SystemRoot\System32\drivers\wazlolv.sys" | Out-Null
@('sha256,kind,name',
  "$((Get-FileHash "$drvDir\wazlolm.sys").Hash.ToLower()),malicious,test-malicious.sys",
  "$((Get-FileHash "$drvDir\wazlolv.sys").Hash.ToLower()),vulnerable,test-vulnerable.sys") | Set-Content -Encoding ASCII "$env:TEMP\test-lol.csv"
$env:WAZIP_TEST_LOLDRIVERS = "$env:TEMP\test-lol.csv"
# Vulnerable driver renamed in Temp (WAZ-P9WPT) vs one keeping its name; HWiNFO's signed Temp driver (WAZ-N5DZS).
[IO.File]::WriteAllBytes("$env:TEMP\WazEmbeddedDrv.sys", $vul); [IO.File]::WriteAllBytes("$env:TEMP\test-vulnerable2.sys", $vul)
New-Item -ItemType Directory -Force -Path "$env:APPDATA\Microsoft" | Out-Null; [IO.File]::WriteAllBytes("$env:APPDATA\Microsoft\test-vulnerable3.sys", $vul)
Copy-Item -LiteralPath "$drvDir\null.sys" -Destination "$env:TEMP\HWiNFO64A_999.SYS" -Force
& sc.exe create HWiNFO_999 type= kernel start= demand binPath= "$env:TEMP\HWiNFO64A_999.SYS" | Out-Null
Copy-Item -LiteralPath "$drvDir\null.sys" -Destination "$env:TEMP\GPU-Z-v99.sys" -Force
& sc.exe create GPU-Z-v99 type= kernel start= demand binPath= "$env:TEMP\GPU-Z-v99.sys" | Out-Null
# HWiNFO closed: its driver file is gone, only the stopped service entry is left.
& sc.exe create HWiNFO_998 type= kernel start= demand binPath= "$env:SystemRoot\Temp\HWiNFO_x64_998.sys" | Out-Null
& sc.exe create WazRmmTest start= demand binPath= "C:\Program Files (x86)\AnyDesk\AnyDesk.exe --service" | Out-Null
# MSP360 and Faronics Deploy agents from phishing e-mails (Microsoft, Sep 2026).
& sc.exe create WazMsp360Test start= demand binPath= "`"C:\Program Files\RMM Agent\RMM.Agent.exe`"" | Out-Null
& sc.exe create WazCrdTest start= demand binPath= "`"C:\Program Files (x86)\Google\Chrome Remote Desktop\157.0.1.1\remoting_host.exe`"" | Out-Null
& sc.exe create WazFaronicsTest start= demand binPath= "`"C:\Program Files\Faronics\Deploy\FaronicsDeployAgent.exe`"" | Out-Null
# UltraViewer is always removed (AFU, Nov 2026): planted folder, service and Apps entry.
$uvDir = 'C:\Program Files (x86)\UltraViewer'
New-Item -ItemType Directory $uvDir -Force | Out-Null
'harmless stand-in' | Set-Content -Encoding ASCII "$uvDir\UltraViewer_Service.exe"
& sc.exe create WazUvTest start= demand binPath= "$uvDir\UltraViewer_Service.exe" | Out-Null
$uvKey = 'HKLM:\SOFTWARE\WOW6432Node\Microsoft\Windows\CurrentVersion\Uninstall\WazUvTest'
New-Item $uvKey -Force | Out-Null; Set-ItemProperty $uvKey DisplayName 'UltraViewer 6.6'
$ciKey = 'HKLM:\SYSTEM\CurrentControlSet\Control\CI\Config'
$ciOld = (Get-ItemProperty -LiteralPath $ciKey -ErrorAction SilentlyContinue).VulnerableDriverBlocklistEnable
New-Item -Path $ciKey -Force -ErrorAction SilentlyContinue | Out-Null
New-ItemProperty -Path $ciKey -Name VulnerableDriverBlocklistEnable -Value 0 -PropertyType DWord -Force | Out-Null
$wuKey = 'HKLM:\SYSTEM\CurrentControlSet\Services\wuauserv'
Set-ItemProperty -LiteralPath $wuKey -Name Start -Value 4

# I. Browser tricks: an extension forced in by policy, a Chrome shortcut that loads a hidden
# extension, and an extension loaded from a folder.
$polKey = 'HKLM:\SOFTWARE\Policies\Google\Chrome\ExtensionInstallForcelist'
New-Item -Path $polKey -Force | Out-Null
New-ItemProperty -Path $polKey -Name '1' -Value 'abcdefghijklmnopabcdefghijklmnop;https://example.invalid/update.xml' -Force | Out-Null
$lnk = 'C:\Users\Public\Desktop\Google Chrome WAZip.lnk'
$s = (New-Object -ComObject WScript.Shell).CreateShortcut($lnk)
$s.TargetPath = 'C:\Program Files\Google\Chrome\Application\chrome.exe'
$s.Arguments = '--load-extension="C:\Users\Public\ext"'
$s.Save()
$prof = "$env:LOCALAPPDATA\Google\Chrome\User Data\Profile 7"
New-Item -ItemType Directory -Force -Path $prof | Out-Null
'{"extensions":{"settings":{"ponmlkjihgfedcbaponmlkjihgfedcba":{"location":4,"path":"C:\\Users\\Public\\ext"}}}}' | Set-Content -Encoding ASCII "$prof\Secure Preferences"
# Y5JSV (Nov 2026): Windows PowerShell could not read the Preferences file; the folder-loaded extension must still show.
$prof8 = "$env:LOCALAPPDATA\Google\Chrome\User Data\Profile 8"
New-Item -ItemType Directory -Force -Path $prof8, 'C:\Users\Public\wazext8' | Out-Null
'{}' | Set-Content -Encoding ASCII 'C:\Users\Public\wazext8\manifest.json'
'{"extensions":{"settings":{"abcdefghijklmnopabcdefghijklmnop":{"location":4,"path":"C:\\Users\\Public\\wazext8"}}}, broken' | Set-Content -Encoding ASCII "$prof8\Preferences"

Write-Host '=== Scan ===' -ForegroundColor Cyan
$r = Scan "$env:TEMP\x1.json"
if ($defOk) {
  Check (Has $r 'DefExcl' 'HIGH' 'QtsUpdater\.exe$') 'Defender process exclusion is HIGH'
  Check (Has $r 'DefExcl' 'HIGH' 'Microsoft\\Update$') 'Defender exclusion of fake Microsoft\Update folder is HIGH'
  Check (Has $r 'DefExcl' 'HIGH' 'wscript\.exe$') 'Defender wscript.exe exclusion is HIGH'
  Check (Has $r 'DefExcl' 'HIGH' 'Users\\WazExclTest$') 'user-folder exclusion next to wscript.exe is HIGH'
} else { Write-Host 'SKIP Defender exclusion checks (Defender unavailable on this runner)' -ForegroundColor Yellow }
Check (Has $r 'File' 'HIGH' 'HashTest\\invoice-copy\.dat$' 'TEST-BAD') 'hash match: known-bad file'
Check (Has $r 'File' 'HIGH' 'HashTest\\helper\.exe$' 'TEST-LEGIT') 'hash match: abused legit file outside vendor folder'
Check (-not ($r.All | Where-Object { $_.Target -match 'ProgramData\\OPSWAT\\helper\.exe' })) 'hash match: legit file inside vendor folder ignored'
Check (Has $r 'Process' 'HIGH' 'powershell' 'Loaded fake rime\.dll') 'process with loaded fake rime.dll'
Check (Has $r 'File' 'WARN' 'RimeTest\\rime\.dll$') 'lone rime.dll outside Program Files is WARN'
Check (Has $r 'Service' 'HIGH' '^ardrv$') 'ardrv service outside OPSWAT folder'
Check (-not ($r.All | Where-Object { $_.Target -eq 'OpswatLegitTest' })) 'ardrv in OPSWAT folder ignored'
Check (Has $r 'Info' 'HIGH' 'ManageEngine' 'other malware') 'ManageEngine is HIGH when other malware is on the PC'
Check (Has $r 'File' 'HIGH' 'Click here to view7\.zip$') 'locked lure file detected'
Check (Has $r 'File' 'HIGH' 'Reconciliation Invoice\.zip$') 'Reconciliation Invoice.zip lure name is HIGH'
Check (Has $r 'File' 'HIGH' 'Rekonsiliasi Akun\.zip$') 'Rekonsiliasi Akun.zip (Indonesian variant) lure name is HIGH'
Check (Has $r 'File' 'HIGH' 'WazVirtualLinux$' 'MicroPoint') 'renamed MicroPoint folder (WinCombo.exe) is HIGH'
Check (Has $r 'Service' 'HIGH' '^WazMsDriver$' 'data file') 'driver loaded from a .dat file in ProgramData is HIGH'
Check (Has $r 'File' 'HIGH' 'Waz Test Lure\.vhd$' 'straight from a ZIP') 'VHD opened straight from a ZIP is HIGH'
Check (Has $r 'File' 'HIGH' 'WazMys\.zip\.WazMys\.zip\\WazMys\.vhd$' 'straight from a ZIP') 'VHD opened from a ZIP (<name>.zip.<name>.zip shape) is HIGH'
Check (Has $r 'File' 'HIGH' 'hs_rt32_wazt0001\.dll$' 'Temp folder') 'Hidden+System hs_rt32 DLL in Temp is HIGH'
Check (-not ($r.All | Where-Object { $_.Target -match 'checkProjectBilling\.js$|build_salary_deck\.js$|WorkflowsStepFailedResponse\.js$' })) 'developer .js files with lure words are not flagged'
Check (Has $r 'File' 'HIGH' 'Invoice Nov 2026\.js$' 'VBS campaign') 'document-named .js that uses Windows Script Host is HIGH'
Check (Has $r 'File' 'HIGH' 'wa\\Account Summary 0411\.zip$' 'Defender flagged as Trojan:Win32/Malgent') 'lure ZIP found from the Defender detection path'
Check (Has $r 'File' 'HIGH' 'Downloads\\Notice\.vhd$') 'Notice.vhd lure is HIGH'
Check (Has $r 'Process' 'HIGH' "PID $($cli.Id)\)" 'attacker server') 'process connected to known C2 is HIGH'
Check (Has $r 'File' 'WARN' 'Downloads\\Other\.vhdx$') 'other VHD in user folder is WARN'
Check (-not ($r.All | Where-Object { $_.Target -match 'ext4\.vhdx' })) 'WSL ext4.vhdx ignored'
Check (Has $r 'Service' 'HIGH' '^WazLolMal$' 'LOLDrivers') 'LOLDrivers malicious driver service is HIGH'
Check (Has $r 'Service' 'WARN' '^WazLolVuln$' 'vulnerable') 'LOLDrivers vulnerable driver service is WARN'
Check (Has $r 'File' 'HIGH' 'WazEmbeddedDrv\.sys$' 'Renamed vulnerable driver') 'renamed vulnerable driver in Temp is HIGH'
Check (Has $r 'File' 'WARN' 'test-vulnerable2\.sys$') 'vulnerable driver in Temp keeping its own name stays WARN'
Check (Has $r 'File' 'HIGH' 'Roaming\\Microsoft\\test-vulnerable3\.sys$' 'Roaming\\Microsoft') 'vulnerable driver loose in AppData\Roaming\Microsoft is HIGH'
$hwSig = (Get-AuthenticodeSignature -LiteralPath "$env:TEMP\HWiNFO64A_999.SYS").Status
if ($hwSig -eq 'Valid') { Check (-not (Has $r 'Service' 'HIGH' '^HWiNFO_999$')) 'signed HWiNFO driver in Temp is not an antivirus killer'
  Check (-not (Has $r 'Service' 'HIGH' '^GPU-Z-v99$')) 'signed GPU-Z driver in Temp is not an antivirus killer' }
else { Write-Host "SKIP HWiNFO: test copy signature is $hwSig" -ForegroundColor Yellow }
Check (-not (Has $r 'Service' 'HIGH' '^HWiNFO_998$')) 'HWiNFO service left after its driver file was deleted is not an antivirus killer'
& sc.exe delete HWiNFO_999 | Out-Null; & sc.exe delete GPU-Z-v99 | Out-Null; & sc.exe delete HWiNFO_998 | Out-Null
Remove-Item -LiteralPath "$env:APPDATA\Microsoft\test-vulnerable3.sys" -Force -ErrorAction SilentlyContinue
Remove-Item -LiteralPath "$env:TEMP\WazEmbeddedDrv.sys", "$env:TEMP\test-vulnerable2.sys", "$env:TEMP\HWiNFO64A_999.SYS", "$env:TEMP\GPU-Z-v99.sys" -Force -ErrorAction SilentlyContinue
Check (Has $r 'Info' 'WARN' 'Remote-control program: AnyDesk') 'remote-control program (AnyDesk) is WARN'
Check (Has $r 'Info' 'WARN' 'Remote-control program: MSP360 RMM') 'MSP360 RMM agent is WARN'
Check (Has $r 'Info' 'WARN' 'Remote-control program: Chrome Remote Desktop') 'Chrome Remote Desktop is WARN'
Check (Has $r 'Info' 'WARN' 'Chrome extension wazext8' 'from a folder') 'folder-loaded extension found when Preferences cannot be parsed'
Check (Has $r 'Info' 'WARN' 'Remote-control program: Faronics Deploy') 'Faronics Deploy agent is WARN'
Check (Has $r 'Service' 'HIGH' '^WazUvTest$' 'UltraViewer') 'UltraViewer service is HIGH'
Check (Has $r 'File' 'HIGH' 'UltraViewer$' 'UltraViewer') 'UltraViewer folder is HIGH'
Check (Has $r 'RegKey' 'HIGH' 'WazUvTest$' 'UltraViewer') 'UltraViewer Apps entry is HIGH'
Check (-not ($r.All | Where-Object { $_.Target -eq 'Remote-control program: UltraViewer' })) 'UltraViewer not also listed as a plain warning'
$scanLog = Get-ChildItem $q -Filter 'scan-*.log' | Sort-Object LastWriteTime | Select-Object -Last 1
Check ($scanLog -and (Select-String -LiteralPath $scanLog.FullName -SimpleMatch 'Maksud: Program kawalan jauh (contoh AnyDesk' -Quiet)) 'warning explained in plain Malay'
Check (Has $r 'Info' 'WARN' 'Blocklist is OFF') 'driver blocklist switched off is WARN'
Check (Has $r 'Info' 'WARN' 'Windows Update is disabled') 'Windows Update switched off is WARN'
Check (Has $r 'RegValue' 'WARN' 'ExtensionInstallForcelist\|1$') 'forced Chrome extension is WARN when owner unknown'
Check (Has $r 'File' 'HIGH' 'Google Chrome WAZip\.lnk$' 'load-extension') 'Chrome shortcut loading a hidden extension is HIGH'
Check (Has $r 'Info' 'WARN' 'Chrome extension ponmlkjihgfedcba' 'from a folder') 'extension loaded from a folder is WARN'

Write-Host '=== Fix while file is locked (and send the opt-in report to a local stand-in inbox) ===' -ForegroundColor Cyan
$repDir = "$env:TEMP\waz-rep"
New-Item -ItemType Directory -Force -Path $repDir | Out-Null
$repJob = Start-Job {
  param($out)
  # Never block for ever: a job stuck in GetContext() cannot be stopped and hangs the whole run (Windows 2025 runner, Nov 2026).
  $l = New-Object Net.HttpListener; $l.Prefixes.Add('http://127.0.0.1:8796/'); $l.Start()
  $wait = $l.GetContextAsync()
  if (-not $wait.Wait(180000)) { $l.Close(); 'stand-in inbox: no request within 3 minutes'; return }
  $ctx = $wait.Result
  $ms = New-Object IO.MemoryStream; $ctx.Request.InputStream.CopyTo($ms); [IO.File]::WriteAllBytes($out, $ms.ToArray())
  $b = [Text.Encoding]::ASCII.GetBytes('{"id":"WAZ-TEST7"}')
  $ctx.Response.ContentType = 'application/json'; $ctx.Response.ContentLength64 = $b.Length; $ctx.Response.OutputStream.Write($b, 0, $b.Length); $ctx.Response.Close(); $l.Stop()
} -ArgumentList "$repDir\posted.zip"
Start-Sleep 5
$env:WAZIP_TEST_REPORT_DIR = $repDir
$env:WAZIP_TEST_REPORT_URL = 'http://127.0.0.1:8796/report'
$r = Scan "$env:TEMP\x2.json" -Fix -Out "$env:TEMP\x2.out"
$x2out = Get-Content -Raw "$env:TEMP\x2.out"
Wait-Job $repJob -Timeout 200 | Out-Null; Receive-Job $repJob -ErrorAction SilentlyContinue | Out-Host
if ($repJob.State -eq 'Running') { Write-Host 'stand-in inbox job still running; leaving it' } else { Remove-Job $repJob -Force }
Check ($x2out -match 'WAZ-TEST7') 'opt-in report sent and the reference number shown'
Check ($x2out -match '(?m)^ KUARANTIN SIAP') 'quarantine-done tag printed at the left edge on its own line'
Check (-not (Test-Path -LiteralPath "$vhdUnzip2\WazMys.vhd")) 'lure VHD (<name>.zip.<name>.zip shape) quarantined by -Fix'
Check (-not (Test-Path -LiteralPath $hsDll)) 'Hidden+System hs_rt32 DLL in Temp quarantined by -Fix'
Remove-Item -LiteralPath $vhdUnzip2, $hsDll -Recurse -Force -ErrorAction SilentlyContinue
$repEntries = @{}
if (Test-Path "$repDir\posted.zip") {
  Add-Type -AssemblyName System.IO.Compression.FileSystem
  $zr = [IO.Compression.ZipFile]::OpenRead("$repDir\posted.zip")
  foreach ($e in $zr.Entries) { $sr = New-Object IO.StreamReader($e.Open()); $repEntries[$e.FullName] = $sr.ReadToEnd(); $sr.Close() }
  $zr.Dispose()
}
Check ($repEntries.ContainsKey('timeline.txt') -and $repEntries['timeline.txt'] -match '== Services installed' -and $repEntries['timeline.txt'] -match 'WazUvTest') 'report timeline lists recently installed services'
Check ($repEntries.ContainsKey('summary.json') -and $repEntries.ContainsKey('scan.log')) "report zip holds summary.json and scan.log ($($repEntries.Keys -join ', '))"
$repSum = $null; try { $repSum = $repEntries['summary.json'] | ConvertFrom-Json } catch {}
Check ($repSum -and $repSum.version -and $repSum.counts.high -gt 0 -and @($repSum.findings).Count -gt 0) 'report summary has version, counts and findings'
Check ($repSum -and @($repSum.c2) -contains '127.77.0.1') 'report summary lists the attacker server'
Check ($repSum -and @($repSum.findings | Where-Object { $_.type -eq 'Process' -and $_.parent }).Count -gt 0) 'report shows which program started a bad process'
Check ($repSum -and @($repSum.findings | Where-Object { $_.type -eq 'File' -and $_.sha256 -match '^[0-9a-f]{64}$' -and $_.size -gt 0 }).Count -gt 0) 'report lists SHA-256 and size of found files'
$repAll = ($repEntries.Values | Out-String)
Check ($repAll -and $repAll -notmatch [regex]::Escape($env:USERNAME) -and $repAll -notmatch [regex]::Escape($env:COMPUTERNAME)) 'report has no account name or PC name'
Check ($repAll -match 'Users\\{1,2}<user>') 'report shows user folders as <user>'
Check ($r.Code -eq 1) "fix does not crash on locked file (exit $($r.Code))"
Check (Test-Path $locked) 'locked file left in place (reported, not lost)'
Check (-not (Test-Path "$hd\invoice-copy.dat")) 'hash-matched file quarantined'
Check (-not (Get-Process -Id $rimeHost.Id -ErrorAction SilentlyContinue)) 'rime.dll host process stopped'
& sc.exe query ardrv | Out-Null; Check ($LASTEXITCODE -ne 0) 'ardrv service deleted'
Check (-not (Test-Path "$env:SystemRoot\System32\drivers\ardrv.sys")) 'ardrv.sys driver file quarantined'
Check (-not (Get-Service MEUemsTest -ErrorAction SilentlyContinue)) 'ManageEngine removed when other malware is on the PC'
& sc.exe query WazUvTest | Out-Null; Check ($LASTEXITCODE -ne 0) 'UltraViewer service deleted'
Check (-not (Test-Path -LiteralPath $uvDir)) 'UltraViewer folder quarantined'
Check (-not (Test-Path $uvKey)) 'UltraViewer Apps entry removed'
Check (Test-Path 'C:\ProgramData\OPSWAT\helper.exe') 'vendor-folder legit file untouched'
Check (-not (Get-Process -Id $cli.Id -ErrorAction SilentlyContinue)) 'C2-connected process stopped'
Check (-not (Test-Path $lnk)) 'hidden-extension shortcut quarantined'
Check (Test-Path $polKey) 'forced extension policy kept when owner unknown'
& sc.exe query WazLolMal | Out-Null; Check ($LASTEXITCODE -ne 0) 'malicious driver service deleted'
Check (-not (Test-Path "$drvDir\wazlolm.sys")) 'malicious driver file quarantined'
& sc.exe query WazLolVuln | Out-Null; Check ($LASTEXITCODE -eq 0) 'vulnerable driver left for the user to decide'
if ($defOk) {
  $mp = Get-MpPreference
  Check (-not (@($mp.ExclusionProcess) -contains 'QtsUpdater.exe')) 'Defender process exclusion removed'
  Check (-not (@($mp.ExclusionPath) -contains $stageDir)) 'Defender folder exclusion removed'
  Check (-not (@($mp.ExclusionProcess) -contains 'wscript.exe')) 'Defender wscript.exe exclusion removed'
  Check (-not (@($mp.ExclusionPath) -contains 'C:\Users\WazExclTest')) 'user-folder exclusion removed'
}
Remove-Item Env:\WAZIP_TEST_C2

Write-Host '=== Release lock, fix again ===' -ForegroundColor Cyan
Stop-Process -Id $locker.Id -Force; Start-Sleep 2
$env:WAZIP_TEST_REPORT_URL = 'http://127.0.0.1:8797/report'
$r = Scan "$env:TEMP\x3.json" -Fix -Out "$env:TEMP\x3.out"
Check (-not (Test-Path $locked)) 'previously locked file quarantined on second run'
Check ((Get-Content -Raw "$env:TEMP\x3.out") -match '@afwazan' -and (Get-ChildItem $repDir -Filter 'Laporan-WAZIP-*.zip')) 'report kept as a file with Telegram steps when the inbox is unreachable'
Remove-Item Env:\WAZIP_TEST_REPORT_DIR, Env:\WAZIP_TEST_REPORT_URL

Write-Host '=== Force-remove ManageEngine ===' -ForegroundColor Cyan
# Look-alike agent: folder, service, scheduled task and Apps entry (nothing real is installed).
$meDir = "${env:ProgramFiles(x86)}\ManageEngine\UEMS_Agent"
New-Item -ItemType Directory -Force -Path "$meDir\bin" | Out-Null
Set-Content "$meDir\bin\dcagentservice.exe" 'dummy'
& sc.exe create MEUemsAgentTest start= demand DisplayName= "ManageEngine UEMS - Agent Test" binPath= "`"$meDir\bin\dcagentservice.exe`"" | Out-Null
Register-ScheduledTask -TaskName 'ManageEngine UEMS Test' -Action (New-ScheduledTaskAction -Execute "$meDir\bin\dcagentservice.exe") -Trigger (New-ScheduledTaskTrigger -AtLogOn) -Force | Out-Null
$meUn = 'HKLM:\Software\WOW6432Node\Microsoft\Windows\CurrentVersion\Uninstall\{WAZIP-ME-TEST}'
New-Item -Path $meUn -Force | Out-Null
New-ItemProperty -Path $meUn -Name DisplayName -Value 'ManageEngine UEMS - Agent' -Force | Out-Null
$meCfg = 'HKLM:\SOFTWARE\WOW6432Node\AdventNet\DesktopCentral\DCAgent'
New-Item -Path $meCfg -Force | Out-Null
$meMsi = 'HKLM:\SOFTWARE\Classes\Installer\Products\WAZIPMETEST0000000000000000000000'
New-Item -Path $meMsi -Force | Out-Null
New-ItemProperty -Path $meMsi -Name ProductName -Value 'ManageEngine UEMS - Agent' -Force | Out-Null
New-NetFirewallRule -Name WazMeFwTest -DisplayName 'WazMeFwTest' -Program "$meDir\bin\dcagentservice.exe" -Direction Inbound -Action Allow | Out-Null
$fwKey = 'HKLM:\SYSTEM\CurrentControlSet\Services\SharedAccess\Parameters\FirewallPolicy\FirewallRules'
New-Item -Path 'HKLM:\SOFTWARE\ManageEngine\WazTest' -Force | Out-Null
& sc.exe create MEARService start= demand binPath= "$env:SystemRoot\System32\svchost.exe" | Out-Null
$r = Scan "$env:TEMP\x4.json" -Fix
Check (Test-Path $meDir) 'ManageEngine kept when the user did not confirm'
$r = Scan "$env:TEMP\x4b.json" -Fix -Owner Office
Check (Test-Path $meDir) 'ManageEngine kept on an office PC'
Check (Has $r 'Info' 'WARN' 'ManageEngine' 'IT') 'office PC gets the ask-your-IT warning'
Check ($r.Code -eq 3) "warnings-only scan exits 3 (got $($r.Code))"
$r = Scan "$env:TEMP\x5.json" -Fix -Owner Personal
Check (Has $r 'Info' 'HIGH' 'ManageEngine') 'ManageEngine is HIGH on a personal PC'
Check (-not (Test-Path $meDir)) 'ManageEngine folder quarantined'
& sc.exe query MEUemsAgentTest | Out-Null; Check ($LASTEXITCODE -ne 0) 'ManageEngine service deleted'
Check (-not (Get-ScheduledTask -TaskName 'ManageEngine UEMS Test' -ErrorAction SilentlyContinue)) 'ManageEngine task removed'
Check (-not (Test-Path $meUn)) 'ManageEngine Apps entry removed'
Check (-not (Test-Path $meCfg)) 'ManageEngine settings key removed'
Check (-not (Test-Path 'HKLM:\SOFTWARE\ManageEngine')) 'SOFTWARE\ManageEngine key removed'
& sc.exe query MEARService | Out-Null; Check ($LASTEXITCODE -ne 0) 'MEARService (no ManageEngine name) deleted'
Check (-not (Test-Path $meMsi)) 'ManageEngine installer record removed'
Check (-not ((Get-Item $fwKey).GetValueNames() -contains 'WazMeFwTest')) 'ManageEngine firewall opening removed'
Check (Has $r 'RegValue' 'HIGH' 'ExtensionInstallForcelist\|1$') 'forced Chrome extension is HIGH on a personal PC'
Check (-not ((Get-Item $polKey -ErrorAction SilentlyContinue).GetValueNames() -contains '1')) 'forced extension policy removed on a personal PC'

# Victim report 2026-10-28: a removed service stays listed until restart and kept the scan red.
& sc.exe create MEPendingTest start= demand DisplayName= "ManageEngine Pending Test" binPath= "$env:SystemRoot\System32\svchost.exe" | Out-Null
Set-ItemProperty 'HKLM:\SYSTEM\CurrentControlSet\Services\MEPendingTest' -Name DeleteFlag -Value 1 -Type DWord
$r = Scan "$env:TEMP\x5p.json" -Owner Personal
Check (-not ($r.All | Where-Object { $_.Target -eq 'MEPendingTest' })) 'service already marked for deletion is not reported again'
& sc.exe delete MEPendingTest | Out-Null

Write-Host '=== October 2026 research additions ===' -ForegroundColor Cyan
# MicroPoint chain (Triage): install folder, Run value and a per-user CLSID admin-prompt bypass.
$mpDir = 'C:\ProgramData\MicroPoint'
New-Item -ItemType Directory -Force -Path $mpDir | Out-Null
Set-Content "$mpDir\WinCombo.exe" 'dummy'
$runKey = 'HKLM:\Software\Microsoft\Windows\CurrentVersion\Run'
New-ItemProperty -Path $runKey -Name ServiceController -Value "$mpDir\WinCombo.exe" -Force | Out-Null
$clsid = 'HKCU:\Software\Classes\CLSID\{0A7E5D1C-3B2F-4C6D-9E8F-WAZTEST00001}'
New-Item -Path "$clsid\Shell\Manage\command" -Force | Out-Null
Set-Item -Path "$clsid\Shell\Manage\command" -Value "$mpDir\WinCombo.exe"
# Chinese reports: settings key, and Defender told to skip every drive (the runner image already skips C: and D:).
New-Item -Path 'HKLM:\SOFTWARE\JDBCC\data' -Force | Out-Null
$rootOk = $false
try { Add-MpPreference -ExclusionPath 'C:\', 'E:\', 'F:\' -ErrorAction Stop; $rootOk = $true } catch { Write-Host "Defender not available: $($_.Exception.Message)" }
# Firewall told to block everything going out. Domain profile only: the runner is not domain-joined.
$fwOld = (Get-NetFirewallProfile -Profile Domain).DefaultOutboundAction
Set-NetFirewallProfile -Profile Domain -DefaultOutboundAction Block
# Double-extension lure and a driver service loaded from Temp (SSM/SOA lures).
Set-Content "$dl\INVOIS.vhd.zip" 'dummy'
Set-Content 'C:\Windows\Temp\EmbeddedDriverService.sys' 'dummy'
& sc.exe create EmbeddedDriverService type= kernel start= demand binPath= 'C:\Windows\Temp\EmbeddedDriverService.sys' | Out-Null
# Ping32 agent (Netresec): the WhatsApp VBS variant that installs it instead of ManageEngine.
$p32 = 'C:\ProgramData\Ping32'
New-Item -ItemType Directory -Force -Path $p32 | Out-Null
Set-Content "$p32\NSecRTS.exe" 'dummy'
& sc.exe create WazPing32Test start= demand binPath= "`"$p32\NSecRTS.exe`"" | Out-Null

$r6 = Scan "$env:TEMP\x6.json"
Check (Has $r6 'File' 'HIGH' 'ProgramData\\MicroPoint$') 'MicroPoint folder is HIGH'
Check (Has $r6 'RegValue' 'HIGH' 'Run\|ServiceController$') 'MicroPoint Run value is HIGH'
Check (Has $r6 'RegKey' 'HIGH' 'WAZTEST00001\}$' 'admin-prompt bypass') 'CLSID Shell\Manage bypass is HIGH'
Check (Has $r6 'RegKey' 'HIGH' 'SOFTWARE\\JDBCC$') 'JDBCC settings key is HIGH'
if ($rootOk) { Check (Has $r6 'DefExcl' 'HIGH' '^Path\|F:\\$' 'whole') 'Defender exclusion of every drive is HIGH' }
Check (Has $r6 'Info' 'WARN' 'Firewall blocks all outgoing connections \(Domain\)') 'firewall blocking all outgoing is WARN'
Check (Has $r6 'File' 'HIGH' 'Downloads\\INVOIS\.vhd\.zip$') 'double-extension lure INVOIS.vhd.zip is HIGH'
Check (Has $r6 'Service' 'HIGH' '^EmbeddedDriverService$') 'driver service loaded from Temp is HIGH'
Check (Has $r6 'Service' 'WARN' '^WazPing32Test$' 'Ping32') 'Ping32 service is WARN when owner unknown'
$scanLog = Get-ChildItem $q -Filter 'scan-*.log' | Sort-Object LastWriteTime | Select-Object -Last 1
Check ($scanLog -and (Select-String -LiteralPath $scanLog.FullName -SimpleMatch 'Maksud: Program kawalan jauh Ping32' -Quiet)) 'Ping32 warning explained in plain Malay'

$r7 = Scan "$env:TEMP\x7.json" -Fix -Owner Personal
Check (Has $r7 'Service' 'HIGH' '^WazPing32Test$' 'Ping32') 'Ping32 service is HIGH on a personal PC'
Check (-not (Test-Path $mpDir)) 'MicroPoint folder quarantined'
Check (-not ((Get-Item $runKey).GetValueNames() -contains 'ServiceController')) 'MicroPoint Run value removed'
Check (-not (Test-Path $clsid)) 'CLSID bypass key removed'
Check (-not (Test-Path 'HKLM:\SOFTWARE\JDBCC')) 'JDBCC key removed'
if ($rootOk) { Check (-not (@((Get-MpPreference).ExclusionPath) -contains 'F:\')) 'whole-drive exclusion removed' }
Check (-not (Test-Path "$dl\INVOIS.vhd.zip")) 'INVOIS.vhd.zip quarantined'
& sc.exe query EmbeddedDriverService | Out-Null; Check ($LASTEXITCODE -ne 0) 'Temp driver service deleted'
Check (-not (Test-Path 'C:\Windows\Temp\EmbeddedDriverService.sys')) 'Temp driver file quarantined'
& sc.exe query WazPing32Test | Out-Null; Check ($LASTEXITCODE -ne 0) 'Ping32 service deleted'
Check (-not (Test-Path $p32)) 'Ping32 folder quarantined'
Set-NetFirewallProfile -Profile Domain -DefaultOutboundAction $fwOld
}

if (InPart 2) {
Write-Host '=== WhatsApp download tag, Defender history, ran-programs records ===' -ForegroundColor Cyan
# Files saved from WhatsApp Web carry a Zone.Identifier tag naming web.whatsapp.com.
$zone = "[ZoneTransfer]`r`nZoneId=3`r`nReferrerUrl=https://web.whatsapp.com/`r`nHostUrl=blob:https://web.whatsapp.com/1f2e3d4c-aaaa-bbbb-cccc-0123456789ab"
$waImg = "$dl\Dokumen penting.img"; $waZip = "$dl\Gambar raya.zip"
Set-Content $waImg 'dummy'; New-TestZip $waZip 'Gambar raya.img'
Set-Content -LiteralPath $waImg -Stream Zone.Identifier -Value $zone
Set-Content -LiteralPath $waZip -Stream Zone.Identifier -Value $zone
# Windows 11's program-launch list and Prefetch, as stand-ins (Windows Server keeps neither by default).
$pcaTest = "$env:TEMP\wazip-pca.txt"
$now = (Get-Date).ToUniversalTime().ToString('yyyy-MM-dd HH:mm:ss.fff')
Set-Content $pcaTest "C:\ProgramData\MicroPoint\WinCombo.exe|$now`r`nC:\Program Files\Notepad++\notepad++.exe|$now" -Encoding Unicode
$pfTest = "$env:TEMP\wazip-prefetch"
New-Item -ItemType Directory -Force -Path $pfTest | Out-Null
Set-Content "$pfTest\TAXFILING.EXE-1A2B3C4D.pf" 'x'; Set-Content "$pfTest\NOTEPAD.EXE-11223344.pf" 'x'
$env:WAZIP_TEST_PCA = $pcaTest; $env:WAZIP_TEST_PREFETCH = $pfTest
# A new exclusion after the last clean-up shows up in Defender's history (event 5007).
$histStart = Get-Date
$histOk = $false
try { Add-MpPreference -ExclusionPath 'C:\Users\Public\WazHistTest' -ErrorAction Stop; $histOk = $true } catch { }
Start-Sleep 3

$r8 = Scan "$env:TEMP\x8.json"
Check (Has $r8 'File' 'HIGH' 'Dokumen penting\.img$' 'WhatsApp Web') 'disk image downloaded from WhatsApp Web is HIGH'
Check (Has $r8 'File' 'HIGH' 'Gambar raya\.zip$' 'WhatsApp Web.*inside') 'zip from WhatsApp Web with a disk image inside is HIGH (tidied away)'
Check (Has $r8 'Info' 'WARN' 'Malware program ran: C:\\ProgramData\\MicroPoint\\WinCombo\.exe$') 'program-launch list entry for WinCombo.exe is WARN'
Check (-not (Has $r8 'Info' 'WARN' 'notepad')) 'ordinary programs in the launch list are ignored'
Check (Has $r8 'Info' 'WARN' 'Malware program ran: TAXFILING\.EXE$' 'Prefetch') 'Prefetch entry for TaxFiling.exe is WARN'
$has5007 = $histOk -and [bool](Get-WinEvent -FilterHashtable @{ LogName = 'Microsoft-Windows-Windows Defender/Operational'; Id = 5007; StartTime = $histStart } -MaxEvents 1 -ErrorAction SilentlyContinue)
if ($has5007) { Check (Has $r8 'Info' 'WARN' 'Defender exclusion added: C:\\Users\\Public\\WazHistTest') 'exclusion added after the last clean-up is listed from Defender history' }
else { Write-Host 'SKIP Defender history: no 5007 event on this runner' -ForegroundColor Yellow }
$scanLog = Get-ChildItem $q -Filter 'scan-*.log' | Sort-Object LastWriteTime | Select-Object -Last 1
Check ($scanLog -and (Select-String -LiteralPath $scanLog.FullName -SimpleMatch 'Maksud: Rekod Windows tunjuk program malware' -Quiet)) 'ran-program warning explained in plain Malay'

$r9 = Scan "$env:TEMP\x9.json" -Fix
Check (-not (Test-Path -LiteralPath $waImg)) 'WhatsApp disk image quarantined'
Check (-not (Test-Path -LiteralPath $waZip)) 'WhatsApp zip quarantined'
$r10 = Scan "$env:TEMP\x10.json"
Check (-not (Has $r10 'Info' 'WARN' 'Malware program ran')) 'history before the last clean-up is not reported again'
Remove-Item -LiteralPath $waZip, $pcaTest -Force -ErrorAction SilentlyContinue
Remove-Item -LiteralPath $pfTest -Recurse -Force -ErrorAction SilentlyContinue
Remove-Item Env:\WAZIP_TEST_PCA, Env:\WAZIP_TEST_PREFETCH
if ($histOk) { Remove-MpPreference -ExclusionPath 'C:\Users\Public\WazHistTest' -ErrorAction SilentlyContinue }

Write-Host '=== Mounted .img lure (opens as a DVD drive) ===' -ForegroundColor Cyan
# Build a tiny ISO-format image with Windows' own IMAPI2 and give it a lure name ending in .img.
$isoSrc = "$env:TEMP\wazip-isosrc"; New-Item -ItemType Directory -Force -Path $isoSrc | Out-Null
Set-Content "$isoSrc\readme.txt" 'dummy'
$lureImg = "$dl\LHDNCUKAI20261029.img"
$imgOk = $false
try {
  Add-Type -TypeDefinition @'
public static class WazIso {
  public static void Save(object stream, string path) {
    var s = (System.Runtime.InteropServices.ComTypes.IStream)stream;
    var buf = new byte[65536];
    var pcb = System.Runtime.InteropServices.Marshal.AllocHGlobal(4);
    try {
      using (var o = System.IO.File.Create(path)) {
        int n;
        do { s.Read(buf, buf.Length, pcb); n = System.Runtime.InteropServices.Marshal.ReadInt32(pcb); o.Write(buf, 0, n); } while (n > 0);
      }
    } finally { System.Runtime.InteropServices.Marshal.FreeHGlobal(pcb); }
  }
}
'@
  $fsi = New-Object -ComObject IMAPI2FS.MsftFileSystemImage
  $fsi.FileSystemsToCreate = 3; $fsi.VolumeName = 'WAZTEST'
  $fsi.Root.AddTree($isoSrc, $false)
  [WazIso]::Save($fsi.CreateResultImage().ImageStream, $lureImg)
  Mount-DiskImage -ImagePath $lureImg -StorageType ISO -ErrorAction Stop | Out-Null
  Start-Sleep 3
  $imgOk = [bool](Get-Volume | Where-Object { $_.DriveType -eq 'CD-ROM' -and $_.FileSystemLabel -eq 'WAZTEST' -and $_.DriveLetter })
} catch { Write-Host "image setup failed: $($_.Exception.Message)" }
if ($imgOk) {
  $r11 = Scan "$env:TEMP\x11.json"
  Check (Has $r11 'Vhd' 'HIGH' 'LHDNCUKAI20261029\.img$' 'DVD drive') 'mounted .img lure (DVD drive) is HIGH'
  $r12 = Scan "$env:TEMP\x12.json" -Fix
  Check (-not (Get-DiskImage -ImagePath $lureImg -ErrorAction SilentlyContinue | Where-Object Attached)) 'mounted .img lure ejected'
  Check (-not (Test-Path -LiteralPath $lureImg)) 'mounted .img lure quarantined'
} else { Write-Host 'SKIP mounted .img: could not build or mount a test image on this runner' -ForegroundColor Yellow }
Dismount-DiskImage -ImagePath $lureImg -ErrorAction SilentlyContinue | Out-Null
Remove-Item -LiteralPath $lureImg -Force -ErrorAction SilentlyContinue
Remove-Item -LiteralPath $isoSrc -Recurse -Force -ErrorAction SilentlyContinue

Write-Host '=== Mounted VHDX with a hidden DLL beside a program (OBS libcef.dll lure) ===' -ForegroundColor Cyan
# Neutral file name, so only what is inside the disk can make it HIGH.
$sideVhd = "$dl\mydisk.vhdx"
"create vdisk file=`"$sideVhd`" maximum=16 type=expandable`nattach vdisk`ncreate partition primary`nformat fs=ntfs quick label=WAZSIDE`nassign" | Out-File -Encoding ASCII "$env:TEMP\dp-side.txt"
& diskpart.exe /s "$env:TEMP\dp-side.txt" | Out-Null
Start-Sleep 3
$sideVol = Get-Volume | Where-Object { $_.FileSystemLabel -eq 'WAZSIDE' -and $_.DriveLetter } | Select-Object -First 1
if ($sideVol) {
  $sd = "$($sideVol.DriveLetter):\"
  Set-Content "$sd\Setup.exe" 'dummy'; Set-Content "$sd\libcef.dll" 'dummy'
  (Get-Item -LiteralPath "$sd\libcef.dll" -Force).Attributes = 'Hidden, System'
  Set-Content "$dl\20261030C754FC89.zip" 'dummy'
  $r15 = Scan "$env:TEMP\x15.json"
  Check (Has $r15 'Vhd' 'HIGH' 'mydisk\.vhdx$' 'libcef\.dll.*sideloading') 'mounted VHDX with hidden DLL beside a program is HIGH'
  Check (Has $r15 'File' 'HIGH' 'mydisk\.vhdx$') 'that VHDX file is HIGH'
  Check (Has $r15 'File' 'HIGH' '20261030C754FC89\.zip$') 'date+hex lure zip name is HIGH'
  $r16 = Scan "$env:TEMP\x16.json" -Fix
  Check (-not (Get-DiskImage -ImagePath $sideVhd -ErrorAction SilentlyContinue | Where-Object Attached)) 'sideload VHDX ejected'
  Check (-not (Test-Path -LiteralPath $sideVhd)) 'sideload VHDX quarantined'
  Check (-not (Test-Path -LiteralPath "$dl\20261030C754FC89.zip")) 'date+hex lure zip quarantined'
} else { Write-Host 'SKIP sideload VHDX: could not create a formatted VHDX on this runner' -ForegroundColor Yellow }
Dismount-DiskImage -ImagePath $sideVhd -ErrorAction SilentlyContinue | Out-Null
Remove-Item -LiteralPath $sideVhd, "$dl\20261030C754FC89.zip" -Force -ErrorAction SilentlyContinue

Write-Host '=== OBS lure drop sites (ProgramData copy, Windows\Tasks kit) ===' -ForegroundColor Cyan
$gyc = "$env:ProgramData\WazGYC"; New-Item -ItemType Directory -Force -Path $gyc | Out-Null
Set-Content "$gyc\libcef.dll" 'dummy'
Set-Content "$env:SystemRoot\Tasks\install.vbs" 'dummy'; Set-Content "$env:SystemRoot\Tasks\UEMSAgent.mst" 'dummy'
$r17 = Scan "$env:TEMP\x17.json"
Check (Has $r17 'File' 'HIGH' 'ProgramData\\WazGYC\\libcef\.dll$') 'libcef.dll in a ProgramData folder is HIGH'
Check (Has $r17 'File' 'HIGH' 'Windows\\Tasks\\install\.vbs$') 'install.vbs in Windows\Tasks is HIGH'
Check (Has $r17 'File' 'HIGH' 'Windows\\Tasks\\UEMSAgent\.mst$') 'UEMSAgent.mst in Windows\Tasks is HIGH'
$r18 = Scan "$env:TEMP\x18.json" -Fix
Check (-not (Test-Path "$gyc\libcef.dll") -and -not (Test-Path "$env:SystemRoot\Tasks\install.vbs") -and -not (Test-Path "$env:SystemRoot\Tasks\UEMSAgent.mst")) 'OBS lure drop files quarantined'
Remove-Item -LiteralPath $gyc -Recurse -Force -ErrorAction SilentlyContinue
Remove-Item -LiteralPath "$env:SystemRoot\Tasks\install.vbs", "$env:SystemRoot\Tasks\UEMSAgent.mst" -Force -ErrorAction SilentlyContinue

Write-Host '=== MyCERT MA-1491/1493 (lure names, sideload DLLs, drop folder, ManageEngineCA) ===' -ForegroundColor Cyan
$myNames = 'PDF_0R-BEPZ_20260924110405.ZIP', 'CRY_GFFXDY_202611061405092.vhd', '20260922_145533_2153.iso', 'Financial_Report_20261008_PDF.44321142.zip', '13211621092027.VHDX', '36251322092026.71A.vhdx', 'CIT.Number.20260827124236.IMG', 'I.T.R.Number-20260825114045.IMG', 'IMPS_2121-9-2026.img', 'UTR_422-9-2026.7CA.vhdx', 'SOA3.IMG', 'E-statement2026.vhdx', '20260827224326.DC40CD2841F6.zip'
foreach ($n in $myNames) { Set-Content "$dl\$n" 'dummy' }
$vlcBad = "$dl\PDF_R6LWXF"; $vlcOk = "$dl\vlc-portable"
New-Item -ItemType Directory -Force -Path $vlcBad, $vlcOk | Out-Null
Set-Content "$vlcBad\PDF_R6LWXF_20261009152217.exe" 'dummy'; Set-Content "$vlcBad\libvlc.dll" 'dummy'
Set-Content "$vlcOk\vlc.exe" 'dummy'; Set-Content "$vlcOk\libvlc.dll" 'dummy'
# WeChat's video player plugin ships libvlc.dll on its own (WAZ-4DX9C report, Nov 2026).
$vlcWc = "$env:APPDATA\Tencent\xwechat\XPlugin\Plugins\WeChatPlayer\5067\extracted"
New-Item -ItemType Directory -Force -Path $vlcWc | Out-Null; Set-Content "$vlcWc\libvlc.dll" 'dummy'
$vlcLone = "$dl\libvlc-alone"; New-Item -ItemType Directory -Force -Path $vlcLone | Out-Null; Set-Content "$vlcLone\libvlc.dll" 'dummy'
Set-Content "$dl\arphaDump.dll" 'dummy'
$tk = "$env:LOCALAPPDATA\Toolkit"; New-Item -ItemType Directory -Force -Path $tk | Out-Null; Set-Content "$tk\msvbvm60.dll" 'dummy'
$ctr = "$env:ProgramData\Microsoft\Windows\Containers\Layers\waztest"; New-Item -ItemType Directory -Force -Path "$ctr\Files\Windows\SysWOW64" | Out-Null; Set-Content "$ctr\Files\Windows\SysWOW64\msvbvm60.dll" 'dummy'
New-Item -ItemType Directory -Force -Path "$env:SystemDrive\cool" | Out-Null; Set-Content "$env:SystemDrive\cool\UEMSAgent.mst" 'dummy'
$meCa = $null
try {
  $tmpCa = New-SelfSignedCertificate -Subject 'CN=ManageEngineCA, O=Zoho Corporation' -CertStoreLocation Cert:\LocalMachine\My -KeyUsage CertSign -ErrorAction Stop
  Export-Certificate -Cert $tmpCa -FilePath "$env:TEMP\meca.cer" | Out-Null
  $meCa = (Import-Certificate -FilePath "$env:TEMP\meca.cer" -CertStoreLocation Cert:\LocalMachine\Root -ErrorAction Stop).Thumbprint
  Remove-Item -LiteralPath "Cert:\LocalMachine\My\$($tmpCa.Thumbprint)" -DeleteKey -ErrorAction SilentlyContinue
} catch { Write-Host "certificate setup failed: $($_.Exception.Message)" }
$r19 = Scan "$env:TEMP\x19.json"
foreach ($n in $myNames) { Check (Has $r19 'File' 'HIGH' ([regex]::Escape($n) + '$')) "MyCERT lure name $n is HIGH" }
Check (Has $r19 'File' 'HIGH' 'PDF_R6LWXF\\libvlc\.dll$') 'libvlc.dll next to a renamed program is HIGH'
Check (-not ($r19.All | Where-Object { $_.Target -match 'vlc-portable\\libvlc\.dll$' })) 'libvlc.dll next to vlc.exe is not reported'
Check (-not ($r19.All | Where-Object { $_.Target -match 'WeChatPlayer\\.*libvlc\.dll$' })) 'WeChat player plugin libvlc.dll is not reported'
Check (-not ($r19.All | Where-Object { $_.Target -match 'libvlc-alone\\libvlc\.dll$' })) 'libvlc.dll with no program beside it is not reported'
Check (Has $r19 'File' 'HIGH' 'Downloads\\arphaDump\.dll$') 'arphaDump.dll outside Program Files is HIGH'
Check (Has $r19 'File' 'HIGH' 'Toolkit\\msvbvm60\.dll$') 'msvbvm60.dll in LocalAppData\Toolkit is HIGH'
Check (-not ($r19.All | Where-Object { $_.Target -match '\\Containers\\Layers\\' })) 'Windows Sandbox container layers are not scanned'
Check (Has $r19 'File' 'HIGH' '^[A-Z]:\\cool$') 'C:\cool ManageEngine kit folder is HIGH'
if ($meCa) { Check (Has $r19 'Cert' 'HIGH' $meCa) 'ManageEngineCA root certificate is HIGH' } else { Write-Host 'SKIP ManageEngineCA: could not plant a test certificate' -ForegroundColor Yellow }
$r20 = Scan "$env:TEMP\x20.json" -Fix
Check (-not ($myNames | Where-Object { Test-Path -LiteralPath "$dl\$_" })) 'MyCERT lure names quarantined'
Check (-not (Test-Path "$vlcBad\libvlc.dll") -and (Test-Path "$vlcOk\libvlc.dll")) 'only the sideload libvlc.dll removed'
Check (-not (Test-Path "$env:SystemDrive\cool")) 'C:\cool quarantined'
if ($meCa) { Check (-not (Test-Path "Cert:\LocalMachine\Root\$meCa")) 'ManageEngineCA root certificate removed' }
Remove-Item -LiteralPath $vlcBad, $vlcOk, $tk, $ctr, "$env:SystemDrive\cool" -Recurse -Force -ErrorAction SilentlyContinue
Remove-Item -LiteralPath "$dl\arphaDump.dll", "$env:TEMP\meca.cer" -Force -ErrorAction SilentlyContinue
foreach ($n in $myNames) { Remove-Item -LiteralPath "$dl\$n" -Force -ErrorAction SilentlyContinue }
if ($meCa) { Remove-Item -LiteralPath "Cert:\LocalMachine\Root\$meCa" -ErrorAction SilentlyContinue }
}

if (InPart 1) {
Write-Host '=== Random hex folder in AppData\Local (CrashHunter_PC3.dll report) ===' -ForegroundColor Cyan
$hexDir = Join-Path $env:LOCALAPPDATA '0115DF0258E52000'
New-Item -ItemType Directory -Force -Path $hexDir | Out-Null
Set-Content "$hexDir\CrashHunter_PC3.dll" 'dummy'; Set-Content "$hexDir\Launcher.exe" 'dummy'
$runH = 'HKCU:\Software\Microsoft\Windows\CurrentVersion\Run'
if (-not (Test-Path $runH)) { New-Item -Path $runH -Force | Out-Null }
Set-ItemProperty -Path $runH -Name WazHexTest -Value "`"$hexDir\Launcher.exe`""
$r21 = Scan "$env:TEMP\x21.json"
Check (Has $r21 'File' 'HIGH' '0115DF0258E52000\\CrashHunter_PC3\.dll$') 'DLL in random hex AppData\Local folder is HIGH'
Check (Has $r21 'File' 'HIGH' '0115DF0258E52000\\Launcher\.exe$') 'program in random hex AppData\Local folder is HIGH'
Check (Has $r21 'RegValue' 'HIGH' '\|WazHexTest$') 'Run value pointing at the hex folder is HIGH'
$r22 = Scan "$env:TEMP\x22.json" -Fix
Check (-not (Test-Path "$hexDir\CrashHunter_PC3.dll") -and -not (Test-Path "$hexDir\Launcher.exe")) 'hex folder files quarantined'
Check (-not (Get-ItemProperty -Path $runH -Name WazHexTest -ErrorAction SilentlyContinue)) 'hex folder Run value removed'
Remove-Item -LiteralPath $hexDir -Recurse -Force -ErrorAction SilentlyContinue
Remove-ItemProperty -Path $runH -Name WazHexTest -ErrorAction SilentlyContinue

Write-Host '=== Program in Public\Libraries symbol folder (SyncEngineDatabase report) ===' -ForegroundColor Cyan
$libDir = 'C:\Users\Public\Libraries\BB&{@#{!@()[{(+)(@%]@(=,[),{}~Lr'
New-Item -ItemType Directory -Force -Path $libDir | Out-Null
$libExe = Join-Path $libDir 'SyncEngineDatabase.db.exe'
[IO.File]::WriteAllText($libExe, 'dummy')
(Get-Item -LiteralPath $libExe -Force).Attributes = 'Hidden, System'
$symDir = Join-Path $env:APPDATA '{@#!(+)%=}'
New-Item -ItemType Directory -Force -Path $symDir | Out-Null
[IO.File]::WriteAllText((Join-Path $symDir 'host.exe'), 'dummy')
$r23 = Scan "$env:TEMP\x23.json"
Check (Has $r23 'File' 'HIGH' 'SyncEngineDatabase\.db\.exe$') 'hidden program in Public\Libraries symbol folder is HIGH'
Check (Has $r23 'File' 'HIGH' '\{@#!\(\+\)%=\}\\host\.exe$') 'program in a folder named with symbols is HIGH'
$r24 = Scan "$env:TEMP\x24.json" -Fix
Check (-not (Test-Path -LiteralPath $libExe)) 'Public\Libraries program quarantined'
Check (-not (Test-Path -LiteralPath (Join-Path $symDir 'host.exe'))) 'symbol folder program quarantined'
Remove-Item -LiteralPath $libDir, $symDir -Recurse -Force -ErrorAction SilentlyContinue

Write-Host '=== ManageEngine on an office PC that has other malware (victim reports, Nov 2026) ===' -ForegroundColor Cyan
$meDir2 = "${env:ProgramFiles(x86)}\ManageEngine\UEMS_Agent"
New-Item -ItemType Directory -Force -Path "$meDir2\bin" | Out-Null
Set-Content "$meDir2\bin\dcagentservice.exe" 'dummy'
& sc.exe create MEOfficeTest start= demand DisplayName= "ManageEngine UEMS - Agent Office Test" binPath= "`"$meDir2\bin\dcagentservice.exe`"" | Out-Null
New-Item -ItemType Directory -Force -Path $libDir | Out-Null
[IO.File]::WriteAllText($libExe, 'dummy')
(Get-Item -LiteralPath $libExe -Force).Attributes = 'Hidden, System'
$rM1 = Scan "$env:TEMP\xm1.json" -Fix -Owner Office
Check (Has $rM1 'Info' 'HIGH' 'ManageEngine' 'other malware') 'office PC with other malware: ManageEngine is HIGH'
Check (-not (Test-Path $meDir2)) 'office PC with other malware: ManageEngine folder quarantined'
& sc.exe query MEOfficeTest | Out-Null; Check ($LASTEXITCODE -ne 0) 'office PC with other malware: ManageEngine service deleted'
Check (-not (Test-Path -LiteralPath $libExe)) 'office PC with other malware: Public\Libraries program quarantined'
Remove-Item -LiteralPath $libDir -Recurse -Force -ErrorAction SilentlyContinue
# Only a WhatsApp zip: not proof of infection, so an office ManageEngine stays a warning.
New-Item -ItemType Directory -Force -Path "$meDir2\bin" | Out-Null
Set-Content "$meDir2\bin\dcagentservice.exe" 'dummy'
& sc.exe create MEOfficeTest start= demand DisplayName= "ManageEngine UEMS - Agent Office Test" binPath= "`"$meDir2\bin\dcagentservice.exe`"" | Out-Null
$waOnly = "$dl\Gambar kenduri.zip"
Set-Content $waOnly 'dummy'
Set-Content -LiteralPath $waOnly -Stream Zone.Identifier -Value "[ZoneTransfer]`r`nZoneId=3`r`nReferrerUrl=https://web.whatsapp.com/`r`nHostUrl=blob:https://web.whatsapp.com/1f2e3d4c-aaaa-bbbb-cccc-0123456789ab"
$rM2 = Scan "$env:TEMP\xm2.json" -Fix -Owner Office
Check (Has $rM2 'File' 'WARN' 'Gambar kenduri\.zip$' 'cannot look inside') 'office PC with only a WhatsApp zip: zip found (warning, not quarantined)'
Check (Test-Path -LiteralPath $waOnly) 'office PC with only a WhatsApp zip: zip left in place'
Check (Has $rM2 'Info' 'WARN' 'ManageEngine' 'IT') "office PC with only a WhatsApp zip: ManageEngine stays a warning (HIGH: $(@($rM2.All | Where-Object Severity -eq 'HIGH' | ForEach-Object { $_.Target }) -join '; '))"
Check (Test-Path $meDir2) 'office PC with only a WhatsApp zip: ManageEngine kept'
& sc.exe delete MEOfficeTest | Out-Null
Remove-Item -LiteralPath "${env:ProgramFiles(x86)}\ManageEngine" -Recurse -Force -ErrorAction SilentlyContinue
Remove-Item -LiteralPath $waOnly -Force -ErrorAction SilentlyContinue
}

if (InPart 3) {
Write-Host '=== IP-guard (OCular) agent pushed by the attacker''s ManageEngine (victim report, Nov 2026) ===' -ForegroundColor Cyan
$ocDir = Join-Path $env:SystemRoot 'SysWOW64\Ocular'
New-Item -ItemType Directory -Force -Path $ocDir | Out-Null
# SIP is the server address, last byte first: B6297C1B = 27.124.41.182 (on the C2 list).
Set-Content -LiteralPath "$ocDir\OAgent.ini" -Value '[AgentConfig]', 'SIP=B6297C1B' -Encoding ASCII
$r25 = Scan "$env:TEMP\x25.json" -Owner Office
Check (Has $r25 'Info' 'HIGH' '^IP-guard' '27\.124\.41\.182') 'IP-guard pointing at an attacker server is HIGH even on an office PC'
# 134.122.155.190 is not on the list but sits next to attacker servers .135/.148/.183/.188.
Set-Content -LiteralPath "$ocDir\OAgent.ini" -Value '[AgentConfig]', 'SIP=BE9B7A86' -Encoding ASCII
$r25b = Scan "$env:TEMP\x25b.json" -Owner Office
Check (Has $r25b 'Info' 'HIGH' '^IP-guard' '134\.122\.155\.190') 'IP-guard server in an attacker /24 is HIGH even on an office PC'
Set-Content -LiteralPath "$ocDir\OAgent.ini" -Value '[AgentConfig]', 'SIP=0A00000A' -Encoding ASCII
# An empty quarantine folder: earlier clean-ups in this run removed ManageEngine, which counts as the attacker's.
$qIpg = Join-Path $env:TEMP 'qIpgOffice'
$r26 = Scan "$env:TEMP\x26.json" -Owner Office -Root $qIpg
Check (Has $r26 'Info' 'WARN' '^IP-guard' 'IT team') 'IP-guard with a company server is WARN on an office PC'
# WAZ-FHYGQ: the attacker's ManageEngine kit on the same office PC makes IP-guard the attacker's, whatever its server.
New-Item -ItemType Directory -Force -Path "$env:SystemDrive\kouren" | Out-Null
Set-Content -LiteralPath "$env:SystemDrive\kouren\UEMSAgent.mst" 'dummy'
$r26m = Scan "$env:TEMP\x26m.json" -Owner Office -Root $qIpg
Remove-Item -LiteralPath "$env:SystemDrive\kouren" -Recurse -Force -ErrorAction SilentlyContinue
Check (Has $r26m 'Info' 'HIGH' '^IP-guard' "attacker's ManageEngine") 'office IP-guard next to the attacker''s ManageEngine kit is HIGH (WAZ-FHYGQ)'
# WAZ-ASQSJ/E9UHN: after an earlier clean-up removed ManageEngine here, IP-guard still counts as the attacker's.
New-Item -ItemType Directory -Force -Path "$qIpg\old" | Out-Null
Set-Content -LiteralPath "$qIpg\old\manifest.json" '[{"Kind":"Service","Target":"ManageEngine UEMS - Agent"}]'
$r26r = Scan "$env:TEMP\x26r.json" -Owner Office -Root $qIpg
Check (Has $r26r 'Info' 'HIGH' '^IP-guard' "attacker's ManageEngine") 'office IP-guard after ManageEngine was removed here is HIGH (WAZ-E9UHN)'
Remove-Item -LiteralPath $qIpg -Recurse -Force -ErrorAction SilentlyContinue
$r27 = Scan "$env:TEMP\x27.json" -Owner Personal -Fix
Check (Has $r27 'Info' 'HIGH' '^IP-guard') 'IP-guard is HIGH on a personal PC'
Check (Test-Path -LiteralPath "$ocDir\OAgent.ini") 'online -Fix leaves IP-guard files for the Safe Mode pass'
Remove-Item -LiteralPath $ocDir -Recurse -Force -ErrorAction SilentlyContinue

Write-Host '=== IP-guard removal: server blocked and Safe Mode entry removed online, files and drivers in Safe Mode ===' -ForegroundColor Cyan
# Harmless stand-ins with IP-guard names: text files and a demand-start driver service that is never started.
$w64 = Join-Path $env:SystemRoot 'SysWOW64'; $drvDirI = Join-Path $env:SystemRoot 'System32\drivers'
New-Item -ItemType Directory -Force -Path $ocDir | Out-Null
Set-Content -LiteralPath "$ocDir\OAgent.ini" -Value '[AgentConfig]', 'SIP=B6297C1B' -Encoding ASCII
Set-Content -LiteralPath "$w64\winoav3.dll" 'dummy'
Set-Content -LiteralPath "$drvDirI\TNullFilter.sys" 'dummy'
& sc.exe create TNullFilter type= kernel start= demand binPath= System32\drivers\TNullFilter.sys | Out-Null
$sbk = 'HKLM:\SYSTEM\CurrentControlSet\Control\SafeBoot\Minimal\TNullFilter'
New-Item -Path $sbk -Force | Out-Null; Set-Item -Path $sbk -Value 'Driver'
$rI1 = Scan "$env:TEMP\xi1.json" -Owner Personal -Fix
Check (Has $rI1 'Info' 'HIGH' '^IP-guard' 'Safe Mode') 'IP-guard finding says it is removed in Safe Mode'
Check ([bool](Get-NetFirewallRule -DisplayName 'WAZip block IP-guard server (Outbound)' -ErrorAction SilentlyContinue)) 'online -Fix blocks the IP-guard server range'
Check (-not (Test-Path -LiteralPath $sbk)) 'online -Fix removes IP-guard from the Safe Mode start list'
Check ((Test-Path -LiteralPath "$w64\winoav3.dll") -and (Test-Path -LiteralPath 'HKLM:\SYSTEM\CurrentControlSet\Services\TNullFilter')) 'online -Fix leaves IP-guard files and services for Safe Mode'
# A running IP-guard program (unsigned stand-in that only sleeps) keeps its file locked, as on User D's PC.
Add-Type -TypeDefinition 'public static class WazIpgStub { public static void Main() { System.Threading.Thread.Sleep(600000); } }' -OutputType ConsoleApplication -OutputAssembly "$w64\wrdlv4.exe"
$stub = Start-Process -FilePath "$w64\wrdlv4.exe" -WindowStyle Hidden -PassThru
Get-NetFirewallRule -DisplayName 'WAZip block IP-guard server*' -ErrorAction SilentlyContinue | Remove-NetFirewallRule
$roundFile = Join-Path $q 'ipguard-safe-round.txt'
Remove-Item -LiteralPath $roundFile -ErrorAction SilentlyContinue
$env:WAZIP_TEST_IPG_SAFE = '1'
$env:WAZIP_TEST_PREWARN = "$w64\winoav3.dll"
$o2 = "$env:TEMP\xi2.txt"
$rI2 = Scan "$env:TEMP\xi2.json" -Owner Personal -Fix -Out $o2
Remove-Item Env:\WAZIP_TEST_PREWARN
Check (Has $rI2 'File' 'HIGH' 'winoav3\.dll$' 'IP-guard file') 'IP-guard file with an earlier warning is raised to HIGH (WAZ-3NR7T winrdgv3.exe)'
Check (Has $rI2 'Service' 'HIGH' '^TNullFilter$' 'IP-guard') 'Safe Mode pass lists the IP-guard driver service'
Check (-not (Test-Path -LiteralPath "$w64\winoav3.dll") -and -not (Test-Path -LiteralPath "$drvDirI\TNullFilter.sys") -and -not (Test-Path -LiteralPath $ocDir)) 'Safe Mode pass quarantines IP-guard files and folders'
$tn = Get-ItemProperty -LiteralPath 'HKLM:\SYSTEM\CurrentControlSet\Services\TNullFilter' -ErrorAction SilentlyContinue
Check (-not $tn -or $tn.DeleteFlag -eq 1) 'Safe Mode pass deletes the IP-guard driver service'
Check ($stub.HasExited -and -not (Test-Path -LiteralPath "$w64\wrdlv4.exe")) 'Safe Mode pass kills the running IP-guard program and quarantines it'
$lnKill = (Select-String -LiteralPath $o2 -Pattern 'OK  IP-guard (dihentikan|stopped): wrdlv4' | Select-Object -First 1).LineNumber
$lnSvc = (Select-String -LiteralPath $o2 -Pattern 'OK  Service: TNullFilter' | Select-Object -First 1).LineNumber
$lnFile = (Select-String -LiteralPath $o2 -Pattern 'OK  File: .*wrdlv4\.exe' | Select-Object -First 1).LineNumber
Check ($lnKill -and $lnSvc -and $lnFile -and $lnKill -lt $lnSvc -and $lnSvc -lt $lnFile) "Safe Mode pass order: kill, then switch off the service, then move files ($lnKill < $lnSvc < $lnFile)"
Check (-not (Get-NetFirewallRule -DisplayName 'WAZip block IP-guard server*' -ErrorAction SilentlyContinue) -and -not (Select-String -LiteralPath $o2 -Pattern 'GAGAL sekat' -Quiet)) 'Safe Mode pass skips the firewall (it does not run there) with no GAGAL line'
Check (((Get-Content -LiteralPath $roundFile -ErrorAction SilentlyContinue) -eq '2') -and (Select-String -LiteralPath $o2 -Pattern 'SEKALI LAGI' -CaseSensitive -Quiet)) 'IP-guard that was running in Safe Mode gets one more automatic Safe Mode round'
Remove-Item Env:\WAZIP_TEST_IPG_SAFE
Remove-Item -LiteralPath $roundFile -ErrorAction SilentlyContinue
$rI3 = Scan "$env:TEMP\xi3.json" -Owner Personal
Check (-not ($rI3.All | Where-Object { $_.Target -match '^IP-guard' })) 'no IP-guard left after the Safe Mode pass'
# IP-guard keeps a file locked in Safe Mode: round 2, then the recovery screen (BUANG.bat) - never a third loop.
New-Item -ItemType Directory -Force -Path $ocDir | Out-Null
Set-Content -LiteralPath "$ocDir\OAgent.ini" -Value '[AgentConfig]', 'SIP=B6297C1B' -Encoding ASCII
Set-Content -LiteralPath "$w64\winoav3.dll" 'dummy'
$lk1 = [System.IO.File]::Open("$w64\winoav3.dll", 'Open', 'Read', 'Read')
$lk2 = [System.IO.File]::Open("$ocDir\OAgent.ini", 'Open', 'Read', 'Read')
Remove-Item -LiteralPath (Join-Path $q 'BUANG.bat'), $roundFile -ErrorAction SilentlyContinue
$env:WAZIP_TEST_IPG_SAFE = '1'
$rI5 = Scan "$env:TEMP\xi5.json" -Owner Personal -Fix -Out "$env:TEMP\xi5.txt"
Check (((Get-Content -LiteralPath $roundFile -ErrorAction SilentlyContinue) -eq '2') -and (Select-String -LiteralPath "$env:TEMP\xi5.txt" -Pattern 'SEKALI LAGI' -CaseSensitive -Quiet)) 'locked IP-guard file in Safe Mode schedules round 2'
$rI6 = Scan "$env:TEMP\xi6.json" -Owner Personal -Fix -Out "$env:TEMP\xi6.txt"
Remove-Item Env:\WAZIP_TEST_IPG_SAFE
$bat = Join-Path $q 'BUANG.bat'
Check ((Test-Path -LiteralPath $bat) -and (Select-String -LiteralPath $bat -Pattern 'winoav3\.dll' -Quiet) -and -not (Select-String -LiteralPath "$env:TEMP\xi6.txt" -Pattern 'SEKALI LAGI' -CaseSensitive -Quiet)) 'after 2 Safe Mode rounds IP-guard goes to the recovery screen (BUANG.bat), no third round'
$lk1.Close(); $lk2.Close()
Remove-Item -LiteralPath $ocDir -Recurse -Force -ErrorAction SilentlyContinue
Remove-Item -LiteralPath "$w64\winoav3.dll", $bat, $roundFile -Force -ErrorAction SilentlyContinue
# Windows build without netcfg.exe: the network filter is switched off cleanly, no script error (WAZ-K6RTR, Nov 2026).
Get-NetFirewallRule -DisplayName 'WAZip block IP-guard server*' -ErrorAction SilentlyContinue | Remove-NetFirewallRule
New-Item -ItemType Directory -Force -Path $ocDir | Out-Null
Set-Content -LiteralPath "$ocDir\OAgent.ini" -Value '[AgentConfig]', 'SIP=B6297C1B' -Encoding ASCII
Set-Content -LiteralPath "$drvDirI\tnfcap.sys" 'dummy'
& sc.exe create tnfcap type= kernel start= demand binPath= System32\drivers\tnfcap.sys | Out-Null
$env:WAZIP_TEST_NO_NETCFG = '1'
$rI7 = Scan "$env:TEMP\xi7.json" -Owner Personal -Fix -Root (Join-Path $env:TEMP 'qIpgNoNetcfg') -Out "$env:TEMP\xi7.txt"
Remove-Item Env:\WAZIP_TEST_NO_NETCFG
$xi7 = Get-Content -Raw "$env:TEMP\xi7.txt"
Check ($xi7 -match 'IP-guard network filter switched off on every connection: tnfcap' -and $xi7 -notmatch 'is not recognized|null-valued|FAILED to switch off') 'no netcfg.exe: IP-guard network filter not bound anywhere counts as switched off (WAZ-LEZ2G)'
Check ((Test-Path -LiteralPath 'HKLM:\SYSTEM\CurrentControlSet\Services\tnfcap') -and (Test-Path -LiteralPath "$drvDirI\tnfcap.sys")) 'no netcfg.exe: network filter driver left in place so the internet keeps working'
& sc.exe delete tnfcap | Out-Null
Remove-Item -LiteralPath "$drvDirI\tnfcap.sys", $ocDir -Recurse -Force -ErrorAction SilentlyContinue
Remove-Item -LiteralPath (Join-Path $env:TEMP 'qIpgNoNetcfg') -Recurse -Force -ErrorAction SilentlyContinue
# Office PC with a company server: a warning only, nothing removed even in Safe Mode.
Get-NetFirewallRule -DisplayName 'WAZip block IP-guard server*' -ErrorAction SilentlyContinue | Remove-NetFirewallRule
New-Item -ItemType Directory -Force -Path $ocDir | Out-Null
Set-Content -LiteralPath "$ocDir\OAgent.ini" -Value '[AgentConfig]', 'SIP=0A00000A' -Encoding ASCII
Set-Content -LiteralPath "$w64\winoav3.dll" 'dummy'
$env:WAZIP_TEST_IPG_SAFE = '1'
$rI4 = Scan "$env:TEMP\xi4.json" -Owner Office -Fix -Root (Join-Path $env:TEMP 'qIpgOffice4')
Remove-Item Env:\WAZIP_TEST_IPG_SAFE
Check ((Has $rI4 'Info' 'WARN' '^IP-guard') -and (Test-Path -LiteralPath "$w64\winoav3.dll") -and (Test-Path -LiteralPath "$ocDir\OAgent.ini")) 'office IP-guard with a company server is never removed'
Check (-not (Get-NetFirewallRule -DisplayName 'WAZip block IP-guard server*' -ErrorAction SilentlyContinue)) 'office IP-guard with a company server is not blocked'
Get-NetFirewallRule -DisplayName 'WAZip block IP-guard server*' -ErrorAction SilentlyContinue | Remove-NetFirewallRule
& sc.exe delete TNullFilter | Out-Null
Remove-Item -LiteralPath $ocDir -Recurse -Force -ErrorAction SilentlyContinue
Remove-Item -LiteralPath "$w64\winoav3.dll", "$drvDirI\TNullFilter.sys", $sbk -Force -ErrorAction SilentlyContinue
# Leftover after the agent is gone (WAZ-3NR7T): winrdgv3.exe with no IP-guard service is removed in normal Windows.
$cfsT = if (${env:CommonProgramFiles(x86)}) { "${env:CommonProgramFiles(x86)}\System" } else { "$env:CommonProgramFiles\System" }
Set-Content -LiteralPath "$cfsT\winrdgv3.exe" 'dummy'
$rI7 = Scan "$env:TEMP\xi7.json" -Owner Personal -Fix
Check ((Has $rI7 'File' 'HIGH' 'winrdgv3\.exe$' 'left behind') -and -not (Test-Path -LiteralPath "$cfsT\winrdgv3.exe")) 'leftover IP-guard winrdgv3.exe with no service is HIGH and quarantined'
Check (-not ($rI7.All | Where-Object { $_.Target -match '^IP-guard' })) 'leftover IP-guard file alone does not start the Safe Mode IP-guard removal'
Remove-Item -LiteralPath "$cfsT\winrdgv3.exe" -Force -ErrorAction SilentlyContinue

Write-Host '=== Second victim PC (Nov 2026): Toolkit.exe sideload, WindowsUpdateSync task, ManageEngine kit in Caches ===' -ForegroundColor Cyan
$tkDir = Join-Path $env:LOCALAPPDATA 'Toolkit'
New-Item -ItemType Directory -Force -Path $tkDir | Out-Null
Copy-Item "$env:SystemRoot\System32\notepad.exe" "$tkDir\Toolkit.exe"
Set-Content "$tkDir\unityplayer.dll" 'dummy'; Set-Content "$tkDir\UX64" 'dummy'
Register-ScheduledTask -TaskName 'WindowsUpdateSync' -Action (New-ScheduledTaskAction -Execute "$tkDir\Toolkit.exe") -Force | Out-Null
$kitDir = Join-Path $env:LOCALAPPDATA 'Microsoft\Windows\Caches\wazkit'
New-Item -ItemType Directory -Force -Path $kitDir | Out-Null
Set-Content "$kitDir\DCAgentServerInfo.json" '{"ServerInfoProps":{"SERVERIPADDRESS":"156.234.7.51","SERVERPORT":"8383"}}' -Encoding ASCII
# Hash known, size not: matched by file name (UX64 outside the Toolkit folder, so only the hash can flag it).
$ux = Join-Path $dl 'UX64'
$uxb = New-Object byte[] 4099; (New-Object Random 7).NextBytes($uxb); [IO.File]::WriteAllBytes($ux, $uxb)
$iocOld = $env:WAZIP_TEST_IOCS
@(@{ Sha = (Get-FileHash $ux).Hash; Size = 0; File = 'UX64'; Name = 'TEST-NAME-ONLY' }) | ConvertTo-Json | Out-File -Encoding UTF8 "$env:TEMP\test-iocs-name.json"
$env:WAZIP_TEST_IOCS = "$env:TEMP\test-iocs-name.json"
$rB1 = Scan "$env:TEMP\xb1.json"
Check (Has $rB1 'File' 'HIGH' 'Toolkit\\unityplayer\.dll$') 'fake unityplayer.dll beside Toolkit.exe is HIGH'
Check (Has $rB1 'File' 'HIGH' 'Toolkit\\UX64$') 'UX64 payload in the Toolkit folder is HIGH'
Check (-not (Has $rB1 'File' 'HIGH' 'Toolkit\\Toolkit\.exe$')) 'the signed Toolkit.exe itself is not flagged'
Check (Has $rB1 'Task' 'HIGH' '\\WindowsUpdateSync$') 'WindowsUpdateSync task running from AppData\Local is HIGH'
Check (Has $rB1 'File' 'HIGH' 'Caches\\wazkit$' '156\.234\.7\.51') 'ManageEngine kit in the Caches folder is HIGH and names its server'
Check (Has $rB1 'File' 'HIGH' 'Downloads\\UX64$' 'TEST-NAME-ONLY') 'hash with unknown size is matched by file name'
$rB2 = Scan "$env:TEMP\xb2.json" -Fix
Check (-not (Test-Path "$tkDir\unityplayer.dll") -and -not (Test-Path $kitDir) -and -not (Get-ScheduledTask -TaskName 'WindowsUpdateSync' -ErrorAction SilentlyContinue)) 'Toolkit sideload, kit and task removed by -Fix'
$env:WAZIP_TEST_IOCS = $iocOld
Unregister-ScheduledTask -TaskName 'WindowsUpdateSync' -Confirm:$false -ErrorAction SilentlyContinue
Remove-Item -LiteralPath $tkDir, $kitDir, $ux -Recurse -Force -ErrorAction SilentlyContinue

Write-Host '=== -Fix turns the admin prompt (UAC) back on ===' -ForegroundColor Cyan
$uacKey = 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System'
$uacOld = (Get-ItemProperty -LiteralPath $uacKey -ErrorAction SilentlyContinue).ConsentPromptBehaviorAdmin
Set-ItemProperty -LiteralPath $uacKey -Name ConsentPromptBehaviorAdmin -Value 0 -Type DWord
$uacDir = Join-Path $env:LOCALAPPDATA '0A1B2C3D4E5F6071'
New-Item -ItemType Directory -Force -Path $uacDir | Out-Null
Set-Content "$uacDir\CrashHunter_PC3.dll" 'dummy'
$r28 = Scan "$env:TEMP\x28.json"
Check (Has $r28 'Info' 'HIGH' '^Admin permission prompt' 'other signs of attack') 'UAC switched off on an infected PC is HIGH'
$r29 = Scan "$env:TEMP\x29.json" -Fix
Check ((Get-ItemProperty -LiteralPath $uacKey).ConsentPromptBehaviorAdmin -eq 5) '-Fix turns the admin prompt (UAC) back on'
if ($null -ne $uacOld) { Set-ItemProperty -LiteralPath $uacKey -Name ConsentPromptBehaviorAdmin -Value $uacOld -Type DWord }
else { Remove-ItemProperty -LiteralPath $uacKey -Name ConsentPromptBehaviorAdmin -ErrorAction SilentlyContinue }
Remove-Item -LiteralPath $uacDir -Recurse -Force -ErrorAction SilentlyContinue
# UAC off with nothing else: still HIGH so Y turns it back on (AFU, Nov 2026), but not called an infection.
Set-ItemProperty -LiteralPath $uacKey -Name ConsentPromptBehaviorAdmin -Value 0 -Type DWord
$r29b = Scan "$env:TEMP\x29b.json"
$uacF = @($r29b.All | Where-Object { $_.Target -match '^Admin permission prompt' })
Check ($uacF.Count -eq 1 -and $uacF[0].Severity -eq 'HIGH') "UAC switched off on its own is HIGH ($($uacF[0].Detail))"
$r29c = Scan "$env:TEMP\x29c.json" -Fix
Check ((Get-ItemProperty -LiteralPath $uacKey).ConsentPromptBehaviorAdmin -eq 5) '-Fix turns UAC back on when it was the only finding'
Set-ItemProperty -LiteralPath $uacKey -Name ConsentPromptBehaviorAdmin -Value 5 -Type DWord

Write-Host '=== Programs inside a folder Defender is told to skip (Caches / Toolkit report, Nov 2026) ===' -ForegroundColor Cyan
$exDir = 'C:\Users\Public\WazExclScan'
New-Item -ItemType Directory -Force -Path "$exDir\sub" | Out-Null
Set-Content "$exDir\helper.bat" '@echo hi'
Set-Content "$exDir\sub\note.vbs" 'WScript.Echo 1'
$exOk = $false
try { Add-MpPreference -ExclusionPath $exDir -ErrorAction Stop; $exOk = @((Get-MpPreference).ExclusionPath) -contains $exDir } catch { }
if ($exOk) {
  $rE1 = Scan "$env:TEMP\xe1.json"
  Check (Has $rE1 'DefExcl' 'HIGH' 'WazExclScan$' 'helper\.bat') 'excluded user folder holding scripts is HIGH and names them'
  Check (Has $rE1 'File' 'HIGH' 'WazExclScan\\helper\.bat$' 'told to ignore') 'script in the excluded folder is HIGH'
  Check (Has $rE1 'File' 'HIGH' 'WazExclScan\\sub\\note\.vbs$') 'script in a subfolder of the excluded folder is HIGH'
  $rE2 = Scan "$env:TEMP\xe2.json" -Fix
  Check (-not (Test-Path "$exDir\helper.bat") -and -not (Test-Path "$exDir\sub\note.vbs")) 'scripts in the excluded folder quarantined'
  Check (-not (@((Get-MpPreference).ExclusionPath) -contains $exDir)) 'exclusion on the folder removed'
} else { Write-Host 'SKIP excluded-folder contents: Defender not available' -ForegroundColor Yellow }
Remove-MpPreference -ExclusionPath $exDir -ErrorAction SilentlyContinue
Start-Sleep 2
Remove-Item -LiteralPath $exDir -Recurse -Force -ErrorAction SilentlyContinue

Write-Host '=== TankRAT / Overlord (LHDN and Penyata Akaun lures) ===' -ForegroundColor Cyan
$tc = Join-Path $env:LOCALAPPDATA 'Microsoft\Windows\Explorer\thumbcache_a1b2c3d4'
New-Item -ItemType Directory -Force -Path $tc | Out-Null
(Get-Item -LiteralPath $tc -Force).Attributes = 'Hidden, Directory'
foreach ($n in 'ExplorerBroker.exe', 'tedutil.dll', 'settings.dat') { [IO.File]::WriteAllText((Join-Path $tc $n), 'dummy') }
$ds = Join-Path $env:APPDATA 'Microsoft\DeviceSync'
New-Item -ItemType Directory -Force -Path $ds | Out-Null
$ovd = Join-Path $ds 'ovd_0123456789ab.exe'; [IO.File]::WriteAllText($ovd, 'dummy')
$runH = 'HKCU:\Software\Microsoft\Windows\CurrentVersion\Run'
if (-not (Test-Path $runH)) { New-Item -Path $runH -Force | Out-Null }
Set-ItemProperty -Path $runH -Name 'WindowsUpdate_Ab12' -Value "`"$tc\ExplorerBroker.exe`""
Set-ItemProperty -Path $runH -Name 'OverlordAgent-1a2b3c4d' -Value "`"$ovd`""
Register-ScheduledTask -TaskName 'ovd_1a2b3c4d' -Action (New-ScheduledTaskAction -Execute 'C:\Windows\System32\notepad.exe') -Force | Out-Null
$wmiOk = $false
try {
  $wf = New-CimInstance -Namespace root\subscription -ClassName __EventFilter -Property @{ Name = 'ovd_f1a2b3c4d'; EventNamespace = 'root\cimv2'; QueryLanguage = 'WQL'
    Query = "SELECT * FROM __InstanceCreationEvent WITHIN 30 WHERE TargetInstance ISA 'Win32_Process' AND TargetInstance.Name='wazip_never.exe'" } -ErrorAction Stop
  $wc = New-CimInstance -Namespace root\subscription -ClassName CommandLineEventConsumer -Property @{ Name = 'ovd_c1a2b3c4d'; ExecutablePath = $ovd; CommandLineTemplate = "`"$ovd`"" } -ErrorAction Stop
  New-CimInstance -Namespace root\subscription -ClassName __FilterToConsumerBinding -Property @{ Filter = [ref]$wf; Consumer = [ref]$wc } -ErrorAction Stop | Out-Null
  $wmiOk = $true
} catch { Write-Host "SKIP WMI setup: $($_.Exception.Message)" -ForegroundColor Yellow }
$oem = Join-Path $env:SystemDrive 'Recovery\OEM'
$oemExisted = Test-Path -LiteralPath $oem
$rcOld = if (Test-Path -LiteralPath "$oem\ResetConfig.xml") { Get-Content -Raw -LiteralPath "$oem\ResetConfig.xml" } else { $null }
New-Item -ItemType Directory -Force -Path "$oem\XRSBackupData" | Out-Null
$bat = 'ABCDEFGHIJ0123456789.bat'; $stub = 'KLMNOPQRST0123456789.exe'
Set-Content -LiteralPath "$oem\$bat" -Value "for /F %%A in ('reg query `"HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\RecoveryEnvironment`" /v TargetOS') DO SET T=%%A`r`nreg load HKLM\XYZ %T%\windows\system32\config\SOFTWARE"
Set-Content -LiteralPath "$oem\$stub" -Value 'dummy'
Set-Content -LiteralPath "$oem\ResetConfig.xml" -Value "<Reset><Run Phase=`"BasicReset_AfterImageApply`"><Path>$bat</Path></Run></Reset>"
Set-Content -LiteralPath "$oem\XRSBackupData\DELETEME" -Value "$bat`n$stub"
$rcOrig = '<Reset><Run Phase="BasicReset_AfterImageApply"><Path>oem-original.cmd</Path></Run></Reset>'
Set-Content -LiteralPath "$oem\XRSBackupData\configBackup" -Value $rcOrig -NoNewline
$cpDir = Join-Path $dl 'Penyata Akaun_2026_D2871820980_2026-10-13'
New-Item -ItemType Directory -Force -Path $cpDir | Out-Null
[IO.File]::WriteAllText((Join-Path $cpDir 'tedutil.dll'), 'dummy'); [IO.File]::WriteAllText((Join-Path $cpDir 'Setup.exe'), 'dummy')
$jp = ([string][char]0x6240 + [char]0x5F97 + [char]0x7A0E + [char]0x306E + [char]0x7D0D + [char]0x7A0E + [char]0x901A + [char]0x77E5 + [char]0x66F8 + '4.zip')
$tkNames = @('Penyata Akaun_2026_D2871820980_2026-10-13.zip', 'Notis_Penalti_S112_LHDN_D1243125560_2026.zip', 'Notis_CP14_TT2025_C8658265270.zip',
             'SENARAI DOKUMEN5.zip', 'MyInvois_e-Invoice_INV77194_LHDN_Validated.zip', 'e-Invoice_INV16697_Tenaga_Systems_Sdn_Bhd_Validated_2026-10-26.zip', $jp)
foreach ($n in $tkNames) { [IO.File]::WriteAllText((Join-Path $dl $n), 'dummy') }
$r25 = Scan "$env:TEMP\x25.json"
Check (Has $r25 'File' 'HIGH' 'thumbcache_a1b2c3d4\\ExplorerBroker\.exe$') 'TankRAT ExplorerBroker.exe in hidden thumbcache_ folder is HIGH'
Check (Has $r25 'File' 'HIGH' 'thumbcache_a1b2c3d4\\settings\.dat$') 'TankRAT settings.dat payload cache is HIGH'
Check (Has $r25 'File' 'HIGH' 'DeviceSync\\ovd_0123456789ab\.exe$') 'Overlord agent in DeviceSync is HIGH'
Check (Has $r25 'RegValue' 'HIGH' '\|WindowsUpdate_Ab12$') 'TankRAT WindowsUpdate_ Run value is HIGH'
Check (Has $r25 'RegValue' 'HIGH' '\|OverlordAgent-1a2b3c4d$') 'OverlordAgent Run value is HIGH'
Check (Has $r25 'Task' 'HIGH' 'ovd_1a2b3c4d$') 'Overlord scheduled task is HIGH'
if ($wmiOk) { Check (Has $r25 'Wmi' 'HIGH' 'ovd_c1a2b3c4d$') 'Overlord WMI consumer is HIGH' }
Check (Has $r25 'WinRE' 'HIGH' 'Recovery\\OEM$') 'Overlord WinRE reset hook is HIGH'
Check (Has $r25 'File' 'HIGH' 'D2871820980_2026-10-13\\tedutil\.dll$') 'fake tedutil.dll beside a program is HIGH'
foreach ($n in $tkNames) { Check (Has $r25 'File' 'HIGH' ([regex]::Escape($n) + '$') 'lure') "TankRAT lure name is HIGH: $n" }
Check (-not ($r25.All | Where-Object { $_.Kind -eq 'Process' -and $_.Target -match 'RuntimeBroker' })) 'real RuntimeBroker (started with -Embedding) is not flagged'
$r26 = Scan "$env:TEMP\x26.json" -Fix
Check (-not (Test-Path -LiteralPath "$tc\ExplorerBroker.exe") -and -not (Test-Path -LiteralPath "$tc\settings.dat")) 'TankRAT thumbcache_ files quarantined'
Check (-not (Test-Path -LiteralPath $ovd)) 'Overlord agent quarantined'
Check (-not (Get-ItemProperty -Path $runH -Name 'WindowsUpdate_Ab12' -ErrorAction SilentlyContinue) -and -not (Get-ItemProperty -Path $runH -Name 'OverlordAgent-1a2b3c4d' -ErrorAction SilentlyContinue)) 'TankRAT and Overlord Run values removed'
Check (-not (Get-ScheduledTask -TaskName 'ovd_1a2b3c4d' -ErrorAction SilentlyContinue)) 'Overlord task removed'
if ($wmiOk) {
  Check (-not (Get-CimInstance -Namespace root\subscription -ClassName CommandLineEventConsumer -Filter "Name='ovd_c1a2b3c4d'" -ErrorAction SilentlyContinue)) 'Overlord WMI consumer removed'
  Check (-not (Get-CimInstance -Namespace root\subscription -ClassName __EventFilter -Filter "Name='ovd_f1a2b3c4d'" -ErrorAction SilentlyContinue)) 'Overlord WMI filter removed'
}
Check (-not (Test-Path -LiteralPath "$oem\$bat") -and -not (Test-Path -LiteralPath "$oem\$stub") -and -not (Test-Path -LiteralPath "$oem\XRSBackupData")) 'WinRE hook files quarantined'
Check ((Get-Content -Raw -LiteralPath "$oem\ResetConfig.xml" -ErrorAction SilentlyContinue) -eq $rcOrig) 'original ResetConfig.xml put back'
Check (-not (Test-Path -LiteralPath (Join-Path $dl 'SENARAI DOKUMEN5.zip'))) 'TankRAT lure zip quarantined'
# Clean up
Remove-Item -LiteralPath $tc, $ds, $cpDir -Recurse -Force -ErrorAction SilentlyContinue
foreach ($n in $tkNames) { Remove-Item -LiteralPath (Join-Path $dl $n) -Force -ErrorAction SilentlyContinue }
Remove-ItemProperty -Path $runH -Name 'WindowsUpdate_Ab12', 'OverlordAgent-1a2b3c4d' -ErrorAction SilentlyContinue
Unregister-ScheduledTask -TaskName 'ovd_1a2b3c4d' -Confirm:$false -ErrorAction SilentlyContinue
Get-CimInstance -Namespace root\subscription -ClassName __FilterToConsumerBinding -ErrorAction SilentlyContinue | Where-Object { $_.Consumer.Name -eq 'ovd_c1a2b3c4d' } | Remove-CimInstance -ErrorAction SilentlyContinue
Get-CimInstance -Namespace root\subscription -ClassName CommandLineEventConsumer -Filter "Name='ovd_c1a2b3c4d'" -ErrorAction SilentlyContinue | Remove-CimInstance -ErrorAction SilentlyContinue
Get-CimInstance -Namespace root\subscription -ClassName __EventFilter -Filter "Name='ovd_f1a2b3c4d'" -ErrorAction SilentlyContinue | Remove-CimInstance -ErrorAction SilentlyContinue
if ($rcOld) { Set-Content -LiteralPath "$oem\ResetConfig.xml" -Value $rcOld -NoNewline } else { Remove-Item -LiteralPath "$oem\ResetConfig.xml" -Force -ErrorAction SilentlyContinue }
if (-not $oemExisted) { Remove-Item -LiteralPath $oem -Recurse -Force -ErrorAction SilentlyContinue }
}

if (InPart 2) {
Write-Host '=== TBK lure (renamed Edge helper + fake dbghelp.dll) ===' -ForegroundColor Cyan
$tbkDir = Join-Path $dl 'TBK20261104_9635'
New-Item -ItemType Directory -Force -Path $tbkDir | Out-Null
[IO.File]::WriteAllText((Join-Path $tbkDir 'TBK20261104.exe'), 'dummy'); [IO.File]::WriteAllText((Join-Path $tbkDir 'dbghelp.dll'), 'dummy')
[IO.File]::WriteAllText((Join-Path $dl 'TBK20261104_9635.zip'), 'dummy'); [IO.File]::WriteAllText((Join-Path $dl 'TBK1700_261102.exe'), 'dummy')
$r27 = Scan "$env:TEMP\x27.json"
Check (Has $r27 'File' 'HIGH' 'TBK20261104_9635\\dbghelp\.dll$') 'unsigned dbghelp.dll beside a program is HIGH'
Check (Has $r27 'File' 'HIGH' 'TBK20261104_9635\.zip$' 'lure') 'TBK lure zip name is HIGH'
Check (Has $r27 'File' 'HIGH' 'TBK1700_261102\.exe$' 'lure') 'TBK lure program name is HIGH'
$r28 = Scan "$env:TEMP\x28.json" -Fix
Check (-not (Test-Path -LiteralPath (Join-Path $tbkDir 'dbghelp.dll')) -and -not (Test-Path -LiteralPath (Join-Path $dl 'TBK20261104_9635.zip'))) 'TBK lure files quarantined'
Remove-Item -LiteralPath $tbkDir -Recurse -Force -ErrorAction SilentlyContinue
Remove-Item -LiteralPath (Join-Path $dl 'TBK1700_261102.exe') -Force -ErrorAction SilentlyContinue

Write-Host '=== Folder link pointing back up the tree (call depth overflow report) ===' -ForegroundColor Cyan
$loopDir = Join-Path $dl 'wazloop'
New-Item -ItemType Directory -Force -Path "$loopDir\sub" | Out-Null
cmd /c mklink /J "$loopDir\sub\back" "$loopDir" | Out-Null
[IO.File]::WriteAllText((Join-Path $loopDir 'sub\TBK20261105_1111.zip'), 'dummy')
$r29 = Scan "$env:TEMP\x29.json"
Check (Test-Path -LiteralPath "$loopDir\sub\back") 'folder link was created'
Check (Has $r29 'File' 'HIGH' 'wazloop\\sub\\TBK20261105_1111\.zip$' 'lure') 'file scan finishes and finds files despite a folder link loop'
cmd /c rmdir "$loopDir\sub\back" | Out-Null
Remove-Item -LiteralPath $loopDir -Recurse -Force -ErrorAction SilentlyContinue

Write-Host '=== Fake Windows\System folder (keylogger report) ===' -ForegroundColor Cyan
$ksDir = Join-Path $env:APPDATA 'Microsoft\Windows\System'
New-Item -ItemType Directory -Force -Path $ksDir | Out-Null
Set-Content "$ksDir\client.exe" 'dummy'; Set-Content "$ksDir\keylogger.exe" 'dummy'
$runK = 'HKCU:\Software\Microsoft\Windows\CurrentVersion\Run'
if (-not (Test-Path $runK)) { New-Item -Path $runK -Force | Out-Null }
Set-ItemProperty -Path $runK -Name WindowsUpdate -Value "`"$ksDir\client.exe`""
$r13 = Scan "$env:TEMP\x13.json"
Check (Has $r13 'File' 'HIGH' 'Microsoft\\Windows\\System\\client\.exe$') 'client.exe in fake Windows\System folder is HIGH'
Check (Has $r13 'File' 'HIGH' 'Microsoft\\Windows\\System\\keylogger\.exe$') 'keylogger.exe in fake Windows\System folder is HIGH'
Check (Has $r13 'RegValue' 'HIGH' '\|WindowsUpdate$') 'Run value WindowsUpdate pointing there is HIGH'
$r14 = Scan "$env:TEMP\x14.json" -Fix
Check (-not (Test-Path "$ksDir\client.exe") -and -not (Test-Path "$ksDir\keylogger.exe")) 'fake Windows\System files quarantined'
Check ($null -eq (Get-ItemProperty -Path $runK -Name WindowsUpdate -ErrorAction SilentlyContinue)) 'Run value WindowsUpdate removed'
Remove-ItemProperty -Path $runK -Name WindowsUpdate -ErrorAction SilentlyContinue
Remove-Item -LiteralPath $ksDir -Recurse -Force -ErrorAction SilentlyContinue
}

if (InPart 3) {
Write-Host '=== Chinese remote-control vendor found by code-signing company (watchlist) ===' -ForegroundColor Cyan
# Two harmless programs that only sleep, signed with throwaway test certificates; one keeps a connection
# to a test "attacker server" on an odd loopback address.
$cnDir = 'C:\Program Files\WazCnTest'
New-Item -ItemType Directory -Force -Path $cnDir | Out-Null
$cnSrc = 'using System; using System.Net.Sockets; using System.Threading; public static class P { public static void Main(string[] a) { TcpClient t = null; if (a.Length > 0) { t = new TcpClient(); t.Connect("127.77.0.2", int.Parse(a[0])); } Thread.Sleep(3600000); GC.KeepAlive(t); } }'
Add-Type -TypeDefinition $cnSrc -OutputAssembly "$cnDir\wazremote.exe" -OutputType ConsoleApplication
Copy-Item "$cnDir\wazremote.exe" "$cnDir\wazspy.exe"
$cnCerts = @()
foreach ($x in @(@('wazremote.exe', 'CN=WAZ Test Remote Co'), @('wazspy.exe', 'CN=WAZ Test Spy Co'))) {
  $ct = New-SelfSignedCertificate -Subject $x[1] -Type CodeSigningCert -CertStoreLocation Cert:\CurrentUser\My
  $cnCerts += $ct
  Set-AuthenticodeSignature -FilePath "$cnDir\$($x[0])" -Certificate $ct | Out-Null
}
$env:WAZIP_TEST_C2 = '127.77.0.2'
$env:WAZIP_TEST_CNSIGNER = 'WAZ Test Remote=WAZ Test Remote Co;WAZ Test Spy=WAZ Test Spy Co'
$cnSrv = Start-Encoded "`$l=[Net.Sockets.TcpListener]::new([Net.IPAddress]::Parse('127.77.0.2'),47124); `$l.Start(); `$c=`$l.AcceptTcpClient(); Start-Sleep 3600"
Start-Sleep 2
$cnA = Start-Process "$cnDir\wazremote.exe" -WindowStyle Hidden -PassThru
$cnB = Start-Process "$cnDir\wazspy.exe" -ArgumentList '47124' -WindowStyle Hidden -PassThru
for ($i = 0; $i -lt 20; $i++) {
  if (Get-NetTCPConnection -RemoteAddress 127.77.0.2 -ErrorAction SilentlyContinue | Where-Object { $_.OwningProcess -eq $cnB.Id }) { break }
  Start-Sleep 1
}
$rCn = Scan "$env:TEMP\xcn.json"
Check (Has $rCn 'Info' 'WARN' '^Remote-control program: WAZ Test Remote$' 'code-signing company') 'program signed by a watched vendor is WARN'
Check (Has $rCn 'Info' 'HIGH' '^Remote-control program: WAZ Test Spy$' '127\.77\.0\.2') 'watched vendor connected to a known attacker server is HIGH'
Check (-not ($rCn.All | Where-Object { $_.Target -match 'WAZ Test' -and $_.Kind -ne 'Info' })) 'watchlist adds no removable items by itself'
Stop-Process -Id $cnA.Id, $cnB.Id, $cnSrv.Id -Force -ErrorAction SilentlyContinue
Start-Sleep 1
Remove-Item -LiteralPath $cnDir -Recurse -Force -ErrorAction SilentlyContinue
$cnCerts | ForEach-Object { Remove-Item -LiteralPath "Cert:\CurrentUser\My\$($_.Thumbprint)" -Force -ErrorAction SilentlyContinue }
Remove-Item Env:\WAZIP_TEST_C2, Env:\WAZIP_TEST_CNSIGNER
}

if (InPart 2) {
Write-Host '=== Exclusion kit: Windows\Temp, SYSTEM profile, root wildcards, fake programs (WAZ-BCMF9, Nov 2026) ===' -ForegroundColor Cyan
$kitP = @('C:\Windows\TEMP', 'C:\Windows\system32\config\systemprofile\AppData\Local\DeviceHub_*', 'C:\WazHub_*')
$kitX = @('svchost_update.exe', 'wazcfg*.exe', 'WazSync.dll')
# Files hidden behind the wildcard exclusion, and an unsigned program running under an excluded name.
$kitDir = 'C:\WazHub_01'
New-Item -ItemType Directory -Force -Path $kitDir | Out-Null
Set-Content -LiteralPath "$kitDir\update.exe" 'unsigned stand-in'
$kitRun = "$env:ProgramData\WazKitRun"
New-Item -ItemType Directory -Force -Path $kitRun | Out-Null
Add-Type -TypeDefinition 'public static class WazKitStub { public static void Main() { System.Threading.Thread.Sleep(600000); } }' -OutputType ConsoleApplication -OutputAssembly "$kitRun\wazcfg01.exe"
$kitP2 = Start-Process -FilePath "$kitRun\wazcfg01.exe" -PassThru -WindowStyle Hidden
$kitOk = $false
try { Add-MpPreference -ExclusionPath $kitP -ExclusionProcess $kitX -ErrorAction Stop; $kitOk = $true } catch { Write-Host "SKIP exclusion kit: $($_.Exception.Message)" -ForegroundColor Yellow }
if ($kitOk) {
  $rK = Scan "$env:TEMP\xkit.json" -Fix
  Check (Has $rK 'File' 'HIGH' ([regex]::Escape("$kitDir\update.exe") + '$')) 'file inside a wildcard-excluded folder is still checked'
  Check (Has $rK 'Process' 'HIGH' '^wazcfg01\.exe' 'told to ignore by name') 'unsigned program running under an excluded name is HIGH'
  Start-Sleep 2
  Check ($kitP2.HasExited -and -not (Test-Path -LiteralPath "$kitDir\update.exe")) 'excluded-name program stopped and hidden file quarantined'
  foreach ($v in $kitP) { Check (Has $rK 'DefExcl' 'HIGH' ('^Path\|' + [regex]::Escape($v) + '$')) "kit path exclusion $v is HIGH" }
  foreach ($v in $kitX) { Check (Has $rK 'DefExcl' 'HIGH' ('^Process\|' + [regex]::Escape($v) + '$')) "kit program exclusion $v is HIGH" }
  $mpK = Get-MpPreference
  Check (-not (@($mpK.ExclusionPath) | Where-Object { $kitP -contains $_ }) -and -not (@($mpK.ExclusionProcess) | Where-Object { $kitX -contains $_ })) 'kit exclusions removed by -Fix'
  Remove-MpPreference -ExclusionPath $kitP -ExclusionProcess $kitX -ErrorAction SilentlyContinue
}
Stop-Process -Id $kitP2.Id -Force -ErrorAction SilentlyContinue
Remove-Item -LiteralPath $kitDir, $kitRun -Recurse -Force -ErrorAction SilentlyContinue
}

if (InPart 3) {
Write-Host '=== Program and service still running from the quarantine (WAZ-WWZUM / WAZ-PCFCA, Nov 2026) ===' -ForegroundColor Cyan
$qrDir = "$q\20260101-0000\file-1-WazRunner.quarantine"
New-Item -ItemType Directory -Force -Path $qrDir | Out-Null
Copy-Item -LiteralPath "$env:SystemRoot\System32\PING.EXE" -Destination "$qrDir\WazRunner.exe" -Force
$qrP = [Diagnostics.Process]::Start("$qrDir\WazRunner.exe", '-n 900 127.0.0.1')
& sc.exe create WazQrSvc start= demand binPath= "`"$qrDir\WazRunner.exe`"" | Out-Null
$rQ = Scan "$env:TEMP\xqr.json" -Fix
Check (Has $rQ 'Service' 'HIGH' '^WazQrSvc$' 'quarantine') 'service pointing into the quarantine is HIGH'
Start-Sleep 2
Check ($qrP.HasExited) 'program running from the quarantine is stopped by the clean-up'
$qrCfg = (& sc.exe qc WazQrSvc 2>&1 | Out-String)
Check ($LASTEXITCODE -ne 0 -or $qrCfg -match 'DISABLED') "service pointing into the quarantine is removed or switched off"
Stop-Process -Id $qrP.Id -Force -ErrorAction SilentlyContinue
& sc.exe delete WazQrSvc | Out-Null
Remove-Item -LiteralPath "$q\20260101-0000" -Recurse -Force -ErrorAction SilentlyContinue
}

if (InPart 1) {
Write-Host '=== Defender event naming our quarantine copy and a live copy elsewhere (WAZ-2JS5E, Nov 2026) ===' -ForegroundColor Cyan
$dlDir = "$env:TEMP\WazDefLive"
New-Item -ItemType Directory -Force -Path $dlDir | Out-Null
Set-Content -LiteralPath "$dlDir\CtxMUi.dll" 'live copy stand-in'
$env:WAZIP_TEST_DEFEVT = "Trojan:Script/WazLiveCopy|file:_$q\20261111-1\x.quarantine\ctxmuI.dll; file:_$dlDir\CtxMUi.dll`nTrojan:Script/WazGoneCopy|file:_$q\20261111-1\y.quarantine\a.dll; file:_C:\WazNoSuchDir\a.dll"
$rD = Scan "$env:TEMP\xdl.json"
Check (Has $rD 'Info' 'WARN' 'Defender detected: Trojan:Script/WazLiveCopy' 'CtxMUi\.dll') 'live copy in the same Defender event as our quarantine copy is still reported'
Check (-not (Has $rD 'Info' 'WARN' 'WazGoneCopy')) 'event naming only our quarantine copy and a gone file stays quiet'
Remove-Item Env:\WAZIP_TEST_DEFEVT
Remove-Item -LiteralPath $dlDir -Recurse -Force -ErrorAction SilentlyContinue
}

if (InPart 1) {
Write-Host '=== Started from 32-bit PowerShell: runs again as 64-bit with the same arguments (WAZ-B6PDP, Nov 2026) ===' -ForegroundColor Cyan
$ps32 = Join-Path $env:windir 'SysWOW64\WindowsPowerShell\v1.0\powershell.exe'
$bitF = "$env:TEMP\waz-bitness.txt"; Remove-Item -LiteralPath $bitF -ErrorAction SilentlyContinue
$env:WAZIP_TEST_BITNESS = $bitF
& $ps32 -NoProfile -ExecutionPolicy Bypass -File $tool -Owner Office -Fix -QuarantineRoot "$env:TEMP\q 32bit" | Out-Host
Remove-Item Env:\WAZIP_TEST_BITNESS
$bitS = "$(Get-Content -LiteralPath $bitF -ErrorAction SilentlyContinue)".Trim()
Check ($bitS -eq 'True Office True') "tool started from 32-bit PowerShell runs as 64-bit with its arguments ($bitS)"
}

if (InPart 1) {
Write-Host '=== Defender caught only the lure disk image: calm message, not "format the PC" (WAZ-TYM3F, Nov 2026) ===' -ForegroundColor Cyan
$env:WAZIP_TEST_DEFEVT = "Trojan:Win32/WazLureVhd|file:_C:\Users\WazNoUser\AppData\Local\Temp\Rar`$DIa0.554\CRY_WAZ_1.vhd"
$rLv = Scan "$env:TEMP\xlv.json" -Out "$env:TEMP\xlv.out"
$xlv = Get-Content -Raw "$env:TEMP\xlv.out"
Check ((Has $rLv 'Info' 'OLD' 'blocked a WhatsApp lure file' 'CRY_WAZ_1\.vhd') -and -not (Has $rLv 'Info' 'WARN' 'WazLureVhd')) 'Defender catching only the lure disk image is history, not a warning'
# The runner has other warnings of its own, so check this record is not one of them rather than "PC BERSIH".
Check ($xlv -match 'Rekod lama[^\r\n]*[\r\n]+[^\r\n]*blocked a WhatsApp lure file' -and $xlv -notmatch 'Defender detected: Trojan:Win32/WazLureVhd' -and $xlv -notmatch 'Defender only removed that file') 'Defender catching only the lure disk image: listed as an old record, not a warning'
$env:WAZIP_TEST_DEFEVT = "Trojan:Win32/WazPayload|file:_C:\Users\WazNoUser\AppData\Local\Temp\Rar`$DIa0.554\setup.exe"
$rLe = Scan "$env:TEMP\xle.json" -Out "$env:TEMP\xle.out"
Remove-Item Env:\WAZIP_TEST_DEFEVT
$xle = Get-Content -Raw "$env:TEMP\xle.out"
Check ($xle -match 'Defender only removed that file' -and -not (Has $rLe 'Info' 'OLD' 'blocked a WhatsApp lure')) 'Defender catching a program keeps the red warning'
}

if (InPart 1) {
Write-Host '=== Defender detection alone does not say Defender was told to ignore it (WAZ-CD9VY, Nov 2026) ===' -ForegroundColor Cyan
$hsDl2 = "$env:TEMP\hs_rt32_wazt0002.dll"
Set-Content $hsDl2 'dummy'
(Get-Item -LiteralPath $hsDl2 -Force).Attributes = 'Hidden, System'
$env:WAZIP_TEST_DEFEVT = "Trojan:Win32/WazSeen|file:_$hsDl2"
$rDs = Scan "$env:TEMP\xds.json" -Out "$env:TEMP\xds.out"
Remove-Item Env:\WAZIP_TEST_DEFEVT
$xds = Get-Content -Raw "$env:TEMP\xds.out"
Check (Has $rDs 'Info' 'WARN' 'Defender detected: Trojan:Win32/WazSeen') 'Defender detection reported'
Check ($xds -match 'PENTING' -and $xds -notmatch 'told Windows Defender to ignore') 'Defender detection alone does not claim Defender was told to ignore the malware'
Remove-Item -LiteralPath $hsDl2 -Force -ErrorAction SilentlyContinue
}

if (InPart 1) {
Write-Host '=== .bat launchers ===' -ForegroundColor Cyan
# Clear WARN-only leftovers so a clean result reads BERSIH.
& sc.exe delete MEUemsTest | Out-Null; & sc.exe delete OpswatLegitTest | Out-Null
& sc.exe delete WazLolVuln | Out-Null; & sc.exe delete WazRmmTest | Out-Null
& sc.exe delete WazCrdTest | Out-Null; & sc.exe delete WazMsp360Test | Out-Null; & sc.exe delete WazFaronicsTest | Out-Null
Remove-Item "$drvDir\wazlolv.sys" -Force -ErrorAction SilentlyContinue
Remove-Item Env:\WAZIP_TEST_LOLDRIVERS
Set-ItemProperty -LiteralPath $wuKey -Name Start -Value 3
Remove-Item $prof -Recurse -Force -ErrorAction SilentlyContinue
Remove-Item 'HKLM:\SOFTWARE\Policies\Google\Chrome' -Recurse -Force -ErrorAction SilentlyContinue
if ($null -eq $ciOld) { Remove-ItemProperty -LiteralPath $ciKey -Name VulnerableDriverBlocklistEnable -ErrorAction SilentlyContinue }
else { Set-ItemProperty -LiteralPath $ciKey -Name VulnerableDriverBlocklistEnable -Value $ciOld }
Remove-Item "$dl\Other.vhdx", "$wsl\ext4.vhdx" -Force -ErrorAction SilentlyContinue
Remove-Item "$rd" -Recurse -Force -ErrorAction SilentlyContinue
Remove-Item "$hd" -Recurse -Force -ErrorAction SilentlyContinue
Remove-Item Env:\WAZIP_TEST_IOCS
Set-Content "$dl\Click here to view8.zip" 'dummy'
Push-Location $root
$out = cmd /c "echo.| 1-SCAN-IMBAS.bat" 2>&1 | Out-String
Check ($out -match 'Click here to view8\.zip' -and $out -match 'HIGH') '1-SCAN-IMBAS.bat runs and reports the lure'
Check ($out -notmatch 'LOLDrivers list') 'real LOLDrivers list loads from data\loldrivers.csv'
Check (Test-Path "$dl\Click here to view8.zip") '1-SCAN-IMBAS.bat changes nothing'
$out = cmd /c "echo.| 2-CLEAN-BERSIH.bat" 2>&1 | Out-String
Check (-not (Test-Path "$dl\Click here to view8.zip")) '2-CLEAN-BERSIH.bat quarantines the lure'
$mf = Get-ChildItem 'C:\WAZipQuarantine' -Recurse -Filter manifest.json -ErrorAction SilentlyContinue | Sort-Object LastWriteTime | Select-Object -Last 1
Check ([bool]$mf) '2-CLEAN-BERSIH.bat writes a manifest'
$out = cmd /c "echo.| 1-SCAN-IMBAS.bat" 2>&1 | Out-String
Check ($out -match 'BERSIH') "1-SCAN-IMBAS.bat reports BERSIH after cleaning"
if ($mf) {
  Set-Content "$env:TEMP\restore-input.txt" "$($mf.FullName)`r`n`r`n" -Encoding ASCII
  $out = cmd /c "3-RESTORE-PULIH.bat < `"$env:TEMP\restore-input.txt`"" 2>&1 | Out-String
  Check (Test-Path "$dl\Click here to view8.zip") '3-RESTORE-PULIH.bat restores the file'
}
Pop-Location
}

if (InPart 4) {
$zoneW = "[ZoneTransfer]`r`nZoneId=3`r`nReferrerUrl=https://web.whatsapp.com/`r`nHostUrl=blob:https://web.whatsapp.com/1f2e3d4c-aaaa-bbbb-cccc-0123456789ab"
$meDir4 = "${env:ProgramFiles(x86)}\ManageEngine\UEMS_Agent"
function New-MePlant($svc) {
  New-Item -ItemType Directory -Force -Path "$meDir4\bin" | Out-Null
  Set-Content "$meDir4\bin\dcagentservice.exe" 'dummy'
  & sc.exe create $svc start= demand DisplayName= "ManageEngine UEMS - Agent $svc" binPath= "`"$meDir4\bin\dcagentservice.exe`"" | Out-Null
}
function Remove-MePlant($svc) {
  & sc.exe delete $svc | Out-Null
  Remove-Item -LiteralPath "${env:ProgramFiles(x86)}\ManageEngine" -Recurse -Force -ErrorAction SilentlyContinue
}

Write-Host '=== Unanswered BUANG question is logged (HXCEB/PZUKK reports, Nov 2026) ===' -ForegroundColor Cyan
New-MePlant 'MEAskTest'
Remove-Item Env:\WAZIP_NO_PROMPT
$inB = "$env:TEMP\waz-blank.txt"; Set-Content $inB ("`r`n" * 8) -Encoding ASCII
$outB = "$env:TEMP\xb0.out"
$pB = Start-Process powershell -ArgumentList '-NoProfile', '-ExecutionPolicy', 'Bypass', '-File', "`"$tool`"", '-QuarantineRoot', $q, '-ReportPath', "$env:TEMP\xb0.json", '-Fix' `
  -RedirectStandardInput $inB -RedirectStandardOutput $outB -NoNewWindow -Wait -PassThru
$env:WAZIP_NO_PROMPT = '1'
$xb = Get-Content -Raw $outB
$rB = @(); if (Test-Path "$env:TEMP\xb0.json") { $rB = @(Get-Content -Raw "$env:TEMP\xb0.json" | ConvertFrom-Json | ForEach-Object { $_ }) }
Check ($xb -match 'ManageEngine TIDAK dibuang \(tiada jawapan\)') 'unanswered BUANG question is shown as not removed'
Check ([bool]($rB | Where-Object { $_.Kind -eq 'Info' -and $_.Target -match 'ManageEngine' -and $_.Detail -match 'Not removed: no answer' })) 'unanswered BUANG question is in the report'
Check (Test-Path $meDir4) 'ManageEngine kept when BUANG is not typed'
Remove-MePlant 'MEAskTest'

# Runs before any antivirus-killer service is planted in this part, so only the earlier removal can explain HIGH.
# Leftover MEARW parts after an earlier clean-up removed the attacker's agent (R5T2B / 7F9EF, Nov 2026).
New-Item -ItemType Directory -Force -Path "$meDir4\EDR\bin" | Out-Null; Set-Content "$meDir4\EDR\bin\MEARWService.exe" 'dummy'
& sc.exe create MEARWLeftTest start= demand DisplayName= 'ManageEngine - EDR Service' binPath= "`"$meDir4\EDR\bin\MEARWService.exe`"" | Out-Null
$leftQ = "$env:TEMP\wazq-left"; New-Item -ItemType Directory -Force -Path "$leftQ\20261111-000000" | Out-Null
'[{"Target":"C:\\Program Files (x86)\\ManageEngine\\UEMS_Agent","Kind":"File"}]' | Set-Content -Encoding ASCII "$leftQ\20261111-000000\manifest.json"
$rL = Scan "$env:TEMP\xl1.json" -Owner Office -Root $leftQ
Check (Has $rL 'Info' 'HIGH' 'ManageEngine' 'already removed') 'office ManageEngine leftovers after an earlier removal are HIGH'
& sc.exe delete MEARWLeftTest | Out-Null; Remove-MePlant 'MEARWLeftTest'; Remove-Item -LiteralPath $leftQ -Recurse -Force -ErrorAction SilentlyContinue

Write-Host '=== ManageEngine installed within an hour of an antivirus killer (94V6P/UYRPQ reports, Nov 2026) ===' -ForegroundColor Cyan
New-MePlant 'MEOfficeTest4'
# A program installed as a service right after the attacker's ManageEngine (WAZ-4X583, C:\dcy\Client\safety.exe).
New-Item -ItemType Directory -Force -Path 'C:\wazdcy\Client' | Out-Null; Set-Content 'C:\wazdcy\Client\safety.exe' 'unknown program stand-in'
& sc.exe create WazNearMe start= demand binPath= 'C:\wazdcy\Client\safety.exe' | Out-Null
$goneLib = 'C:\Users\Public\Libraries\9&]!])^}[!!]%[#~##Gone'
& sc.exe create WazArdrvGone type= kernel start= demand binPath= ($goneLib + '\4=!=[)](gone') | Out-Null
& sc.exe delete WazArdrvGone | Out-Null
Start-Sleep 2
$rT = Scan "$env:TEMP\xt1.json" -Owner Office
Check (Has $rT 'Info' 'HIGH' 'Antivirus killer still active: WazArdrvGone') 'service installed from a hiding place in the last 48 hours (file gone) is HIGH'
Check (Has $rT 'Info' 'HIGH' 'ManageEngine' 'within an hour') "office ManageEngine installed within an hour of the antivirus killer is HIGH ($(@($rT.All | Where-Object { $_.Target -match 'ManageEngine' } | ForEach-Object { "$($_.Severity) $($_.Detail)" }) -join '; '))"
Check (Has $rT 'File' 'WARN' 'wazdcy\\Client\\safety\.exe$' "attacker's ManageEngine") 'service installed within an hour of the attacker ManageEngine is a warning'
& sc.exe delete WazNearMe | Out-Null; Remove-Item -LiteralPath 'C:\wazdcy' -Recurse -Force -ErrorAction SilentlyContinue
Remove-MePlant 'MEOfficeTest4'

Write-Host '=== Hiding folders, service-install history, linked task, zips (opt-in reports, Nov 2026) ===' -ForegroundColor Cyan
$libU = 'C:\Users\Public\Libraries\1&]!])^}[!!]%[#~##41242331885'
[IO.Directory]::CreateDirectory($libU) | Out-Null
$libF = $libU + '\3=!=[)](844'
[IO.File]::WriteAllText($libF, 'dummy')
for ($k = 0; $k -lt 3; $k++) { & sc.exe create WazArdrvHist type= kernel start= demand binPath= $libF | Out-Null; & sc.exe delete WazArdrvHist | Out-Null }
$pdU = 'C:\ProgramData\_z}#,(@[+%${,^(&!]]&}~#V'
[IO.Directory]::CreateDirectory($pdU) | Out-Null
[IO.File]::WriteAllText($pdU + '\iS.dLl', 'dummy'); [IO.File]::WriteAllText($pdU + '\3#.8', 'dummy'); [IO.File]::WriteAllText($pdU + '\PrivacyPolicy_wazt.exe', 'dummy')
Copy-Item -LiteralPath "$env:SystemRoot\System32\PING.EXE" -Destination ($pdU + '\wazping.exe')
$pingP = [Diagnostics.Process]::Start($pdU + '\wazping.exe', '-n 900 127.0.0.1')
$taskXml = @"
<?xml version="1.0" encoding="UTF-16"?>
<Task version="1.2" xmlns="http://schemas.microsoft.com/windows/2004/02/mit/task">
  <RegistrationInfo><Author>WAZOLDPC\wazuser</Author></RegistrationInfo>
  <Triggers><LogonTrigger><Enabled>true</Enabled></LogonTrigger></Triggers>
  <Principals><Principal id="Author"><UserId>S-1-5-18</UserId><RunLevel>HighestAvailable</RunLevel></Principal></Principals>
  <Settings><Enabled>false</Enabled></Settings>
  <Actions Context="Author"><Exec><Command>$([Security.SecurityElement]::Escape($pdU + '\PrivacyPolicy_wazt.exe'))</Command></Exec></Actions>
</Task>
"@
Register-ScheduledTask -TaskName 'WazPrivacyPolicyTest' -Xml $taskXml -Force | Out-Null
$drv1 = "$env:SystemRoot\System32\drivers\wazq1jlk5t"; Set-Content $drv1 'dummy'
& sc.exe create Wazq1jlk5t type= kernel start= demand binPath= 'System32\drivers\wazq1jlk5t' | Out-Null
$drv2 = "$env:SystemRoot\System32\drivers\wazq2hist"; Set-Content $drv2 'dummy'
& sc.exe create Wazq2hist type= kernel start= demand binPath= 'System32\drivers\wazq2hist' | Out-Null
& sc.exe delete Wazq2hist | Out-Null
$zDoc = "$dl\SPK SOLEH 2024.zip"; New-TestZip $zDoc 'SPK.pdf', 'foto/ktp.jpg'
$zVhd = "$dl\Gambar majlis.zip"; New-TestZip $zVhd 'Gambar majlis.vhd'
$zRar = "$dl\Arsip kerja.rar"; Set-Content $zRar 'dummy'
$zEmpty = "$dl\Kosong.zip"; New-TestZip $zEmpty @()
foreach ($z in $zDoc, $zVhd, $zRar, $zEmpty) { Set-Content -LiteralPath $z -Stream Zone.Identifier -Value $zoneW }
$locked9 = "$dl\Click here to view9.zip"; Set-Content $locked9 'dummy'
$locker9 = Start-Encoded "`$f=[IO.File]::Open('$locked9','Open','Read','None'); Start-Sleep 3600"
# WAZ-DYTEK (Nov 2026): logon script in Public\Documents
$logonBat = 'C:\Users\Public\Documents\wazlogon1.bat'
Set-Content -LiteralPath $logonBat -Value '@echo wazlogontest'
New-ItemProperty -Path 'HKCU:\Environment' -Name 'UserInitMprLogonScript' -Value $logonBat -Force | Out-Null
Start-Sleep 2
$env:WAZIP_TEST_TIMELINE = "$env:TEMP\waz-timeline.txt"
$r41 = Scan "$env:TEMP\x41.json"
Remove-Item Env:\WAZIP_TEST_TIMELINE
Check (Has $r41 'File' 'HIGH' ('^' + [regex]::Escape($libU) + '$') 'hiding place') 'Public\Libraries hiding folder is one HIGH finding'
Check (Has $r41 'File' 'HIGH' ('^' + [regex]::Escape($pdU) + '$') 'hiding place') 'symbol-named ProgramData folder is one HIGH finding'
Check (Has $r41 'Process' 'HIGH' '^wazping\.exe' 'hiding folder') 'program running from a hiding folder is HIGH'
Check (Has $r41 'Task' 'HIGH' '\\WazPrivacyPolicyTest$' 'being removed') 'task that starts a file in a hiding folder is HIGH'
Check (Has $r41 'Service' 'HIGH' '^Wazq1jlk5t$' 'hiding place') 'live driver with no file extension is HIGH'
Check (Has $r41 'File' 'HIGH' 'wazq2hist$' 'installed as a service') 'driver file of a deleted no-extension service (service-install history) is HIGH'
Check (Has $r41 'File' 'HIGH' 'Gambar majlis\.zip$' 'inside') 'WhatsApp zip with a disk image inside is HIGH'
Check (Has $r41 'File' 'WARN' 'SPK SOLEH 2024\.zip$' 'Only documents') 'WhatsApp zip with only documents is a warning'
Check (Has $r41 'File' 'WARN' 'Kosong\.zip$' 'no files inside') 'empty WhatsApp zip is called empty, not documents-only'
Check (Has $r41 'File' 'WARN' 'Arsip kerja\.rar$' 'cannot look inside') 'WhatsApp .rar the tool cannot open is a warning'
$tl = if (Test-Path "$env:TEMP\waz-timeline.txt") { Get-Content -Raw "$env:TEMP\waz-timeline.txt" } else { '' }
Check ($tl -match 'x3 \| WazArdrvHist') "repeated service installs are one timeline line ($(([regex]::Matches($tl, '[^\r\n]*WazArdrvHist[^\r\n]*') | ForEach-Object { $_.Value }) -join ' / '))"
Check ($tl -match 'WazPrivacyPolicyTest \| <host>\\<user>' -and $tl -notmatch 'WAZOLDPC') 'task author PC name is hidden in the timeline'
Check (Has $r41 'RegValue' 'HIGH' 'UserInitMprLogonScript$') 'logon script in Public\Documents is HIGH'
Check (Has $r41 'File' 'HIGH' 'wazlogon1\.bat$' 'sign-in') 'logon script file in Public\Documents is HIGH'
Check ($tl -match '== Logon script' -and $tl -match 'wazlogontest') 'timeline shows the first lines of the logon script'
Check ($tl -match '== Auto-start entries') 'timeline lists auto-start entries'
Check (Has $r41 'Info' 'HIGH' 'Antivirus killer still active: WazArdrvGone') 'antivirus killer installed in the last 48 hours (file gone) is HIGH'
$r42 = Scan "$env:TEMP\x42.json" -Fix
Check (-not (Test-Path -LiteralPath $libU)) 'Public\Libraries hiding folder quarantined whole'
Check (-not (Test-Path -LiteralPath $logonBat)) 'logon script file quarantined'
Remove-ItemProperty -Path 'HKCU:\Environment' -Name 'UserInitMprLogonScript' -ErrorAction SilentlyContinue
Remove-Item -LiteralPath $logonBat -Force -ErrorAction SilentlyContinue
Check (-not (Test-Path -LiteralPath $pdU)) 'ProgramData hiding folder quarantined whole (files with any extension)'
Check (-not (Get-Process -Id $pingP.Id -ErrorAction SilentlyContinue)) 'program running from the hiding folder stopped'
Check (-not (Get-ScheduledTask -TaskName 'WazPrivacyPolicyTest' -ErrorAction SilentlyContinue)) 'task pointing into the hiding folder removed'
& sc.exe query Wazq1jlk5t | Out-Null; Check ($LASTEXITCODE -ne 0) 'no-extension driver service deleted'
Check (-not (Test-Path -LiteralPath $drv1) -and -not (Test-Path -LiteralPath $drv2)) 'no-extension driver files quarantined'
Check (-not (Test-Path -LiteralPath $zVhd)) 'WhatsApp zip with a disk image quarantined'
Check ((Test-Path -LiteralPath $zDoc) -and (Test-Path -LiteralPath $zRar)) 'WhatsApp document zip and .rar left in place'
$mf4 = Get-ChildItem $q -Recurse -Filter manifest.json -ErrorAction SilentlyContinue | Sort-Object LastWriteTime | Select-Object -Last 1
$mfItems = @(); if ($mf4) { $mfItems = @(Get-Content -Raw $mf4.FullName | ConvertFrom-Json | ForEach-Object { $_ }) }
Check ([bool]($mfItems | Where-Object { $_.Kind -eq 'Failed' -and $_.Target -match 'Click here to view9\.zip$' })) 'item that could not be removed is listed in the manifest'
Stop-Process -Id $locker9.Id -Force -ErrorAction SilentlyContinue; Start-Sleep 1
if ($mf4) {
  & powershell -NoProfile -ExecutionPolicy Bypass -File $tool -Restore -Manifest $mf4.FullName | Out-Host
  Check (Test-Path -LiteralPath $pdU) 'restore puts the hiding folder back (Failed entries are skipped)'
}
Unregister-ScheduledTask -TaskName 'WazPrivacyPolicyTest' -Confirm:$false -ErrorAction SilentlyContinue
& sc.exe delete Wazq1jlk5t | Out-Null
Remove-Item -LiteralPath $libU, $pdU -Recurse -Force -ErrorAction SilentlyContinue
Remove-Item -LiteralPath $drv1, $drv2, $zDoc, $zVhd, $zRar, $zEmpty, $locked9 -Force -ErrorAction SilentlyContinue
# After a clean-up the killer that stopped coming back is history, not active (WAZ-625V3); KV<hex>.sys in Temp (WAZ-AZVRM).
$kvDrv = "$env:TEMP\KV1A2B3C4D.sys"; Set-Content -LiteralPath $kvDrv 'killer driver stand-in'
# Logon script wrapped in cmd.exe /c start (WAZ-V8NC2): the started program is the target, cmd.exe is never touched.
$lgDir = "$env:APPDATA\e30f73f9-wazlogon"; New-Item -ItemType Directory -Force -Path $lgDir | Out-Null; Set-Content "$lgDir\kquhowaz.exe" 'dummy'
Set-ItemProperty -Path 'HKCU:\Environment' -Name 'UserInitMprLogonScript' -Value "`"$env:SystemRoot\system32\cmd.exe`" /c start /b `"`" `"$lgDir\kquhowaz.exe`""
$r43 = Scan "$env:TEMP\x43.json"
Check (Has $r43 'File' 'HIGH' 'kquhowaz\.exe$') 'program started by a cmd.exe logon script is HIGH'
Check (-not ($r43.All | Where-Object { $_.Target -match '(?i)\\system32\\cmd\.exe$' })) 'cmd.exe itself is never reported'
Check (-not ($r43.All | Where-Object { $_.Kind -eq 'Task' -and $_.Target -match '^\\Microsoft\\Windows\\' })) 'no Windows task is reported as starting malware'
Remove-ItemProperty -Path 'HKCU:\Environment' -Name 'UserInitMprLogonScript' -ErrorAction SilentlyContinue
Remove-Item -LiteralPath $lgDir -Recurse -Force -ErrorAction SilentlyContinue
Check (Has $r43 'Info' 'OLD' 'Service installed from a malware hiding place: WazArdrvGone' 'history only') 'killer installed before the last clean-up is an old record, not a warning'
Check (-not (Has $r43 'Info' 'HIGH' 'Antivirus killer still active: WazArdrvGone')) 'killer installed before the last clean-up is not reported as still active'
Check (Has $r43 'File' 'HIGH' 'KV1A2B3C4D\.sys$') 'KV<hex>.sys driver in Temp is HIGH'
Remove-Item -LiteralPath $kvDrv -Force -ErrorAction SilentlyContinue

Write-Host '=== Loader in a {GUID} folder under AppData\Local re-drops everything (6S85A report, Nov 2026) ===' -ForegroundColor Cyan
$gDir = Join-Path $env:LOCALAPPDATA '{437711d0-7b49-7cbc-e129-df32973225aa}'
New-Item -ItemType Directory -Force -Path $gDir | Out-Null
$gExe = "$gDir\RuntimeBroker.exe"; $gDll = "$gDir\QtsVFS.dll"
Copy-Item -LiteralPath "$env:SystemRoot\System32\PING.EXE" -Destination $gExe
Set-Content $gDll 'dummy'
foreach ($x in $gExe, $gDll) { (Get-Item -LiteralPath $x -Force).Attributes = 'Hidden, System' }
$gP = [Diagnostics.Process]::Start($gExe, '-n 900 127.0.0.1')
$runG = 'HKCU:\Software\Microsoft\Windows\CurrentVersion\Run'
if (-not (Test-Path $runG)) { New-Item -Path $runG -Force | Out-Null }
# Unquoted rundll32 line: the Hidden+System DLL comes after the Windows program.
Set-ItemProperty -Path $runG -Name WazTokenBrokerTest -Value "$env:SystemRoot\System32\rundll32.exe $gDll,Start"
$hsDir = "$env:TEMP\hs5b46aa00"; New-Item -ItemType Directory -Force -Path $hsDir | Out-Null
Set-Content "$hsDir\eneio64.dat" 'dummy'; Set-Content "$hsDir\other.bin" 'dummy'
Start-Sleep 2
$r45 = Scan "$env:TEMP\x45.json"
Check (Has $r45 'Process' 'HIGH' '^RuntimeBroker\.exe') 'RuntimeBroker.exe running from a {GUID} folder is HIGH'
Check (Has $r45 'RegValue' 'HIGH' '\|WazTokenBrokerTest$' 'Hidden\+System') 'unquoted rundll32 Run value pointing at a Hidden+System DLL is HIGH'
Check (Has $r45 'File' 'HIGH' ('^' + [regex]::Escape($gDir) + '$') 'Random-named folder') '{GUID} loader folder is one HIGH finding'
Check (Has $r45 'File' 'HIGH' 'QtsVFS\.dll$' 'Hidden\+System') 'Hidden+System DLL in an AppData\Local {GUID} folder is HIGH'
Check (Has $r45 'File' 'HIGH' '\\Temp\\hs5b46aa00$' 'Random-named folder') 'Temp\hs<hex> drop folder is one HIGH finding'
$r46 = Scan "$env:TEMP\x46.json" -Fix
Check (-not (Get-Process -Id $gP.Id -ErrorAction SilentlyContinue)) 'loader process stopped'
Check (-not (Test-Path -LiteralPath $gDir)) '{GUID} loader folder quarantined (RuntimeBroker.exe and QtsVFS.dll gone)'
Check (-not (Get-ItemProperty -Path $runG -Name WazTokenBrokerTest -ErrorAction SilentlyContinue)) 'rundll32 Run value removed'
Check (-not (Test-Path -LiteralPath $hsDir)) 'Temp\hs<hex> drop folder quarantined whole'
Stop-Process -Id $gP.Id -Force -ErrorAction SilentlyContinue
Remove-ItemProperty -Path $runG -Name WazTokenBrokerTest -ErrorAction SilentlyContinue
Remove-Item -LiteralPath $gDir, $hsDir -Recurse -Force -ErrorAction SilentlyContinue

Write-Host '=== Opt-in malware samples go to the stand-in inbox; documents, zips and Downloads files never do ===' -ForegroundColor Cyan
$sq = 'C:\WAZipQuarantineSample'
Remove-Item -LiteralPath $sq -Recurse -Force -ErrorAction SilentlyContinue
function New-SampleKit($tagName) {
  $d = Join-Path $env:LOCALAPPDATA ('{437711d0-7b49-7cbc-e129-df3297' + $tagName + '}')
  New-Item -ItemType Directory -Force -Path $d | Out-Null
  Copy-Item -LiteralPath "$env:SystemRoot\System32\PING.EXE" -Destination "$d\RuntimeBroker.exe"
  # Different bytes in every file, so the sha256 de-duplication keeps them apart.
  Set-Content "$d\QtsVFS.dll" "dll $tagName"; Set-Content "$d\KV99AA0000.sys" "sys $tagName"; Set-Content "$d\eneio64.dat" "dat $tagName"
  Set-Content "$d\notes.docx" "doc $tagName"; New-TestZip "$d\bundle.zip" @('a.txt')
  foreach ($x in Get-ChildItem -LiteralPath $d -Force) { $x.Attributes = 'Hidden, System' }
  # Running from the hiding folder, like the real loader.
  [Diagnostics.Process]::Start("$d\RuntimeBroker.exe", '-n 900 127.0.0.1') | Out-Null
  Start-Sleep 2
  $d
}
function Start-SampleInbox($out, $port) {
  Start-Job {
    param($out, $port)
    $l = New-Object Net.HttpListener; $l.Prefixes.Add("http://127.0.0.1:$port/"); $l.Start()
    $limit = 150000
    while ($true) {
      $w = $l.GetContextAsync()
      if (-not $w.Wait($limit)) { break }
      $limit = 20000
      $c = $w.Result
      $ms = New-Object IO.MemoryStream; $c.Request.InputStream.CopyTo($ms)
      Add-Content -LiteralPath $out -Value ("{0}|{1}|{2}|{3}|{4}" -f $c.Request.Url.AbsolutePath, $c.Request.Headers['X-Sha256'], $c.Request.Headers['X-File-Ext'], $ms.Length, $c.Request.Headers['X-Sample-Kind'])
      $b = [Text.Encoding]::ASCII.GetBytes('{"ok":true}')
      $c.Response.ContentType = 'application/json'; $c.Response.ContentLength64 = $b.Length; $c.Response.OutputStream.Write($b, 0, $b.Length); $c.Response.Close()
    }
    $l.Close()
  } -ArgumentList $out, $port
}
$sKit = New-SampleKit 'aa0001'
$sLure = Join-Path $dl 'Notis Denda Sample 2026.exe'
Set-Content -LiteralPath $sLure 'lure program stand-in from Downloads'
$lureSha = (Get-FileHash -LiteralPath $sLure -Algorithm SHA256).Hash.ToLower()
# Antivirus killer driver with no file extension in System32\drivers (WAZ-7WGFZ, Nov 2026).
$kDrv = "$env:SystemRoot\System32\drivers\wazk1lr"; Set-Content -LiteralPath $kDrv 'antivirus killer stand-in'
$kSha = (Get-FileHash -LiteralPath $kDrv -Algorithm SHA256).Hash.ToLower()
& sc.exe create WazK1lr type= kernel start= demand binPath= $kDrv | Out-Null
# Firefox WhatsApp Web storage: the '+' signs in its folder name must not make its files samples (Nov 2026).
$ffWa = "$env:APPDATA\Mozilla\Firefox\Profiles\waz1.default-release\storage\default\https+++web.whatsapp.com"
New-Item -ItemType Directory -Force -Path "$ffWa\idb" | Out-Null
Set-Content -LiteralPath "$ffWa\.metadata-v2" 'https://web.whatsapp.com metadata stand-in'
Set-Content -LiteralPath "$ffWa\idb\waz-blob" 'whatsapp data stand-in'
# Inno Setup uninstall log next to a program: never a sample (WAZ-JPV34, Nov 2026).
$innoDir = "$env:ProgramData\WazInnoTest"; New-Item -ItemType Directory -Force -Path $innoDir | Out-Null
Set-Content -LiteralPath "$innoDir\unins000.dat" ('Inno Setup Uninstall Log (b) stand-in ' + ('x' * 20000))
$innoSha = (Get-FileHash -LiteralPath "$innoDir\unins000.dat" -Algorithm SHA256).Hash.ToLower()
$ffSha = @("$ffWa\.metadata-v2", "$ffWa\idb\waz-blob" | ForEach-Object { (Get-FileHash -LiteralPath $_ -Algorithm SHA256).Hash.ToLower() })
$sGot = "$env:TEMP\waz-samples-got.txt"; Remove-Item -LiteralPath $sGot -Force -ErrorAction SilentlyContinue
$sJob = Start-SampleInbox $sGot 8798
Start-Sleep 5
$env:WAZIP_TEST_SAMPLE_URL = 'http://127.0.0.1:8798/sample'
$env:WAZIP_TEST_SAMPLE_ANSWER = 'Y'
$r52 = Scan "$env:TEMP\x52.json" -Fix -Root $sq -Out "$env:TEMP\x52.out"
$x52 = Get-Content -Raw "$env:TEMP\x52.out"
Wait-Job $sJob -Timeout 60 | Out-Null; Stop-Job $sJob -ErrorAction SilentlyContinue; Remove-Job $sJob -Force -ErrorAction SilentlyContinue
$got = @(if (Test-Path $sGot) { Get-Content -LiteralPath $sGot })
$gotExt = @($got | ForEach-Object { ($_ -split '\|')[2] })
Write-Host "samples received: $($got -join '; ')"
Check (-not (Test-Path -LiteralPath $sKit)) 'sample kit folder quarantined by -Fix'
Check (-not (Test-Path -LiteralPath $sLure)) 'Downloads lure program quarantined by -Fix'
Check ($x52 -match 'SAMPEL VIRUS' -and $x52 -match 'BUKAN dokumen') 'sample question asked, saying documents are not sent'
Check (($gotExt -contains '.dll') -and ($gotExt -contains '.sys') -and ($gotExt -contains '.dat') -and ($gotExt -contains '.exe')) "quarantined .exe/.dll/.sys/.dat sent ($($gotExt -join ','))"
Check (-not ($gotExt | Where-Object { $_ -match '^\.(docx|zip)$' })) 'no document or zip sent'
Check (-not (@($got | ForEach-Object { ($_ -split '\|')[1] }) | Where-Object { $ffSha -contains $_ })) 'Firefox WhatsApp Web files never sent as samples'
Check (-not (@($got | ForEach-Object { ($_ -split '\|')[1] }) | Where-Object { $_ -eq $innoSha })) 'installer uninstall log never sent as a sample'
Remove-Item -LiteralPath $innoDir -Recurse -Force -ErrorAction SilentlyContinue
Remove-Item -LiteralPath "$env:APPDATA\Mozilla\Firefox\Profiles\waz1.default-release" -Recurse -Force -ErrorAction SilentlyContinue
Check ((@($got | ForEach-Object { ($_ -split '\|')[1] }) -contains $kSha)) 'quarantined antivirus killer with no file extension sent'
& sc.exe delete WazK1lr | Out-Null; Remove-Item -LiteralPath $kDrv -Force -ErrorAction SilentlyContinue
Check (-not ($got | Where-Object { ($_ -split '\|')[1] -eq $lureSha })) 'quarantined program from Downloads not sent'
Check (@($got | Where-Object { ($_ -split '\|')[0] -ne '/sample' }).Count -eq 0 -and @($got | Where-Object { [int](($_ -split '\|')[3]) -le 0 }).Count -eq 0) 'every sample posted to /sample with its bytes'
Check ($x52 -match 'OK  sampel [0-9a-f]{12}') 'each sent sample shown with its sha256 start'
Check (-not (Test-Path -LiteralPath "$sq\samples-pending.txt")) 'pending sample list cleared after sending'
# Second run: the victim answers no, so nothing is sent.
$sKit2 = New-SampleKit 'aa0002'
Remove-Item -LiteralPath $sGot -Force -ErrorAction SilentlyContinue
$sJob = Start-SampleInbox $sGot 8799
Start-Sleep 5
$env:WAZIP_TEST_SAMPLE_URL = 'http://127.0.0.1:8799/sample'
$env:WAZIP_TEST_SAMPLE_ANSWER = 'N'
$r53 = Scan "$env:TEMP\x53.json" -Fix -Root $sq -Out "$env:TEMP\x53.out"
$x53 = Get-Content -Raw "$env:TEMP\x53.out"
Stop-Job $sJob -ErrorAction SilentlyContinue; Remove-Job $sJob -Force -ErrorAction SilentlyContinue
Check (-not (Test-Path -LiteralPath $sKit2)) 'second kit quarantined'
Check ($x53 -match 'tiada sampel dihantar' -and -not (Test-Path $sGot)) 'answer other than Y sends no sample'
Check (-not (Test-Path -LiteralPath "$sq\samples-pending.txt")) 'pending sample list cleared after a no'
# Third run: suspicious program files the tool leaves in place (a driver installed while the antivirus killer was
# active, a file Windows Defender detected) are offered too, as copies (WAJJE report, Nov 2026).
$susDir = "$env:ProgramData\WazSuspect"
New-Item -ItemType Directory -Force -Path $susDir | Out-Null
$susDrv = "$susDir\wazsusdrv.sys"; $susDef = "$susDir\IS.dll"; $susDoc = "$susDir\readme.docx"
Set-Content $susDrv 'suspect driver stand-in'; Set-Content $susDef 'defender detected stand-in'; Set-Content $susDoc 'document stand-in'
& sc.exe create WazGoneNear type= kernel start= demand binPath= ($goneLib + '\5=!=[)](gone') | Out-Null
& sc.exe delete WazGoneNear | Out-Null
& sc.exe create WazSusDrv type= kernel start= demand binPath= $susDrv | Out-Null
& sc.exe create WazSusMs start= demand binPath= "$env:SystemRoot\System32\svchost.exe -k WazSusTest" | Out-Null
$drvSha = (Get-FileHash -LiteralPath $susDrv -Algorithm SHA256).Hash.ToLower()
$defSha = (Get-FileHash -LiteralPath $susDef -Algorithm SHA256).Hash.ToLower()
$docSha = (Get-FileHash -LiteralPath $susDoc -Algorithm SHA256).Hash.ToLower()
$msSha = (Get-FileHash -LiteralPath "$env:SystemRoot\System32\svchost.exe" -Algorithm SHA256).Hash.ToLower()
$oldDefDet = $env:WAZIP_TEST_DEFDET
$env:WAZIP_TEST_DEFDET = "Trojan:Win32/Bearfoos.A!ml|file:_$susDef;file:_$susDoc"
Remove-Item -LiteralPath $sGot -Force -ErrorAction SilentlyContinue
$sJob = Start-SampleInbox $sGot 8797
Start-Sleep 5
$env:WAZIP_TEST_SAMPLE_URL = 'http://127.0.0.1:8797/sample'
$env:WAZIP_TEST_SAMPLE_ANSWER = 'Y'
$r54 = Scan "$env:TEMP\x54.json" -Fix -Root $sq -Out "$env:TEMP\x54.out"
$x54 = Get-Content -Raw "$env:TEMP\x54.out"
Wait-Job $sJob -Timeout 60 | Out-Null; Stop-Job $sJob -ErrorAction SilentlyContinue; Remove-Job $sJob -Force -ErrorAction SilentlyContinue
$got = @(if (Test-Path $sGot) { Get-Content -LiteralPath $sGot })
$gotSha = @($got | ForEach-Object { ($_ -split '\|')[1] })
Write-Host "suspect samples received: $($got -join '; ')"
Check ($x54 -match 'mencurigakan') "suspicious files offered ($(([regex]::Matches($x54, 'sampel[^\r\n]*')).Value -join ' / '))"
Check ($gotSha -contains $drvSha) 'driver installed near the antivirus killer sent as a suspect sample'
Check ($gotSha -contains $defSha) 'file Windows Defender detected sent as a suspect sample'
Check (@($got | Where-Object { ($_ -split '\|')[1] -in $drvSha, $defSha -and ($_ -split '\|')[4] -ne 'suspect' }).Count -eq 0) 'suspect samples marked as suspect'
Check (-not ($gotSha -contains $msSha)) 'Microsoft-signed service program not sent'
Check (-not ($gotSha -contains $docSha)) 'document Defender detected not sent'
Check ((Test-Path -LiteralPath $susDrv) -and (Test-Path -LiteralPath $susDef)) 'suspect files left in place (only a copy is sent)'
& sc.exe delete WazSusDrv | Out-Null; & sc.exe delete WazSusMs | Out-Null
$env:WAZIP_TEST_DEFDET = $oldDefDet
Remove-Item -LiteralPath $susDir -Recurse -Force -ErrorAction SilentlyContinue
Remove-Item Env:\WAZIP_TEST_SAMPLE_URL, Env:\WAZIP_TEST_SAMPLE_ANSWER
Get-Process -ErrorAction SilentlyContinue | Where-Object { $_.Path -like "$env:LOCALAPPDATA\{437711d0-7b49-7cbc-e129-df3297aa000*" } | Stop-Process -Force -ErrorAction SilentlyContinue
Remove-Item -LiteralPath $sKit, $sKit2, $sLure, $sq -Recurse -Force -ErrorAction SilentlyContinue

Write-Host '=== Task MicrosoftTokenBroker: rundll32 loads QtsVFS.dll from a {GUID} folder (WAZ-EU5BG, Nov 2026) ===' -ForegroundColor Cyan
$tDir = Join-Path $env:LOCALAPPDATA '{437711d0-7b49-7cbc-e129-df32973225cc}'
New-Item -ItemType Directory -Force -Path $tDir | Out-Null
$tDll = "$tDir\QtsVFS.dll"; Set-Content $tDll 'dummy'
$tbXml = @"
<?xml version="1.0" encoding="UTF-16"?>
<Task version="1.2" xmlns="http://schemas.microsoft.com/windows/2004/02/mit/task">
  <Triggers><LogonTrigger><Enabled>true</Enabled></LogonTrigger></Triggers>
  <Settings><Enabled>false</Enabled></Settings>
  <Actions Context="Author"><Exec><Command>C:\Windows\System32\rundll32.exe</Command><Arguments>$([Security.SecurityElement]::Escape($tDll)),VFS_Initialize</Arguments></Exec></Actions>
</Task>
"@
Register-ScheduledTask -TaskName 'MicrosoftTokenBroker' -Xml $tbXml -Force | Out-Null
$r50 = Scan "$env:TEMP\x50.json"
Check (Has $r50 'Task' 'HIGH' '\\MicrosoftTokenBroker$' 'rundll32') 'task running rundll32 on a DLL in a {GUID} folder is HIGH'
Check (Has $r50 'File' 'HIGH' '\{437711d0-7b49-7cbc-e129-df32973225cc\}$' 'Random-named folder') 'the {GUID} folder of that DLL is one HIGH finding'
$r51 = Scan "$env:TEMP\x51.json" -Fix
Check (-not (Get-ScheduledTask -TaskName 'MicrosoftTokenBroker' -ErrorAction SilentlyContinue)) 'MicrosoftTokenBroker task removed'
Check (-not (Test-Path -LiteralPath $tDir)) '{GUID} folder with QtsVFS.dll quarantined'
Unregister-ScheduledTask -TaskName 'MicrosoftTokenBroker' -Confirm:$false -ErrorAction SilentlyContinue
Remove-Item -LiteralPath $tDir -Recurse -Force -ErrorAction SilentlyContinue
Remove-Item -LiteralPath $safeDry -Force -ErrorAction SilentlyContinue

Write-Host '=== Infection that comes back goes straight to Safe Mode (6S85A report, Nov 2026) ===' -ForegroundColor Cyan
$qR = 'C:\WAZipQuarantineRecur'
Remove-Item -LiteralPath $qR -Recurse -Force -ErrorAction SilentlyContinue
Remove-Item -LiteralPath $safeDry -Force -ErrorAction SilentlyContinue
# First-ever clean-up with one bad file: no forced Safe Mode.
$nDll = "$env:TEMP\hs_rt32_waznrc01.dll"; Set-Content $nDll 'dummy'; (Get-Item -LiteralPath $nDll -Force).Attributes = 'Hidden, System'
$r47 = Scan "$env:TEMP\x47.json" -Fix -Root $qR
Check (-not (Test-Path -LiteralPath $nDll)) 'first clean-up quarantines the single bad file'
Check (-not ((Test-Path $safeDry) -and ((Get-Content -Raw $safeDry) -match 'safeauto'))) 'first-ever clean-up with one bad file does not force Safe Mode'
# An earlier clean-up stopped a malware process; now a loader process is running again.
$oldD = Join-Path $qR '20200101-000000'; New-Item -ItemType Directory -Force -Path $oldD | Out-Null
'[{"Kind":"Process","Target":"RuntimeBroker.exe (PID 1)"}]' | Out-File -Encoding UTF8 (Join-Path $oldD 'manifest.json')
$rDir = Join-Path $env:LOCALAPPDATA '{437711d0-7b49-7cbc-e129-df32973225bb}'
New-Item -ItemType Directory -Force -Path $rDir | Out-Null
Copy-Item -LiteralPath "$env:SystemRoot\System32\PING.EXE" -Destination "$rDir\RuntimeBroker.exe"
$rP = [Diagnostics.Process]::Start("$rDir\RuntimeBroker.exe", '-n 900 127.0.0.1')
Start-Sleep 2
# The report is offered before the reboot, while there is internet (stand-in inbox unreachable, so it lands as a file).
$repDirPre = "$env:TEMP\waz-rep-pre"; Remove-Item -LiteralPath $repDirPre -Recurse -Force -ErrorAction SilentlyContinue
New-Item -ItemType Directory -Force -Path $repDirPre | Out-Null
$env:WAZIP_TEST_REPORT_DIR = $repDirPre; $env:WAZIP_TEST_REPORT_URL = 'http://127.0.0.1:8795/report'
$r48 = Scan "$env:TEMP\x48.json" -Fix -Root $qR
Remove-Item Env:\WAZIP_TEST_REPORT_DIR, Env:\WAZIP_TEST_REPORT_URL
Check (@(Get-ChildItem -LiteralPath $repDirPre -Filter 'Laporan-WAZIP-*.zip').Count -ge 1) 'first-scan report offered before the Safe Mode reboot'
Remove-Item -LiteralPath $repDirPre -Recurse -Force -ErrorAction SilentlyContinue
$sd = if (Test-Path $safeDry) { Get-Content -Raw $safeDry } else { '' }
Check ($sd -match 'safeauto .*came back') "malware back after an earlier clean-up goes to Safe Mode ($("$sd".Trim()))"
# The online pass holds the evidence (loader, folder, task): its report must be kept before the reboot (GMK9P/ED88Q, Nov 2026).
$pend = @(Get-ChildItem -LiteralPath $qR -Filter 'report-pending-*.zip' -ErrorAction SilentlyContinue)
$pendSum = $null
if ($pend.Count) {
  $zr = [IO.Compression.ZipFile]::OpenRead($pend[0].FullName)
  $e = $zr.GetEntry('summary.json'); if ($e) { $sr = New-Object IO.StreamReader($e.Open()); $pendSum = $sr.ReadToEnd(); $sr.Close() }
  $zr.Dispose()
}
Check ($pend.Count -eq 1 -and $pendSum -match 'RuntimeBroker') "online report kept as pending before the Safe Mode reboot ($($pend.Count) file(s))"
# Next normal run: the pending report goes out with the offer (stand-in inbox unreachable, so it lands as a file).
$repDirR = "$env:TEMP\waz-rep-recur"; Remove-Item -LiteralPath $repDirR -Recurse -Force -ErrorAction SilentlyContinue
New-Item -ItemType Directory -Force -Path $repDirR | Out-Null
$env:WAZIP_TEST_REPORT_DIR = $repDirR; $env:WAZIP_TEST_REPORT_URL = 'http://127.0.0.1:8795/report'
$r54 = Scan "$env:TEMP\x54.json" -Fix -Root $qR -Out "$env:TEMP\x54.out"
Remove-Item Env:\WAZIP_TEST_REPORT_DIR, Env:\WAZIP_TEST_REPORT_URL
Check (@(Get-ChildItem -LiteralPath $repDirR -Filter 'Laporan-WAZIP-*.zip').Count -ge 1 -and -not (Get-ChildItem -LiteralPath $qR -Filter 'report-pending-*.zip')) 'pending online report offered and handed on at the next run'
Remove-Item -LiteralPath $repDirR -Recurse -Force -ErrorAction SilentlyContinue
Check (-not (Test-Path -LiteralPath $rDir)) 'online pass still quarantines the loader folder before Safe Mode'
Stop-Process -Id $rP.Id -Force -ErrorAction SilentlyContinue
# Loader running together with an antivirus-killer driver, on a PC never cleaned before.
Remove-Item -LiteralPath $qR, $safeDry -Recurse -Force -ErrorAction SilentlyContinue
New-Item -ItemType Directory -Force -Path $rDir | Out-Null
Copy-Item -LiteralPath "$env:SystemRoot\System32\PING.EXE" -Destination "$rDir\RuntimeBroker.exe"
$rP = [Diagnostics.Process]::Start("$rDir\RuntimeBroker.exe", '-n 900 127.0.0.1')
$kvSys = "$env:TEMP\KVwazrc01.sys"; Set-Content $kvSys 'dummy'
& sc.exe create WazBootRepairRc type= kernel start= demand binPath= $kvSys | Out-Null
Start-Sleep 2
$r49 = Scan "$env:TEMP\x49.json" -Fix -Root $qR
$sd = if (Test-Path $safeDry) { Get-Content -Raw $safeDry } else { '' }
Check (Has $r49 'Service' 'HIGH' '^WazBootRepairRc$' 'antivirus killer') 'driver loaded from Temp is an antivirus killer'
Check ($sd -match 'safeauto .*antivirus killer') "loader running with an antivirus killer goes to Safe Mode ($("$sd".Trim()))"
Check ((Get-Content -Raw -LiteralPath "$qR\safeauto-queued.txt" -ErrorAction SilentlyContinue) -match '^queued ') 'automatic Safe Mode leaves a note that it was set up'
Stop-Process -Id $rP.Id -Force -ErrorAction SilentlyContinue
& sc.exe delete WazBootRepairRc | Out-Null
Remove-Item -LiteralPath $rDir, $qR, $safeDry, $kvSys -Recurse -Force -ErrorAction SilentlyContinue
# Safe Mode setup fails: the reason and the recovery steps are shown right there (WAZ-PU7JW, Nov 2026).
New-Item -ItemType Directory -Force -Path $rDir | Out-Null
Copy-Item -LiteralPath "$env:SystemRoot\System32\PING.EXE" -Destination "$rDir\RuntimeBroker.exe"
$rP = [Diagnostics.Process]::Start("$rDir\RuntimeBroker.exe", '-n 900 127.0.0.1')
Set-Content $kvSys 'dummy'
& sc.exe create WazBootRepairRc type= kernel start= demand binPath= $kvSys | Out-Null
Start-Sleep 2
$env:WAZIP_TEST_SAFEAUTO_FAIL = '1'
$r49f = Scan "$env:TEMP\x49f.json" -Fix -Root $qR -Out "$env:TEMP\x49f.out"
Remove-Item Env:\WAZIP_TEST_SAFEAUTO_FAIL
$x49f = Get-Content -Raw "$env:TEMP\x49f.out"
Check ($x49f -match 'Could not set up automatic Safe Mode \(test bcdedit failure\)\. (Remove it from the recovery screen|Start in Safe Mode with Networking)' -and $x49f -notmatch 'red steps above') 'Safe Mode setup failure shows the reason and the recovery steps'
Check ((Get-Content -Raw -LiteralPath "$qR\safeauto-queued.txt" -ErrorAction SilentlyContinue) -match '^setup failed .*test bcdedit failure') 'Safe Mode setup failure is noted for the next report'
Stop-Process -Id $rP.Id -Force -ErrorAction SilentlyContinue
& sc.exe delete WazBootRepairRc | Out-Null
Remove-Item -LiteralPath $rDir, $qR, $safeDry, $kvSys -Recurse -Force -ErrorAction SilentlyContinue
# Safe Mode set up earlier but never started: the next run says so (WAZ-K6RTR..CT2HP, Nov 2026).
$qSm = Join-Path $env:TEMP 'qSafeMissed'
New-Item -ItemType Directory -Force -Path $qSm | Out-Null
Set-Content -LiteralPath "$qSm\safeauto-queued.txt" -Value 'queued 2026-11-13T23:00:00'
$rSm = Scan "$env:TEMP\xsm.json" -Root $qSm
Check (Has $rSm 'Info' 'WARN' '^Automatic Safe Mode did not run' 'queued 2026-11-13') 'Safe Mode set up but never started is reported on the next run'
Check (Test-Path -LiteralPath "$qSm\safeauto-queued.txt") 'scan-only pass keeps the Safe Mode did-not-run note for the clean-up pass (WAZ-B6PDP)'
Set-Content -LiteralPath "$qSm\safeauto-queued.txt" -Value 'queued 2026-11-13T23:00:00'
Start-Sleep 2
Set-Content -LiteralPath "$qSm\safeauto-ran.txt" -Value 'ran'
$rSm2 = Scan "$env:TEMP\xsm2.json" -Root $qSm
Check (-not (Has $rSm2 'Info' 'WARN' '^Automatic Safe Mode did not run')) 'Safe Mode that did run is not reported as missed'
Remove-Item -LiteralPath $qSm -Recurse -Force -ErrorAction SilentlyContinue
# Same loader, but a Windows update waits for a restart: no Safe Mode (it would fail with "undoing changes").
New-Item -ItemType Directory -Force -Path $rDir | Out-Null
Copy-Item -LiteralPath "$env:SystemRoot\System32\PING.EXE" -Destination "$rDir\RuntimeBroker.exe"
$rP = [Diagnostics.Process]::Start("$rDir\RuntimeBroker.exe", '-n 900 127.0.0.1')
Set-Content $kvSys 'dummy'
& sc.exe create WazBootRepairRc type= kernel start= demand binPath= $kvSys | Out-Null
Start-Sleep 2
$env:WAZIP_TEST_UPDATEPENDING = '1'
$r49u = Scan "$env:TEMP\x49u.json" -Fix -Root $qR -Out "$env:TEMP\x49u.out"
Remove-Item Env:\WAZIP_TEST_UPDATEPENDING
$sd = if (Test-Path $safeDry) { Get-Content -Raw $safeDry } else { '' }
Check ($sd -match 'update-pending' -and $sd -notmatch 'safeauto') "pending Windows update stops the Safe Mode restart ($("$sd".Trim()))"
Check ((Get-Content -Raw "$env:TEMP\x49u.out") -match 'Update and restart') 'pending Windows update: user told to Update and restart first'
Stop-Process -Id $rP.Id -Force -ErrorAction SilentlyContinue
& sc.exe delete WazBootRepairRc | Out-Null
Remove-Item -LiteralPath $rDir, $qR, $safeDry, $kvSys -Recurse -Force -ErrorAction SilentlyContinue

Write-Host '=== ManageEngine leftovers and task files in Safe Mode (VVF5Z/2F44T reports, Nov 2026) ===' -ForegroundColor Cyan
New-MePlant 'MEUemsTest5'
& sc.exe create DCFAFilter type= kernel start= demand binPath= 'System32\DRIVERS\DCFAFilter.sys' | Out-Null
& sc.exe create MEARWFltDriver type= kernel start= demand binPath= '\SystemRoot\System32\drivers\MEARWFltDriver.sys' | Out-Null
& sc.exe create uesAgentService start= demand DisplayName= 'Device Control Test' binPath= "$env:SystemRoot\System32\svchost.exe" | Out-Null
foreach ($tn in 'DCAgentUpdater', 'UEMSLogCollector') { Register-ScheduledTask -TaskName $tn -Action (New-ScheduledTaskAction -Execute 'notepad.exe') -Force | Out-Null }
$env:WAZIP_TEST_TASKFILES = '1'
$rM5 = Scan "$env:TEMP\xm5.json" -Fix -RemoveME
Remove-Item Env:\WAZIP_TEST_TASKFILES
foreach ($sv in 'DCFAFilter', 'MEARWFltDriver', 'uesAgentService') {
  Check (Has $rM5 'Service' 'HIGH' "^$sv$" 'ManageEngine') "ManageEngine leftover service $sv found"
  & sc.exe query $sv | Out-Null; Check ($LASTEXITCODE -ne 0) "ManageEngine leftover service $sv deleted"
}
foreach ($tn in 'DCAgentUpdater', 'UEMSLogCollector') {
  Check (Has $rM5 'Task' 'HIGH' "\\$tn$" 'ManageEngine') "ManageEngine task $tn found from the task files"
  Check (-not (Test-Path -LiteralPath "$env:SystemRoot\System32\Tasks\$tn")) "ManageEngine task file $tn removed without the Task Scheduler"
  Check (-not (Test-Path -LiteralPath "HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Schedule\TaskCache\Tree\$tn")) "ManageEngine task $tn registry entry removed"
  Unregister-ScheduledTask -TaskName $tn -Confirm:$false -ErrorAction SilentlyContinue
}
foreach ($sv in 'MEUemsTest5', 'DCFAFilter', 'MEARWFltDriver', 'uesAgentService') { & sc.exe delete $sv 2>&1 | Out-Null }
Remove-MePlant 'MEUemsTest5'

Write-Host '=== Step errors, Defender exclusions from the registry, vendor disk, report names ===' -ForegroundColor Cyan
$mpOk = $false; try { Add-MpPreference -ExclusionProcess 'QtsUpdater.exe' -ErrorAction Stop; $mpOk = $true } catch {}
$regOk = $false; try { $regOk = @((Get-Item 'HKLM:\SOFTWARE\Microsoft\Windows Defender\Exclusions\Processes' -ErrorAction Stop).GetValueNames()) -contains 'QtsUpdater.exe' } catch {}
$vdir = "$env:ProgramFiles\WazVendorTest"; New-Item -ItemType Directory -Force -Path $vdir | Out-Null
$vhdV = "$vdir\Vendor_Virtual_Disk.vhd"
Set-Content "$env:TEMP\dp1.txt" "create vdisk file=`"$vhdV`" maximum=8 type=expandable`r`nattach vdisk`r`n" -Encoding ASCII
& diskpart.exe /s "$env:TEMP\dp1.txt" | Out-Null
$vAtt = [bool](Get-Disk -ErrorAction SilentlyContinue | Where-Object { $_.BusType -eq 'File Backed Virtual' -and $_.Location -eq $vhdV })
$env:WAZIP_TEST_MPFAIL = '1'; $env:WAZIP_TEST_STEPERR = '8'
$rD = Scan "$env:TEMP\xd1.json" -Out "$env:TEMP\xd1.out"
Remove-Item Env:\WAZIP_TEST_MPFAIL, Env:\WAZIP_TEST_STEPERR
$xd = Get-Content -Raw "$env:TEMP\xd1.out"
Check ($xd -match 'could not check\): test step error' -and $xd -notmatch '\[8/8\] Browser[^\r\n]*BERSIH') 'a step that hit an error is not shown as BERSIH'
Check ($xd -match '\[6/8\] Fail' -and $xd -match '\[8/8\] Browser' -and $xd -notmatch 'Mengimbas PC \(Scanning') 'progress bar leaves the step lines and the saved output unchanged'
if ($mpOk -and $regOk) { Check (Has $rD 'DefExcl' 'HIGH' 'QtsUpdater\.exe') 'Defender exclusions read from the registry when Get-MpPreference fails' }
else { Write-Host "SKIP Defender registry fallback: exclusion added $mpOk, registry readable $regOk" -ForegroundColor Yellow }
if ($vAtt) { Check (-not ($rD.All | Where-Object { $_.Kind -eq 'Vhd' -and $_.Target -eq $vhdV })) 'vendor virtual disk under Program Files is not flagged' }
else { Write-Host 'SKIP vendor virtual disk: could not attach a test VHD' -ForegroundColor Yellow }
Set-Content "$env:TEMP\dp2.txt" "select vdisk file=`"$vhdV`"`r`ndetach vdisk`r`n" -Encoding ASCII
& diskpart.exe /s "$env:TEMP\dp2.txt" | Out-Null
Remove-Item -LiteralPath $vdir -Recurse -Force -ErrorAction SilentlyContinue
Remove-MpPreference -ExclusionProcess 'QtsUpdater.exe' -ErrorAction SilentlyContinue
# Report anonymiser: everyday-word account names, Downloads file names, quarantine copies.
New-Item -ItemType Directory -Force -Path 'C:\Users\Dell', 'C:\Users\User' | Out-Null
$piiIn = "$env:TEMP\waz-pii.txt"
@(
  "C:\Users\$env:USERNAME\AppData\Local\Google\Chrome\User Data\Default"
  'C:\Program Files\Dell\SupportAssist\x.exe'
  'Publisher: Dell, Inc.'
  "C:\Users\$env:USERNAME\Downloads\SPK SOLEH 2024.zip"
  "C:\Users\$env:USERNAME\Downloads\KPMG-ITMAX\ITMAX.rar"
  "C:\Users\$env:USERNAME\Downloads\Rekonsiliasi Akun.zip"
  'C:\WAZipQuarantine\20261106-1\file-3-SPK SOLEH 2024.zip.quarantine'
  "$env:COMPUTERNAME\User"
) -join "`r`n" | Set-Content -LiteralPath $piiIn -Encoding ASCII
$env:WAZIP_TEST_PII = $piiIn
& powershell -NoProfile -ExecutionPolicy Bypass -File $tool | Out-Null
Remove-Item Env:\WAZIP_TEST_PII
$po = if (Test-Path "$piiIn.out") { Get-Content -Raw "$piiIn.out" } else { '' }
Write-Host $po
Check ($po -match 'Chrome\\User Data' -and $po -match 'Program Files\\Dell\\SupportAssist' -and $po -match 'Dell, Inc\.') 'everyday words that are also account names are kept'
Check ($po -match '<user>\\Downloads\\<file>\.zip' -and $po -match '<user>\\Downloads\\<folder>\\<file>\.rar' -and $po -notmatch 'SOLEH|ITMAX') 'Downloads file and folder names are hidden'
Check ($po -match 'Rekonsiliasi Akun\.zip') 'lure file names are kept as evidence'
Check ($po -match 'file-3-<file>\.zip\.quarantine') 'quarantine copies of hidden names are hidden too'
Check ($po -match '<name>\\<name>' -and $po -notmatch [regex]::Escape($env:COMPUTERNAME) -and $po -notmatch '<<') 'account name after the PC name is hidden, with no doubled markers'
Remove-Item -LiteralPath 'C:\Users\Dell', 'C:\Users\User' -Recurse -Force -ErrorAction SilentlyContinue

# Last in this part: the service history it plants would make every later clean-up here go to Safe Mode.
Write-Host '=== Loader folder straight in Public, antivirus killer reinstalled in waves (KBXTR/LLW58 reports, Nov 2026) ===' -ForegroundColor Cyan
$qW = 'C:\WAZipQuarantineWaves'
Remove-Item -LiteralPath $qW, $safeDry -Recurse -Force -ErrorAction SilentlyContinue
$pubSym = 'C:\Users\Public\9~]=(.wazQ_'
New-Item -ItemType Directory -Force -Path $pubSym | Out-Null
Copy-Item -LiteralPath "$env:SystemRoot\System32\PING.EXE" -Destination "$pubSym\fingerprint.db.exe"
Set-Content "$pubSym\847#}#.362" 'driver stand-in'
$pP = [Diagnostics.Process]::Start("$pubSym\fingerprint.db.exe", '-n 900 127.0.0.1')
$wavLib = 'C:\Users\Public\Libraries\9&]!])^}[!!]%[#~##Waves'
foreach ($i in 1..5) {
  & sc.exe create WazKillerWaves type= kernel start= demand binPath= ($wavLib + '\18_++%&(&.224') | Out-Null
  & sc.exe delete WazKillerWaves | Out-Null
}
Start-Sleep 2
$rW = Scan "$env:TEMP\xw1.json" -Fix -Root $qW
$sd = if (Test-Path $safeDry) { Get-Content -Raw $safeDry } else { '' }
Check (Has $rW 'File' 'HIGH' ([regex]::Escape($pubSym) + '$') 'Public or ProgramData folder named with symbols') 'symbol-named folder straight in Public is one hiding unit'
Check (Has $rW 'Process' 'HIGH' 'fingerprint\.db\.exe' 'hiding folder') 'loader running from the Public folder is stopped'
Check (-not (Test-Path -LiteralPath $pubSym)) 'whole Public symbol folder quarantined, driver file included'
Check ($sd -match 'safeauto .*again and again') "antivirus killer reinstalled again and again goes to Safe Mode ($("$sd".Trim()))"
Stop-Process -Id $pP.Id -Force -ErrorAction SilentlyContinue
Remove-Item -LiteralPath $pubSym, $qW, $safeDry -Recurse -Force -ErrorAction SilentlyContinue
}

Write-Host ''
if ($fail) { Write-Host "$fail check(s) failed" -ForegroundColor Red; exit 1 }
Write-Host 'ALL CHECKS PASSED' -ForegroundColor Green
exit 0
