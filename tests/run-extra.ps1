# Extra coverage: hash matching, loaded fake rime.dll, ardrv/OPSWAT, ManageEngine,
# locked files, and the double-click .bat launchers. Harmless stand-ins only.
$ErrorActionPreference = 'Continue'
$root = Split-Path -Parent $PSScriptRoot
$tool = Join-Path $root 'wa-zip-cleaner.ps1'
$q = 'C:\WAZipQuarantineExtra'
$fail = 0
$env:WAZIP_NO_PROMPT = '1'
$env:WAZIP_TIMING = '1'
Get-MpComputerStatus -ErrorAction SilentlyContinue | Format-List RealTimeProtectionEnabled, AMRunningMode, OnAccessProtectionEnabled
function Check($ok, $msg) {
  if ($ok) { Write-Host "PASS $msg" -ForegroundColor Green } else { Write-Host "FAIL $msg" -ForegroundColor Red; $script:fail++ }
}
function Scan($report, [switch]$Fix, [switch]$RemoveME, [string]$Owner) {
  $a = @('-NoProfile', '-ExecutionPolicy', 'Bypass', '-File', $tool, '-QuarantineRoot', $q, '-ReportPath', $report)
  if ($Fix) { $a += '-Fix' }
  if ($RemoveME) { $a += '-RemoveManageEngine' }
  if ($Owner) { $a += '-Owner', $Owner }
  & powershell @a | Out-Host
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
function Start-Encoded($script) {
  $enc = [Convert]::ToBase64String([Text.Encoding]::Unicode.GetBytes($script))
  Start-Process powershell -ArgumentList '-NoProfile', '-EncodedCommand', $enc -WindowStyle Hidden -PassThru
}
$rimeHost = Start-Encoded $loader

# C. Driver services and a ManageEngine agent look-alike (never started)
Set-Content "$env:SystemRoot\System32\drivers\ardrv.sys" 'dummy'
& sc.exe create ardrv type= kernel start= demand binPath= "System32\drivers\ardrv.sys" | Out-Null
& sc.exe create OpswatLegitTest type= kernel start= demand binPath= "C:\Program Files\OPSWAT\ardrv.sys" | Out-Null
& sc.exe create MEUemsTest start= demand DisplayName= "ManageEngine UEMS - Agent" binPath= "$env:SystemRoot\System32\svchost.exe" | Out-Null

# D. Lure file held open by a running process (stands in for malware resisting removal)
$locked = "$dl\Click here to view7.zip"
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
& sc.exe create WazRmmTest start= demand binPath= "C:\Program Files (x86)\AnyDesk\AnyDesk.exe --service" | Out-Null
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
Check (Has $r 'Info' 'WARN' 'ManageEngine') 'ManageEngine agent warning'
Check (Has $r 'File' 'HIGH' 'Click here to view7\.zip$') 'locked lure file detected'
Check (Has $r 'File' 'HIGH' 'Downloads\\Notice\.vhd$') 'Notice.vhd lure is HIGH'
Check (Has $r 'Process' 'HIGH' "PID $($cli.Id)\)" 'attacker server') 'process connected to known C2 is HIGH'
Check (Has $r 'File' 'WARN' 'Downloads\\Other\.vhdx$') 'other VHD in user folder is WARN'
Check (-not ($r.All | Where-Object { $_.Target -match 'ext4\.vhdx' })) 'WSL ext4.vhdx ignored'
Check (Has $r 'Service' 'HIGH' '^WazLolMal$' 'LOLDrivers') 'LOLDrivers malicious driver service is HIGH'
Check (Has $r 'Service' 'WARN' '^WazLolVuln$' 'vulnerable') 'LOLDrivers vulnerable driver service is WARN'
Check (Has $r 'Info' 'WARN' 'Remote-control program: AnyDesk') 'remote-control program (AnyDesk) is WARN'
$scanLog = Get-ChildItem $q -Filter 'scan-*.log' | Sort-Object LastWriteTime | Select-Object -Last 1
Check ($scanLog -and (Select-String -LiteralPath $scanLog.FullName -SimpleMatch 'Maksud: Program kawalan jauh (contoh AnyDesk' -Quiet)) 'warning explained in plain Malay'
Check (Has $r 'Info' 'WARN' 'Blocklist is OFF') 'driver blocklist switched off is WARN'
Check (Has $r 'Info' 'WARN' 'Windows Update is disabled') 'Windows Update switched off is WARN'
Check (Has $r 'RegValue' 'WARN' 'ExtensionInstallForcelist\|1$') 'forced Chrome extension is WARN when owner unknown'
Check (Has $r 'File' 'HIGH' 'Google Chrome WAZip\.lnk$' 'load-extension') 'Chrome shortcut loading a hidden extension is HIGH'
Check (Has $r 'Info' 'WARN' 'Chrome extension ponmlkjihgfedcba' 'from a folder') 'extension loaded from a folder is WARN'

Write-Host '=== Fix while file is locked ===' -ForegroundColor Cyan
$r = Scan "$env:TEMP\x2.json" -Fix
Check ($r.Code -eq 1) "fix does not crash on locked file (exit $($r.Code))"
Check (Test-Path $locked) 'locked file left in place (reported, not lost)'
Check (-not (Test-Path "$hd\invoice-copy.dat")) 'hash-matched file quarantined'
Check (-not (Get-Process -Id $rimeHost.Id -ErrorAction SilentlyContinue)) 'rime.dll host process stopped'
& sc.exe query ardrv | Out-Null; Check ($LASTEXITCODE -ne 0) 'ardrv service deleted'
Check (-not (Test-Path "$env:SystemRoot\System32\drivers\ardrv.sys")) 'ardrv.sys driver file quarantined'
Check ([bool](Get-Service MEUemsTest -ErrorAction SilentlyContinue)) 'ManageEngine left for the user to decide'
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
$r = Scan "$env:TEMP\x3.json" -Fix
Check (-not (Test-Path $locked)) 'previously locked file quarantined on second run'

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

Write-Host '=== WhatsApp download tag, Defender history, ran-programs records ===' -ForegroundColor Cyan
# Files saved from WhatsApp Web carry a Zone.Identifier tag naming web.whatsapp.com.
$zone = "[ZoneTransfer]`r`nZoneId=3`r`nReferrerUrl=https://web.whatsapp.com/`r`nHostUrl=blob:https://web.whatsapp.com/1f2e3d4c-aaaa-bbbb-cccc-0123456789ab"
$waImg = "$dl\Dokumen penting.img"; $waZip = "$dl\Gambar raya.zip"
Set-Content $waImg 'dummy'; Set-Content $waZip 'dummy'
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
Check (Has $r8 'File' 'WARN' 'Gambar raya\.zip$' 'WhatsApp Web') 'zip downloaded from WhatsApp Web is WARN'
Check (Has $r8 'Info' 'WARN' 'Malware program ran: C:\\ProgramData\\MicroPoint\\WinCombo\.exe$') 'program-launch list entry for WinCombo.exe is WARN'
Check (-not (Has $r8 'Info' 'WARN' 'notepad')) 'ordinary programs in the launch list are ignored'
Check (Has $r8 'Info' 'WARN' 'Malware program ran: TAXFILING\.EXE$' 'Prefetch') 'Prefetch entry for TaxFiling.exe is WARN'
$has5007 = $histOk -and [bool](Get-WinEvent -FilterHashtable @{ LogName = 'Microsoft-Windows-Windows Defender/Operational'; Id = 5007; StartTime = $histStart } -MaxEvents 1 -ErrorAction SilentlyContinue)
if ($has5007) { Check (Has $r8 'Info' 'WARN' 'Defender exclusion added: C:\\Users\\Public\\WazHistTest') 'exclusion added after the last clean-up is listed from Defender history' }
else { Write-Host 'SKIP Defender history: no 5007 event on this runner' -ForegroundColor Yellow }
$scanLog = Get-ChildItem $q -Filter 'scan-*.log' | Sort-Object LastWriteTime | Select-Object -Last 1
Check ($scanLog -and (Select-String -LiteralPath $scanLog.FullName -SimpleMatch 'Maksud: Fail ni dimuat turun dari WhatsApp Web' -Quiet)) 'WhatsApp download warning explained in plain Malay'
Check ($scanLog -and (Select-String -LiteralPath $scanLog.FullName -SimpleMatch 'Maksud: Rekod Windows tunjuk program malware' -Quiet)) 'ran-program warning explained in plain Malay'

$r9 = Scan "$env:TEMP\x9.json" -Fix
Check (-not (Test-Path -LiteralPath $waImg)) 'WhatsApp disk image quarantined'
Check (Test-Path -LiteralPath $waZip) 'WhatsApp zip (WARN only) left in place'
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

Write-Host '=== Fake Windows\System folder (keylogger report) ===' -ForegroundColor Cyan
$ksDir = Join-Path $env:APPDATA 'Microsoft\Windows\System'
New-Item -ItemType Directory -Force -Path $ksDir | Out-Null
Set-Content "$ksDir\client.exe" 'dummy'; Set-Content "$ksDir\keylogger.exe" 'dummy'
$runK = 'HKCU:\Software\Microsoft\Windows\CurrentVersion\Run'
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

Write-Host '=== .bat launchers ===' -ForegroundColor Cyan
# Clear WARN-only leftovers so a clean result reads BERSIH.
& sc.exe delete MEUemsTest | Out-Null; & sc.exe delete OpswatLegitTest | Out-Null
& sc.exe delete WazLolVuln | Out-Null; & sc.exe delete WazRmmTest | Out-Null
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

Write-Host ''
if ($fail) { Write-Host "$fail check(s) failed" -ForegroundColor Red; exit 1 }
Write-Host 'ALL CHECKS PASSED' -ForegroundColor Green
exit 0
