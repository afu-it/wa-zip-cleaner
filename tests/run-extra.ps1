# Extra coverage: hash matching, loaded fake rime.dll, ardrv/OPSWAT, ManageEngine,
# locked files, and the double-click .bat launchers. Harmless stand-ins only.
$ErrorActionPreference = 'Continue'
$root = Split-Path -Parent $PSScriptRoot
$tool = Join-Path $root 'wa-zip-cleaner.ps1'
$q = 'C:\WAZipQuarantineExtra'
$fail = 0
$env:WAZIP_NO_PROMPT = '1'
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
$lock = "`$f=[IO.File]::Open('$locked','Open','Read','None'); Start-Sleep 900"
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
$srv = Start-Encoded "`$l=[Net.Sockets.TcpListener]::new([Net.IPAddress]::Parse('127.77.0.1'),47123); `$l.Start(); `$c=`$l.AcceptTcpClient(); Start-Sleep 900"
Start-Sleep 2
$cli = Start-Encoded "`$t=[Net.Sockets.TcpClient]::new(); `$t.Connect('127.77.0.1',47123); Start-Sleep 900"
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

Write-Host '=== Scan ===' -ForegroundColor Cyan
$r = Scan "$env:TEMP\x1.json"
if ($defOk) {
  Check (Has $r 'DefExcl' 'HIGH' 'QtsUpdater\.exe$') 'Defender process exclusion is HIGH'
  Check (Has $r 'DefExcl' 'HIGH' 'Microsoft\\Update$') 'Defender exclusion of fake Microsoft\Update folder is HIGH'
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
Check (Has $r 'Info' 'WARN' 'Blocklist is OFF') 'driver blocklist switched off is WARN'

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
& sc.exe query WazLolMal | Out-Null; Check ($LASTEXITCODE -ne 0) 'malicious driver service deleted'
Check (-not (Test-Path "$drvDir\wazlolm.sys")) 'malicious driver file quarantined'
& sc.exe query WazLolVuln | Out-Null; Check ($LASTEXITCODE -eq 0) 'vulnerable driver left for the user to decide'
if ($defOk) {
  $mp = Get-MpPreference
  Check (-not (@($mp.ExclusionProcess) -contains 'QtsUpdater.exe')) 'Defender process exclusion removed'
  Check (-not (@($mp.ExclusionPath) -contains $stageDir)) 'Defender folder exclusion removed'
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

Write-Host '=== .bat launchers ===' -ForegroundColor Cyan
# Clear WARN-only leftovers so a clean result reads BERSIH.
& sc.exe delete MEUemsTest | Out-Null; & sc.exe delete OpswatLegitTest | Out-Null
& sc.exe delete WazLolVuln | Out-Null; & sc.exe delete WazRmmTest | Out-Null
Remove-Item "$drvDir\wazlolv.sys" -Force -ErrorAction SilentlyContinue
Remove-Item Env:\WAZIP_TEST_LOLDRIVERS
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
