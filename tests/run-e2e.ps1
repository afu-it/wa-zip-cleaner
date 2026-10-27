# End-to-end test: clean scan -> plant -> scan -> fix -> rescan -> restore.
# Runs on Windows PowerShell 5.1 as Administrator (GitHub Actions windows runner).
$ErrorActionPreference = 'Continue'
$root = Split-Path -Parent $PSScriptRoot
$tool = Join-Path $root 'wa-zip-cleaner.ps1'
$q = 'C:\WAZipQuarantineTest'
$fail = 0
$env:WAZIP_NO_PROMPT = '1'
function Check($ok, $msg) {
  if ($ok) { Write-Host "PASS $msg" -ForegroundColor Green } else { Write-Host "FAIL $msg" -ForegroundColor Red; $script:fail++ }
}
function Scan($report, [switch]$Fix) {
  if ($Fix) { & powershell -NoProfile -ExecutionPolicy Bypass -File $tool -QuarantineRoot $q -ReportPath $report -Fix | Out-Host }
  else      { & powershell -NoProfile -ExecutionPolicy Bypass -File $tool -QuarantineRoot $q -ReportPath $report | Out-Host }
  $code = $LASTEXITCODE
  $items = @()
  # PS 5.1 emits a JSON array as one pipeline object; assign first, then unroll.
  if (Test-Path $report) { $parsed = Get-Content -Raw $report | ConvertFrom-Json; $items = @($parsed | ForEach-Object { $_ }) }
  @{ Code = $code; High = @($items | Where-Object Severity -eq 'HIGH'); All = $items }
}

Write-Host '=== 1. Clean machine ===' -ForegroundColor Cyan
$r = Scan "$env:TEMP\r1.json"
Check ($r.High.Count -eq 0) "clean machine has no HIGH findings (got $($r.High.Count): $(($r.High | ForEach-Object Target) -join '; '))"

Write-Host '=== 2. Plant simulated infection ===' -ForegroundColor Cyan
& powershell -NoProfile -ExecutionPolicy Bypass -File (Join-Path $PSScriptRoot 'simulate-infection.ps1') | Out-Host
Start-Sleep 3

Write-Host '=== 3. Scan infected ===' -ForegroundColor Cyan
$r = Scan "$env:TEMP\r2.json"
Check ($r.Code -eq 1) "exit code 1 on infected machine (got $($r.Code))"
$t = ($r.High | ForEach-Object { "$($_.Kind)|$($_.Target)" }) -join "`n"
$expect = @(
  @('RegKey', 'Console\\0$'), @('RegValue', 'Console\|IpDate$'), @('RegKey', 'IpDates_info$'),
  @('RegValue', 'Run\|WAZipTestRun$'), @('Task', 'WAZipTestTask$'), @('File', 'wazip-test\.bat$'),
  @('Service', '^ZyArk$'), @('File', 'ZyArk\.dat$'), @('File', 'Click here to view10\.6_9999\.zip$'),
  @('File', 'Account Statement\.vbs$'), @('File', 'Work Snapshot\.vbs$'), @('File', 'vcRuntimeMinimum_x86\.exe$'), @('File', 'WAZipTest\\rime\.dll$'),
  @('Process', 'cmd\.exe'), @('Vhd', 'Click here to view10\.6\.vhd$'),
  @('File', 'WAZipTest\\hidserv\.dll$'),
  @('RegValue', 'Console\|Magisk$'), @('RegValue', 'Run\|WinHelperRun$'),
  @('RegValue', 'Run\|MicrosoftUpdate$'), @('Process', 'PDF_C2089'), @('File', 'Update\\PDF_C2089_20260911100446\.exe$'),
  @('File', 'Update\\active_desktop_render_x64\.dll$'), @('File', 'DOC_7748_20260924152821\.zip$'), @('File', 'PDF_C2841_20260911100446\.img$'),
  @('File', 'PDF_FTFWCI_20261009125351\.vhd$'), @('File', '20261019-MYS2026Y1019E51AC\.zip$'), @('File', '20261019\.MYS2026Y1019A7F2E\.zip$'),
  @('File', 'WAZipOct\\eneio64\.dat$'), @('Task', 'WAZipDefTask$'),
  @('File', 'AppData\\Local\\appclient$'), @('RegValue', 'Run\|AppClient$'), @('RegValue', 'Environment\|UserInitMprLogonScript$'),
  @('RegKey', 'Software\\CarEmu$'), @('File', 'nsWAZip\.tmp\\libexpat\.dll$'), @('File', 'DOC-50998906_17774E7A\.lnk$'),
  @('File', 'Startup\\HealthApp-0d97b7\.bat$'), @('File', 'Startup\\Updater\.bat$'), @('File', 'wazsel\\chromedriver\.exe$'), @('File', 'ORCAMENTO_114418\.zip$'),
  @('File', '^C:\\temp\\ChromeWpp$'), @('File', '^C:\\temp\\wppconnect-wa\.js$'), @('File', '^C:\\temp\\chromedriver\.exe$'), @('File', 'Downloads\\Review the file\.exe$'),
  @('WaSession', 'Chrome\\User Data\\Default\\IndexedDB\\https_web\.whatsapp\.com_0'), @('WaSession', 'https\+\+\+web\.whatsapp\.com$')
)
foreach ($e in $expect) {
  $hit = $r.High | Where-Object { $_.Kind -eq $e[0] -and $_.Target -match $e[1] }
  Check ([bool]$hit) "detects $($e[0]) $($e[1])"
}
Check (-not ($r.All | Where-Object { $_.Target -match 'normal-document\.pdf' })) 'ignores normal file'
Check ([bool]($r.All | Where-Object { $_.Kind -eq 'File' -and $_.Severity -eq 'WARN' -and $_.Target -match 'WindowsHelper\.exe$' })) 'detects hidden+system program (WARN)'
Check ([bool]($r.All | Where-Object { $_.Kind -eq 'Service' -and $_.Severity -eq 'WARN' -and $_.Target -match 'WAZipFakeSvc$' })) 'detects interpreter service from user folder (WARN)'
Check ([bool]($r.All | Where-Object { $_.Kind -eq 'Info' -and $_.Target -match 'fetish-friends\.com' })) 'attacker domain in DNS cache (WARN)'
Check ([bool]($r.All | Where-Object { $_.Kind -eq 'Info' -and $_.Target -match 'Selenium PowerShell module' })) 'Selenium module installed by the worm (WARN)'
Write-Host "All findings:`n$t"

Write-Host '=== 4. Fix ===' -ForegroundColor Cyan
$r = Scan "$env:TEMP\r3.json" -Fix
$mf = Get-ChildItem $q -Recurse -Filter manifest.json | Sort-Object LastWriteTime | Select-Object -Last 1
Check ([bool]$mf) 'manifest.json written'
Check (-not (Test-Path 'HKCU:\Console\0')) 'Console\0 removed'
Check (-not (Get-ScheduledTask -TaskName WAZipTestTask -ErrorAction SilentlyContinue)) 'task removed'
Check (-not (Test-Path "$env:USERPROFILE\Downloads\Click here to view10.6_9999.zip")) 'lure zip quarantined'
Check (Test-Path "$env:USERPROFILE\Downloads\normal-document.pdf") 'normal file untouched'
Check (-not (Test-Path "$env:APPDATA\Microsoft\Update\active_desktop_render_x64.dll")) 'KuGou-variant loader quarantined'
$waChrome = "$env:LOCALAPPDATA\Google\Chrome\User Data\Default\IndexedDB\https_web.whatsapp.com_0.indexeddb.leveldb"
Check (-not (Test-Path $waChrome)) 'WhatsApp Web login removed from Chrome'
Check (-not (Test-Path "$env:LOCALAPPDATA\appclient")) 'ABCDoor folder quarantined'
Check (-not (Test-Path 'C:\temp\ChromeWpp')) 'worm copy of Chrome profile quarantined'
Check (-not (Test-Path 'C:\temp\wppconnect-wa.js')) 'wppconnect script quarantined'
Check (-not (Test-Path 'HKCU:\Software\CarEmu')) 'ABCDoor CarEmu key removed'
Check (-not (Get-ItemProperty 'HKCU:\Environment').UserInitMprLogonScript) 'ABCDoor logon script removed'
Check (-not (Test-Path "$env:APPDATA\Mozilla\Firefox\Profiles\wazip.default\storage\default\https+++web.whatsapp.com")) 'WhatsApp Web login removed from Firefox'
Check (-not (Get-CimInstance Win32_Process | Where-Object { $_.CommandLine -match '_vmclientcore@16' })) 'malware-marked process stopped'
& sc.exe query ZyArk | Out-Null
Check ($LASTEXITCODE -ne 0) 'ZyArk service deleted'

Write-Host '=== 5. Rescan after fix ===' -ForegroundColor Cyan
$r = Scan "$env:TEMP\r4.json"
Check ($r.High.Count -eq 0) "no HIGH after fix (left: $(($r.High | ForEach-Object Target) -join '; '))"

Write-Host '=== 6. Restore ===' -ForegroundColor Cyan
& powershell -NoProfile -ExecutionPolicy Bypass -File $tool -Restore -Manifest $mf.FullName | Out-Host
Check (Test-Path 'HKCU:\Console\0') 'Console\0 restored'
Check (Test-Path "$env:USERPROFILE\Downloads\Click here to view10.6_9999.zip") 'lure zip restored'
Check ([bool](Get-ScheduledTask -TaskName WAZipTestTask -ErrorAction SilentlyContinue)) 'task restored'
Check (Test-Path "$waChrome\000003.log") 'WhatsApp Web login restored'

Write-Host ''
if ($fail) { Write-Host "$fail check(s) failed" -ForegroundColor Red; exit 1 }
Write-Host 'ALL CHECKS PASSED' -ForegroundColor Green
exit 0
