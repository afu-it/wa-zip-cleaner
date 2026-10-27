<#
.SYNOPSIS
  WA-ZIP Cleaner: scan and clean Windows PCs infected by the WhatsApp
  "Click here to view" ZIP malware (Winos4.0 / ValleyRAT family).
  Pengimbas & pembersih malware ZIP WhatsApp (keluarga Winos4.0 / ValleyRAT).

.DESCRIPTION
  Default mode only SCANS and changes nothing.
  -Fix      : quarantine what was found (files moved, registry exported first).
  -Restore  : undo a previous -Fix using its manifest.
  -Owner    : Office or Personal. Asked at the start when not given; decides what to do with ManageEngine.

  Mod asal hanya MENGIMBAS, tiada apa diubah.
  -Fix      : kuarantin apa yang dijumpai (fail dialih, registry disalin dulu).
  -Restore  : undur -Fix yang lepas guna manifest.

.EXAMPLE
  powershell -ExecutionPolicy Bypass -File .\wa-zip-cleaner.ps1
  powershell -ExecutionPolicy Bypass -File .\wa-zip-cleaner.ps1 -Fix
  powershell -ExecutionPolicy Bypass -File .\wa-zip-cleaner.ps1 -Restore -Manifest C:\WAZipQuarantine\20261022-2100\manifest.json
#>
[CmdletBinding()]
param(
  [switch]$Fix,
  [switch]$RemoveManageEngine,
  [ValidateSet('Office', 'Personal')][string]$Owner = '',
  [switch]$Restore,
  [string]$Manifest,
  [string]$QuarantineRoot = "$env:SystemDrive\WAZipQuarantine",
  [string]$ReportPath
)

$ErrorActionPreference = 'Continue'
$Version = '1.0.0'

# ---------------------------------------------------------------- IOCs ---
# Known bad files (SHA-256). Sizes let us skip hashing unrelated files.
$KnownBad = @(
  @{ Sha = '550d08c8459ef11e6177309526c0738848d064f7de5c91e0760255fc93159f99'; Size = 3141543;  Name = 'Lure ZIP (Click here to view*.zip)' }
  @{ Sha = '053432539a408652f1104aad3c9c4d72d9e68f530f509aa5c982c75451f71958'; Size = 18919424; Name = 'Lure VHD (Click here to view*.vhd)' }
  @{ Sha = '539b49f6ddfa070d25adbd8cd47c10bbba5cacf5bf27fddfe89d96f0c729b2fb'; Size = 3361792;  Name = 'Winos4.0 stager (fake rime.dll)' }
  @{ Sha = '12b9470634bb7f76419c70ee9a510147cd6bcfce920f2abee5afdd13901b383d'; Size = 6076;     Name = 'Encrypted payload (.dat)' }
  @{ Sha = '46883bc25c77678f60c1b836f4c438d87158c9af6b229f533522f635a0d5276e'; Size = 93664;    Name = 'AV-killer driver ZyArk.sys (Baidu BdArKit, abused)' }
  @{ Sha = 'c1e184615241fe69db3bf4093a22c7c0bf5d6072d2f51e558142b844e871084f'; Size = 5242880;  Name = 'SilverFox loader active_desktop_render_x64.dll (Pelagos, KuGou variant)' }
)
# Signed, legitimate files that this malware abuses. Bad only outside their vendor folder.
$AbusedLegit = @(
  @{ Sha = '1c5129b4d63f2d5252b5b02a0a7d655dac3b6eac23dd4ed92b4dd55f243387ff'; Size = 18248;   Name = 'ardrv.sys (OPSWAT, abused as AV killer)'; Vendor = 'OPSWAT' }
  @{ Sha = 'c74f55247aa2c72001024bd977c869cb5adce6f8604a4d32329f015b73ae2a49'; Size = 1994600; Name = 'KafanInputService.exe (sideload host)';      Vendor = 'Kafan' }
  @{ Sha = 'f712c2a8b4abf2e299a2b480020333deb0f43364e9686cda78b1243c62e4830d'; Size = 102536;  Name = 'KuGou active_desktop_launcher.exe (sideload host)'; Vendor = 'KuGou' }
)
# Test hook: extra IOCs from a JSON file, so CI can exercise hash matching without real malware.
if ($env:WAZIP_TEST_IOCS -and (Test-Path -LiteralPath $env:WAZIP_TEST_IOCS)) {
  $extra = Get-Content -Raw -LiteralPath $env:WAZIP_TEST_IOCS | ConvertFrom-Json
  foreach ($e in @($extra | ForEach-Object { $_ })) {
    $entry = @{ Sha = $e.Sha.ToLower(); Size = [long]$e.Size; Name = $e.Name }
    if ($e.Vendor) { $entry.Vendor = $e.Vendor; $AbusedLegit += $entry } else { $KnownBad += $entry }
  }
}
$PersistRegex ='rime\.dll|_vmclientcore@16|KafanInput|vcRuntimeMinimum_x86\.exe|\\H\d{8,}\.exe|ZyArk|\\ardrv\.sys|\\AppData\\Roaming\\Microsoft\\Update\\[^\\]+\.exe|active_desktop_(launcher|render)|Add-MpPreference|eneio64\.dat|plcc3a\.dat|-m\s+appclient|\\appclient\\python\\'
$LureRegex    = '^(Click here to view.*\.(zip|vhd|vhdx)|Notice.*\.vhdx?|(PDF|DOC)_[A-Z0-9]{3,8}_20\d{12}\.(zip|img|iso|exe|vhd|vhdx)|20\d{6}[.-]MYS20\d{2}Y\d{4}[A-Z0-9]{4,6}\.(zip|img|iso|vhd|vhdx))$'
# Programs the October 2026 wave tells Windows Defender to skip. No real program needs these excluded.
$ExclProcRegex = '(?i)^(QtsUpdater|svchost|rundll32|powershell|cmd|wscript|cscript|mshta|regsvr32|explorer)\.exe$'
# Known attacker servers (C2). A process talking to one of these is the malware.
# Kaspersky (Apr 2026): ValleyRAT and ABCDoor servers from the Silver Fox tax campaign.
$C2Ips = @('134.122.155.135', '108.187.37.85', '108.187.42.63', '207.56.138.28', '45.118.133.203', '154.82.81.205', '154.82.81.192', '108.187.41.221',
            '103.20.195.147', '45.207.231.94', '45.207.231.107', '160.124.9.103', '109.176.30.141')  # last four: CloudSEK, Dec 2025
$C2Domains = '(?i)(^|\.)(fetish-friends\.com|3mkorealtd\.com|sudsmama\.com|woopami\.com|ilptour\.com|petitechanson\.com|doublemobile\.com|mcagov\.cc|roldco\.com|kcii2\.com|haijing88\.com|ggwk\.cc|yuxuanow\.top|itdd\.club|xzghjec\.com|gov-a\.(work|fit|club)|gvo-b\.club|gov-c\.club|govk\.club|swjc2025bjkb\.cn|2025swmm\.cn|zapgrande\.com)$'
# Silver Fox fake-document programs (Kaspersky, Apr 2026: Statement of Account / GST / tax lures).
$ExeLureRegex = '(?i)^(Review the file|BillReceipt|statement verify ?|Click File|GST ?Suvidha|Related material|MCA-Ministry|RemoteInstaller_[\d_]+_\w+)\.exe$'
if ($env:WAZIP_TEST_C2) { $C2Ips += $env:WAZIP_TEST_C2 }
# SilverFox KuGou variant (Pelagos Intel, Sep 2026) stages here and runs from a Run value named MicrosoftUpdate.
$StageRegex   = '(?i)\\AppData\\Roaming\\Microsoft\\Update\\[^\\]+\.(exe|dll)$'
# Remote-control programs (names from LOLRMM, lolrmm.io). Fine when you or your IT installed them;
# scammers and RAT crews also use them to control a PC.
$RmmTools = [ordered]@{
  'AnyDesk' = '^anydesk'; 'TeamViewer' = '^teamviewer'; 'RustDesk' = '^rustdesk'; 'HopToDesk' = '^hoptodesk'
  'ToDesk' = '^todesk'; 'SunLogin (Oray)' = '^(sunlogin|orayremote)'; 'GotoHTTP' = '^gotohttp'; 'UltraViewer' = '^ultraviewer'
  'ScreenConnect / ConnectWise' = '^screenconnect\.'; 'Splashtop' = '^(splashtop|strwinclt|srserver|srmanager|sragent)'
  'SimpleHelp' = '^(simplehelpcustomer|simpleservice)'; 'Atera' = '^ateraagent'; 'MeshCentral' = '^meshagent'
  'Tactical RMM' = '^tacticalrmm'; 'Remote Utilities' = '^rut(serv|view)'; 'Ammyy Admin' = '^ammyy'; 'AeroAdmin' = '^aeroadmin'
  'Supremo' = '^supremo'; 'Zoho Assist' = '^(zaservice|zmagent)'; 'NetSupport' = '\\netsupport\\'; 'Action1' = '\\windows\\action1\\'
}
# Browsers whose profiles we check. Chromium ones keep profiles under User Data; Opera keeps one in its own folder.
$BrowserRoots = @(
  @{ Name = 'Chrome'; Dir = 'AppData\Local\Google\Chrome\User Data'; Proc = 'chrome'; Policy = 'Google\Chrome' }
  @{ Name = 'Edge'; Dir = 'AppData\Local\Microsoft\Edge\User Data'; Proc = 'msedge'; Policy = 'Microsoft\Edge' }
  @{ Name = 'Brave'; Dir = 'AppData\Local\BraveSoftware\Brave-Browser\User Data'; Proc = 'brave'; Policy = 'BraveSoftware\Brave' }
  @{ Name = 'Opera'; Dir = 'AppData\Roaming\Opera Software\Opera Stable'; Proc = 'opera'; Policy = $null }
)
$VbsLureRegex = '(?i)(Account Statement|Debt Statement|Financial Report|Penyata|Invoice|Invois|Payment|Work Snapshot|Salary|Gaji|Claim|Tuntutan|LHDN|KWSP|EPF).*\.(vbs|vbe|js|wsf)$'

# ------------------------------------------------------------- helpers ---
function Say([string]$ms, [string]$en, [string]$color = 'Gray') {
  Write-Host "$ms" -ForegroundColor $color
  Write-Host "  ($en)" -ForegroundColor DarkGray
}

$Findings = New-Object System.Collections.Generic.List[object]
function Add-Finding($Kind, $Severity, $Target, $Detail, $Extra = $null) {
  $key = "$Kind|$Target"
  if ($Findings | Where-Object { "$($_.Kind)|$($_.Target)" -eq $key }) { return }
  $Findings.Add([pscustomobject]@{ Kind = $Kind; Severity = $Severity; Target = $Target; Detail = $Detail; Extra = $Extra })
}

function Test-Admin {
  $id = [Security.Principal.WindowsIdentity]::GetCurrent()
  (New-Object Security.Principal.WindowsPrincipal $id).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)
}

$SizeIndex = @{}
foreach ($k in $KnownBad + $AbusedLegit) { $SizeIndex[[long]$k.Size] = $true }

function Get-Ioc([System.IO.FileInfo]$f) {
  if (-not $SizeIndex.ContainsKey([long]$f.Length)) { return $null }
  $h = (Get-FileHash -LiteralPath $f.FullName -Algorithm SHA256 -ErrorAction SilentlyContinue).Hash
  if (-not $h) { return $null }
  $h = $h.ToLower()
  foreach ($k in $KnownBad)    { if ($k.Sha -eq $h) { return @{ Bad = $true;  Name = $k.Name } } }
  foreach ($k in $AbusedLegit) { if ($k.Sha -eq $h) { return @{ Bad = $false; Name = $k.Name; Vendor = $k.Vendor } } }
  $null
}

function Get-UserHives {
  Get-ChildItem Registry::HKEY_USERS -ErrorAction SilentlyContinue |
    Where-Object { $_.PSChildName -match '^S-1-5-21-[\d-]+$' } |
    ForEach-Object { "Registry::HKEY_USERS\$($_.PSChildName)" }
}

# Service ImagePath (\??\C:\..., \SystemRoot\..., System32\...) to a plain file path.
function Resolve-ImagePath([string]$img) {
  $img = $img.Trim().Trim('"')
  ($img -replace '^\\\?\?\\', '' -replace '^\\SystemRoot', $env:SystemRoot -replace '^System32', "$env:SystemRoot\System32").Trim('"')
}

# Vulnerable and malicious Windows drivers from LOLDrivers (loldrivers.io). Refresh with tools/update-loldrivers.py.
function Get-LolDrivers {
  $src = if ($env:WAZIP_TEST_LOLDRIVERS) { $env:WAZIP_TEST_LOLDRIVERS } else { Join-Path $PSScriptRoot 'data\loldrivers.csv' }
  if (-not (Test-Path -LiteralPath $src)) {
    $src = Join-Path $env:TEMP 'wazip-loldrivers.csv'
    try {
      [Net.ServicePointManager]::SecurityProtocol = [Net.ServicePointManager]::SecurityProtocol -bor [Net.SecurityProtocolType]::Tls12
      Invoke-WebRequest -UseBasicParsing -TimeoutSec 30 -Uri 'https://raw.githubusercontent.com/afu-it/wa-zip-cleaner/main/data/loldrivers.csv' -OutFile $src -ErrorAction Stop
    } catch { return $null }
  }
  $idx = @{}
  foreach ($row in Import-Csv -LiteralPath $src) { $idx[$row.sha256.ToLower()] = $row }
  $idx
}

function Get-LolMatch([string]$path) {
  if (-not $LolDrivers -or -not $path -or -not (Test-Path -LiteralPath $path -PathType Leaf)) { return $null }
  $h = (Get-FileHash -LiteralPath $path -Algorithm SHA256 -ErrorAction SilentlyContinue).Hash
  if ($h) { $LolDrivers[$h.ToLower()] }
}

function ConvertTo-RegExePath([string]$psPath) {
  $p = $psPath -replace '^Registry::', '' -replace '^Microsoft\.PowerShell\.Core\\Registry::', ''
  $p = $p -replace '^HKEY_USERS', 'HKU' -replace '^HKEY_LOCAL_MACHINE', 'HKLM' -replace '^HKEY_CURRENT_USER', 'HKCU'
  $p -replace '^HKLM:', 'HKLM' -replace '^HKCU:', 'HKCU'
}

# --------------------------------------------------------------- scans ---
function Scan-Registry {
  Say '[1/8] Semak registry (tempat malware sorok muatan)...' '[1/8] Checking registry (where the payload hides)...' Cyan
  foreach ($hive in Get-UserHives) {
    foreach ($sub in '0', '1') {
      $k = "$hive\Console\$sub"
      if (Test-Path -LiteralPath $k) {
        $item = Get-Item -LiteralPath $k
        $sizes = foreach ($n in $item.GetValueNames()) {
          $v = $item.GetValue($n); if ($v -is [byte[]]) { $v.Length } }
        $big = @($sizes | Where-Object { $_ -gt 1024 }).Count
        # A 32-hex value name under Console is a strong Winos4.0 marker, whatever the blob size.
        $hex32 = [bool]($item.GetValueNames() | Where-Object { $_ -match '^[0-9a-fA-F]{32}$' })
        $sev = if ($big -gt 0 -or $hex32) { 'HIGH' } else { 'WARN' }
        $why = if ($hex32) { "32-hex value name + $big blob(s) > 1 KB" } else { "$big binary blob(s) > 1 KB" }
        Add-Finding 'RegKey' $sev $k "Console\$sub key ($why). Winos4.0 stores its module here."
      }
    }
    $c = "$hive\Console"
    if (Test-Path -LiteralPath $c) {
      $cnames = (Get-Item -LiteralPath $c).GetValueNames()
      foreach ($marker in 'IpDate', 'IpDates_sun', 'Magisk', 'FaCai2024') {
        if ($cnames -contains $marker) { Add-Finding 'RegValue' 'HIGH' "$c|$marker" "Winos4.0 C2/config marker (Console\$marker)." }
      }
    }
    foreach ($k in "$hive\Software\IpDates_info", "$hive\Software\IpDates_sun", "$hive\Software\Magisk", "$hive\Software\FaCai2024") {
      if (Test-Path -LiteralPath $k) { Add-Finding 'RegKey' 'HIGH' $k "Winos4.0 config marker ($(Split-Path $k -Leaf))." }
    }
  }
  foreach ($k in 'HKLM:\SOFTWARE\IpDates_info', 'HKLM:\SOFTWARE\WOW6432Node\IpDates_info') {
    if (Test-Path -LiteralPath $k) { Add-Finding 'RegKey' 'HIGH' $k 'Winos4.0 final-stage config (IpDates_info).' }
  }
}

function Scan-Services {
  Say '[2/8] Semak driver & servis (pembunuh antivirus)...' '[2/8] Checking drivers & services (antivirus killers)...' Cyan
  $root = 'HKLM:\SYSTEM\CurrentControlSet\Services'
  foreach ($svc in Get-ChildItem $root -ErrorAction SilentlyContinue) {
    $p = Get-ItemProperty -LiteralPath $svc.PSPath -ErrorAction SilentlyContinue
    $img = [string]$p.ImagePath
    $name = $svc.PSChildName
    $hit = $null
    if ($name -match '^(ZyArk|ZyArkFilter)$' -or $img -match 'zyark') { $hit = 'ZyArk driver (abused Baidu anti-rootkit, kills antivirus).' }
    elseif (($name -eq 'ardrv' -or $img -match '\\ardrv\.sys') -and $img -notmatch 'OPSWAT') { $hit = 'ardrv.sys outside OPSWAT folder (abused to kill antivirus).' }
    elseif ($img -match $PersistRegex -and $img -notmatch 'OPSWAT') { $hit = "Service points at malware path: $img" }
    if ($hit) { Add-Finding 'Service' 'HIGH' $name $hit @{ RegPath = $svc.PSPath; Image = $img } }
    # A service that launches a script interpreter from a user-writable folder is a common persistence trick.
    elseif ($img -match '(?i)\b(cmd|powershell|pwsh|wscript|cscript|mshta|rundll32)\b' -and
            $img -match '(?i)\\(Users|ProgramData|AppData|Temp|Public)\\') {
      Add-Finding 'Service' 'WARN' $name "Service runs a script interpreter from a user folder: $img" @{ RegPath = $svc.PSPath; Image = $img }
    }
    elseif ($p.Type -in 1, 2 -and ($lol = Get-LolMatch (Resolve-ImagePath $img))) {
      if ($lol.kind -eq 'malicious') {
        Add-Finding 'Service' 'HIGH' $name "Malicious driver listed by LOLDrivers: $($lol.name)" @{ RegPath = $svc.PSPath; Image = $img }
      } else {
        Add-Finding 'Service' 'WARN' $name "Known-vulnerable driver ($($lol.name), LOLDrivers). Attackers load drivers like this to switch off antivirus. If you do not know which program installed it, uninstall that program." @{ RegPath = $svc.PSPath; Image = $img }
      }
    }
  }
  # Microsoft's blocklist stops known-bad drivers from loading. Malware or tweak tools may switch it off.
  $ci = Get-ItemProperty -LiteralPath 'HKLM:\SYSTEM\CurrentControlSet\Control\CI\Config' -ErrorAction SilentlyContinue
  if ($ci -and $null -ne $ci.VulnerableDriverBlocklistEnable -and $ci.VulnerableDriverBlocklistEnable -eq 0) {
    Add-Finding 'Info' 'WARN' 'Microsoft Vulnerable Driver Blocklist is OFF' 'Turn it on: Windows Security > Device security > Core isolation details > Microsoft Vulnerable Driver Blocklist, then restart.'
  }
  $drv = Join-Path $env:SystemRoot 'System32\drivers\ZyArk.dat'
  if (Test-Path -LiteralPath $drv) { Add-Finding 'File' 'HIGH' $drv 'ZyArk driver data file.' }
}

function Scan-Processes {
  Say '[3/8] Semak program yang sedang berjalan...' '[3/8] Checking running programs...' Cyan
  foreach ($p in Get-CimInstance Win32_Process -ErrorAction SilentlyContinue) {
    $cl = [string]$p.CommandLine; $exe = [string]$p.ExecutablePath
    if ($cl -match '_vmclientcore@16' -or $cl -match '(?i)-m\s+appclient\b' -or $p.Name -eq 'KafanInputService.exe' -or $exe -match '\\H\d{8,}\.exe$' -or $exe -match $StageRegex) {
      Add-Finding 'Process' 'HIGH' "$($p.Name) (PID $($p.ProcessId))" "Malware process: $cl" @{ Pid = $p.ProcessId; Path = $exe }
    }
  }
  foreach ($c in Get-NetTCPConnection -ErrorAction SilentlyContinue | Where-Object { $C2Ips -contains $_.RemoteAddress }) {
    $pp = Get-Process -Id $c.OwningProcess -ErrorAction SilentlyContinue
    Add-Finding 'Process' 'HIGH' "$($pp.ProcessName) (PID $($c.OwningProcess))" "Connected to known attacker server $($c.RemoteAddress):$($c.RemotePort)" @{ Pid = $c.OwningProcess; Path = $pp.Path }
  }
  # The DNS cache shows which servers this PC looked up recently.
  foreach ($d in Get-DnsClientCache -ErrorAction SilentlyContinue | Where-Object { $_.Entry -match $C2Domains } | Select-Object -ExpandProperty Entry -Unique) {
    Add-Finding 'Info' 'WARN' "Attacker server looked up: $d" 'This PC contacted a Silver Fox server recently (Kaspersky list). Treat the PC as infected: change passwords from your phone and consider reinstalling Windows.'
  }
  foreach ($proc in Get-Process -ErrorAction SilentlyContinue) {
    try { $mods = $proc.Modules } catch { continue }
    foreach ($m in $mods) {
      if ($m.ModuleName -ieq 'rime.dll' -and $m.FileName -notmatch '\\Program Files( \(x86\))?\\') {
        Add-Finding 'Process' 'HIGH' "$($proc.ProcessName) (PID $($proc.Id))" "Loaded fake rime.dll from $($m.FileName)" @{ Pid = $proc.Id; Path = $m.FileName }
      }
    }
  }
}

function Scan-Persistence {
  Say '[4/8] Semak program yang auto-jalan bila PC hidup...' '[4/8] Checking auto-start entries...' Cyan
  $runKeys = @('HKLM:\Software\Microsoft\Windows\CurrentVersion\Run', 'HKLM:\Software\Microsoft\Windows\CurrentVersion\RunOnce',
               'HKLM:\Software\WOW6432Node\Microsoft\Windows\CurrentVersion\Run', 'HKLM:\Software\WOW6432Node\Microsoft\Windows\CurrentVersion\RunOnce')
  foreach ($hive in Get-UserHives) {
    $runKeys += "$hive\Software\Microsoft\Windows\CurrentVersion\Run", "$hive\Software\Microsoft\Windows\CurrentVersion\RunOnce"
  }
  foreach ($k in $runKeys) {
    if (-not (Test-Path -LiteralPath $k)) { continue }
    $item = Get-Item -LiteralPath $k
    foreach ($n in $item.GetValueNames()) {
      $v = [string]$item.GetValue($n)
      if ($v -match $PersistRegex) { Add-Finding 'RegValue' 'HIGH' "$k|$n" "Auto-start: $v"; continue }
      # A Run entry whose target file is Hidden+System is a strong sign, even with an unknown name.
      $target = if ($v -match '"([^"]+\.(exe|dll|bat|cmd|scr))"') { $Matches[1] }
                elseif ($v -match '([A-Za-z]:\\[^"]+?\.(exe|dll|bat|cmd|scr))') { $Matches[1] } else { $null }
      if ($target -and (Test-Path -LiteralPath $target)) {
        $a = (Get-Item -LiteralPath $target -Force -ErrorAction SilentlyContinue).Attributes
        if (($a -band [IO.FileAttributes]::Hidden) -and ($a -band [IO.FileAttributes]::System)) {
          Add-Finding 'RegValue' 'HIGH' "$k|$n" "Auto-start points at a Hidden+System file: $target"
        }
      }
    }
  }
  foreach ($t in Get-ScheduledTask -ErrorAction SilentlyContinue) {
    $txt = ($t.Actions | ForEach-Object { "$($_.Execute) $($_.Arguments)" }) -join ' ; '
    if ($txt -match $PersistRegex) { Add-Finding 'Task' 'HIGH' "$($t.TaskPath)$($t.TaskName)" "Scheduled task: $txt" @{ Path = $t.TaskPath; Name = $t.TaskName } }
  }
  # CloudSEK (Dec 2025): the loader switches off Windows Update so the PC stops getting fixes.
  if ((Get-ItemProperty -LiteralPath 'HKLM:\SYSTEM\CurrentControlSet\Services\wuauserv' -ErrorAction SilentlyContinue).Start -eq 4) {
    Add-Finding 'Info' 'WARN' 'Windows Update is disabled' 'Silver Fox switches off Windows Update. Unless you did this yourself, turn it back on: services.msc > Windows Update > Startup type Manual.'
  }
  # ABCDoor (Kaspersky, Apr 2026) runs at logon through UserInitMprLogonScript and keeps settings in Software\CarEmu.
  foreach ($hive in Get-UserHives) {
    $logon = [string](Get-ItemProperty -LiteralPath "$hive\Environment" -ErrorAction SilentlyContinue).UserInitMprLogonScript
    if ($logon) {
      $sev = if ($logon -match $PersistRegex) { 'HIGH' } else { 'WARN' }
      Add-Finding 'RegValue' $sev "$hive\Environment|UserInitMprLogonScript" "Logon script runs at every sign-in: $logon"
    }
    if (Test-Path -LiteralPath "$hive\Software\CarEmu") { Add-Finding 'RegKey' 'HIGH' "$hive\Software\CarEmu" 'ABCDoor backdoor settings (Silver Fox).' }
  }
  foreach ($u in Get-ChildItem "$env:SystemDrive\Users" -Directory -ErrorAction SilentlyContinue) {
    $ac = Join-Path $u.FullName 'AppData\Local\appclient'
    if ((Test-Path -LiteralPath "$ac\python\pythonw.exe") -or (Test-Path -LiteralPath "$ac\update.bat")) {
      Add-Finding 'File' 'HIGH' $ac 'ABCDoor backdoor folder (Python remote-control malware, Silver Fox).'
    }
    $el = Join-Path $u.FullName 'AppData\Local\applogs\exception_logs.zip'
    if (Test-Path -LiteralPath $el) { Add-Finding 'File' 'HIGH' $el 'ABCDoor error log.' }
  }
  Scan-DefenderExclusions
  $startups = @("$env:ProgramData\Microsoft\Windows\Start Menu\Programs\StartUp")
  $startups += Get-ChildItem "$env:SystemDrive\Users" -Directory -ErrorAction SilentlyContinue |
    ForEach-Object { Join-Path $_.FullName 'AppData\Roaming\Microsoft\Windows\Start Menu\Programs\Startup' }
  foreach ($s in $startups) {
    Get-ChildItem -LiteralPath $s -File -ErrorAction SilentlyContinue | ForEach-Object {
      $body = ''
      if ($_.Extension -match '\.(bat|cmd|vbs|js|ps1|lnk)$') { $body = [IO.File]::ReadAllText($_.FullName) -replace "`0", '' }
      if ("$($_.Name) $body" -match $PersistRegex) { Add-Finding 'File' 'HIGH' $_.FullName 'Startup folder entry pointing at malware.' }
    }
  }
}

# The malware tells Windows Defender to ignore svchost.exe/QtsUpdater.exe, so antivirus scans come back clean.
function Scan-DefenderExclusions {
  $policy = @{}
  foreach ($kind in 'Processes', 'Paths') {
    $k = "HKLM:\SOFTWARE\Policies\Microsoft\Windows Defender\Exclusions\$kind"
    if (-not (Test-Path -LiteralPath $k)) { continue }
    foreach ($n in (Get-Item -LiteralPath $k).GetValueNames()) {
      $policy[$n] = $true
      $bad = if ($kind -eq 'Processes') { (Split-Path $n -Leaf) -match $ExclProcRegex -or $n -match $PersistRegex } else { $n -match '(?i)\\AppData\\Roaming\\Microsoft\\Update' -or $n -match $PersistRegex }
      if ($bad) { Add-Finding 'RegValue' 'HIGH' "$k|$n" 'Windows Defender policy told to ignore this (malware hiding from antivirus).' }
    }
  }
  $mp = try { Get-MpPreference -ErrorAction Stop } catch { $null }
  if (-not $mp) { return }
  foreach ($v in @($mp.ExclusionProcess) | Where-Object { $_ -and -not $policy[$_] }) {
    if ((Split-Path $v -Leaf) -match $ExclProcRegex -or $v -match $PersistRegex) {
      Add-Finding 'DefExcl' 'HIGH' "Process|$v" 'Windows Defender told to ignore this program (malware hiding from antivirus).' @{ Type = 'Process'; Value = $v }
    }
  }
  foreach ($v in @($mp.ExclusionPath) | Where-Object { $_ -and -not $policy[$_] }) {
    if ($v -match '(?i)\\AppData\\Roaming\\Microsoft\\Update' -or $v -match $PersistRegex) {
      Add-Finding 'DefExcl' 'HIGH' "Path|$v" 'Windows Defender told to ignore this folder (malware hiding from antivirus).' @{ Type = 'Path'; Value = $v }
    } elseif ($v -match '(?i)^[a-z]:\\Users\\|%(APPDATA|LOCALAPPDATA|TEMP|USERPROFILE)%') {
      Add-Finding 'DefExcl' 'WARN' "Path|$v" 'Windows Defender skips this user folder. Remove the exclusion unless you added it yourself.' @{ Type = 'Path'; Value = $v }
    }
  }
}

function Scan-Files {
  Say '[5/8] Imbas fail (boleh ambil 2-10 minit)...' '[5/8] Scanning files (can take 2-10 minutes)...' Cyan
  $roots = @("$env:ProgramData", "$env:SystemDrive\Users\Public", "$env:SystemRoot\Temp")
  foreach ($u in Get-ChildItem "$env:SystemDrive\Users" -Directory -ErrorAction SilentlyContinue) {
    $roots += 'Downloads', 'Desktop', 'Documents', 'AppData\Roaming', 'AppData\Local\Temp', 'AppData\Local\Packages' |
      ForEach-Object { Join-Path $u.FullName $_ }
  }
  $exts = '\.(zip|vhd|vhdx|img|iso|dll|exe|dat|sys|tar|vbs|vbe|js|wsf|lnk)$'
  $wsh = New-Object -ComObject WScript.Shell
  foreach ($r in $roots | Where-Object { Test-Path -LiteralPath $_ }) {
    Get-ChildItem -LiteralPath $r -Recurse -File -Force -ErrorAction SilentlyContinue |
      Where-Object { $_.Name -match $exts } | ForEach-Object {
        $f = $_
        $ioc = Get-Ioc $f
        if ($ioc -and $ioc.Bad) { Add-Finding 'File' 'HIGH' $f.FullName "Known malware: $($ioc.Name)"; return }
        if ($ioc -and -not $ioc.Bad -and $f.FullName -notmatch [regex]::Escape($ioc.Vendor)) {
          Add-Finding 'File' 'HIGH' $f.FullName "Legit file abused by malware, in wrong place: $($ioc.Name)"; return }
        # SORVEPOTEL (Trend Micro, Oct 2025): a shortcut named like a document that runs hidden
        # cmd/PowerShell to download the next stage.
        if ($f.Extension -ieq '.lnk') {
          $l = try { $wsh.CreateShortcut($f.FullName) } catch { $null }
          if ($l -and $l.TargetPath -match '(?i)\\(cmd|powershell|pwsh|mshta|wscript|cscript)\.exe$' -and
              $l.Arguments -match '(?i)(-e(nc|ncodedcommand)?\s+[A-Za-z0-9+/=]{20,}|for\s+%\w+\s+in|DownloadString|\bIEX\b|https?://)') {
            Add-Finding 'File' 'HIGH' $f.FullName "Shortcut disguised as a document runs hidden commands (SORVEPOTEL WhatsApp worm): $(Split-Path $l.TargetPath -Leaf) $($l.Arguments.Substring(0, [Math]::Min(80, $l.Arguments.Length)))"
          }
          return
        }
        if ($f.Name -match $LureRegex) { Add-Finding 'File' 'HIGH' $f.FullName 'WhatsApp lure file name.'; return }
        if ($f.FullName -match $StageRegex -or $f.Name -ieq 'active_desktop_render_x64.dll') {
          Add-Finding 'File' 'HIGH' $f.FullName 'SilverFox loader staged in a fake Microsoft\Update folder (KuGou variant).'; return }
        if ($f.Name -match '(?i)\.vhdx?$' -and $f.Name -ine 'ext4.vhdx' -and
            $f.FullName -match '(?i)^[a-z]:\\Users\\' -and
            $f.FullName -notmatch '(?i)\\AppData\\Local\\(Docker\\|Packages\\(?!5319275A\.WhatsAppDesktop))') {
          Add-Finding 'File' 'WARN' $f.FullName 'Virtual disk (VHD) in a user folder. The WhatsApp ZIP hides its payload in a VHD; delete it unless you made it.'; return }
        # CloudSEK (Dec 2025): signed Xunlei Thunder.exe dropped next to a fake libexpat.dll.
        if ($f.Name -ieq 'libexpat.dll' -and $f.DirectoryName -notmatch '\\Program Files( \(x86\))?\\' -and
            (Test-Path -LiteralPath (Join-Path $f.DirectoryName 'Thunder.exe'))) {
          Add-Finding 'File' 'HIGH' $f.FullName 'Fake libexpat.dll next to Thunder.exe (DLL sideloading, Silver Fox).'; return }
        if ($f.Name -ieq 'wppconnect-wa.js') { Add-Finding 'File' 'HIGH' $f.FullName 'WhatsApp automation script the worm uses to message all your contacts.'; return }
        if ($f.Name -match $ExeLureRegex) { Add-Finding 'File' 'HIGH' $f.FullName 'Fake document program (Silver Fox tax/statement lure).'; return }
        if ($f.Name -match $VbsLureRegex) { Add-Finding 'File' 'HIGH' $f.FullName 'Script disguised as a document (WhatsApp VBS campaign).'; return }
        if ($f.Extension -ieq '.sys' -and ($lol = Get-LolMatch $f.FullName)) {
          $sev = if ($lol.kind -eq 'malicious') { 'HIGH' } else { 'WARN' }
          Add-Finding 'File' $sev $f.FullName "Driver listed by LOLDrivers ($($lol.kind)): $($lol.name). Attackers use these to switch off antivirus."; return }
        if ($f.Name -match '(?i)^(eneio64|plcc3a)\.dat$') { Add-Finding 'File' 'HIGH' $f.FullName 'Encrypted payload from the October 2026 WhatsApp ZIP wave.'; return }
        if ($f.Name -match '^dd_vcredist_x86_.*_vcRuntimeMinimum_x86\.exe$') { Add-Finding 'File' 'HIGH' $f.FullName 'Fake Visual C++ installer (Winos4.0 next stage).'; return }
        if ($f.Name -ieq 'rime.dll' -and $f.DirectoryName -notmatch '\\Program Files( \(x86\))?\\') {
          $sev = if (Get-ChildItem -LiteralPath $f.DirectoryName -Filter *.exe -ErrorAction SilentlyContinue | Where-Object { $_.Name -match '^(KafanInputService|H\d{8,})\.exe$' }) { 'HIGH' } else { 'WARN' }
          Add-Finding 'File' $sev $f.FullName 'rime.dll outside Program Files (DLL sideloading).'
        }
        if ($f.Name -ieq 'hidserv.dll' -and $f.DirectoryName -notmatch '(?i)\\Windows\\(System32|SysWOW64|WinSxS)(\\|$)') {
          Add-Finding 'File' 'HIGH' $f.FullName 'hidserv.dll outside System32 (fake HID service for persistence).'; return }
        if ($f.Name -match '(?i)\.(exe|dll|sys)$' -and
            ($f.Attributes -band [IO.FileAttributes]::Hidden) -and ($f.Attributes -band [IO.FileAttributes]::System)) {
          Add-Finding 'File' 'WARN' $f.FullName 'Hidden+System program in a user folder (common Winos4.0 hiding trick).'; return }
      }
  }
}

function Scan-Vhd {
  Say '[6/8] Semak cakera maya (VHD) yang sedang dibuka...' '[6/8] Checking mounted virtual disks (VHD)...' Cyan
  foreach ($d in Get-Disk -ErrorAction SilentlyContinue | Where-Object { $_.BusType -eq 'File Backed Virtual' }) {
    $loc = [string]$d.Location
    $sev = if ((Split-Path $loc -Leaf) -match $LureRegex) { 'HIGH' } else { 'WARN' }
    Add-Finding 'Vhd' $sev $loc 'Mounted virtual disk. The WhatsApp ZIP opens as a VHD drive.'
  }
}

function Scan-ManageEngine {
  Say '[7/8] Semak program kawalan jauh (ManageEngine, AnyDesk, dll)...' '[7/8] Checking remote-control programs (ManageEngine, AnyDesk, etc.)...' Cyan
  Scan-Rmm
  $hits = @()
  $hits += Get-Service -ErrorAction SilentlyContinue | Where-Object { $_.DisplayName -match 'ManageEngine|UEMS' }
  foreach ($p in "${env:ProgramFiles(x86)}\ManageEngine\UEMS_Agent", "$env:ProgramFiles\ManageEngine\UEMS_Agent") {
    if (Test-Path -LiteralPath $p) { $hits += $p }
  }
  if ($hits.Count) {
    $d = switch ($Owner) {
      'Office'   { 'Remote-management agent found. Company IT often installs it; ask your IT team to confirm. This tool leaves it alone on an office PC.' }
      'Personal' { 'Remote-management agent on a personal PC: the WhatsApp VBS campaign uses it to control PCs remotely. This tool will force-remove it.' }
      default    { 'Remote-management agent found. If your company did NOT install it, the WhatsApp VBS campaign gave attackers remote control. Its normal uninstaller asks for the attacker''s PIN.' }
    }
    Add-Finding 'Info' 'WARN' 'ManageEngine UEMS Agent' $d
  }
}

function Scan-Rmm {
  $paths = @(Get-CimInstance Win32_Process -ErrorAction SilentlyContinue | ForEach-Object { [string]$_.ExecutablePath })
  $paths += Get-CimInstance Win32_Service -ErrorAction SilentlyContinue | ForEach-Object {
    $pn = [string]$_.PathName
    if ($pn -match '^"([^"]+)"') { $Matches[1] } elseif ($pn -match '^(\S+\.exe)') { $Matches[1] } else { $pn } }
  foreach ($tool in $RmmTools.Keys) {
    $hit = $paths | Where-Object { $_ -and (($_ -split '\\')[-1] -match $RmmTools[$tool] -or $_ -match $RmmTools[$tool]) } | Select-Object -First 1
    if (-not $hit) { continue }
    $d = if ($Owner -eq 'Office') { "Remote-control program ($hit). Ask your IT team if they installed it." }
         else { "Remote-control program ($hit). Fine if you installed it yourself. If not, someone may be controlling this PC: uninstall it (Bulk Crap Uninstaller can force-remove it) and change your passwords from your phone." }
    Add-Finding 'Info' 'WARN' "Remote-control program: $tool" $d
  }
}

function Get-BrowserProfiles {
  foreach ($u in Get-ChildItem "$env:SystemDrive\Users" -Directory -ErrorAction SilentlyContinue) {
    foreach ($b in $BrowserRoots) {
      $ud = Join-Path $u.FullName $b.Dir
      if (-not (Test-Path -LiteralPath $ud)) { continue }
      $dirs = @(Get-ChildItem -LiteralPath $ud -Directory -ErrorAction SilentlyContinue | Where-Object { $_.Name -match '^(Default|Profile \d+)$' })
      if (Test-Path -LiteralPath (Join-Path $ud 'Preferences')) { $dirs += Get-Item -LiteralPath $ud }
      foreach ($d in $dirs) { [pscustomobject]@{ Browser = $b.Name; Proc = $b.Proc; Path = $d.FullName } }
    }
    foreach ($d in Get-ChildItem -LiteralPath (Join-Path $u.FullName 'AppData\Roaming\Mozilla\Firefox\Profiles') -Directory -ErrorAction SilentlyContinue) {
      [pscustomobject]@{ Browser = 'Firefox'; Proc = 'firefox'; Path = $d.FullName }
    }
  }
}

function Scan-Browsers {
  Say '[8/8] Semak browser (Chrome, Edge, Brave, Opera, Firefox)...' '[8/8] Checking browsers (Chrome, Edge, Brave, Opera, Firefox)...' Cyan
  # Extensions forced in by policy. Offices do this on purpose; a personal PC never should.
  foreach ($h in @('HKLM:\SOFTWARE') + @(Get-UserHives | ForEach-Object { "$_\Software" })) {
    foreach ($b in $BrowserRoots | Where-Object { $_.Policy }) {
      $k = "$h\Policies\$($b.Policy)\ExtensionInstallForcelist"
      if (-not (Test-Path -LiteralPath $k)) { continue }
      $item = Get-Item -LiteralPath $k
      foreach ($n in $item.GetValueNames()) {
        $sev = if ($Owner -eq 'Personal') { 'HIGH' } else { 'WARN' }
        Add-Finding 'RegValue' $sev "$k|$n" "$($b.Name) is forced to install extension $($item.GetValue($n)). Fine if your office IT set it; on a personal PC this is malware."
      }
    }
  }
  # Browser shortcuts that quietly load an extension from a folder.
  $sh = New-Object -ComObject WScript.Shell
  $lnkDirs = @("$env:PUBLIC\Desktop", "$env:ProgramData\Microsoft\Windows\Start Menu\Programs")
  foreach ($u in Get-ChildItem "$env:SystemDrive\Users" -Directory -ErrorAction SilentlyContinue) {
    $lnkDirs += 'Desktop', 'AppData\Roaming\Microsoft\Windows\Start Menu\Programs', 'AppData\Roaming\Microsoft\Internet Explorer\Quick Launch' |
      ForEach-Object { Join-Path $u.FullName $_ }
  }
  foreach ($d in $lnkDirs | Where-Object { Test-Path -LiteralPath $_ }) {
    Get-ChildItem -LiteralPath $d -Recurse -File -Force -Filter *.lnk -ErrorAction SilentlyContinue | ForEach-Object {
      $l = try { $sh.CreateShortcut($_.FullName) } catch { $null }
      if ($l -and $l.TargetPath -match '(?i)\\(chrome|msedge|brave|opera|launcher)\.exe$' -and $l.Arguments -match '(?i)--load-extension') {
        Add-Finding 'File' 'HIGH' $_.FullName "Browser shortcut loads a hidden extension: $($l.Arguments)"
      }
    }
  }
  # SORVEPOTEL stage 2 (Brazil): copies the Chrome profile to C:\temp\ChromeWpp and drives
  # WhatsApp Web with Selenium + wppconnect to message every contact and upload the contact list.
  foreach ($d in "$env:SystemDrive\temp", "$env:SystemDrive\tmp" | Where-Object { Test-Path -LiteralPath $_ }) {
    $wpp = Test-Path -LiteralPath "$d\wppconnect-wa.js"
    if (Test-Path -LiteralPath "$d\ChromeWpp") { Add-Finding 'File' 'HIGH' "$d\ChromeWpp" 'Copy of your Chrome profile (with the WhatsApp login) made by the WhatsApp worm to send messages as you.' }
    if ($wpp) { Add-Finding 'File' 'HIGH' "$d\wppconnect-wa.js" 'WhatsApp automation script the worm uses to message all your contacts.' }
    if ($wpp -and (Test-Path -LiteralPath "$d\chromedriver.exe")) { Add-Finding 'File' 'HIGH' "$d\chromedriver.exe" 'Browser-control program used by the WhatsApp worm.' }
  }
  foreach ($p in Get-CimInstance Win32_Process -ErrorAction SilentlyContinue | Where-Object { $_.Name -match '^(chrome|chromedriver)\.exe$' -and [string]$_.CommandLine -match '(?i)ChromeWpp|wppconnect' }) {
    Add-Finding 'Process' 'HIGH' "$($p.Name) (PID $($p.ProcessId))" 'Chrome driven by the WhatsApp worm.' @{ Pid = $p.ProcessId; Path = $p.ExecutablePath }
  }
  foreach ($u in Get-ChildItem "$env:SystemDrive\Users" -Directory -ErrorAction SilentlyContinue) {
    $m = Join-Path $u.FullName 'Documents\WindowsPowerShell\Modules\Selenium'
    if (Test-Path -LiteralPath $m) { Add-Finding 'Info' 'WARN' "Selenium PowerShell module: $m" 'The WhatsApp worm installs this to control Chrome. Remove that folder unless you use Selenium yourself.' }
  }
  # Extensions loaded from a folder instead of the web store.
  foreach ($p in Get-BrowserProfiles | Where-Object { $_.Browser -ne 'Firefox' }) {
    foreach ($pf in 'Secure Preferences', 'Preferences') {
      $file = Join-Path $p.Path $pf
      if (-not (Test-Path -LiteralPath $file)) { continue }
      $json = try { Get-Content -Raw -LiteralPath $file -ErrorAction Stop | ConvertFrom-Json -ErrorAction Stop } catch { $null }
      if (-not $json.extensions.settings) { continue }
      foreach ($e in $json.extensions.settings.PSObject.Properties) {
        if ($e.Value.location -eq 4 -and $e.Value.path) {
          Add-Finding 'Info' 'WARN' "$($p.Browser) extension $($e.Name)" "Extension loaded from a folder, not the web store: $($e.Value.path). Remove it in $($p.Browser) > Extensions unless you added it yourself."
        }
      }
    }
  }
}

# On an infected PC, log WhatsApp Web out of every browser. The login lives in the site's
# IndexedDB folder, not in cookies. The attacker's stolen copy keeps working until the phone
# logs out Linked devices; this stops the PC handing it over again.
function Add-WhatsAppWebSessions {
  foreach ($p in Get-BrowserProfiles) {
    $dirs = if ($p.Browser -eq 'Firefox') { Join-Path $p.Path 'storage\default\https+++web.whatsapp.com' }
            else { Get-ChildItem -LiteralPath (Join-Path $p.Path 'IndexedDB') -Directory -Filter 'https_web.whatsapp.com_0*' -ErrorAction SilentlyContinue | ForEach-Object { $_.FullName } }
    foreach ($d in @($dirs) | Where-Object { $_ -and (Test-Path -LiteralPath $_) }) {
      Add-Finding 'WaSession' 'HIGH' $d "WhatsApp Web login saved in $($p.Browser). Removing it logs this PC out." @{ Proc = $p.Proc }
    }
  }
}

# Force-remove a ManageEngine UEMS agent the user did not install. Its own uninstaller asks
# for a PIN only the attacker has, so take it apart piece by piece; everything is backed up.
function Add-ManageEngineRemoval {
  $rx = '(?i)ManageEngine|UEMS|DesktopCentral|Endpoint Central'
  foreach ($p in Get-CimInstance Win32_Process -ErrorAction SilentlyContinue | Where-Object { [string]$_.ExecutablePath -match $rx }) {
    Add-Finding 'Process' 'HIGH' "$($p.Name) (PID $($p.ProcessId))" 'ManageEngine process' @{ Pid = $p.ProcessId; Path = $p.ExecutablePath }
  }
  foreach ($svc in Get-ChildItem 'HKLM:\SYSTEM\CurrentControlSet\Services' -ErrorAction SilentlyContinue) {
    $pr = Get-ItemProperty -LiteralPath $svc.PSPath -ErrorAction SilentlyContinue
    if ("$($svc.PSChildName) $($pr.DisplayName) $($pr.ImagePath)" -match $rx) {
      Add-Finding 'Service' 'HIGH' $svc.PSChildName 'ManageEngine service' @{ RegPath = $svc.PSPath; Image = '' }
    }
  }
  foreach ($t in Get-ScheduledTask -ErrorAction SilentlyContinue) {
    $txt = "$($t.TaskPath)$($t.TaskName) " + (($t.Actions | ForEach-Object { "$($_.Execute) $($_.Arguments)" }) -join ' ')
    if ($txt -match $rx) { Add-Finding 'Task' 'HIGH' "$($t.TaskPath)$($t.TaskName)" 'ManageEngine task' @{ Path = $t.TaskPath; Name = $t.TaskName } }
  }
  foreach ($k in 'HKLM:\Software\Microsoft\Windows\CurrentVersion\Uninstall', 'HKLM:\Software\WOW6432Node\Microsoft\Windows\CurrentVersion\Uninstall') {
    foreach ($u in Get-ChildItem -LiteralPath $k -ErrorAction SilentlyContinue) {
      if ((Get-ItemProperty -LiteralPath $u.PSPath -ErrorAction SilentlyContinue).DisplayName -match $rx) {
        Add-Finding 'RegKey' 'HIGH' ($u.PSPath -replace '^Microsoft\.PowerShell\.Core\\Registry::', 'Registry::') 'ManageEngine uninstall entry'
      }
    }
  }
  foreach ($d in "${env:ProgramFiles(x86)}\ManageEngine\UEMS_Agent", "$env:ProgramFiles\ManageEngine\UEMS_Agent") {
    if (Test-Path -LiteralPath $d) { Add-Finding 'File' 'HIGH' $d 'ManageEngine agent folder' }
  }
}

# --------------------------------------------------------------- fixes ---
function Invoke-Fix($qdir) {
  New-Item -ItemType Directory -Force -Path $qdir | Out-Null
  $log = New-Object System.Collections.Generic.List[object]
  $i = 0
  $closed = $false
  foreach ($f in $Findings | Sort-Object { @('Process', 'WaSession', 'Vhd', 'Task', 'DefExcl', 'RegValue', 'Service', 'RegKey', 'File').IndexOf($_.Kind) }) {
    if ($f.Severity -ne 'HIGH' -or $f.Kind -eq 'Info') { continue }
    $i++
    try {
      switch ($f.Kind) {
        'Process' { Stop-Process -Id $f.Extra.Pid -Force -ErrorAction Stop; $log.Add(@{ Kind = 'Process'; Target = $f.Target }) }
        'WaSession' {
          if (-not $closed) {
            Say '  Browser ditutup untuk log keluar WhatsApp Web (buka balik lepas ni).' '  Closing browsers to log out WhatsApp Web (reopen them afterwards).' Yellow
            Stop-Process -Name chrome, msedge, brave, opera, firefox -Force -ErrorAction SilentlyContinue
            Start-Sleep 2; $closed = $true
          }
          $dest = Join-Path $qdir ("wa-$i-" + (Split-Path $f.Target -Leaf))
          Move-Item -LiteralPath $f.Target -Destination $dest -Force -ErrorAction Stop
          $log.Add(@{ Kind = 'File'; Target = $f.Target; Backup = $dest })
        }
        'Vhd'     { Dismount-DiskImage -ImagePath $f.Target -ErrorAction Stop | Out-Null; $log.Add(@{ Kind = 'Vhd'; Target = $f.Target }) }
        'Task'    {
          $xml = Join-Path $qdir "task-$i.xml"
          Export-ScheduledTask -TaskPath $f.Extra.Path -TaskName $f.Extra.Name | Out-File -Encoding Unicode $xml
          Unregister-ScheduledTask -TaskPath $f.Extra.Path -TaskName $f.Extra.Name -Confirm:$false -ErrorAction Stop
          $log.Add(@{ Kind = 'Task'; Target = $f.Target; Backup = $xml; Path = $f.Extra.Path; Name = $f.Extra.Name })
        }
        'DefExcl' {
          if ($f.Extra.Type -eq 'Process') { Remove-MpPreference -ExclusionProcess $f.Extra.Value -ErrorAction Stop }
          else { Remove-MpPreference -ExclusionPath $f.Extra.Value -ErrorAction Stop }
          $log.Add(@{ Kind = 'DefExcl'; Target = $f.Target; Type = $f.Extra.Type; Value = $f.Extra.Value })
        }
        'RegValue' {
          $key, $val = $f.Target -split '\|', 2
          $reg = Join-Path $qdir "reg-$i.reg"
          & reg.exe export (ConvertTo-RegExePath $key) $reg /y | Out-Null
          Remove-ItemProperty -LiteralPath $key -Name $val -ErrorAction Stop
          $log.Add(@{ Kind = 'Reg'; Target = $f.Target; Backup = $reg })
        }
        'RegKey' {
          $reg = Join-Path $qdir "reg-$i.reg"
          & reg.exe export (ConvertTo-RegExePath $f.Target) $reg /y | Out-Null
          Remove-Item -LiteralPath $f.Target -Recurse -Force -ErrorAction Stop
          $log.Add(@{ Kind = 'Reg'; Target = $f.Target; Backup = $reg })
        }
        'Service' {
          $reg = Join-Path $qdir "reg-$i.reg"
          & reg.exe export (ConvertTo-RegExePath $f.Extra.RegPath) $reg /y | Out-Null
          & sc.exe stop $f.Target | Out-Null
          & sc.exe delete $f.Target | Out-Null
          $log.Add(@{ Kind = 'Reg'; Target = $f.Target; Backup = $reg })
          $img = Resolve-ImagePath $f.Extra.Image
          if ($img -and (Test-Path -LiteralPath $img)) { Add-Finding 'File' 'HIGH' $img 'Driver file of removed service.' }
        }
        'File' {
          $dest = Join-Path $qdir ("file-$i-" + (Split-Path $f.Target -Leaf) + '.quarantine')
          Move-Item -LiteralPath $f.Target -Destination $dest -Force -ErrorAction Stop
          $log.Add(@{ Kind = 'File'; Target = $f.Target; Backup = $dest })
        }
      }
      Say "  OK  $($f.Kind): $($f.Target)" "  OK  $($f.Kind): $($f.Target)" Green
    } catch {
      Say "  GAGAL $($f.Kind): $($f.Target) - $($_.Exception.Message) (cuba restart & jalankan semula)" "  FAILED $($f.Kind): $($f.Target) (restart and run again)" Red
    }
  }
  # Driver files found while removing services are added late; quarantine them now.
  foreach ($f in $Findings | Where-Object { $_.Kind -eq 'File' -and $_.Detail -eq 'Driver file of removed service.' }) {
    if ($log | Where-Object { $_.Target -eq $f.Target }) { continue }
    $i++
    $dest = Join-Path $qdir ("file-$i-" + (Split-Path $f.Target -Leaf) + '.quarantine')
    try { Move-Item -LiteralPath $f.Target -Destination $dest -Force -ErrorAction Stop; $log.Add(@{ Kind = 'File'; Target = $f.Target; Backup = $dest }) }
    catch { Say "  Fail driver dikunci, akan dibuang selepas restart: $($f.Target)" "  Driver file locked; restart and run -Fix again: $($f.Target)" Yellow }
  }
  $mf = Join-Path $qdir 'manifest.json'
  $log | ConvertTo-Json -Depth 4 | Out-File -Encoding UTF8 $mf
  $mf
}

function Invoke-Restore($mf) {
  $items = Get-Content -Raw -LiteralPath $mf | ConvertFrom-Json
  foreach ($it in @($items)) {
    switch ($it.Kind) {
      'File' { Move-Item -LiteralPath $it.Backup -Destination $it.Target -Force; Say "  Dipulih: $($it.Target)" "  Restored: $($it.Target)" Green }
      'Reg'  { & reg.exe import $it.Backup | Out-Null; Say "  Registry dipulih: $($it.Target)" "  Registry restored: $($it.Target)" Green }
      'DefExcl' {
        if ($it.Type -eq 'Process') { Add-MpPreference -ExclusionProcess $it.Value } else { Add-MpPreference -ExclusionPath $it.Value }
        Say "  Pengecualian Defender dipulih: $($it.Value)" "  Defender exclusion restored: $($it.Value)" Green
      }
      'Task' { Register-ScheduledTask -TaskPath $it.Path -TaskName $it.Name -Xml (Get-Content -Raw $it.Backup) | Out-Null; Say "  Task dipulih: $($it.Target)" "  Task restored: $($it.Target)" Green }
    }
  }
  Say 'Siap. Restart PC.' 'Done. Restart the PC.' Cyan
}

# ---------------------------------------------------------------- main ---
Write-Host "WA-ZIP Cleaner v$Version" -ForegroundColor White
if (-not (Test-Admin)) {
  Say 'Sila jalankan sebagai Administrator (klik kanan > Run as administrator).' 'Please run as Administrator.' Red
  exit 2
}

if ($Restore) {
  if (-not $Manifest -or -not (Test-Path -LiteralPath $Manifest)) { Say 'Beri -Manifest <laluan manifest.json>.' 'Pass -Manifest <path to manifest.json>.' Red; exit 2 }
  Invoke-Restore $Manifest; exit 0
}

$stamp = Get-Date -Format 'yyyyMMdd-HHmmss'
New-Item -ItemType Directory -Force -Path $QuarantineRoot | Out-Null

# Office or personal PC decides what to do with ManageEngine. Every scan asks; a -Fix run within
# two hours of the scan (the "type Y" step) reuses that answer instead of asking again.
$ownerFile = Join-Path $QuarantineRoot 'owner.txt'
if (-not $Owner -and $Fix -and (Test-Path -LiteralPath $ownerFile) -and
    (Get-Item -LiteralPath $ownerFile).LastWriteTime -gt (Get-Date).AddHours(-2)) {
  $saved = (Get-Content -Raw -LiteralPath $ownerFile).Trim()
  if ($saved -in 'Office', 'Personal') { $Owner = $saved }
}
if (-not $Owner -and -not $env:WAZIP_NO_PROMPT) {
  Write-Host ''
  Say 'Soalan dulu: PC/laptop ni milik office (IT syarikat yang urus) atau milik sendiri?' 'First: is this PC/laptop managed by your office IT, or your own?' White
  Say '  Taip 1 = office, 2 = sendiri, lepas tu Enter. Tak pasti? Tekan Enter je.' '  Type 1 = office, 2 = personal, then Enter. Not sure? Just press Enter.' White
  $ans = [string](Read-Host)
  $Owner = switch ($ans.Trim()) { '1' { 'Office' } '2' { 'Personal' } default { '' } }
  if ($Owner) { Set-Content -LiteralPath $ownerFile -Value $Owner }
}
if ($Owner -eq 'Office')   { Say 'OK, PC office.' 'OK, office PC.' Gray }
if ($Owner -eq 'Personal') { Say 'OK, PC sendiri.' 'OK, personal PC.' Gray }

Start-Transcript -Path (Join-Path $QuarantineRoot "scan-$stamp.log") | Out-Null
$LolDrivers = Get-LolDrivers
if (-not $LolDrivers) { Say '  (Senarai driver bahaya tak dapat dimuat, semakan driver LOLDrivers dilangkau.)' '  (Could not load the LOLDrivers list; that driver check is skipped.)' DarkGray }

Scan-Processes; Scan-Vhd; Scan-Registry; Scan-Services; Scan-Persistence; Scan-Files; Scan-ManageEngine; Scan-Browsers

# ManageEngine: a personal PC should never have it, an office PC often does.
$me = $Findings | Where-Object { $_.Kind -eq 'Info' -and $_.Target -match 'ManageEngine' }
$meRemove = $false
if ($me) {
  $meRemove = [bool]$RemoveManageEngine -or $Owner -eq 'Personal'
  if (-not $meRemove -and $Fix -and -not $Owner -and -not $env:WAZIP_NO_PROMPT) {
    Write-Host ''
    Say 'ManageEngine dijumpai. Kalau office/syarikat anda yang pasang, JANGAN buang. Kalau anda tak pernah pasang, taip BUANG dan Enter:' `
        'ManageEngine found. If your company installed it, do NOT remove it. If you never installed it, type BUANG and press Enter:' Yellow
    $meRemove = (Read-Host) -ceq 'BUANG'
  }
  if ($meRemove) {
    $me.Severity = 'HIGH'
    Add-ManageEngineRemoval
    if ($RemoveManageEngine) { $Fix = $true }
  }
}

if ($Findings | Where-Object { $_.Severity -eq 'HIGH' }) { Add-WhatsAppWebSessions }

if ($ReportPath) {
  @($Findings | Select-Object Kind, Severity, Target, Detail) | ConvertTo-Json -Depth 3 | Out-File -Encoding UTF8 $ReportPath
}

Write-Host ''
$high = @($Findings | Where-Object Severity -eq 'HIGH')
$warn = @($Findings | Where-Object Severity -eq 'WARN')
if (-not $Findings.Count) {
  Say 'BERSIH: tiada tanda malware ZIP WhatsApp dijumpai.' 'CLEAN: no signs of the WhatsApp ZIP malware found.' Green
  Stop-Transcript | Out-Null; exit 0
}
foreach ($f in $Findings) {
  $c = if ($f.Severity -eq 'HIGH') { 'Red' } else { 'Yellow' }
  Write-Host ("[{0}] {1}: {2}" -f $f.Severity, $f.Kind, $f.Target) -ForegroundColor $c
  Write-Host ("        {0}" -f $f.Detail) -ForegroundColor DarkGray
}
Write-Host ''
Say "Jumpa: $($high.Count) bahaya, $($warn.Count) amaran." "Found: $($high.Count) high, $($warn.Count) warnings." White

if ($Fix -and $high.Count) {
  $qdir = Join-Path $QuarantineRoot $stamp
  $mf = Invoke-Fix $qdir
  Write-Host ''
  Say "Kuarantin siap. Salinan & manifest: $mf" "Quarantine done. Backups & manifest: $mf" Green
  Say 'Seterusnya: RESTART PC, kemudian imbas sekali lagi.' 'Next: RESTART the PC, then scan again.' Cyan
} elseif ($high.Count) {
  Say 'Untuk buang semua yang [HIGH] di atas, taip Y bila ditanya kat bawah (atau jalankan semula dengan -Fix / 2-CLEAN-BERSIH.bat).' 'To remove everything marked [HIGH], type Y when asked below (or run again with -Fix / 2-CLEAN-BERSIH.bat).' Cyan
} else {
  Say 'Cuma ada amaran, tiada apa yang tool ni akan buang. Baca amaran di atas.' 'Warnings only; nothing for this tool to remove. Read the warnings above.' Cyan
}
if ($high.Count) {
  Write-Host ''
  Say 'PENTING: dari telefon/PC lain, tukar kata laluan bank & emel, dan log keluar WhatsApp Web (Peranti dipaut > Log keluar semua).' `
      'IMPORTANT: from another device, change bank/email passwords and log out WhatsApp Web (Linked devices > Log out all).' Yellow
  if ($Findings | Where-Object { $_.Kind -eq 'WaSession' }) {
    if ($Fix) { Say 'WhatsApp Web dah dilog keluar dari browser kat PC ni. Hacker masih boleh guna salinan yang dia curi sampai anda log keluar dari phone: WhatsApp > Peranti dipaut > log keluar semua.' `
                    'WhatsApp Web is logged out of the browsers on this PC. The attacker''s stolen copy works until you log out from your phone: WhatsApp > Linked devices > log out all.' Yellow }
    else { Say 'Bila taip Y, browser akan tertutup sendiri dan WhatsApp Web kat PC ni akan log keluar.' 'When you type Y, browsers close and WhatsApp Web on this PC is logged out.' Yellow }
  }
  if ($Findings | Where-Object { $_.Kind -eq 'DefExcl' -or $_.Detail -match 'Defender' }) {
    Say 'Malware ni suruh Windows Defender abaikan dia, sebab tu scan antivirus nampak bersih. Lepas bersihkan dan restart, buat Full scan Windows Defender sekali lagi.' `
        'This malware told Windows Defender to ignore it, which is why antivirus scans looked clean. After cleaning and restarting, run a Windows Defender full scan again.' Yellow
  }
  if ($Findings | Where-Object { $_.Kind -eq 'Service' }) {
    Say 'Driver pembunuh antivirus dijumpai. Paling selamat: backup data & pasang semula Windows.' `
        'An antivirus-killer driver was found. Safest option: back up data and reinstall Windows.' Yellow
  }
}
if ($me -and $meRemove -and $Fix) {
  Say 'ManageEngine dah dibuang. Program ni bagi hacker control penuh PC ni, jadi paling selamat: backup data & pasang semula Windows, dan tukar semua password guna phone.' `
      'ManageEngine removed. It gave the attacker full control of this PC, so the safest option is to back up data and reinstall Windows, and change every password from your phone.' Yellow
} elseif ($me -and $meRemove) {
  Say 'PC sendiri tak patut ada ManageEngine. Taip Y bila ditanya untuk buang dia.' 'A personal PC should not have ManageEngine. Type Y when asked to remove it.' Yellow
} elseif ($me -and $Owner -eq 'Office') {
  Say 'PC office: ManageEngine biasanya IT syarikat yang pasang. Tunjuk skrin ni kat IT office dan tanya betul ke dia yang pasang. Kalau IT kata bukan, jalankan tool ni semula dan jawab 2 (sendiri).' `
      'Office PC: company IT usually installs ManageEngine. Show this screen to your IT team and ask if they installed it. If they did not, run this tool again and answer 2 (personal).' Yellow
} elseif ($me) {
  Say 'ManageEngine dijumpai. Kalau PC sendiri, jalankan tool ni semula dan jawab 2 (sendiri), tool akan buang dia. Atau buang sendiri: (1) pasang Bulk Crap Uninstaller (percuma, bcuninstaller.com), cari ManageEngine, klik kanan > Uninstall manually (uninstall biasa minta PIN hacker); (2) buka services.msc, set semua servis ManageEngine ke Disabled; (3) buka Task Scheduler, padam task ManageEngine; (4) restart dan imbas semula. Paling selamat: backup data & pasang semula Windows.' `
      'ManageEngine found. If this is your own PC, run this tool again and answer 2 (personal); it will remove it. Or remove it yourself: (1) install Bulk Crap Uninstaller (free, bcuninstaller.com), find ManageEngine, right-click > Uninstall manually (normal uninstall asks for the attacker''s PIN); (2) open services.msc and set every ManageEngine service to Disabled; (3) open Task Scheduler and delete ManageEngine tasks; (4) restart and scan again. Safest: back up data and reinstall Windows.' Yellow
}
Stop-Transcript | Out-Null
if ($high.Count) { exit 1 }
exit 3
