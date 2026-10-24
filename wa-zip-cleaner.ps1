<#
.SYNOPSIS
  WA-ZIP Cleaner: scan and clean Windows PCs infected by the WhatsApp
  "Click here to view" ZIP malware (Winos4.0 / ValleyRAT family).
  Pengimbas & pembersih malware ZIP WhatsApp (keluarga Winos4.0 / ValleyRAT).

.DESCRIPTION
  Default mode only SCANS and changes nothing.
  -Fix      : quarantine what was found (files moved, registry exported first).
  -Restore  : undo a previous -Fix using its manifest.

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
$PersistRegex ='rime\.dll|_vmclientcore@16|KafanInput|vcRuntimeMinimum_x86\.exe|\\H\d{8,}\.exe|ZyArk|\\ardrv\.sys|\\AppData\\Roaming\\Microsoft\\Update\\[^\\]+\.exe|active_desktop_(launcher|render)'
$LureRegex    = '^(Click here to view.*\.(zip|vhd|vhdx)|Notice.*\.vhdx?|(PDF|DOC)_C?\d{3,6}_20\d{12}\.(zip|img|iso|exe))$'
# Known attacker servers (C2). A process talking to one of these is the malware.
$C2Ips = @('134.122.155.135')
if ($env:WAZIP_TEST_C2) { $C2Ips += $env:WAZIP_TEST_C2 }
# SilverFox KuGou variant (Pelagos Intel, Sep 2026) stages here and runs from a Run value named MicrosoftUpdate.
$StageRegex   = '(?i)\\AppData\\Roaming\\Microsoft\\Update\\[^\\]+\.(exe|dll)$'
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

function ConvertTo-RegExePath([string]$psPath) {
  $p = $psPath -replace '^Registry::', '' -replace '^Microsoft\.PowerShell\.Core\\Registry::', ''
  $p = $p -replace '^HKEY_USERS', 'HKU' -replace '^HKEY_LOCAL_MACHINE', 'HKLM' -replace '^HKEY_CURRENT_USER', 'HKCU'
  $p -replace '^HKLM:', 'HKLM' -replace '^HKCU:', 'HKCU'
}

# --------------------------------------------------------------- scans ---
function Scan-Registry {
  Say '[1/7] Semak registry (tempat malware sorok muatan)...' '[1/7] Checking registry (where the payload hides)...' Cyan
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
  Say '[2/7] Semak driver & servis (pembunuh antivirus)...' '[2/7] Checking drivers & services (antivirus killers)...' Cyan
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
  }
  $drv = Join-Path $env:SystemRoot 'System32\drivers\ZyArk.dat'
  if (Test-Path -LiteralPath $drv) { Add-Finding 'File' 'HIGH' $drv 'ZyArk driver data file.' }
}

function Scan-Processes {
  Say '[3/7] Semak program yang sedang berjalan...' '[3/7] Checking running programs...' Cyan
  foreach ($p in Get-CimInstance Win32_Process -ErrorAction SilentlyContinue) {
    $cl = [string]$p.CommandLine; $exe = [string]$p.ExecutablePath
    if ($cl -match '_vmclientcore@16' -or $p.Name -eq 'KafanInputService.exe' -or $exe -match '\\H\d{8,}\.exe$' -or $exe -match $StageRegex) {
      Add-Finding 'Process' 'HIGH' "$($p.Name) (PID $($p.ProcessId))" "Malware process: $cl" @{ Pid = $p.ProcessId; Path = $exe }
    }
  }
  foreach ($c in Get-NetTCPConnection -ErrorAction SilentlyContinue | Where-Object { $C2Ips -contains $_.RemoteAddress }) {
    $pp = Get-Process -Id $c.OwningProcess -ErrorAction SilentlyContinue
    Add-Finding 'Process' 'HIGH' "$($pp.ProcessName) (PID $($c.OwningProcess))" "Connected to known attacker server $($c.RemoteAddress):$($c.RemotePort)" @{ Pid = $c.OwningProcess; Path = $pp.Path }
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
  Say '[4/7] Semak program yang auto-jalan bila PC hidup...' '[4/7] Checking auto-start entries...' Cyan
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

function Scan-Files {
  Say '[5/7] Imbas fail (boleh ambil 2-10 minit)...' '[5/7] Scanning files (can take 2-10 minutes)...' Cyan
  $roots = @("$env:ProgramData", "$env:SystemDrive\Users\Public", "$env:SystemRoot\Temp")
  foreach ($u in Get-ChildItem "$env:SystemDrive\Users" -Directory -ErrorAction SilentlyContinue) {
    $roots += 'Downloads', 'Desktop', 'Documents', 'AppData\Roaming', 'AppData\Local\Temp', 'AppData\Local\Packages' |
      ForEach-Object { Join-Path $u.FullName $_ }
  }
  $exts = '\.(zip|vhd|vhdx|img|iso|dll|exe|dat|sys|tar|vbs|vbe|js|wsf)$'
  foreach ($r in $roots | Where-Object { Test-Path -LiteralPath $_ }) {
    Get-ChildItem -LiteralPath $r -Recurse -File -Force -ErrorAction SilentlyContinue |
      Where-Object { $_.Name -match $exts } | ForEach-Object {
        $f = $_
        $ioc = Get-Ioc $f
        if ($ioc -and $ioc.Bad) { Add-Finding 'File' 'HIGH' $f.FullName "Known malware: $($ioc.Name)"; return }
        if ($ioc -and -not $ioc.Bad -and $f.FullName -notmatch [regex]::Escape($ioc.Vendor)) {
          Add-Finding 'File' 'HIGH' $f.FullName "Legit file abused by malware, in wrong place: $($ioc.Name)"; return }
        if ($f.Name -match $LureRegex) { Add-Finding 'File' 'HIGH' $f.FullName 'WhatsApp lure file name.'; return }
        if ($f.FullName -match $StageRegex -or $f.Name -ieq 'active_desktop_render_x64.dll') {
          Add-Finding 'File' 'HIGH' $f.FullName 'SilverFox loader staged in a fake Microsoft\Update folder (KuGou variant).'; return }
        if ($f.Name -match '(?i)\.vhdx?$' -and $f.Name -ine 'ext4.vhdx' -and
            $f.FullName -match '(?i)^[a-z]:\\Users\\' -and
            $f.FullName -notmatch '(?i)\\AppData\\Local\\(Docker\\|Packages\\(?!5319275A\.WhatsAppDesktop))') {
          Add-Finding 'File' 'WARN' $f.FullName 'Virtual disk (VHD) in a user folder. The WhatsApp ZIP hides its payload in a VHD; delete it unless you made it.'; return }
        if ($f.Name -match $VbsLureRegex) { Add-Finding 'File' 'HIGH' $f.FullName 'Script disguised as a document (WhatsApp VBS campaign).'; return }
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
  Say '[6/7] Semak cakera maya (VHD) yang sedang dibuka...' '[6/7] Checking mounted virtual disks (VHD)...' Cyan
  foreach ($d in Get-Disk -ErrorAction SilentlyContinue | Where-Object { $_.BusType -eq 'File Backed Virtual' }) {
    $loc = [string]$d.Location
    $sev = if ((Split-Path $loc -Leaf) -match $LureRegex) { 'HIGH' } else { 'WARN' }
    Add-Finding 'Vhd' $sev $loc 'Mounted virtual disk. The WhatsApp ZIP opens as a VHD drive.'
  }
}

function Scan-ManageEngine {
  Say '[7/7] Semak alat kawalan jauh (kempen VBS WhatsApp)...' '[7/7] Checking remote-control agents (WhatsApp VBS campaign)...' Cyan
  $hits = @()
  $hits += Get-Service -ErrorAction SilentlyContinue | Where-Object { $_.DisplayName -match 'ManageEngine|UEMS' }
  foreach ($p in "${env:ProgramFiles(x86)}\ManageEngine\UEMS_Agent", "$env:ProgramFiles\ManageEngine\UEMS_Agent") {
    if (Test-Path -LiteralPath $p) { $hits += $p }
  }
  if ($hits.Count) {
    Add-Finding 'Info' 'WARN' 'ManageEngine UEMS Agent' ('Remote-management agent found. If your company did NOT install it, the WhatsApp VBS campaign gave attackers remote control. ' +
      'Remove via Settings > Apps > ManageEngine and change all passwords.')
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
  foreach ($f in $Findings | Sort-Object { @('Process', 'Vhd', 'Task', 'RegValue', 'Service', 'RegKey', 'File').IndexOf($_.Kind) }) {
    if ($f.Severity -ne 'HIGH' -or $f.Kind -eq 'Info') { continue }
    $i++
    try {
      switch ($f.Kind) {
        'Process' { Stop-Process -Id $f.Extra.Pid -Force -ErrorAction Stop; $log.Add(@{ Kind = 'Process'; Target = $f.Target }) }
        'Vhd'     { Dismount-DiskImage -ImagePath $f.Target -ErrorAction Stop | Out-Null; $log.Add(@{ Kind = 'Vhd'; Target = $f.Target }) }
        'Task'    {
          $xml = Join-Path $qdir "task-$i.xml"
          Export-ScheduledTask -TaskPath $f.Extra.Path -TaskName $f.Extra.Name | Out-File -Encoding Unicode $xml
          Unregister-ScheduledTask -TaskPath $f.Extra.Path -TaskName $f.Extra.Name -Confirm:$false -ErrorAction Stop
          $log.Add(@{ Kind = 'Task'; Target = $f.Target; Backup = $xml; Path = $f.Extra.Path; Name = $f.Extra.Name })
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
          $img = ($f.Extra.Image -replace '^\\\?\?\\', '' -replace '^\\SystemRoot', $env:SystemRoot -replace '^System32', "$env:SystemRoot\System32").Trim('"')
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
Start-Transcript -Path (Join-Path $QuarantineRoot "scan-$stamp.log") | Out-Null

Scan-Processes; Scan-Vhd; Scan-Registry; Scan-Services; Scan-Persistence; Scan-Files; Scan-ManageEngine

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

$me = $Findings | Where-Object { $_.Kind -eq 'Info' -and $_.Target -match 'ManageEngine' }
if ($me -and ($Fix -or $RemoveManageEngine)) {
  $go = [bool]$RemoveManageEngine
  if (-not $go -and -not $env:WAZIP_NO_PROMPT) {
    Write-Host ''
    Say 'ManageEngine dijumpai. Kalau office/syarikat anda yang pasang, JANGAN buang. Kalau anda tak pernah pasang, taip BUANG dan Enter:' `
        'ManageEngine found. If your company installed it, do NOT remove it. If you never installed it, type BUANG and press Enter:' Yellow
    $go = (Read-Host) -ceq 'BUANG'
  }
  if ($go) {
    Add-ManageEngineRemoval
    $high = @($Findings | Where-Object Severity -eq 'HIGH')
    $Fix = $true
  }
}
if ($Fix -and $high.Count) {
  $qdir = Join-Path $QuarantineRoot $stamp
  $mf = Invoke-Fix $qdir
  Write-Host ''
  Say "Kuarantin siap. Salinan & manifest: $mf" "Quarantine done. Backups & manifest: $mf" Green
  Say 'Seterusnya: RESTART PC, kemudian imbas sekali lagi.' 'Next: RESTART the PC, then scan again.' Cyan
} elseif ($high.Count) {
  Say 'Untuk bersihkan, jalankan semula dengan -Fix (atau 2-CLEAN-BERSIH.bat).' 'To clean, run again with -Fix (or 2-CLEAN-BERSIH.bat).' Cyan
}
if ($high.Count) {
  Write-Host ''
  Say 'PENTING: dari telefon/PC lain, tukar kata laluan bank & emel, dan log keluar WhatsApp Web (Peranti dipaut > Log keluar semua).' `
      'IMPORTANT: from another device, change bank/email passwords and log out WhatsApp Web (Linked devices > Log out all).' Yellow
  if ($Findings | Where-Object { $_.Kind -eq 'Service' }) {
    Say 'Driver pembunuh antivirus dijumpai. Paling selamat: backup data & pasang semula Windows.' `
        'An antivirus-killer driver was found. Safest option: back up data and reinstall Windows.' Yellow
  }
}
if ($Findings | Where-Object { $_.Kind -eq 'Info' -and $_.Target -match 'ManageEngine' }) {
  Say 'ManageEngine dijumpai. Kalau office anda tak pasang, buang begini: (1) pasang Revo Uninstaller Free, buang ManageEngine guna Revo (uninstall biasa minta PIN hacker); (2) buka services.msc, set semua servis ManageEngine ke Disabled; (3) buka Task Scheduler, padam task ManageEngine; (4) restart dan imbas semula. Paling selamat: backup data & pasang semula Windows.' `
      'ManageEngine found. If your company did not install it: (1) install Revo Uninstaller Free and remove ManageEngine with it (normal uninstall asks for the attacker''s PIN); (2) open services.msc and set every ManageEngine service to Disabled; (3) open Task Scheduler and delete ManageEngine tasks; (4) restart and scan again. Safest: back up data and reinstall Windows.' Yellow
}
Stop-Transcript | Out-Null
exit 1
