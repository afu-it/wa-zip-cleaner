# Plants harmless stand-ins for every artifact the cleaner looks for.
# No real malware: files are dummy bytes, the service is never started.
$ErrorActionPreference = 'Stop'

# Registry
New-Item -Path 'HKCU:\Console\0' -Force | Out-Null
New-ItemProperty -Path 'HKCU:\Console\0' -Name 'd33f351a4aeea5e608853d1a56661059' -PropertyType Binary -Value ([byte[]](1..4096 | ForEach-Object { 0x41 })) -Force | Out-Null
New-ItemProperty -Path 'HKCU:\Console' -Name 'IpDate' -PropertyType Binary -Value ([byte[]](1, 2, 3)) -Force | Out-Null
New-ItemProperty -Path 'HKCU:\Console' -Name 'Magisk' -PropertyType Binary -Value ([byte[]](1, 2, 3)) -Force | Out-Null
New-Item -Path 'HKCU:\Software\IpDates_info' -Force | Out-Null

# Fake sideload folder
$dir = 'C:\Users\Public\WAZipTest'
New-Item -ItemType Directory -Force -Path $dir | Out-Null
Set-Content -Path "$dir\rime.dll" -Value 'dummy'
Set-Content -Path "$dir\KafanInputService.exe" -Value 'dummy'
Set-Content -Path "$dir\hidserv.dll" -Value 'dummy'
Set-Content -Path "$dir\WindowsHelper.exe" -Value 'dummy'
(Get-Item -LiteralPath "$dir\WindowsHelper.exe" -Force).Attributes = 'Hidden, System, Archive'

# Auto-start
$cmd = "rundll32.exe `"$dir\RIME.dll`",_vmclientcore@16 test"
if (-not (Test-Path 'HKCU:\Software\Microsoft\Windows\CurrentVersion\Run')) {
  New-Item -Path 'HKCU:\Software\Microsoft\Windows\CurrentVersion\Run' -Force | Out-Null
}
New-ItemProperty -Path 'HKCU:\Software\Microsoft\Windows\CurrentVersion\Run' -Name 'WAZipTestRun' -Value $cmd -Force | Out-Null
# Run entry with an innocent name that points at a Hidden+System file (unknown-variant case)
Set-Content -Path "$dir\svc-helper.exe" -Value 'dummy'
(Get-Item -LiteralPath "$dir\svc-helper.exe" -Force).Attributes = 'Hidden, System, Archive'
New-ItemProperty -Path 'HKCU:\Software\Microsoft\Windows\CurrentVersion\Run' -Name 'WinHelperRun' -Value "`"$dir\svc-helper.exe`"" -Force | Out-Null
$act = New-ScheduledTaskAction -Execute 'rundll32.exe' -Argument "`"$dir\RIME.dll`",_vmclientcore@16 test"
Register-ScheduledTask -TaskName 'WAZipTestTask' -Action $act -Trigger (New-ScheduledTaskTrigger -AtLogOn) -Force | Out-Null
$startup = Join-Path $env:APPDATA 'Microsoft\Windows\Start Menu\Programs\Startup'
New-Item -ItemType Directory -Force -Path $startup | Out-Null
Set-Content -Path "$startup\wazip-test.bat" -Value "start rundll32 `"$dir\RIME.dll`",_vmclientcore@16"

# Driver service (registered, never started) + dummy driver files
$drv = "$env:SystemRoot\System32\drivers\ZyArk.sys"
Set-Content -Path $drv -Value 'dummy'
Set-Content -Path "$env:SystemRoot\System32\drivers\ZyArk.dat" -Value 'dummy'
& sc.exe create ZyArk type= kernel start= demand binPath= "System32\drivers\ZyArk.sys" | Out-Null
# Service that launches a script interpreter from a user folder (generic persistence)
& sc.exe create WAZipFakeSvc binPath= "cmd /c $dir\wazip-test.bat" start= demand | Out-Null

# Lure files
$dl = Join-Path $env:USERPROFILE 'Downloads'
New-Item -ItemType Directory -Force -Path $dl | Out-Null
Set-Content -Path "$dl\Click here to view10.6_9999.zip" -Value 'dummy'
Set-Content -Path "$dl\Account Statement.vbs" -Value "' dummy"
Set-Content -Path "$dl\Work Snapshot.vbs" -Value "' dummy"
Set-Content -Path "$env:TEMP\dd_vcredist_x86_20261022_1_vcRuntimeMinimum_x86.exe" -Value 'dummy'
Set-Content -Path "$dl\normal-document.pdf" -Value 'keep me'

# Running process whose command line carries the malware marker
Start-Process -FilePath 'cmd.exe' -ArgumentList '/c ping -n 900 127.0.0.1 >nul & rem _vmclientcore@16' -WindowStyle Hidden

# SilverFox KuGou variant: staged loader pair, MicrosoftUpdate Run value, running process, new lure names
$stage = Join-Path $env:APPDATA 'Microsoft\Update'
New-Item -ItemType Directory -Force -Path $stage | Out-Null
Copy-Item "$env:SystemRoot\System32\PING.EXE" "$stage\PDF_C2089_20260911100446.exe"
Set-Content -Path "$stage\active_desktop_render_x64.dll" -Value 'dummy'
New-ItemProperty -Path 'HKCU:\Software\Microsoft\Windows\CurrentVersion\Run' -Name 'MicrosoftUpdate' -Value "`"$stage\PDF_C2089_20260911100446.exe`"" -Force | Out-Null
Start-Process -FilePath "$stage\PDF_C2089_20260911100446.exe" -ArgumentList '-n 900 127.0.0.1' -WindowStyle Hidden
Set-Content -Path "$dl\DOC_7748_20260924152821.zip" -Value 'dummy'
Set-Content -Path "$dl\PDF_C2841_20260911100446.img" -Value 'dummy'

# October 2026 wave: new lure names, payload .dat, and a hidden task that adds Defender exclusions (never run)
Set-Content -Path "$dl\PDF_FTFWCI_20261009125351.vhd" -Value 'dummy'
Set-Content -Path "$dl\20261019-MYS2026Y1019E51AC.zip" -Value 'dummy'
Set-Content -Path "$dl\20261019.MYS2026Y1019A7F2E.zip" -Value 'dummy'
New-Item -ItemType Directory -Force -Path 'C:\ProgramData\WAZipOct' | Out-Null
Set-Content -Path 'C:\ProgramData\WAZipOct\eneio64.dat' -Value 'dummy'
$act = New-ScheduledTaskAction -Execute 'powershell.exe' -Argument "-NoProfile -WindowStyle Hidden -Command `"Add-MpPreference -ExclusionProcess 'QtsUpdater.exe'`""
Register-ScheduledTask -TaskName 'WAZipDefTask' -Action $act -Trigger (New-ScheduledTaskTrigger -AtLogOn) -Force | Out-Null

# WhatsApp Web logins in a Chrome and a Firefox profile (stand-in folders, no real session)
$waChrome = "$env:LOCALAPPDATA\Google\Chrome\User Data\Default\IndexedDB\https_web.whatsapp.com_0.indexeddb.leveldb"
$waFox = "$env:APPDATA\Mozilla\Firefox\Profiles\wazip.default\storage\default\https+++web.whatsapp.com"
New-Item -ItemType Directory -Force -Path $waChrome, $waFox | Out-Null
Set-Content -Path "$waChrome\000003.log" -Value 'dummy'
Set-Content -Path "$waFox\.metadata-v2" -Value 'dummy'

# Mounted lure VHD
$vhd = "$dl\Click here to view10.6.vhd"
"create vdisk file=`"$vhd`" maximum=8 type=fixed`nattach vdisk" | Out-File -Encoding ASCII "$env:TEMP\dp.txt"
& diskpart.exe /s "$env:TEMP\dp.txt" | Out-Null

Write-Host 'Simulated infection planted.'
