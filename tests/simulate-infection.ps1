# Plants harmless stand-ins for every artifact the cleaner looks for.
# No real malware: files are dummy bytes, the service is never started.
$ErrorActionPreference = 'Stop'

# Registry
New-Item -Path 'HKCU:\Console\0' -Force | Out-Null
New-ItemProperty -Path 'HKCU:\Console\0' -Name 'd33f351a4aeea5e608853d1a56661059' -PropertyType Binary -Value ([byte[]](1..4096 | ForEach-Object { 0x41 })) -Force | Out-Null
New-ItemProperty -Path 'HKCU:\Console' -Name 'IpDate' -PropertyType Binary -Value ([byte[]](1, 2, 3)) -Force | Out-Null
New-Item -Path 'HKCU:\Software\IpDates_info' -Force | Out-Null

# Fake sideload folder
$dir = 'C:\Users\Public\WAZipTest'
New-Item -ItemType Directory -Force -Path $dir | Out-Null
Set-Content -Path "$dir\rime.dll" -Value 'dummy'
Set-Content -Path "$dir\KafanInputService.exe" -Value 'dummy'

# Auto-start
$cmd = "rundll32.exe `"$dir\RIME.dll`",_vmclientcore@16 test"
New-ItemProperty -Path 'HKCU:\Software\Microsoft\Windows\CurrentVersion\Run' -Name 'WAZipTestRun' -Value $cmd -Force | Out-Null
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

# Lure files
$dl = Join-Path $env:USERPROFILE 'Downloads'
New-Item -ItemType Directory -Force -Path $dl | Out-Null
Set-Content -Path "$dl\Click here to view10.6_9999.zip" -Value 'dummy'
Set-Content -Path "$dl\Account Statement.vbs" -Value "' dummy"
Set-Content -Path "$env:TEMP\dd_vcredist_x86_20261022_1_vcRuntimeMinimum_x86.exe" -Value 'dummy'
Set-Content -Path "$dl\normal-document.pdf" -Value 'keep me'

# Running process whose command line carries the malware marker
Start-Process -FilePath 'cmd.exe' -ArgumentList '/c ping -n 900 127.0.0.1 >nul & rem _vmclientcore@16' -WindowStyle Hidden

# Mounted lure VHD
$vhd = "$dl\Click here to view10.6.vhd"
"create vdisk file=`"$vhd`" maximum=8 type=fixed`nattach vdisk" | Out-File -Encoding ASCII "$env:TEMP\dp.txt"
& diskpart.exe /s "$env:TEMP\dp.txt" | Out-Null

Write-Host 'Simulated infection planted.'
