# WA-ZIP Cleaner short launcher:  irm waz.afuit.dev | iex
# Downloads the full tool from this GitHub repo, scans, and asks before cleaning anything.
& {
  [Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls12
  $admin = ([Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)
  if (-not $admin) {
    Write-Host 'Perlu Administrator. Tekan Yes bila Windows tanya. (Needs Administrator: click Yes.)' -ForegroundColor Yellow
    Start-Process powershell -Verb RunAs -ArgumentList '-NoProfile -NoExit -Command irm waz.afuit.dev | iex'
    return
  }
  $p = "$env:TEMP\waz.ps1"
  Invoke-WebRequest 'https://raw.githubusercontent.com/afu-it/wa-zip-cleaner/main/wa-zip-cleaner.ps1' -OutFile $p -UseBasicParsing
  powershell -NoProfile -ExecutionPolicy Bypass -File $p
  if ($LASTEXITCODE -eq 1 -and (Read-Host 'Taip Y dan Enter untuk bersihkan') -eq 'Y') { powershell -NoProfile -ExecutionPolicy Bypass -File $p -Fix }
}
