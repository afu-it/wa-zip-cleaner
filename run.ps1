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
  # An antivirus (Malwarebytes, Nov 2026) can quarantine the tool as soon as it lands or while it runs:
  # say so in plain words instead of a red PowerShell error.
  $blocked = {
    Write-Host ''
    Write-Host 'Antivirus anda sekat tool ni (salah tangkap). Buka antivirus > Quarantine / Detection History > pilih waz.ps1 > Restore dan Allow. Kemudian jalankan semula: irm waz.afuit.dev | iex' -ForegroundColor Yellow
    Write-Host '(Your antivirus blocked this tool by mistake. Open it > Quarantine > restore and allow waz.ps1, then run irm waz.afuit.dev | iex again.)' -ForegroundColor DarkGray
  }
  Remove-Item -LiteralPath $p -Force -ErrorAction SilentlyContinue
  try { Invoke-WebRequest 'https://raw.githubusercontent.com/afu-it/wa-zip-cleaner/main/wa-zip-cleaner.ps1' -OutFile $p -UseBasicParsing -ErrorAction Stop }
  catch {
    if ("$($_.Exception.Message)" -match '(?i)virus|unwanted|access') { & $blocked }
    else { Write-Host 'Tak dapat muat turun tool. Semak internet dan cuba lagi. (Could not download the tool: check the internet and try again.)' -ForegroundColor Yellow }
    return
  }
  Start-Sleep -Seconds 2
  if (-not (Test-Path -LiteralPath $p)) { & $blocked; return }
  powershell -NoProfile -ExecutionPolicy Bypass -File $p
  $code = $LASTEXITCODE
  if (-not (Test-Path -LiteralPath $p)) { & $blocked; return }
  if ($code -eq 1 -and (Read-Host 'Taip Y dan Enter untuk bersihkan') -eq 'Y') {
    powershell -NoProfile -ExecutionPolicy Bypass -File $p -Fix
    if (-not (Test-Path -LiteralPath $p)) { & $blocked }
  }
}
