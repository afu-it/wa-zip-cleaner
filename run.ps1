# WA-ZIP Cleaner short launcher:  irm waz.afuit.dev | iex
# Downloads the full tool from this GitHub repo, scans, and asks before cleaning anything.
# waz.afuit.dev is a Cloudflare Worker (tools/waz-launcher) that serves this file directly:
# old Windows 10 PowerShell starts on TLS 1.0 and cannot follow a redirect to GitHub.
& {
  [Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls12
  $admin = ([Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)
  if (-not $admin) {
    Write-Host 'Perlu Administrator. Tekan Yes bila Windows tanya. (Needs Administrator: click Yes.)' -ForegroundColor Yellow
    Start-Process powershell -Verb RunAs -ArgumentList '-NoProfile -NoExit -Command [Net.ServicePointManager]::SecurityProtocol=''Tls12''; irm waz.afuit.dev | iex'
    return
  }
  $url = 'https://raw.githubusercontent.com/afu-it/wa-zip-cleaner/main/wa-zip-cleaner.ps1'
  # Opened as 32-bit PowerShell (x86): start the tool in 64-bit PowerShell, or Safe Mode cannot be set up (WAZ-B6PDP).
  $ps = Join-Path $env:windir 'Sysnative\WindowsPowerShell\v1.0\powershell.exe'
  if (-not (Test-Path -LiteralPath $ps)) { $ps = 'powershell' }
  $start = Get-Date

  # The tool file can vanish while it runs: an antivirus quarantines it (Malwarebytes, Nov 2026),
  # or malware on the PC deletes it (PC with an antivirus-killer driver, Nov 2026).
  # Only blame an antivirus when Defender's own history shows it; otherwise say we do not know.
  $why = {
    $name = $null
    try {
      $d = @(Get-MpThreatDetection -ErrorAction Stop | Where-Object { $_.InitialDetectionTime -ge $start.AddMinutes(-1) -and "$($_.Resources)" -match '(?i)waz[^\\]*\.ps1|wa-zip-cleaner' })
      if ($d.Count) { $name = (Get-MpThreat -ThreatID $d[0].ThreatID -ErrorAction Stop).ThreatName; if (-not $name) { $name = 'Defender' } }
    } catch {}
    Write-Host ''
    if ($name) {
      Write-Host "Windows Defender sekat tool ni (salah tangkap: $name). Buka Windows Security > Virus & threat protection > Protection history > pilih waz.ps1 > Allow. Kemudian jalankan semula: irm waz.afuit.dev | iex" -ForegroundColor Yellow
      Write-Host "(Windows Defender blocked this tool by mistake: $name. Open Protection history, allow waz.ps1, then run irm waz.afuit.dev | iex again.)" -ForegroundColor DarkGray
    } else {
      Write-Host 'Fail tool ni dipadam masa ia berjalan. Mungkin antivirus lain (semak Quarantine dia, pilih Restore dan Allow), atau malware dalam PC ni yang padam.' -ForegroundColor Yellow
      Write-Host '(The tool file was deleted while it ran: another antivirus (check its Quarantine) or malware on this PC.)' -ForegroundColor DarkGray
    }
  }
  # Each download gets a fresh name, so a second copy is not caught by a name-based delete.
  $get = {
    $p = Join-Path $env:TEMP ('waz-' + [Guid]::NewGuid().ToString('N').Substring(0, 8) + '.ps1')
    try { Invoke-WebRequest $url -OutFile $p -UseBasicParsing -ErrorAction Stop }
    catch {
      if ("$($_.Exception.Message)" -match '(?i)virus|unwanted|access') { & $why }
      else { Write-Host 'Tak dapat muat turun tool. Semak internet dan cuba lagi. (Could not download the tool: check the internet and try again.)' -ForegroundColor Yellow }
      return $null
    }
    Start-Sleep -Seconds 2
    if (-not (Test-Path -LiteralPath $p)) { & $why; return $null }
    return $p
  }

  $p = & $get
  if (-not $p) { return }
  & $ps -NoProfile -ExecutionPolicy Bypass -File $p
  $code = $LASTEXITCODE
  if ($code -ne 1) { if (-not (Test-Path -LiteralPath $p)) { & $why }; return }
  # Exit 1 = HIGH findings. Never lose the Y question because the tool file vanished (2026-11-26).
  if (-not (Test-Path -LiteralPath $p)) {
    & $why
    Write-Host 'Muat turun semula supaya boleh bersihkan... (Downloading again so cleaning can still run...)' -ForegroundColor Cyan
    $p = & $get
    if (-not $p) { return }
  }
  if ((Read-Host 'Taip Y dan Enter untuk bersihkan') -eq 'Y') {
    & $ps -NoProfile -ExecutionPolicy Bypass -File $p -Fix
    if (-not (Test-Path -LiteralPath $p)) { & $why }
  }
}
