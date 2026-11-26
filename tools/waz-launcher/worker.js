// waz.afuit.dev: serve run.ps1 directly instead of redirecting to GitHub.
// Old Windows 10 PowerShell starts on TLS 1.0, which raw.githubusercontent.com refuses,
// so `irm waz.afuit.dev | iex` failed before run.ps1 could switch itself to TLS 1.2.
const SRC = 'https://raw.githubusercontent.com/afu-it/wa-zip-cleaner/main/run.ps1';

export default {
  async fetch() {
    const r = await fetch(SRC, { cf: { cacheTtl: 60, cacheEverything: true } });
    if (!r.ok) return new Response(`Write-Host 'waz.afuit.dev: GitHub error ${r.status}, try again in a minute.'`, { status: 502, headers: { 'content-type': 'text/plain; charset=utf-8' } });
    return new Response(r.body, { headers: { 'content-type': 'text/plain; charset=utf-8', 'cache-control': 'no-store' } });
  },
};
