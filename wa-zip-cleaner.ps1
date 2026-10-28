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
$Version = '2026.10.28'

# ---------------------------------------------------------------- IOCs ---
# Known bad files (SHA-256). Sizes let us skip hashing unrelated files.
$KnownBad = @(
  @{ Sha = '550d08c8459ef11e6177309526c0738848d064f7de5c91e0760255fc93159f99'; Size = 3141543;  Name = 'Lure ZIP (Click here to view*.zip)' }
  @{ Sha = '053432539a408652f1104aad3c9c4d72d9e68f530f509aa5c982c75451f71958'; Size = 18919424; Name = 'Lure VHD (Click here to view*.vhd)' }
  @{ Sha = '539b49f6ddfa070d25adbd8cd47c10bbba5cacf5bf27fddfe89d96f0c729b2fb'; Size = 3361792;  Name = 'Winos4.0 stager (fake rime.dll)' }
  @{ Sha = '12b9470634bb7f76419c70ee9a510147cd6bcfce920f2abee5afdd13901b383d'; Size = 6076;     Name = 'Encrypted payload (.dat)' }
  @{ Sha = '46883bc25c77678f60c1b836f4c438d87158c9af6b229f533522f635a0d5276e'; Size = 93664;    Name = 'AV-killer driver ZyArk.sys (Baidu BdArKit, abused)' }
  @{ Sha = 'c1e184615241fe69db3bf4093a22c7c0bf5d6072d2f51e558142b844e871084f'; Size = 5242880;  Name = 'SilverFox loader active_desktop_render_x64.dll (Pelagos, KuGou variant)' }
  @{ Sha = '38e37bdef23d31ca49c2b72effd4d46ab617b86a5227343a3e407cfb7af92971'; Size = 6787333; Name = 'Lure ZIP 20260921125639-A901C2F58FFEBD.zip (Triage, Sep 2026)' }
  @{ Sha = '9524d7051fde6bfcfb8a90c305994e66df20686bd06cdfa9173149db9eb05467'; Size = 6966908; Name = 'Lure ZIP 20260928011445-82407B6DADBFA0.zip (Triage, Sep 2026)' }
  @{ Sha = '88e32dfea6c94b16a89e9c3b66a01f5bc1c99b4abddb48060cbe5c06b77907d3'; Size = 2619192; Name = 'ValleyRAT dropper L3914012809.exe (Triage, Sep 2026)' }
  @{ Sha = 'ff5c63c88e165d842ca962c442dc6199e56f544b00d24c0580783771814f456e'; Size = 8263680; Name = 'ValleyRAT loader pdfcorE8.dll (Triage, Sep 2026)' }
  @{ Sha = '4dfce433a8cea1829fc8fc9d7284cb5fdb332695413923a7fa1b702fd637bcb3'; Size = 12928233; Name = 'Lure ZIP PDF_<Japanese name>.ZIP (Triage, Sep 2026)' }
  @{ Sha = '7aad062881f577d7bb560bb7288800a29e041b11b3aef3c0103d08659e894c5e'; Size = 3950592; Name = 'Lure disk image DX03_702A.img (Triage, Oct 2026)' }
  @{ Sha = '743cc997baf10e3a072cd5dc6d724b1127b59c4d201524eaab3df0ccde6cbd35'; Size = 1610752; Name = 'ValleyRAT loader desk_compositor_x64.dll (Triage, Oct 2026)' }
  @{ Sha = '7eca6ff78c9a067293de9ac651b8f1292acc5f098e8e97dcafa1bdef9b8a61c2'; Size = 108928; Name = 'ValleyRAT launcher, Chinese HR-notice name (Triage, Oct 2026)' }
  @{ Sha = '633700324ad7abdf0fcaee0498e4d3bef9093c51ee4d611e02303e0f8f1a58e2'; Size = 1559216; Name = 'ValleyRAT stage 2 exe (Triage, Oct 2026)' }
  @{ Sha = '25a87693ff2e67858bb5379f7f30092b1eba127307b0bcf24029d04911b6ebbe'; Size = 4444160; Name = 'Lure disk image, Japanese tax-report name (Triage, Sep 2026)' }
  @{ Sha = 'c09d9caef509f0f6001f1d3e3bb7f71d57aa77b7bfa751e198fe12c317cb77f2'; Size = 450192; Name = 'ValleyRAT launcher, Japanese tax-report name (Triage, Sep 2026)' }
  @{ Sha = '42f21f4389db441c9b57b765320ba628673bd9856002bb20f0359bfd783d48a9'; Size = 463904; Name = 'Encrypted payload _Top.dat (Triage, Sep 2026)' }
  @{ Sha = 'c5d9b6e889ac776410b9e70930bc12afa202843d8ec2aa971204c416a3251c76'; Size = 35896; Name = 'Encrypted payload _Bottom.dat (Triage, Sep 2026)' }
  @{ Sha = '29f67c17b528a877949878a3d0453a34c6f5eee7d872edd33c0996b057b56258'; Size = 726016; Name = 'Encrypted payload _Driver.cnf (Triage, Sep 2026)' }
  @{ Sha = '65662fbfee31784502f46a4ea3cf58a5146d6f6299b40391cd71c9fc67e3e621'; Size = 7107; Name = 'WhatsApp VBS lure Statement of Debt(30K).vbs (MyCERT MA-1464)' }
  @{ Sha = '3fb74a2ca0526e34eafa9060f4a548d6c60b79966f4ff9facf47098a3a0391e3'; Size = 6899; Name = 'WhatsApp VBS stage 2 spsx.vbs' }
  @{ Sha = 'c26a0e6c06cfaff5680d6ce03a1028dfe04259f0c568904dc6e3d6764a9951b1'; Size = 1193; Name = 'WhatsApp VBS stage 2 run.vbs' }
  @{ Sha = '3d1a86ad729817d85377f59c3d5dcc67ba59af9824ae64aea8e626f6a4956d52'; Size = 1592; Name = 'ManageEngine silent installer setup1.vbs' }
  @{ Sha = '7d266ee06799032bbd627e19d5dedeeb099deb9666d2557e487599dcd146e8bd'; Size = 32869697; Name = 'ManageEngine installer kit alOffic.zip / temp.zip' }
  @{ Sha = 'a8000f6bcf5b22fa1b27ca1901f743fe252cfae95b33aab58ac8f70e6755abb4'; Size = 32869803; Name = 'ManageEngine installer kit lose.zip' }
  @{ Sha = '74e58a7dc7b4d2395175bc4c46dd806ab5b7d0e8131944e953e2f73a2ab925dd'; Size = 900; Name = 'SORVEPOTEL lure COMPROVANTE_*.zip' }
  @{ Sha = '177bf59f3566ba84a15dfb29a944d256fd65f490f6e5b45b6c313eab60f31d8d'; Size = 1041; Name = 'SORVEPOTEL shortcut COMPROVANTE_*.lnk' }
  @{ Sha = '03f24d66323fd63b5f675dc48bb413ac688f93f55cd6ea1f72342cec7b795961'; Size = 32869803; Name = 'ManageEngine installer kit ffice.zip (WhatsApp VBS campaign, Triage)' }
  @{ Sha = '595d90dde0e74566397cffb01d51035336cca27124bea81f3c07179ed221a771'; Size = 32869805; Name = 'ManageEngine installer kit ficeo.zip (WhatsApp VBS campaign, Triage)' }
  @{ Sha = '6065297689a5072e649970a7b59cadb2201a257cd11261d361e884cda63d74d5'; Size = 32869794; Name = 'ManageEngine installer kit baollaaa.zip (WhatsApp VBS campaign, Triage)' }
  @{ Sha = 'd73ae223669bea2ffbb614fa947bc076a4d26894a0de87b1f0a9b64deddf678f'; Size = 32869800; Name = 'ManageEngine installer kit sunlloo.zip (WhatsApp VBS campaign, Triage)' }
  @{ Sha = 'e8e133c761d5aac5af8525286185dae8efe5963ebcd1eed8521682dce4713a8e'; Size = 32869690; Name = 'ManageEngine installer kit chrmgolm.zip (WhatsApp VBS campaign, Triage)' }
  @{ Sha = 'e7d45a098c6f6cc6f3732342a04a1623fd1600cbf89ed8b40ecff60a9550299e'; Size = 32869689; Name = 'ManageEngine installer kit LocOffice.zip (WhatsApp VBS campaign, Triage)' }
  @{ Sha = '3cd7b59ce013f160b2184c1c01c043a1e3be6b45e1f68fa87ced7d8782ab7517'; Size = 32869797; Name = 'ManageEngine installer kit 8aa.zip (WhatsApp VBS campaign, Triage)' }
  @{ Sha = '03643c2de44d47baf485ac13ef19ccd5fa57872b0b54fcc51e92bb1da102dd83'; Size = 32869812; Name = 'ManageEngine installer kit Lfic11e.zip (WhatsApp VBS campaign, Triage)' }
  @{ Sha = 'ef29a493709ee78d1e27d8146b7315b3a6f673e6f770696993b7712dab2b78e0'; Size = 32869796; Name = 'ManageEngine installer kit azhu.zip (WhatsApp VBS campaign, Triage)' }
  @{ Sha = '548736f279070da7d9c4681768e915dc5e8771980c90dd523389acd13871cc64'; Size = 32869799; Name = 'ManageEngine installer kit kioop.zip (WhatsApp VBS campaign, Triage)' }
  @{ Sha = 'fddab5f43dbec60c3a1820567319718a3054fa9a4417b589c4ffbfaa2b4a5691'; Size = 32869795; Name = 'ManageEngine installer kit xiaox.zip (WhatsApp VBS campaign, Triage)' }
  @{ Sha = 'c232666d44d6b4b22ec8f0b84fd9f3bf7d3a06fec40247c88e1f2b0784b75854'; Size = 32869799; Name = 'ManageEngine installer kit .bin (WhatsApp VBS campaign, Triage)' }
  @{ Sha = 'd32c6269361615085cf996dd14e0b2c0a07bd5c20dd6e384da55d79bb7a064b9'; Size = 32869805; Name = 'ManageEngine installer kit .bin (WhatsApp VBS campaign, Triage)' }
  @{ Sha = 'b988bc34d240204a586504d73a04b82e70fa71fab93e26ee85ca89cc1d26ffb8'; Size = 32870031; Name = 'ManageEngine installer kit .bin (WhatsApp VBS campaign, Triage)' }
  @{ Sha = 'f0ca28df5607f66448229439e0bd2adb0a3a134952ad83bb41aa5e45cdf9eed2'; Size = 32869811; Name = 'ManageEngine installer kit unnamed (WhatsApp VBS campaign, Triage)' }
  @{ Sha = '6d68cac0477bedd3fdac978e9553dcbac1719ddb1a2e5c5deeb8179f53dc2c80'; Size = 32799144; Name = 'ManageEngine installer kit 25405092496.zip (WhatsApp VBS campaign, Triage)' }
  @{ Sha = 'b57b23342e6d7dbaf4cebd3e3664bb2697eca3e8593aee6a81757cd30dbf6e92'; Size = 1670; Name = 'Attacker DCAgentServerInfo.json (WhatsApp VBS campaign)' }
  @{ Sha = '68eaeb29ad982b515ef13fcf731a60ec2b3c02e5be250a0099c7cff5fdc90048'; Size = 3950313; Name = 'Lure ZIP SENARAIDOKUMEN.zip (Triage, Oct 2026)' }
  @{ Sha = '5f7446871ba78c9c19eac3b5bbb1db62a983b754100e6d5b0b502966fdfa2e74'; Size = 3972897; Name = 'Lure ZIP SENARAIDOKUMEN.zip (Triage, Oct 2026)' }
  @{ Sha = 'a692da9f60b4eb890c8636bb57e380af7d6517835b863e66c81c3f8b00658cf1'; Size = 3868051; Name = 'Lure ZIP SENARAIDOKUMEN.zip (Triage, Oct 2026)' }
  @{ Sha = '355ee70e091b82b987d09db3cf8ba4176da316c220a72742f74a9e604199c79b'; Size = 411648; Name = 'Lure ISO LHDNCUKAI*.iso (Triage, Oct 2026)' }
  @{ Sha = '1b89fbcd8fdf994ca32c48889ba617919ee16443692b1cfc7a2b8f3f5518a2c9'; Size = 448512; Name = 'Lure ISO Open_to_view*.iso (Triage, Oct 2026)' }
  @{ Sha = 'de0b9b6656c9e9fc9db4271610a09c2ae27d07c5a4757e94b2e0314a9dda6ee4'; Size = 25672; Name = 'ValleyRAT launcher Open_to_view.exe (LHDN/Open_to_view ISOs, Oct 2026)' }
  @{ Sha = '5634caef6a5988f33d5116c74403892ddb648929983c52a6b9d7893ac5549401'; Size = 3041300; Name = 'Lure ZIP <date>-INVOIS_<n>.zip (Triage, Oct 2026)' }
  @{ Sha = '2db09f27b7f8b17dee095f71e65910864345659a7c4fe00d0fff30f95d0a8c57'; Size = 3347821; Name = 'Lure ZIP INVOIS.vhd.zip (Triage, Oct 2026)' }
  @{ Sha = '0569371406eeca4d84078be94c2be98916294b89a7121c1e757b687a5ccdfe30'; Size = 3170806; Name = 'Lure ZIP Memeriksa.vhd.zip (Triage, Oct 2026)' }
  @{ Sha = 'b46788cb5d9def3e1c7136de29eb8904ac9543b5c28035fb1fa0e9006c3aeb29'; Size = 13063; Name = 'Lure email NOTIS TUNTUTAN CUKAI DAN PENALTI.eml (Triage, Oct 2026)' }
  @{ Sha = '9eaa140159f6e91af428a5f3ae608a170346238eb4ebca27ed36cb791af8bfc4'; Size = 1766235; Name = 'Lure ZIP SSM-1.IMG.zip (Triage, Oct 2026)' }
  @{ Sha = '3a89fee824764cd99e6e0c7c7f1655bc2fe1bd41b79ab4f2eb0074e0e866fd9b'; Size = 4525653; Name = 'Lure ZIP PDF_32JG2C_*.ZIP (Triage, Oct 2026)' }
  @{ Sha = '23b927dd668e5707d1de867e9e3f6217ef8cfc6803d18ac9a168dcfc9416070b'; Size = 3140084; Name = 'Lure ZIP SOA.vhd.zip (Triage, Oct 2026)' }
  @{ Sha = '971eecc4288a550ff9606dd8af9601c10714f9e41a2d5fcac325647a0cdf0cd0'; Size = 18919424; Name = 'Lure VHD 10200944247016.*.vhd (Triage, Oct 2026)' }
  @{ Sha = '07806661d056305e832b509a1b517241420d8aa6bccadaff5e0768d5131406fd'; Size = 2009626; Name = 'Lure ZIP JK-18005144.zip (Notice from Tax Departmen.exe, Oct 2026)' }
  @{ Sha = '426bfd72b3143c76c83bfb3246f820e3cc17902ea04293a35764b67fc635ec3d'; Size = 655359; Name = 'ValleyRAT IRBM sample ZIP (Triage, Oct 2026)' }
  @{ Sha = 'e43c872558aeac504df57d7f292518086f61c8b5c4abf282576bcf6bd1cecbed'; Size = 1564951; Name = 'Lure ZIP TAX_*.img.zip (TaxFiling.exe, Oct 2026)' }
  @{ Sha = '2c77d954eb79cc5b038b024d84848360d496b51c85ac8e97399d70d1bc3d0413'; Size = 1288192; Name = 'ValleyRAT dropper, becomes WinCombo.exe (MicroPoint chain, Oct 2026)' }
  @{ Sha = '9f326ede322930a7d5e149fa8720802b0623c1972dc54e41a2a73608fb6810dd'; Size = 17224; Name = 'Unknown file dropped with ZyArk.sys (crClient chain, Oct 2026)' }
  @{ Sha = '701d51b7be8b034c860bf97847bd59a87dca8481c4625328813746964995b626'; Size = 16603648; Name = 'TCLBANKER loader (Elastic, Oct 2026)' }
  @{ Sha = '8a174aa70a4396547045aef6c69eb0259bae1706880f4375af71085eeb537059'; Size = 3844096; Name = 'TCLBANKER payload (Elastic, Oct 2026)' }
  @{ Sha = '668f932433a24bbae89d60b24eee4a24808fc741f62c5a3043bb7c9152342f40'; Size = 3845120; Name = 'TCLBANKER payload (Elastic, Oct 2026)' }
  @{ Sha = '3ba89047b9fb9ae2281e06a7f10a407698174b201f28fc1cadb930207254e485'; Size = 109848541; Name = 'Silver Fox installer (Chinese security reports, 2026)' }
  @{ Sha = '9ace6a1e4bee5834be38b4c2fd26780d1fcc18ea9d58224e31d6382c19e53296'; Size = 291328; Name = 'Silver Fox component (Chinese security reports, 2026)' }
  @{ Sha = 'a14b681ec50328d3ac04f76ac18ef96fb7176425ff96325e2099ea57df3a1998'; Size = 149504; Name = 'Silver Fox component (Chinese security reports, 2026)' }
  @{ Sha = 'ad91e674edb5f376d27a3c56df45ebb967229ee9ba623ec158f8c4835d577def'; Size = 1724051; Name = 'Lure ZIP, Japanese tax-report .img.zip (Triage, Sep 2026)' }
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
$PersistRegex ='rime\.dll|_vmclientcore@16|KafanInput|vcRuntimeMinimum_x86\.exe|\\H\d{8,}\.exe|ZyArk|\\ardrv\.sys|\\AppData\\Roaming\\Microsoft\\Update\\[^\\]+\.exe|active_desktop_(launcher|render)|Add-MpPreference|eneio64\.dat|plcc3a\.dat|-m\s+appclient|\\appclient\\python\\|HealthApp-[0-9a-f]{6}\.bat|\\ProgramData\\MicroPoint\\|WinCombo\.exe|CRClient\.dll|\\Toolkit\\winhttp\.dll|webview2_integration\.exe|encrashrep\.dll|\\ProgramData\\WindowsData\\|ExceptCatch\.dll|\\QNWallpaper\\|\\msvc-rt14\\|NtHandleCallback\.exe|\\(XiaoH|rwdriver|kabuto)\.sys'
$LureRegex    = '^(Click here to view.*\.(zip|vhd|vhdx)|Notice.*\.vhdx?|(PDF|DOC)_[A-Z0-9]{3,8}_20\d{12}\.(zip|img|iso|exe|vhd|vhdx)|20\d{6}[.-]MYS20\d{2}Y\d{4}[A-Z0-9]{4,6}\.(zip|img|iso|vhd|vhdx)|(RES-20\d{6}_\d{6}|ORCAMENTO_\d{6}|COMPROVANTE_20\d{6}_\d{6}|ComprovanteSantander-[\d.]+|NEW-20\d{6}_\d{6}-PED_[0-9A-F]+|DOC-\d{8}_[0-9A-F]{8})\.(zip|lnk)|20\d{12}-[0-9A-F]{14}\.zip|SENARAI ?DOKUMEN.*\.zip|.+\.(vhdx?|img|iso)\.zip|LHDN.*\.(iso|img|vhdx?)|Open_to_view.*\.(iso|img)|TAX_[A-Za-z0-9]{6,}\.img(\.zip)?|SSM-\d+\.img(\.zip)?)$'
# Programs the October 2026 wave tells Windows Defender to skip. No real program needs these excluded.
$ExclProcRegex = '(?i)^(QtsUpdater|svchost|rundll32|powershell|cmd|wscript|cscript|mshta|regsvr32|explorer)\.exe$'
# Known attacker servers (C2). A process talking to one of these is the malware.
# Kaspersky (Apr 2026): ValleyRAT and ABCDoor servers from the Silver Fox tax campaign.
$C2Ips = @('134.122.155.135', '14.128.53.155', '45.202.1.249', '108.187.37.85', '108.187.42.63', '207.56.138.28', '45.118.133.203', '154.82.81.205', '154.82.81.192', '108.187.41.221',
            '103.20.195.147', '45.207.231.94', '45.207.231.107', '160.124.9.103', '109.176.30.141',
            '202.61.160.208', '202.61.160.202', '202.61.160.201', '202.61.160.160', '202.61.160.137', '38.55.151.63', '61.18.208.27',
            '202.61.160.203', '202.61.160.145', '137.220.205.167', '137.220.205.162', '137.220.224.63', '103.140.154.117', '206.238.68.33', '43.224.224.151',
            '165.154.254.44', '23.227.203.148', '77.111.101.169', '23.227.203.179', '140.99.164.81', '92.246.130.15',  # SORVEPOTEL (Trend Micro); last four: CloudSEK, Dec 2025
            '202.61.85.151', '202.61.85.179', '202.61.85.173', '202.61.85.47', '87.84.204.93', '156.251.11.79', '137.220.152.244', '154.213.180.91', '137.220.153.147',
            '202.146.222.95', '202.61.157.33', '202.61.160.183', '101.33.117.120', '143.109.37.187', '47.243.109.132', '204.194.50.231',
            '143.92.37.168', '103.45.66.18', '192.253.225.173', '154.201.87.124', '191.96.224.96',
            '38.91.115.114', '8.210.25.225', '95.40.29.190', '16.163.105.153', '183.90.186.193', '52.128.226.74', '154.83.17.175', '45.204.2.166')
# Added Oct 2026: Triage/ThreatFox ValleyRAT (Malaysian lures), Netresec Ping32 (143.92.37.168), Kaspersky QN Wallpaper,
# Sekoia (Malaysia), Elastic TCLBANKER, and Chinese reports (ThreatBook, Huorong, QiAnXin).
$C2Domains = '(?i)(^|\.)(fetish-friends\.com|3mkorealtd\.com|sudsmama\.com|woopami\.com|ilptour\.com|petitechanson\.com|doublemobile\.com|mcagov\.cc|roldco\.com|kcii2\.com|haijing88\.com|ggwk\.cc|yuxuanow\.top|itdd\.club|xzghjec\.com|gov-a\.(work|fit|club)|gvo-b\.club|gov-c\.club|govk\.club|swjc2025bjkb\.cn|2025swmm\.cn|zapgrande\.com|sorvetenopo(a)?te\.com|sorvetenoopote\.com|sorvetenopotel\.com|etenopote\.com|expa(h)?nsiveuser\.com|expansivebot\.com|imobiliariaricardoparanhos\.com|casadecampoamazonas\.com|bravexolutions\.com|adoblesecuryt\.com|saogeraldoshoping\.com|baskwms\.top|msopsa\.top|shoppes\.help|shaaslong\.one|baoxis\.cc|kammwv\.cc|azuheq\.s3\.ap-southeast-1\.amazonaws\.com|d156sk07toobyl\.cloudfront\.net|neescil\.top|velthora\.top|sinjiabo-1398259625\.cos\.ap-singapore\.myqcloud\.com|(bafauac|9ding)\.s3\.ap-southeast-1\.amazonaws\.com|(baolongwes|sdcwww)\.oss-ap-southeast-1\.aliyuncs\.com|(baoyuw2s|hksha3|sjdkjj23|xijkwm2|yifubafu)\.s3\.ap-southeast-1\.amazonaws\.com|(caiwuascw|facaia)\.s3\.us-east-005\.backblazeb2\.com|khltt1\.club|lsf168\.club|pxxjbh\.club|liyunee\.top|articio\.top|kyur7oz\.top|uykb10\.club|gntr30\.club|kufp16\.club|txpfproxy\.vip|jksdjkjs\.cc|shougong9\.com|thinnected\.com|tax(cerf|low|gg|zz|yy)\.top|fadaoxiao\.s3\.us-west-004\.backblazeb2\.com|xqwmwru\.top|360sdgg\.com|ef971a42\.workers\.dev|mxtestacionamentos\.com|uuuucome\.com|laosjdhd\.cn|xxxjjj250711\.com|twsww\.xin|cn-hk-oss-vip\.com)$'
# Silver Fox fake-document programs (Kaspersky, Apr 2026: Statement of Account / GST / tax lures).
$ExeLureRegex = '(?i)^(Statement|Tax-\d{8,}|Review the file|BillReceipt|statement verify ?|Click File|GST ?Suvidha|Related material|MCA-Ministry|RemoteInstaller_[\d_]+_\w+|Open_to_view|TaxFiling|Notice from Tax Depart\w*)\.exe$'
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
  'Ping32' = '^nsecrts'
}
# Browsers whose profiles we check. Chromium ones keep profiles under User Data; Opera keeps one in its own folder.
$BrowserRoots = @(
  @{ Name = 'Chrome'; Dir = 'AppData\Local\Google\Chrome\User Data'; Proc = 'chrome'; Policy = 'Google\Chrome' }
  @{ Name = 'Edge'; Dir = 'AppData\Local\Microsoft\Edge\User Data'; Proc = 'msedge'; Policy = 'Microsoft\Edge' }
  @{ Name = 'Brave'; Dir = 'AppData\Local\BraveSoftware\Brave-Browser\User Data'; Proc = 'brave'; Policy = 'BraveSoftware\Brave' }
  @{ Name = 'Opera'; Dir = 'AppData\Roaming\Opera Software\Opera Stable'; Proc = 'opera'; Policy = $null }
)
$VbsLureRegex = '(?i)(Statement|Debt|Hutang|Outstanding|Balance Sheet|Financial ?Report|Penyata|Invoice|Invois|Payment|Billing|Sila semak|Promissory|Reconciliation|Acknowledg|Application ?form|Income Tax|Cukai|Work Snapshot|Salary|Gaji|Claim|Tuntutan|LHDN|KWSP|EPF).*\.(vbs|vbe|js|wsf)$'

# ------------------------------------------------------------- helpers ---
function Say([string]$ms, [string]$en, [string]$color = 'Gray') {
  Write-Host "$ms" -ForegroundColor $color
  Write-Host "  ($en)" -ForegroundColor DarkGray
}

$Findings = New-Object System.Collections.Generic.List[object]
$DefExclLeft = @()
# ManageEngine pieces that can outlive the agent folder (user reports, Oct 2026).
$MeSvcRegex = '(?i)^MEARW?Service$'
$MeRegKeys = 'HKLM:\SOFTWARE\ManageEngine', 'HKLM:\SOFTWARE\WOW6432Node\ManageEngine', 'HKLM:\SOFTWARE\AdventNet', 'HKLM:\SOFTWARE\WOW6432Node\AdventNet'
$SvcLeft = @()
$NeedRestart = $false
# A deleted service stays listed until the next restart, with DeleteFlag set.
function Test-ServicePendingDelete($name) {
  (Get-ItemProperty -LiteralPath "HKLM:\SYSTEM\CurrentControlSet\Services\$name" -ErrorAction SilentlyContinue).DeleteFlag -eq 1
}
function Add-Finding($Kind, $Severity, $Target, $Detail, $Extra = $null) {
  $key = "$Kind|$Target"
  if ($Findings | Where-Object { "$($_.Kind)|$($_.Target)" -eq $key }) { return }
  $Findings.Add([pscustomobject]@{ Kind = $Kind; Severity = $Severity; Target = $Target; Detail = $Detail; Extra = $Extra })
}

# Plain-Malay meaning and next step for each warning, shown under the English detail.
# A warning is something the tool will not remove by itself, so the user has to decide.
$WarnHelp = @(
  ,@('downloaded from WhatsApp Web', 'Fail ni dimuat turun dari WhatsApp Web. Malware ZIP WhatsApp sampai dengan cara ni.', 'Kalau anda tak minta fail ni atau tak kenal pengirim: padam dia. Kalau dah buka dan ada program atau VHD di dalam, jalankan tool ni dan taip Y.')
  ,@('Malware program ran', 'Rekod Windows tunjuk program malware ni pernah jalan di PC ni. Failnya mungkin dah dipadam, tapi PC ni pernah dijangkiti.', 'Jalankan tool ni dan taip Y untuk bersihkan. Tukar kata laluan bank dan emel guna telefon. Kalau tak pasti, backup dokumen dan format PC.')
  ,@('Defender detected', 'Windows Defender pernah jumpa virus di PC ni dalam 30 hari lepas.', 'Kalau nama virus tu ada ValleyRAT, Winos, Rozena atau Trojan: anggap PC pernah dijangkiti. Jalankan tool ni dan taip Y, kemudian tukar kata laluan guna telefon.')
  ,@('real-time protection was turned off', 'Perlindungan antivirus pernah dimatikan. Malware buat ni sebelum pasang dirinya.', 'Pastikan dia hidup semula: Windows Security > Virus & threat protection > Manage settings > Real-time protection: On. Lepas tu buat Full scan.')
  ,@('Defender exclusion added', 'Ada program suruh antivirus abaikan folder atau program ni. Malware buat ni supaya dia tak diperiksa.', 'Kalau bukan anda yang tambah: Windows Security > Virus & threat protection > Manage settings > Exclusions > Remove. Tool ni dah buang yang dia kenal sebagai jahat.')
  ,@('Ping32', 'Program kawalan jauh Ping32. Syarikat kadang pasang untuk pantau PC staf. Kalau PC sendiri, penggodam yang pasang (versi lain kempen VBS WhatsApp) untuk kawal PC anda.', 'Kalau bukan office yang pasang: jalankan tool sekali lagi, pilih "PC sendiri" bila ditanya, kemudian taip Y. Tool akan buang dia.')
  ,@('Firewall blocks', 'Firewall disuruh sekat semua sambungan keluar. Malware buat ni supaya antivirus tak dapat update atau hantar amaran, tapi benarkan dirinya sendiri.', 'Kalau bukan anda atau IT yang tetapkan: Windows Security > Firewall & network protection > Restore firewalls to default > Restore.')
  ,@('VulcanRAT', 'Fail driver sementara dalam folder driver Windows. VulcanRAT guna fail macam ni untuk matikan antivirus.', 'Hantar screenshot kepada orang IT. Kalau ada juga merah [HIGH], taip Y untuk bersihkan, kemudian restart.')
  ,@('ManageEngine UEMS', 'Program kawalan jauh. Office kadang pasang untuk urus PC staf. Kalau PC sendiri, penggodam yang pasang untuk kawal PC anda.', 'Kalau bukan office yang pasang: jalankan tool sekali lagi, pilih "PC sendiri" bila ditanya, kemudian taip Y.')
  ,@('Remote-control program', 'Program kawalan jauh (contoh AnyDesk, UltraViewer). Sesiapa yang ada akses boleh guna PC anda dari jauh.', 'Kalau anda tak pasang sendiri: Settings > Apps > cari nama program tu > Uninstall.')
  ,@('Admin permission prompt', 'Tetingkap "Benarkan program ni buat perubahan?" dah dimatikan. Program boleh pasang diri tanpa tanya anda.', 'Taip UAC dalam carian Windows > Change User Account Control settings > naikkan slider satu tingkat > OK.')
  ,@('Attacker server looked up', 'PC ni pernah cuba hubungi server penggodam baru-baru ini.', 'Anggap PC dijangkiti. Tukar kata laluan guna telefon. Paling selamat: backup dokumen dan format.')
  ,@('Windows Update is disabled', 'Windows Update dimatikan. Malware buat ni supaya Windows tak dapat pembaikan keselamatan.', 'Kalau bukan anda yang matikan: taip services.msc dalam carian > Windows Update > Startup type: Manual > OK.')
  ,@('Blocklist is OFF', 'Perlindungan Windows yang sekat driver bahaya dimatikan.', 'Windows Security > Device security > Core isolation details > hidupkan Microsoft Vulnerable Driver Blocklist > restart.')
  ,@('DefExcl', 'Antivirus disuruh abaikan folder ni, jadi fail dalam tu tak diperiksa.', 'Kalau bukan anda yang tetapkan: Windows Security > Virus & threat protection > Manage settings > Exclusions > Remove.')
  ,@('extension|Extension', 'Browser dipaksa pasang extension, atau extension dipasang dari folder (bukan kedai rasmi). Extension boleh baca semua laman yang anda buka.', 'Biasa di PC office. Kalau PC sendiri: buang di browser > Extensions, atau jalankan tool semula dan pilih "PC sendiri".')
  ,@('Selenium|chromedriver', 'Alat untuk kawal Chrome secara automatik. Worm WhatsApp guna ni untuk hantar mesej kepada semua kenalan anda.', 'Kalau anda bukan programmer: padam fail atau folder tu.')
  ,@('VHD|virtual disk', 'Fail cakera maya. Malware ZIP WhatsApp sorok dirinya dalam fail macam ni.', 'Kalau bukan anda yang buat: padam fail tu (kalau ia sedang dibuka sebagai drive, Eject dulu).')
  ,@('driver|Driver', 'Driver lama yang ada lubang keselamatan. Penggodam guna driver macam ni untuk matikan antivirus.', 'Kalau tak kenal program yang pasang driver ni: Settings > Apps > uninstall program tu. Kalau tak pasti, hantar screenshot kepada orang IT.')
  ,@('rime\.dll|Hidden\+System', 'Fail yang menyamar atau tersorok dalam folder anda. Cara ni biasa diguna malware Winos.', 'Kalau tak kenal fail tu: padam. Kalau tak pasti, hantar screenshot kepada orang IT.')
  ,@('Logon script|script interpreter', 'Ada skrip yang jalan sendiri setiap kali PC hidup atau log masuk.', 'Biasa di PC office. Kalau PC sendiri dan anda tak kenal skrip tu, hantar screenshot kepada orang IT.')
  ,@('Console', 'Ada data pelik dalam registry, di tempat yang malware Winos guna untuk simpan dirinya.', 'Hantar screenshot kepada orang IT. Kalau ada juga merah [HIGH], taip Y untuk bersihkan.')
)
function Get-WarnHelp($f) {
  $txt = "$($f.Kind)|$($f.Target)|$($f.Detail)"
  foreach ($h in $WarnHelp) { if ($txt -match $h[0]) { return $h } }
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

# Windows tags each download with the page it came from (Zone.Identifier). web.whatsapp.com there
# ties a file to WhatsApp Web even after it was renamed or unpacked.
function Test-WaOrigin([System.IO.FileInfo]$f) {
  if ($f.FullName -notmatch '(?i)^[a-z]:\\Users\\[^\\]+\\(Downloads|Desktop|Documents)\\') { return $false }
  $z = Get-Content -LiteralPath $f.FullName -Stream Zone.Identifier -ErrorAction SilentlyContinue
  [bool]($z | Where-Object { $_ -match '(?i)^(HostUrl|ReferrerUrl)=(blob:)?https?://web\.whatsapp\.com' })
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
  # ThreatBook / Huorong (2026): Silver Fox keeps its settings in these keys.
  foreach ($k in 'HKLM:\SOFTWARE\JDBCC', 'HKLM:\SOFTWARE\WOW6432Node\JDBCC', 'HKLM:\SOFTWARE\SysConfigDate', 'HKLM:\SOFTWARE\WOW6432Node\SysConfigDate') {
    if (Test-Path -LiteralPath $k) { Add-Finding 'RegKey' 'HIGH' $k 'Silver Fox settings key (Chinese security reports, 2026).' }
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
    # Triage (Oct 2026, SSM/SOA lures): a driver loaded straight out of a Temp folder is the antivirus killer.
    elseif ($name -eq 'EmbeddedDriverService' -or $img -match '(?i)\\Temp\\[^\\]+\.sys"?$') { $hit = "Driver loaded from a Temp folder (antivirus killer): $img" }
    elseif ($name -match '^(TCLService|Cndom6)$' -and $img -notmatch '(?i)\\Program Files') { $hit = "Silver Fox service (Chinese security reports): $img" }
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
  # VulcanRAT (Morphisec, Oct 2026) drops its driver as drivers\tp_<tick>.tmp.
  foreach ($t in Get-ChildItem -LiteralPath "$env:SystemRoot\System32\drivers" -Filter 'tp_*.tmp' -File -Force -ErrorAction SilentlyContinue) {
    Add-Finding 'File' 'WARN' $t.FullName 'Temporary driver file in the Windows drivers folder (VulcanRAT uses this name).'
  }
  # Huorong (2026): the AV killer sets the firewall to block everything going out, then allows itself.
  foreach ($fp in Get-NetFirewallProfile -ErrorAction SilentlyContinue | Where-Object { [string]$_.DefaultOutboundAction -eq 'Block' }) {
    Add-Finding 'Info' 'WARN' "Firewall blocks all outgoing connections ($($fp.Name))" 'Silver Fox does this so antivirus cannot update. Unless you or your IT set it, restore the firewall defaults: Windows Security > Firewall & network protection > Restore firewalls to default.'
  }
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
    # VulcanRAT (Morphisec via 2-Spyware, Oct 2026) hides as a fake Windows update task that runs vulkaninfo.
    # Chinese reports (2026) and Elastic TCLBANKER: task names that copy Edge, WMI or runtime updaters.
    if ($txt -notmatch $PersistRegex -and (($t.TaskPath -match '(?i)\\Microsoft\\Windows\\AppID\\$' -and $t.TaskName -match '^MicrosoftEdgeUpdateTaskUA') -or $t.TaskName -match '^(WindowsPowerShell\.WbemScripting\.WindowsData|RuntimeOptimizeService)$')) {
      Add-Finding 'Task' 'HIGH' "$($t.TaskPath)$($t.TaskName)" "Fake system task (Silver Fox): $txt" @{ Path = $t.TaskPath; Name = $t.TaskName } }
    if ($txt -notmatch $PersistRegex -and ($t.TaskName -match '^USOPrivate( Kit)?$' -or $txt -match '(?i)\\Common Files\\vulkaninfo')) { Add-Finding 'Task' 'HIGH' "$($t.TaskPath)$($t.TaskName)" "Fake Windows update task (VulcanRAT): $txt" @{ Path = $t.TaskPath; Name = $t.TaskName } }
  }
  # Microsoft (Mar 2026): the WhatsApp VBS dropper's reg add leaves a junk key that Windows never creates.
  if (Test-Path -LiteralPath 'HKLM:\SOFTWARE\Microsoft\Win') { Add-Finding 'RegKey' 'HIGH' 'HKLM:\SOFTWARE\Microsoft\Win' 'Junk registry key left by the WhatsApp VBS dropper (Microsoft, Mar 2026).' }
  foreach ($v in 'vulkaninfo-64.exe', 'vulkan-1.bin', 'vulkan-1.dll') {
    $p = Join-Path $env:CommonProgramFiles $v
    if (Test-Path -LiteralPath $p) { Add-Finding 'File' 'HIGH' $p 'VulcanRAT sideloading file in Common Files (WhatsApp Statement.exe lure).' }
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
    # Triage (Oct 2026, MicroPoint chain): a per-user CLSID with Shell\Manage\command runs the malware elevated
    # through explorer.exe shell:::{GUID}, skipping the admin prompt.
    foreach ($c in Get-ChildItem -LiteralPath "$hive\Software\Classes\CLSID" -ErrorAction SilentlyContinue) {
      $cmd = Get-Item -LiteralPath "$($c.PSPath)\Shell\Manage\command" -ErrorAction SilentlyContinue
      if (-not $cmd) { continue }
      $v = [string]$cmd.GetValue('')
      if ($v -match $PersistRegex -or $v -match '(?i)\\(ProgramData|Users|AppData|Temp)\\') {
        Add-Finding 'RegKey' 'HIGH' ($c.PSPath -replace '^Microsoft\.PowerShell\.Core\\Registry::', 'Registry::') "Hidden admin-prompt bypass runs: $v"
      }
    }
  }
  # Fixed paths from Triage, Kaspersky, Sekoia and Chinese reports (Oct 2026).
  $fixed = [ordered]@{
    "$env:ProgramData\MicroPoint" = 'ValleyRAT install folder (LHDN/tax lures, Oct 2026).'
    "$env:ProgramData\WindowsData" = 'Silver Fox work folder (ThreatBook / QiAnXin reports).'
    "$env:ProgramFiles\QNWallpaper" = 'Fake wallpaper program that carries ValleyRAT (Kaspersky, Aug 2026).'
    "$env:SystemRoot\System32\CRClient.dll" = 'Fake CRClient.dll in System32 (ValleyRAT, SENARAIDOKUMEN lure).'
    "$env:SystemDrive\XiaoH.sys" = 'Silver Fox antivirus-killer driver.'
    "$env:SystemRoot\Temp\ranchserv.jpg" = 'Silver Fox payload disguised as a picture.'
    "$env:SystemDrive\Users\Public\Download\bb.jpg" = 'ValleyRAT payload disguised as a picture (Sekoia, Malaysia).'
    "$env:SystemDrive\WhatsAppBackup\WhatsAppData.zip" = 'Stolen WhatsApp data packed for upload (Sekoia, Malaysia).'
  }
  foreach ($p in $fixed.Keys) { if (Test-Path -LiteralPath $p) { Add-Finding 'File' 'HIGH' $p $fixed[$p] } }
  foreach ($u in Get-ChildItem "$env:SystemDrive\Users" -Directory -ErrorAction SilentlyContinue) {
    $ac = Join-Path $u.FullName 'AppData\Local\appclient'
    if ((Test-Path -LiteralPath "$ac\python\pythonw.exe") -or (Test-Path -LiteralPath "$ac\update.bat")) {
      Add-Finding 'File' 'HIGH' $ac 'ABCDoor backdoor folder (Python remote-control malware, Silver Fox).'
    }
    $el = Join-Path $u.FullName 'AppData\Local\applogs\exception_logs.zip'
    if (Test-Path -LiteralPath $el) { Add-Finding 'File' 'HIGH' $el 'ABCDoor error log.' }
    $wh = Join-Path $u.FullName 'AppData\Local\Toolkit\winhttp.dll'
    if (Test-Path -LiteralPath $wh) { Add-Finding 'File' 'HIGH' $wh 'Fake winhttp.dll (ValleyRAT, LHDN/Open_to_view ISO lures).' }
    $wl = Join-Path $u.FullName 'AppData\Local\Temp\whatsapp_backup.lock'
    if (Test-Path -LiteralPath $wl) { Add-Finding 'File' 'HIGH' $wl 'Marker left while stealing WhatsApp data (Sekoia, Malaysia).' }
  }
  Scan-DefenderExclusions
  Scan-DefenderHistory
  Scan-RanPrograms
  $startups = @("$env:ProgramData\Microsoft\Windows\Start Menu\Programs\StartUp")
  $startups += Get-ChildItem "$env:SystemDrive\Users" -Directory -ErrorAction SilentlyContinue |
    ForEach-Object { Join-Path $_.FullName 'AppData\Roaming\Microsoft\Windows\Start Menu\Programs\Startup' }
  foreach ($s in $startups) {
    Get-ChildItem -LiteralPath $s -File -ErrorAction SilentlyContinue | ForEach-Object {
      $body = ''
      if ($_.Extension -match '\.(bat|cmd|vbs|js|ps1|lnk)$') { $body = [IO.File]::ReadAllText($_.FullName) -replace "`0", '' }
      if ("$($_.Name) $body" -match $PersistRegex) { Add-Finding 'File' 'HIGH' $_.FullName 'Startup folder entry pointing at malware.' }
      # SORVEPOTEL's startup .bat builds a hidden PowerShell command out of for-loops plus base64.
      elseif ($body -match '(?i)for\s+%{1,2}\w+\s+in' -and $body -match '[A-Za-z0-9+/]{40,}') { Add-Finding 'File' 'HIGH' $_.FullName 'Startup script that hides a PowerShell command (SORVEPOTEL WhatsApp worm).' }
    }
  }
}

# The malware tells Windows Defender to ignore svchost.exe/QtsUpdater.exe, so antivirus scans come back clean.
function Scan-DefenderExclusions {
  $policy = @{}
  $mp = try { Get-MpPreference -ErrorAction Stop } catch { $null }
  # Huorong (2026): the AV killer excludes every drive. Build machines often skip C:\ and D:\, so it takes three
  # drives, or the system drive together with cmd/powershell/wscript, before it counts.
  $driveRx = '^[A-Za-z]:\\?$'
  $pk = 'HKLM:\SOFTWARE\Policies\Microsoft\Windows Defender\Exclusions\Paths'
  $pnames = if (Test-Path -LiteralPath $pk) { @((Get-Item -LiteralPath $pk).GetValueNames()) } else { @() }
  $roots = @(@($pnames) + @($mp.ExclusionPath) | Where-Object { $_ -match $driveRx } | ForEach-Object { $_.Substring(0, 1).ToUpper() } | Sort-Object -Unique)
  $lolExcl = @($mp.ExclusionProcess) | Where-Object { $_ -and (Split-Path $_ -Leaf) -match '(?i)^(cmd|powershell|wscript|cscript|mshta)\.exe$' }
  $badRoot = { param($v) $v -match $driveRx -and ($roots.Count -ge 3 -or ($lolExcl -and $v.Substring(0, 1) -ieq $env:SystemDrive.Substring(0, 1))) }
  foreach ($kind in 'Processes', 'Paths') {
    $k = "HKLM:\SOFTWARE\Policies\Microsoft\Windows Defender\Exclusions\$kind"
    if (-not (Test-Path -LiteralPath $k)) { continue }
    foreach ($n in (Get-Item -LiteralPath $k).GetValueNames()) {
      $policy[$n] = $true
      $bad = if ($kind -eq 'Processes') { (Split-Path $n -Leaf) -match $ExclProcRegex -or $n -match $PersistRegex } else { $n -match '(?i)\\AppData\\Roaming\\Microsoft\\Update' -or $n -match $PersistRegex -or (& $badRoot $n) }
      if ($bad) { Add-Finding 'RegValue' 'HIGH' "$k|$n" 'Windows Defender policy told to ignore this (malware hiding from antivirus).' }
    }
  }
  if (-not $mp) { return }
  foreach ($v in @($mp.ExclusionProcess) | Where-Object { $_ -and -not $policy[$_] }) {
    if ((Split-Path $v -Leaf) -match $ExclProcRegex -or $v -match $PersistRegex) {
      Add-Finding 'DefExcl' 'HIGH' "Process|$v" 'Windows Defender told to ignore this program (malware hiding from antivirus).' @{ Type = 'Process'; Value = $v }
    }
  }
  # Windows' own script runners excluded too ($lolExcl) means the user-folder exclusion is the malware's, not the owner's.
  foreach ($v in @($mp.ExclusionPath) | Where-Object { $_ -and -not $policy[$_] }) {
    if ($v -match '(?i)\\AppData\\Roaming\\Microsoft\\Update' -or $v -match $PersistRegex) {
      Add-Finding 'DefExcl' 'HIGH' "Path|$v" 'Windows Defender told to ignore this folder (malware hiding from antivirus).' @{ Type = 'Path'; Value = $v }
    } elseif (& $badRoot $v) {
      Add-Finding 'DefExcl' 'HIGH' "Path|$v" "Windows Defender told to skip the whole $v drive (malware hiding from antivirus)." @{ Type = 'Path'; Value = $v }
    } elseif ($lolExcl -and $v -match '(?i)^[a-z]:\\Users\\|%(APPDATA|LOCALAPPDATA|TEMP|USERPROFILE)%') {
      Add-Finding 'DefExcl' 'HIGH' "Path|$v" 'Windows Defender told to skip this user folder, together with cmd/powershell/wscript (malware hiding from antivirus).' @{ Type = 'Path'; Value = $v }
    } elseif ($v -match '(?i)^[a-z]:\\Users\\|%(APPDATA|LOCALAPPDATA|TEMP|USERPROFILE)%') {
      Add-Finding 'DefExcl' 'WARN' "Path|$v" 'Windows Defender skips this user folder. Remove the exclusion unless you added it yourself.' @{ Type = 'Path'; Value = $v }
    }
  }
}

# Defender's own log keeps what it found, when it was switched off and which exclusions were added,
# even after the malware removed its exclusions again. Only events since the last clean-up count.
function Scan-DefenderHistory {
  $ev = @(try { Get-WinEvent -FilterHashtable @{ LogName = 'Microsoft-Windows-Windows Defender/Operational'; Id = 1116, 1117, 5001, 5007; StartTime = $HistorySince } -MaxEvents 500 -ErrorAction Stop } catch { })
  $det = [ordered]@{}; $rtp = @()
  foreach ($e in $ev) {
    $d = @{}
    try { foreach ($n in ([xml]$e.ToXml()).Event.EventData.Data) { $d[[string]$n.Name] = [string]$n.'#text' } } catch { continue }
    $when = $e.TimeCreated.ToString('yyyy-MM-dd')
    if ($e.Id -in 1116, 1117) {
      $t = $d['Threat Name']; if (-not $t) { continue }
      if (-not $det.Contains($t)) { $det[$t] = @{ Count = 0; Last = $when; Path = ($d['Path'] -replace '^\w+:_', '') } }
      $det[$t].Count++
    } elseif ($e.Id -eq 5001) { $rtp += $when }
    elseif ($e.Id -eq 5007 -and -not $d['Old Value'] -and $d['New Value'] -match '(?i)\\Exclusions\\(Paths|Processes|Extensions)\\(.+?) = ') {
      Add-Finding 'Info' 'WARN' "Defender exclusion added: $($Matches[2])" "Added on $when. If it is no longer in the exclusion list, it was removed since."
    }
  }
  foreach ($t in $det.Keys) {
    Add-Finding 'Info' 'WARN' "Defender detected: $t" "Windows Defender found this $($det[$t].Count) time(s), last on $($det[$t].Last): $($det[$t].Path)"
  }
  if ($rtp) { Add-Finding 'Info' 'WARN' 'Defender real-time protection was turned off' "Last on $($rtp[0]) ($($rtp.Count) time(s) since $($HistorySince.ToString('yyyy-MM-dd')))." }
}

# Windows remembers which programs ran (Program Compatibility Assistant list on Windows 11, and
# Prefetch), even when the file is gone. A known malware name there means it ran on this PC.
function Test-MalwareRun([string]$path) {
  $leaf = Split-Path $path -Leaf
  $path -match $PersistRegex -or $path -match $StageRegex -or $leaf -match $ExeLureRegex -or $leaf -match $LureRegex -or
  $path -match '(?i)\\Common Files\\vulkaninfo' -or
  $path -match '(?i)\\5319275A\.WhatsAppDesktop_[^\\]+\\LocalState\\Sessions\\[^\\]+\\Transfers\\[^\\]+\.(exe|scr)$'
}
function Scan-RanPrograms {
  $pca = if ($env:WAZIP_TEST_PCA) { $env:WAZIP_TEST_PCA } else { "$env:SystemRoot\appcompat\pca\PcaAppLaunchDic.txt" }
  foreach ($line in @(Get-Content -LiteralPath $pca -ErrorAction SilentlyContinue)) {
    $path, $ts = ([string]$line).Trim() -split '\|', 2
    if (-not $path -or -not (Test-MalwareRun $path)) { continue }
    $when = [datetime]::MinValue
    # PCA times are UTC.
    if (-not [datetime]::TryParse([string]$ts, [Globalization.CultureInfo]::InvariantCulture, [Globalization.DateTimeStyles]::AssumeUniversal, [ref]$when)) { $when = Get-Date }
    if ($when -lt $HistorySince) { continue }
    Add-Finding 'Info' 'WARN' "Malware program ran: $path" "Windows records show it ran on $($when.ToString('yyyy-MM-dd')) (the file may already be deleted)."
  }
  # Prefetch names are PROGRAM.EXE-1A2B3C4D.pf; the file's write time is the last run.
  $pf = if ($env:WAZIP_TEST_PREFETCH) { $env:WAZIP_TEST_PREFETCH } else { "$env:SystemRoot\Prefetch" }
  foreach ($f in Get-ChildItem -LiteralPath $pf -Filter *.pf -File -ErrorAction SilentlyContinue | Where-Object { $_.LastWriteTime -ge $HistorySince }) {
    $exe = $f.Name -replace '-[0-9A-F]{8}\.pf$', ''
    if ($exe -match '(?i)\.(exe|scr)$' -and (Test-MalwareRun "\$exe")) {
      Add-Finding 'Info' 'WARN' "Malware program ran: $exe" "Windows Prefetch shows it ran, last on $($f.LastWriteTime.ToString('yyyy-MM-dd')) (the file may already be deleted)."
    }
  }
}

function Scan-Files {
  Say '[5/8] Imbas fail (boleh ambil 2-10 minit)...' '[5/8] Scanning files (can take 2-10 minutes)...' Cyan
  # ProgramData is walked one level down so Docker's Windows container layers (docker\windowsfilter,
  # tens of thousands of copied Windows files) are skipped. Top-level files are still checked.
  $roots = @(Get-ChildItem -LiteralPath $env:ProgramData -Force -ErrorAction SilentlyContinue | Where-Object { $_.Name -ne 'docker' } | ForEach-Object { $_.FullName })
  $roots += "$env:ProgramData\docker\config", "$env:SystemDrive\Users\Public", "$env:SystemRoot\Temp"
  foreach ($u in Get-ChildItem "$env:SystemDrive\Users" -Directory -ErrorAction SilentlyContinue) {
    $roots += 'Downloads', 'Desktop', 'Documents', 'AppData\Roaming', 'AppData\Local\Temp', 'AppData\Local\Packages' |
      ForEach-Object { Join-Path $u.FullName $_ }
  }
  $exts = '\.(zip|rar|7z|vhd|vhdx|img|iso|dll|exe|scr|dat|cnf|sys|tar|vbs|vbe|js|wsf|lnk|msi|mst|key)$|^DCAgentServerInfo\.json$'
  $wsh = New-Object -ComObject WScript.Shell
  # WAZIP_TIMING=1 prints how long each folder takes (used to find slow folders on CI and real PCs).
  foreach ($r in $roots | Where-Object { Test-Path -LiteralPath $_ }) {
    $sw = [Diagnostics.Stopwatch]::StartNew(); $tn = 0
    Get-ChildItem -LiteralPath $r -Recurse -File -Force -ErrorAction SilentlyContinue |
      Where-Object { $_.Name -match $exts } | ForEach-Object {
        $f = $_
        $tn++
        $ioc = Get-Ioc $f
        if ($ioc -and $ioc.Bad) { Add-Finding 'File' 'HIGH' $f.FullName "Known malware: $($ioc.Name)"; return }
        if ($ioc -and -not $ioc.Bad -and $f.FullName -notmatch [regex]::Escape($ioc.Vendor)) {
          Add-Finding 'File' 'HIGH' $f.FullName "Legit file abused by malware, in wrong place: $($ioc.Name)"; return }
        # SORVEPOTEL (Trend Micro, Oct 2025): a shortcut named like a document that runs hidden
        # cmd/PowerShell to download the next stage.
        if ($f.Extension -ieq '.lnk') {
          $l = try { $wsh.CreateShortcut($f.FullName) } catch { $null }
          if ($l -and $l.TargetPath -match '(?i)\\(cmd|powershell|pwsh|mshta|wscript|cscript)\.exe$' -and
              $l.Arguments -match '(?i)(-e(nc|ncodedcommand)?\s+[A-Za-z0-9+/=]{20,}|for\s+%{1,2}\w+\s+in|DownloadString|\bIEX\b|https?://)') {
            Add-Finding 'File' 'HIGH' $f.FullName "Shortcut disguised as a document runs hidden commands (SORVEPOTEL WhatsApp worm): $(Split-Path $l.TargetPath -Leaf) $($l.Arguments.Substring(0, [Math]::Min(80, $l.Arguments.Length)))"
          } elseif ($f.Name -match $LureRegex) { Add-Finding 'File' 'HIGH' $f.FullName 'WhatsApp lure file name.' }
          elseif (Test-WaOrigin $f) { Add-Finding 'File' 'HIGH' $f.FullName 'Shortcut downloaded from WhatsApp Web. Real documents are never shortcuts.' }
          return
        }
        if ($f.Name -match $LureRegex) { Add-Finding 'File' 'HIGH' $f.FullName 'WhatsApp lure file name.'; return }
        if ($f.FullName -match $StageRegex -or $f.Name -ieq 'active_desktop_render_x64.dll' -or $f.Name -ieq 'desk_compositor_x64.dll') {
          Add-Finding 'File' 'HIGH' $f.FullName 'SilverFox loader DLL (fake Microsoft\Update folder or KuGou/desk_compositor variant).'; return }
        if ($f.Name -match '(?i)\.vhdx?$' -and $f.Name -ine 'ext4.vhdx' -and
            $f.FullName -match '(?i)^[a-z]:\\Users\\' -and
            $f.FullName -notmatch '(?i)\\AppData\\Local\\(Docker\\|Packages\\(?!5319275A\.WhatsAppDesktop))') {
          if (Test-WaOrigin $f) { Add-Finding 'File' 'HIGH' $f.FullName 'Virtual disk (VHD) downloaded from WhatsApp Web. The WhatsApp ZIP hides its payload in a VHD.'; return }
          Add-Finding 'File' 'WARN' $f.FullName 'Virtual disk (VHD) in a user folder. The WhatsApp ZIP hides its payload in a VHD; delete it unless you made it.'; return }
        # CloudSEK (Dec 2025): signed Xunlei Thunder.exe dropped next to a fake libexpat.dll.
        if ($f.Name -ieq 'libexpat.dll' -and $f.DirectoryName -notmatch '\\Program Files( \(x86\))?\\' -and
            (Test-Path -LiteralPath (Join-Path $f.DirectoryName 'Thunder.exe'))) {
          Add-Finding 'File' 'HIGH' $f.FullName 'Fake libexpat.dll next to Thunder.exe (DLL sideloading, Silver Fox).'; return }
        # Trend Micro: the worm drops Selenium (WebDriver.dll) and chromedriver.exe in the user's Temp folder.
        if ($f.Name -ieq 'chromedriver.exe' -and $f.FullName -match '(?i)\\AppData\\Local\\Temp\\') {
          $sev = if (Get-ChildItem -LiteralPath $f.DirectoryName -File -ErrorAction SilentlyContinue | Where-Object { $_.Name -match '(?i)^(WebDriver\.dll|wppconnect(-wa)?\.js)$' }) { 'HIGH' } else { 'WARN' }
          Add-Finding 'File' $sev $f.FullName 'chromedriver in the Temp folder: the WhatsApp worm uses it to control Chrome and message your contacts.'; return }
        if ($f.Name -match '(?i)^wppconnect(-wa)?\.js$') { Add-Finding 'File' 'HIGH' $f.FullName 'WhatsApp automation script the worm uses to message all your contacts.'; return }
        if ($f.Name -match $ExeLureRegex) { Add-Finding 'File' 'HIGH' $f.FullName 'Fake document program (Silver Fox tax/statement lure).'; return }
        # Securelist (Jun 2026, 80% of victims in Malaysia): scripts sent over WhatsApp install a ManageEngine agent.
        if ($f.Extension -match '(?i)^\.(vbs|vbe|wsf)$' -and $f.FullName -match '(?i)\\5319275A\.WhatsAppDesktop_[^\\]+\\LocalState\\Sessions\\[^\\]+\\Transfers\\') {
          Add-Finding 'File' 'HIGH' $f.FullName 'Script file received through WhatsApp. Real documents are never scripts (WhatsApp VBS campaign).'; return }
        if ($f.FullName -match '(?i)\\Users\\Public\\Documents\\[^\\]+\\' -and $f.Name -match '(?i)(\.(vbs|vbe)|^UEMSAgent\.(msi|mst)|^DCAgentServerInfo\.json)$') {
          Add-Finding 'File' 'HIGH' $f.FullName 'Hidden script or ManageEngine installer kit from the WhatsApp VBS campaign.'; return }
        # Oct 2026 reports: Triage (encrashRep chain), C1BAS (ExceptCatch.dll), Netresec (Ping32 CoreShield.msi),
        # Sekoia (SyncFuture <ip>ClientSetup.exe), Elastic (TCLBANKER hostfxr.exe), Chinese reports (drivers and tools).
        if ($f.FullName -match '(?i)\\Users\\Public\\Libraries\\' -and $f.Name -match '(?i)^(webview2_integration\.exe|encrashrep\.dll)$') { Add-Finding 'File' 'HIGH' $f.FullName 'ValleyRAT loader hidden in Public\Libraries (INVOIS/Memeriksa VHD lures).'; return }
        if ($f.Name -ieq 'ExceptCatch.dll') { Add-Finding 'File' 'HIGH' $f.FullName 'Silver Fox loader DLL (ExceptCatch.dll).'; return }
        if ($f.Name -ieq 'CoreShield.msi' -and $f.FullName -match '(?i)^[a-z]:\\Users\\') { Add-Finding 'File' 'HIGH' $f.FullName 'Ping32 remote-control installer from the WhatsApp VBS campaign (Netresec).'; return }
        if ($f.Name -match '^\d{1,3}(\.\d{1,3}){3}ClientSetup\.exe$') { Add-Finding 'File' 'HIGH' $f.FullName 'SyncFuture remote-control installer named after the attacker server (Sekoia).'; return }
        if ($f.FullName -match '(?i)\\msvc-rt14\\bin\\hostfxr\.exe$') { Add-Finding 'File' 'HIGH' $f.FullName 'TCLBANKER loader (Elastic).'; return }
        if ($f.Name -match '(?i)^(rwdriver|kabuto|XiaoH)\.sys$') { Add-Finding 'File' 'HIGH' $f.FullName 'Silver Fox antivirus-killer driver.'; return }
        if ($f.FullName -match '(?i)\\Users\\Public\\Documents\\' -and $f.Name -match '(?i)^((funzip|men|KANG|kail|NtHandleCallback)\.exe|(edr|me)\.key)$') { Add-Finding 'File' 'HIGH' $f.FullName 'Silver Fox tool dropped in Public\Documents (Chinese security reports).'; return }
        if ($f.FullName -match '(?i)\\ProgramData\\EDS\d{4}\\') { Add-Finding 'File' 'HIGH' $f.FullName 'Hidden work folder of the WhatsApp VBS dropper (Microsoft, Mar 2026).'; return }
        # Reading version info opens the file, so only try DLLs (and sc.exe) the size of curl or bitsadmin.
        if (($f.Extension -ieq '.dll' -or $f.Name -ieq 'sc.exe') -and $f.Length -gt 150KB -and $f.Length -lt 1MB -and $f.FullName -match '(?i)\\(ProgramData|Users\\Public)\\' -and [string]$f.VersionInfo.OriginalFilename -match '(?i)^(curl|bitsadmin)\.exe') {
          Add-Finding 'File' 'HIGH' $f.FullName 'curl or bitsadmin renamed to a Windows DLL name (WhatsApp VBS campaign downloader).'; return }
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
        if ($f.Extension -match '(?i)^\.(exe|scr|vbs|vbe|js|wsf|msi|img|iso)$' -and (Test-WaOrigin $f)) {
          Add-Finding 'File' 'HIGH' $f.FullName 'Program, script or disk image downloaded from WhatsApp Web. Real documents are never programs.'; return }
        if ($f.Extension -match '(?i)^\.(zip|rar|7z)$' -and (Test-WaOrigin $f)) {
          Add-Finding 'File' 'WARN' $f.FullName 'Archive downloaded from WhatsApp Web. The WhatsApp malware arrives as a zip; delete it unless you expected it.' }
      }
    if ($env:WAZIP_TIMING) { Write-Host "[timing] $r : $tn files checked, $([int]$sw.Elapsed.TotalSeconds)s" }
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
  $svcs = @(Get-Service -ErrorAction SilentlyContinue | Where-Object { $_.DisplayName -match 'ManageEngine|UEMS' })
  $pending = @($svcs | Where-Object { Test-ServicePendingDelete $_.Name })
  $hits += $svcs | Where-Object { $pending -notcontains $_ }
  if ($pending.Count) {
    Say "  ManageEngine dah dibuang ($(@($pending.Name) -join ', ')). Restart PC untuk habiskan." "  ManageEngine already removed ($(@($pending.Name) -join ', ')). Restart the PC to finish." Yellow
  }
  foreach ($p in "${env:ProgramFiles(x86)}\ManageEngine\UEMS_Agent", "$env:ProgramFiles\ManageEngine\UEMS_Agent") {
    if (Test-Path -LiteralPath $p) { $hits += $p }
  }
  # Leftovers after the folder was deleted by hand: services and settings keys still count, so -Fix clears them.
  $hits += @(Get-ChildItem 'HKLM:\SYSTEM\CurrentControlSet\Services' -ErrorAction SilentlyContinue | Where-Object { $_.PSChildName -match $MeSvcRegex -and -not (Test-ServicePendingDelete $_.PSChildName) } | ForEach-Object { "service $($_.PSChildName)" })
  $hits += @($MeRegKeys | Where-Object { Test-Path -LiteralPath $_ } | ForEach-Object { "registry $_" })
  # Securelist (Jun 2026): the attacker's agent ships a server-info file pointing at their own servers.
  # A match means this agent is the attacker's, so it is removed even on an office PC.
  $script:MeAttacker = $false
  # The attacker's agent keeps its root certificates in the hidden Public\Documents work folder.
  foreach ($k in 'HKLM:\SOFTWARE\WOW6432Node\AdventNet\DesktopCentral\DCAgent', 'HKLM:\SOFTWARE\AdventNet\DesktopCentral\DCAgent') {
    $vals = Get-ChildItem -LiteralPath $k -Recurse -ErrorAction SilentlyContinue | ForEach-Object { (Get-ItemProperty -LiteralPath $_.PSPath -ErrorAction SilentlyContinue).PSObject.Properties.Value }
    $vals += (Get-ItemProperty -LiteralPath $k -ErrorAction SilentlyContinue).PSObject.Properties.Value
    if ($vals | Where-Object { $_ -is [string] -and ($_ -match '(?i)\\Users\\Public\\Documents\\' -or $C2Ips -contains ($_ -replace ':\d+$', '')) }) { $script:MeAttacker = $true }
  }
  foreach ($p in $hits | Where-Object { $_ -is [string] -and $_ -match '^[a-z]:\\' }) {
    $cfg = Get-ChildItem -LiteralPath $p -Recurse -File -Include *.json, *.conf, *.ini, *.xml, *.txt, *.props -ErrorAction SilentlyContinue | Where-Object { $_.Length -lt 2MB }
    if ($cfg -and ($cfg | Select-String -SimpleMatch -Pattern $C2Ips -List -ErrorAction SilentlyContinue)) { $script:MeAttacker = $true }
  }
  Scan-Ping32
  # Both the VBS campaign and the MicroPoint ValleyRAT chain switch this off; only worth saying on an infected PC.
  if (($hits.Count -or ($Findings | Where-Object { $_.Severity -eq 'HIGH' })) -and (Get-ItemProperty -LiteralPath 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System' -ErrorAction SilentlyContinue).ConsentPromptBehaviorAdmin -eq 0) {
    Add-Finding 'Info' 'WARN' 'Admin permission prompt is switched off' 'The WhatsApp VBS campaign and ValleyRAT switch this off before installing their programs. Turn it back on: search UAC > Change User Account Control settings > move the slider up one step.'
  }
  if ($hits.Count) {
    $d = if ($script:MeAttacker) { 'Remote-management agent connected to a known attacker server (WhatsApp VBS campaign). This tool will force-remove it.' } else { switch ($Owner) {
      'Office'   { 'Remote-management agent found. Company IT often installs it; ask your IT team to confirm. This tool leaves it alone on an office PC.' }
      'Personal' { 'Remote-management agent on a personal PC: the WhatsApp VBS campaign uses it to control PCs remotely. This tool will force-remove it.' }
      default    { 'Remote-management agent found. If your company did NOT install it, the WhatsApp VBS campaign gave attackers remote control. Its normal uninstaller asks for the attacker''s PIN.' }
    } }
    Add-Finding 'Info' 'WARN' 'ManageEngine UEMS Agent' $d
  }
}

# Netresec (Jun 2026): a WhatsApp VBS variant installs the Ping32 monitoring agent (NSecRTS.exe) instead of ManageEngine.
# Same rule as ManageEngine: removed on a personal PC or when it talks to the attacker, left to the owner otherwise.
function Scan-Ping32 {
  $rx = '(?i)\\NSecRTS\.exe|\\Ping32\\'
  $procs = @(Get-CimInstance Win32_Process -ErrorAction SilentlyContinue | Where-Object { [string]$_.ExecutablePath -match $rx })
  $bad = [bool](Get-NetTCPConnection -RemoteAddress '143.92.37.168' -ErrorAction SilentlyContinue | Where-Object { $procs.ProcessId -contains $_.OwningProcess })
  $sev = if ($Owner -eq 'Personal' -or $bad) { 'HIGH' } else { 'WARN' }
  $why = switch ($Owner) {
    'Office'   { 'Ask your IT team if they installed it.' }
    'Personal' { 'A personal PC should not have it: the WhatsApp VBS campaign uses it to control PCs. This tool will remove it.' }
    default    { 'Fine if your company installed it. If not, the WhatsApp VBS campaign gave attackers control of this PC.' }
  }
  $dirs = @()
  foreach ($svc in Get-ChildItem 'HKLM:\SYSTEM\CurrentControlSet\Services' -ErrorAction SilentlyContinue) {
    $pr = Get-ItemProperty -LiteralPath $svc.PSPath -ErrorAction SilentlyContinue
    $img = [string]$pr.ImagePath
    if ($img -notmatch $rx -or $pr.DeleteFlag -eq 1) { continue }
    Add-Finding 'Service' $sev $svc.PSChildName "Ping32 remote-control service ($img). $why" @{ RegPath = $svc.PSPath; Image = '' }
    $dirs += Split-Path (Resolve-ImagePath ($img -replace '^"([^"]+)".*', '$1' -replace '(?i)(\.exe)\s.*$', '$1'))
  }
  foreach ($p in $procs) {
    Add-Finding 'Process' $sev "$($p.Name) (PID $($p.ProcessId))" "Ping32 remote-control program. $why" @{ Pid = $p.ProcessId; Path = $p.ExecutablePath }
    $dirs += Split-Path $p.ExecutablePath
  }
  foreach ($d in $dirs | Sort-Object -Unique) {
    if ($d -and $d -notmatch '(?i)^[a-z]:\\Windows(\\|$)' -and (Test-Path -LiteralPath $d)) { Add-Finding 'File' $sev $d "Ping32 program folder. $why" }
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
    if (("$($svc.PSChildName) $($pr.DisplayName) $($pr.ImagePath)" -match $rx -or $svc.PSChildName -match $MeSvcRegex) -and $pr.DeleteFlag -ne 1) {
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
  # Registry leftovers: the agent's settings (the attacker's server address), installer records and firewall openings.
  foreach ($k in $MeRegKeys) {
    if (Test-Path -LiteralPath $k) { Add-Finding 'RegKey' 'HIGH' $k 'ManageEngine settings (server address and keys)' }
  }
  foreach ($u in Get-ChildItem -LiteralPath 'HKLM:\SOFTWARE\Classes\Installer\Products' -ErrorAction SilentlyContinue) {
    if ((Get-ItemProperty -LiteralPath $u.PSPath -ErrorAction SilentlyContinue).ProductName -match $rx) {
      Add-Finding 'RegKey' 'HIGH' ($u.PSPath -replace '^Microsoft\.PowerShell\.Core\\Registry::', 'Registry::') 'ManageEngine installer record'
    }
  }
  $fw = 'HKLM:\SYSTEM\CurrentControlSet\Services\SharedAccess\Parameters\FirewallPolicy\FirewallRules'
  $fwp = Get-ItemProperty -LiteralPath $fw -ErrorAction SilentlyContinue
  if ($fwp) {
    foreach ($pp in $fwp.PSObject.Properties | Where-Object { $_.Name -notmatch '^PS(Path|ParentPath|ChildName|Drive|Provider)$' -and [string]$_.Value -match $rx }) {
      Add-Finding 'RegValue' 'HIGH' "$fw|$($pp.Name)" 'ManageEngine firewall opening'
    }
  }
}

# --------------------------------------------------------------- fixes ---
function Invoke-Fix($qdir) {
  New-Item -ItemType Directory -Force -Path $qdir | Out-Null
  $log = New-Object System.Collections.Generic.List[object]
  $i = 0
  $closed = $false
  # Files inside a flagged folder go before the folder itself.
  foreach ($f in $Findings | Sort-Object { @('Process', 'WaSession', 'Vhd', 'Task', 'DefExcl', 'RegValue', 'Service', 'RegKey', 'File').IndexOf($_.Kind) }, { -([string]$_.Target).Length }) {
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
          try {
            if ($f.Extra.Type -eq 'Process') { Remove-MpPreference -ExclusionProcess $f.Extra.Value -ErrorAction Stop }
            else { Remove-MpPreference -ExclusionPath $f.Extra.Value -ErrorAction Stop }
          } catch {
            # Defender sometimes refuses with "0x%1!x!"; the exclusion still lives as a plain registry value.
            $ek = 'HKLM:\SOFTWARE\Microsoft\Windows Defender\Exclusions\' + $(if ($f.Extra.Type -eq 'Process') { 'Processes' } else { 'Paths' })
            try { Remove-ItemProperty -LiteralPath $ek -Name $f.Extra.Value -ErrorAction Stop }
            catch { $script:DefExclLeft += $f.Extra.Value; throw }
          }
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
          # 1072 = already marked for deletion. Anything else: drop the registry entry so it is gone after a restart.
          if ($LASTEXITCODE -and $LASTEXITCODE -ne 1072) {
            try { Remove-Item -LiteralPath $f.Extra.RegPath -Recurse -Force -ErrorAction Stop }
            catch { $script:SvcLeft += $f.Target; throw }
          }
          $script:NeedRestart = $true
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
  Set-Content -LiteralPath (Join-Path $QuarantineRoot 'last-fix.txt') -Value (Get-Date -Format o)
  $mf = Join-Path $qdir 'manifest.json'
  $log | ConvertTo-Json -Depth 4 | Out-File -Encoding UTF8 $mf
  $mf
}

function Invoke-Restore($mf) {
  $items = Get-Content -Raw -LiteralPath $mf | ConvertFrom-Json
  $items = @($items | ForEach-Object { $_ })
  # Undo in reverse, so a folder comes back before the files that were inside it.
  [array]::Reverse($items)
  foreach ($it in $items) {
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
# Defender and ran-program history only counts from the last clean-up, at most 30 days back.
$HistorySince = (Get-Date).AddDays(-30)
$lastFix = Join-Path $QuarantineRoot 'last-fix.txt'
if (Test-Path -LiteralPath $lastFix) {
  $t = [datetime]::MinValue
  if ([datetime]::TryParse((Get-Content -Raw -LiteralPath $lastFix).Trim(), [ref]$t) -and $t -gt $HistorySince) { $HistorySince = $t }
}
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
  $meRemove = [bool]$RemoveManageEngine -or $Owner -eq 'Personal' -or $script:MeAttacker
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
  if ($f.Severity -eq 'WARN' -and ($h = Get-WarnHelp $f)) {
    Write-Host ("        Maksud: {0}" -f $h[1]) -ForegroundColor White
    Write-Host ("        Buat:   {0}" -f $h[2]) -ForegroundColor Cyan
  }
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
  if ($script:DefExclLeft) {
    Say "Windows tak bagi tool buang pengecualian antivirus ni: $($script:DefExclLeft -join ', '). Buang sendiri: Windows Security > Virus & threat protection > Manage settings > Exclusions > Add or remove exclusions > tekan setiap satu > Remove. Lepas tu restart dan jalankan tool ni semula." `
        "Windows would not let the tool remove these antivirus exclusions: $($script:DefExclLeft -join ', '). Remove them yourself: Windows Security > Virus & threat protection > Manage settings > Exclusions > Add or remove exclusions > click each one > Remove. Then restart and run this tool again." Red
  }
  if ($Findings | Where-Object { $_.Kind -eq 'DefExcl' -or $_.Detail -match 'Defender' }) {
    Say 'Malware ni suruh Windows Defender abaikan dia, sebab tu scan antivirus nampak bersih. Lepas bersihkan dan restart, buat Full scan Windows Defender sekali lagi.' `
        'This malware told Windows Defender to ignore it, which is why antivirus scans looked clean. After cleaning and restarting, run a Windows Defender full scan again.' Yellow
  }
  if ($script:SvcLeft) {
    Say "Windows tak bagi buang servis ni: $($script:SvcLeft -join ', '). Masuk Safe Mode (Settings > System > Recovery > Advanced startup > Restart now > Troubleshoot > Advanced options > Startup Settings > Restart > tekan 4), kemudian jalankan tool ni sekali lagi." `
        "Windows would not let the tool remove these services: $($script:SvcLeft -join ', '). Start in Safe Mode (Settings > System > Recovery > Advanced startup > Restart now > Troubleshoot > Advanced options > Startup Settings > Restart > press 4), then run this tool again." Red
  } elseif ($script:NeedRestart) {
    Say 'Servis jahat dah dibuang, tapi masih nampak sampai PC di-restart. RESTART dulu sebelum imbas semula.' 'Bad services are removed but stay listed until the PC restarts. RESTART before scanning again.' Yellow
  }
  if ($Findings | Where-Object { $_.Kind -eq 'Service' -and $_.Detail -ne 'ManageEngine service' -and $_.Detail -notmatch '^Ping32' }) {
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
