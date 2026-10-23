/*
   YARA rules — WhatsApp "Click here to view*.zip" campaign (Winos 4.0 / Silver Fox / 银狐)
   For scanning files in bulk (e.g. mail gateways, file shares, DFIR triage).
   Written for the sample dissected 2026-10-23. Generic rules first, exact-hash rules last.

   Use: yara -r winos4-whatsapp.yar <path>
*/

import "hash"
import "pe"

rule Winos4_RImE_Stager
{
    meta:
        description = "Winos4.0 fake rime.dll stager (DLL-sideloaded by KafanInputService.exe)"
        family     = "Winos4.0 / Silver Fox"
        reference  = "WhatsApp ZIP->VHD lure campaign (Malaysia)"
        severity   = "high"
    strings:
        $relaunch = "/c start \"\" \"%s\" \"%s\",_vmclientcore@16" ascii
        $exp1     = "_vmclientcore@16" ascii
        $vm1      = "vmware-vdiskmanager" ascii
        $vm2      = "vmware-remotemks" ascii
        $rime1    = "RimeConfigOpen" ascii
        $rime2    = "RimeStartMaintenance" ascii
        $con      = "Console\\0" ascii wide
    condition:
        uint16(0) == 0x5A4D and
        $exp1 and $con and
        ( $relaunch or ( 1 of ($vm*) and 1 of ($rime*) ) )
}

rule Winos4_Config_Markers
{
    meta:
        description = "Winos4.0 registry/config markers (payload hidden in HKCU\\Console, stage markers)"
        family      = "Winos4.0 / Silver Fox"
        severity    = "high"
    strings:
        $m1 = "IpDates_info" ascii wide
        $m2 = "IpDates_sun" ascii wide
        $m3 = "FaCai2024" ascii wide
        $m4 = "Magisk" ascii wide
        $c1 = "Console\\0" ascii wide
        $c2 = "IpDate" ascii wide
    condition:
        uint16(0) == 0x5A4D and ( 2 of ($m*) or ( $c1 and $c2 ) )
}

rule WhatsApp_Lure_VHD_Carrier
{
    meta:
        description = "VHD that carries the Winos4.0 sideload set (signed EXE + fake rime.dll + .dat)"
        severity    = "medium"
    strings:
        $a = "KafanInputService" ascii wide
        $b = "RImE.dLl" ascii wide nocase
        $c = "vmclientcore" ascii
    condition:
        2 of them
}

rule Winos4_WhatsApp_KnownSamples
{
    meta:
        description = "Exact files from the 2026-10-23 WhatsApp campaign sample"
        severity    = "high"
    condition:
        hash.sha256(0, filesize) == "539b49f6ddfa070d25adbd8cd47c10bbba5cacf5bf27fddfe89d96f0c729b2fb" or  // RImE.dLl (stager)
        hash.sha256(0, filesize) == "c74f55247aa2c72001024bd977c869cb5adce6f8604a4d32329f015b73ae2a49" or  // KafanInputService.exe (sideload host)
        hash.sha256(0, filesize) == "2da61980a54cf44081a111e319ee7ab2165743383a4dbb0dca811389779721ba" or  // hidserv.dll (persistence)
        hash.sha256(0, filesize) == "12b9470634bb7f76419c70ee9a510147cd6bcfce920f2abee5afdd13901b383d" or  // encrypted .dat config
        hash.sha256(0, filesize) == "46883bc25c77678f60c1b836f4c438d87158c9af6b229f533522f635a0d5276e" or  // ZyArk.sys (Baidu, AV killer)
        hash.sha256(0, filesize) == "1c5129b4d63f2d5252b5b02a0a7d655dac3b6eac23dd4ed92b4dd55f243387ff"     // ardrv.sys (OPSWAT, AV killer)
}
