<#
.SYNOPSIS
Scans Windows services and kernel drivers for unquoted service paths and known vulnerable driver patterns.
#>
[CmdletBinding()]
param(
    [string]$OutputPath = "",
    [switch]$Quiet
)

$ErrorActionPreference = 'SilentlyContinue'
$findings = New-Object System.Collections.Generic.List[object]
$knownVulnerableDrivers = @(
    'gdrv.sys','rtcore64.sys','dbk64.sys','winring0.sys','winring0x64.sys',
    'msio64.sys','msio32.sys','cpuz141.sys','cpuz149.sys','speedfan.sys',
    'asio.sys','asio64.sys','iomap64.sys','ene.sys','inpoutx64.sys',
    'piddrv.sys','directio.sys','hwinterface.sys','physmem.sys','winio.sys',
    'winio64.sys','bs.sys','bs64.sys','kprocesshacker.sys','ntiolib.sys'
)

function Add-Finding {
    param(
        [string]$Type,
        [string]$Severity,
        [string]$Name,
        [string]$Path,
        [string]$Detail
    )
    $findings.Add([pscustomobject]@{
        type = $Type
        severity = $Severity
        name = $Name
        path = $Path
        detail = $Detail
    })
}

function Test-UnquotedServicePath {
    param([string]$PathName)
    if ([string]::IsNullOrWhiteSpace($PathName)) { return $false }
    $p = $PathName.Trim()
    if ($p.StartsWith('"')) { return $false }
    $candidate = $p -replace '^\\\?\?\\', ''
    $m = [regex]::Match($candidate, '^(?<exe>[A-Za-z]:\\[^"]*?\.exe)(?:\s|$)', 'IgnoreCase')
    if (-not $m.Success) { return $false }
    return ($m.Groups['exe'].Value -match '\s')
}

function Get-DriverLeaf {
    param([string]$PathName)
    if ([string]::IsNullOrWhiteSpace($PathName)) { return '' }
    $p = $PathName.Trim().Trim('"')
    $p = $p -replace '^\\\?\?\\', ''
    return [System.IO.Path]::GetFileName($p)
}

$services = Get-CimInstance Win32_Service | Where-Object { $_.PathName }
foreach ($svc in $services) {
    if (Test-UnquotedServicePath $svc.PathName) {
        Add-Finding -Type 'UnquotedServicePath' -Severity 'High' -Name $svc.Name -Path $svc.PathName -Detail 'Service executable path contains spaces and is not quoted.'
    }
}

$drivers = Get-CimInstance Win32_SystemDriver | Where-Object { $_.PathName }
foreach ($drv in $drivers) {
    if (Test-UnquotedServicePath $drv.PathName) {
        Add-Finding -Type 'UnquotedServicePath' -Severity 'High' -Name $drv.Name -Path $drv.PathName -Detail 'Kernel driver path contains spaces and is not quoted.'
    }

    $leaf = Get-DriverLeaf $drv.PathName
    if ($leaf -and ($knownVulnerableDrivers -contains $leaf.ToLowerInvariant())) {
        Add-Finding -Type 'VulnerableDriver' -Severity 'High' -Name $drv.Name -Path $drv.PathName -Detail "Known vulnerable driver pattern: $leaf"
    }

    $file = $drv.PathName.Trim().Trim('"') -replace '^\\\?\?\\', ''
    $file = $file -replace '^\\SystemRoot', $env:SystemRoot
    if ($file -and (Test-Path -LiteralPath $file)) {
        $sig = Get-AuthenticodeSignature -LiteralPath $file
        if ($sig.Status -ne 'Valid') {
            Add-Finding -Type 'InvalidDriverSignature' -Severity 'Medium' -Name $drv.Name -Path $drv.PathName -Detail "Authenticode status: $($sig.Status)"
        }
    }
}

$summary = [pscustomobject]@{
    total = $findings.Count
    unquoted_service_paths = @($findings | Where-Object { $_.type -eq 'UnquotedServicePath' }).Count
    vulnerable_drivers = @($findings | Where-Object { $_.type -eq 'VulnerableDriver' }).Count
    invalid_driver_signatures = @($findings | Where-Object { $_.type -eq 'InvalidDriverSignature' }).Count
}

$result = [pscustomobject]@{
    scanned_at = (Get-Date).ToUniversalTime().ToString('o')
    host = $env:COMPUTERNAME
    summary = $summary
    findings = @($findings)
}

$json = $result | ConvertTo-Json -Depth 6
if ($OutputPath) {
    $json | Set-Content -LiteralPath $OutputPath -Encoding UTF8
}
if (-not $Quiet) {
    $json
}
