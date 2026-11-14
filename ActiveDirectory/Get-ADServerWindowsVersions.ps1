#requires -Version 7.0
#requires -Modules ActiveDirectory
<#
.SYNOPSIS
  Inventory enabled Windows Server computers in AD and query their live OS/build/UBR.
.DESCRIPTION
  Read-only. Uses CIM over WSMan. Records unreachable servers and partial results.
  -Test limits the scan to 5 AD servers (or -MaxServers to a chosen number).
.EXAMPLE
  .\Get-ADServerWindowsVersions.ps1 -Test
.EXAMPLE
  .\Get-ADServerWindowsVersions.ps1 -MaxServers 25
.EXAMPLE
  .\Get-ADServerWindowsVersions.ps1
#>
[CmdletBinding()]
param(
    [switch]$Test,
    [ValidateRange(1,100000)]
    [int]$MaxServers,
    [string]$OutputPath = 'C:\Temp\AD-Server-Windows-Versions.csv'
)

$ErrorActionPreference = 'Stop'
Import-Module ActiveDirectory -ErrorAction Stop

$servers = @(Get-ADComputer -Filter {
    Enabled -eq $true -and OperatingSystem -like '*Server*'
} -Properties OperatingSystem, OperatingSystemVersion, DNSHostName |
    Sort-Object Name)

if ($Test) { $servers = @($servers | Select-Object -First 5) }
elseif ($PSBoundParameters.ContainsKey('MaxServers')) {
    $servers = @($servers | Select-Object -First $MaxServers)
}

$results = [System.Collections.Generic.List[object]]::new()
$index = 0

foreach ($server in $servers) {
    $index++
    $target = if ($server.DNSHostName) { $server.DNSHostName } else { $server.Name }
    Write-Host "[$index/$($servers.Count)] Scanning $target..." -ForegroundColor Cyan

    $row = [ordered]@{
        ServerName   = $server.Name
        DNSHostName  = $target
        AD_OS        = $server.OperatingSystem
        CurrentOS    = ''
        Version      = ''
        Build        = ''
        UBR          = ''
        FullBuild    = ''
        LastBoot     = ''
        Status       = 'Failed'
        ErrorMessage = ''
    }

    $session = $null
    try {
        # New-CimSession does NOT have an -OperationTimeoutSec parameter.
        $session = New-CimSession -ComputerName $target -ErrorAction Stop
        $os = Get-CimInstance -CimSession $session -ClassName Win32_OperatingSystem -OperationTimeoutSec 15 -ErrorAction Stop

        $row.CurrentOS = $os.Caption
        $row.Version   = $os.Version
        $row.Build     = $os.BuildNumber
        $row.LastBoot  = $os.LastBootUpTime
        $row.FullBuild = [string]$os.BuildNumber
        $row.Status    = 'Success'

        try {
            $reg = Invoke-CimMethod -CimSession $session -Namespace root/default -ClassName StdRegProv -MethodName GetDWORDValue -Arguments @{
                hDefKey     = [uint32]2147483650
                sSubKeyName = 'SOFTWARE\Microsoft\Windows NT\CurrentVersion'
                sValueName  = 'UBR'
            } -ErrorAction Stop

            if ($reg.ReturnValue -eq 0) {
                $row.UBR = $reg.uValue
                $row.FullBuild = "$($os.BuildNumber).$($reg.uValue)"
            } else {
                $row.Status = 'Partial'
                $row.ErrorMessage = "UBR registry lookup returned $($reg.ReturnValue)"
            }
        } catch {
            $row.Status = 'Partial'
            $row.ErrorMessage = "UBR lookup: $($_.Exception.Message)"
        }
    } catch {
        $row.ErrorMessage = "OS/CIM: $($_.Exception.Message)"
    } finally {
        if ($null -ne $session) { Remove-CimSession -CimSession $session -ErrorAction SilentlyContinue }
    }

    $results.Add([pscustomobject]$row)
    if ($row.Status -eq 'Success') { Write-Host "  $($row.CurrentOS) $($row.FullBuild)" -ForegroundColor Green }
    elseif ($row.Status -eq 'Partial') { Write-Warning "$target partial: $($row.ErrorMessage)" }
    else { Write-Warning "$target failed: $($row.ErrorMessage)" }
}

$folder = Split-Path -Path $OutputPath -Parent
if ($folder -and -not (Test-Path -LiteralPath $folder)) {
    New-Item -ItemType Directory -Path $folder -Force | Out-Null
}
$results | Export-Csv -LiteralPath $OutputPath -NoTypeInformation -Encoding utf8
Write-Host "Inventory saved: $OutputPath" -ForegroundColor Green
$results | Group-Object Status | Select-Object Name, Count | Format-Table -AutoSize
$results | Where-Object CurrentOS | Group-Object CurrentOS |
    Sort-Object Count -Descending | Select-Object Name, Count | Format-Table -AutoSize
