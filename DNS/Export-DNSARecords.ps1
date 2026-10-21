#Requires -Modules DnsServer
<#
.SYNOPSIS
    Exports DNS A (IPv4) records from all forward lookup zones.
.DESCRIPTION
    Read-only inventory. By default, discovers DNS-enabled domain controllers
    using Active Directory. Alternatively, provide one or more DNS servers.
    Results include DNS server, zone, hostname, FQDN, IPv4 address and timestamp.
    Identical entries hosted on multiple servers can be retained with
    -IncludeDnsServerDuplicates.
.EXAMPLE
    .\Export-DNSARecords.ps1
.EXAMPLE
    .\Export-DNSARecords.ps1 -DnsServers DC01,DC02 -OutputPath C:\Temp\DNS-A-Records.csv
#>
[CmdletBinding()]
param(
    [string[]]$DnsServers,
    [string]$OutputPath = '.\DNS-A-Records.csv',
    [switch]$IncludeDnsServerDuplicates
)

$ErrorActionPreference = 'Stop'
if (-not $DnsServers -or $DnsServers.Count -eq 0) {
    Import-Module ActiveDirectory -ErrorAction Stop
    $DnsServers = @(
        Get-ADDomainController -Filter * |
            Where-Object { $_.IsDnsServer } |
            Select-Object -ExpandProperty HostName
    )
}

$DnsServers = @($DnsServers | Where-Object { -not [string]::IsNullOrWhiteSpace($_) } | Sort-Object -Unique)
if ($DnsServers.Count -eq 0) {
    throw 'No DNS servers found. Supply -DnsServers explicitly.'
}

$results = [System.Collections.Generic.List[object]]::new()
$failures = 0
foreach ($server in $DnsServers) {
    Write-Host "Querying $server..." -ForegroundColor Cyan
    try {
        $zones = @(Get-DnsServerZone -ComputerName $server -ErrorAction Stop |
            Where-Object { -not $_.IsReverseLookupZone })
    }
    catch {
        $failures++
        Write-Warning ("Cannot enumerate zones on {0}: {1}" -f $server, $_.Exception.Message)
        continue
    }

    foreach ($zone in $zones) {
        try {
            $records = @(Get-DnsServerResourceRecord -ComputerName $server -ZoneName $zone.ZoneName -RRType A -ErrorAction Stop)
            foreach ($record in $records) {
                $hostPart = [string]$record.HostName
                $fqdn = if ($hostPart -eq '@' -or [string]::IsNullOrEmpty($hostPart)) {
                    $zone.ZoneName
                } else {
                    "$hostPart.$($zone.ZoneName)"
                }
                $ip = $record.RecordData.IPv4Address
                if ($null -eq $ip) { continue }
                $results.Add([pscustomobject]@{
                    DNSServer = $server
                    Zone      = $zone.ZoneName
                    HostName  = $hostPart
                    FQDN      = $fqdn
                    IPAddress = $ip.IPAddressToString
                    Timestamp = $record.Timestamp
                })
            }
        }
        catch {
            $failures++
            Write-Warning ("Cannot enumerate A records in {0} on {1}: {2}" -f $zone.ZoneName, $server, $_.Exception.Message)
        }
    }
}

$rows = if ($IncludeDnsServerDuplicates) {
    @($results | Sort-Object FQDN, IPAddress, DNSServer -Unique)
} else {
    # Collapse identical zone/name/address records replicated across DNS servers.
    @($results | Sort-Object Zone, FQDN, IPAddress -Unique)
}

$directory = Split-Path -Parent $OutputPath
if ($directory -and -not (Test-Path -LiteralPath $directory -PathType Container)) {
    New-Item -Path $directory -ItemType Directory -Force | Out-Null
}

if ($rows.Count -gt 0) {
    $rows | Export-Csv -LiteralPath $OutputPath -NoTypeInformation -Encoding UTF8
} else {
    'DNSServer,Zone,HostName,FQDN,IPAddress,Timestamp' |
        Set-Content -LiteralPath $OutputPath -Encoding UTF8
}

Write-Host ("Exported {0} A records to {1}. Query failures: {2}" -f $rows.Count, $OutputPath, $failures) -ForegroundColor Green
if ($failures -gt 0) { Write-Warning 'Export may be incomplete due to DNS query failures.' }
