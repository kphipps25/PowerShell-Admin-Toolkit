#requires -Version 5.1
<#
.SYNOPSIS
    Read-only audit of DNS Server against a domain-controller-only policy.
.DESCRIPTION
    Discovers enabled Windows Server accounts in the current AD domain, or accepts
    explicit names. Uses WinRM without requiring a successful ping. Collects DNS
    role/service, domain-controller status, zones, forwarders, local addresses and
    NIC DNS settings. Samples DNS query totals twice and reports actual duration.
    Failed checks are Unknown, never zero. No roles, services or logging are changed.

    Policy: DNS Server belongs only on domain controllers. A confirmed non-DC
    with the DNS role or DNS Server service installed is a removal candidate,
    regardless of observed traffic. Unknown DC status never produces a candidate.
    This audit does not uninstall DNS or stop services.

    No observed queries does not establish that DNS is unused.
    Caching/forwarding DNS needs no hosted zones. NIC references cover only audited
    Windows servers: workstations, appliances, DHCP options, delegations, other DNS
    forwarders, load balancers and disaster-recovery dependencies are not checked.
    Verify those and observe a representative business/backup cycle before removal.
.EXAMPLE
    .\Complete-Domain-DNS-Audit.ps1
.EXAMPLE
    .\Complete-Domain-DNS-Audit.ps1 -ComputerName DNS01,DNS02 -ObservationSeconds 300
.EXAMPLE
    .\Complete-Domain-DNS-Audit.ps1 -SearchBase 'OU=Servers,DC=example,DC=com'
.NOTES
    Run from Windows PowerShell 5.1 with permissions to query targets using WinRM.
    AD discovery requires the ActiveDirectory module on the audit computer.
    Target servers require ServerManager and DnsServer for those individual checks.
    DNS Client service (Dnscache) is not the DNS Server service (DNS).
    Statistics are read via Get-DnsServerStatistics, without clearing counters.
    Runtime reports: Domain-DNS-Audit.csv and DNS-Review-Candidates.csv.
    Reference: https://learn.microsoft.com/powershell/module/dnsserver/get-dnsserverstatistics
#>
[CmdletBinding()]
param(
    [string[]]$ComputerName,
    [string]$SearchBase,
    [ValidateRange(10,86400)][int]$ObservationSeconds = 60,
    [string]$OutputDirectory = (Get-Location).Path,
    [PSCredential]$Credential
)
$ErrorActionPreference = 'Stop'

# Normalize IPs so IPv6 formatting differences do not hide NIC references.
function ConvertTo-AddressKey {
    param([string]$Address)
    try { ([System.Net.IPAddress]::Parse(($Address -split '%')[0])).ToString() }
    catch { $Address }
}

if ($ComputerName) {
    $Servers = @($ComputerName | Where-Object { $_ -and $_.Trim() } |
        ForEach-Object { $_.Trim() } | Sort-Object -Unique |
        ForEach-Object { [pscustomobject]@{Name=$_; DNSHostName=$_; OperatingSystem='Not queried in AD'} })
} else {
    Import-Module ActiveDirectory -ErrorAction Stop
    $ADParameters = @{
        Filter = 'Enabled -eq $true'
        Properties = @('OperatingSystem','DNSHostName')
        ErrorAction = 'Stop'
    }
    if ($SearchBase) { $ADParameters.SearchBase = $SearchBase }
    $Servers = @(Get-ADComputer @ADParameters |
        Where-Object { $_.OperatingSystem -like '*Server*' } | Sort-Object Name)
}
if (-not $Servers.Count) { throw 'No Windows servers were selected.' }
New-Item -ItemType Directory -Path $OutputDirectory -Force | Out-Null
Write-Host "DOMAIN DNS AUDIT: $($Servers.Count) servers" -ForegroundColor Cyan

# Independent checks preserve partial results if one provider fails.
$InventoryBlock = {
    $notes = New-Object 'System.Collections.Generic.List[string]'
    $r = [ordered]@{
        DNSRole='Unknown'; DNSService='Unknown'; ServiceStatus='Unknown'
        DomainController='Unknown'; IPAddresses=@(); ClientDNS=@()
        NICCheck='Unknown'; AddressCheck='Unknown'; ZoneCount=$null
        Zones=''; ADIntegratedZoneCount=$null; Forwarders=''
        TotalQueries=$null; SampleTime=$null; ServerStartTime=$null
        LastClearTime=$null; StatisticsStatus='Not collected'; Notes=''
    }
    try {
        Import-Module ServerManager -ErrorAction Stop
        $feature = Get-WindowsFeature -Name DNS -ErrorAction Stop
        if (-not $feature) { throw 'DNS feature result missing' }
        $r.DNSRole = if ($feature.Installed) { 'Installed' } else { 'Not Installed' }
    } catch { $notes.Add("Role check: $($_.Exception.Message)") }
    try {
        $svc = @(Get-CimInstance Win32_Service -Filter "Name='DNS'" -ErrorAction Stop)
        $r.DNSService = if ($svc.Count) { 'Installed' } else { 'Not Installed' }
        $r.ServiceStatus = if ($svc.Count) { $svc[0].State } else { 'Not Installed' }
    } catch { $notes.Add("Service check: $($_.Exception.Message)") }
    try {
        $cs = Get-CimInstance Win32_ComputerSystem -ErrorAction Stop
        $r.DomainController = if ($cs.DomainRole -in 4,5) { 'Yes' } else { 'No' }
    } catch { $notes.Add("DC check: $($_.Exception.Message)") }
    try {
        $r.IPAddresses = @(Get-NetIPAddress -ErrorAction Stop |
            Where-Object { $_.IPAddress -notin '127.0.0.1','::1' -and $_.AddressState -eq 'Preferred' } |
            Select-Object -ExpandProperty IPAddress -Unique)
        $r.AddressCheck = 'OK'
    } catch { $notes.Add("Address check: $($_.Exception.Message)") }
    try {
        $r.ClientDNS = @(Get-DnsClientServerAddress -ErrorAction Stop |
            ForEach-Object { $_.ServerAddresses } | Sort-Object -Unique)
        $r.NICCheck = 'OK'
    } catch { $notes.Add("NIC DNS check: $($_.Exception.Message)") }
    if ($r.DNSService -eq 'Installed' -and $r.ServiceStatus -eq 'Running') {
        try {
            Import-Module DnsServer -ErrorAction Stop
            $zones = @(Get-DnsServerZone -ErrorAction Stop | Where-Object { -not $_.IsAutoCreated })
            $r.ZoneCount = $zones.Count
            $r.ADIntegratedZoneCount = @($zones | Where-Object { $_.IsDsIntegrated }).Count
            $r.Zones = ($zones | ForEach-Object { "$($_.ZoneName) [$($_.ZoneType)] AD=$($_.IsDsIntegrated)" }) -join '; '
        } catch { $notes.Add("Zone check: $($_.Exception.Message)") }
        try {
            $r.Forwarders = ((Get-DnsServerForwarder -ErrorAction Stop).IPAddress |
                ForEach-Object { $_.ToString() }) -join '; '
        } catch { $notes.Add("Forwarder check: $($_.Exception.Message)") }
        try {
            $stats = Get-DnsServerStatistics -ErrorAction Stop
            if ($null -eq $stats.Query2Statistics.TotalQueries -or
                $null -eq $stats.TimeStatistics.ServerStartTime -or
                $null -eq $stats.TimeStatistics.LastClearTime) { throw 'Required statistics properties missing' }
            $r.TotalQueries = [decimal]$stats.Query2Statistics.TotalQueries
            $r.SampleTime = [datetime]::UtcNow
            $r.ServerStartTime = $stats.TimeStatistics.ServerStartTime
            $r.LastClearTime = $stats.TimeStatistics.LastClearTime
            $r.StatisticsStatus = 'OK'
        } catch { $r.StatisticsStatus='Unknown'; $notes.Add("Statistics check: $($_.Exception.Message)") }
    }
    $r.Notes = $notes -join '; '
    [pscustomobject]$r
}
$SecondSampleBlock = {
    Import-Module DnsServer -ErrorAction Stop
    $svc = Get-Service DNS -ErrorAction Stop
    if ($svc.Status -ne 'Running') { throw 'DNS service is no longer running' }
    $s = Get-DnsServerStatistics -ErrorAction Stop
    if ($null -eq $s.Query2Statistics.TotalQueries -or
        $null -eq $s.TimeStatistics.ServerStartTime -or
        $null -eq $s.TimeStatistics.LastClearTime) { throw 'Required statistics properties missing' }
    [pscustomobject]@{
        TotalQueries=[decimal]$s.Query2Statistics.TotalQueries
        SampleTime=[datetime]::UtcNow
        ServerStartTime=$s.TimeStatistics.ServerStartTime
        LastClearTime=$s.TimeStatistics.LastClearTime
    }
}
$RemoteParameters = @{
    ErrorAction='Stop'
    SessionOption=(New-PSSessionOption -OpenTimeout 15000 -OperationTimeout 60000)
}
if ($Credential) { $RemoteParameters.Credential=$Credential }

# First sweep: inventory and initial statistics for all selected servers.
$Rows = @()
$FirstSamples = @{}
foreach ($computer in $Servers) {
    $server = if ($computer.DNSHostName) { $computer.DNSHostName } else { $computer.Name }
    Write-Host "Checking $server ..." -ForegroundColor Cyan
    $row = [pscustomobject][ordered]@{
        Server=$server; OperatingSystem=$computer.OperatingSystem; RemoteQuery='Failed'
        DNSRole='Unknown'; DNSService='Unknown'; ServiceStatus='Unknown'
        DomainController='Unknown'; IPAddresses=''; ClientDNS=''
        NICCheck='Unknown'; AddressCheck='Unknown'; ZoneCount=$null; Zones=''
        ADIntegratedZoneCount=$null; Forwarders=''; InitialQueries=$null
        FinalQueries=$null; QueriesObserved=$null; ObservationSeconds=$null
        StatisticsStatus='Unknown'; ServerStartTime=$null; LastClearTime=$null
        ReferencedByServerCount=$null; ReferencedByServers=''
        Assessment='Unknown'; Notes=''
    }
    try {
        $r = Invoke-Command -ComputerName $server -ScriptBlock $InventoryBlock @RemoteParameters
        $row.RemoteQuery='OK'
        foreach ($p in 'DNSRole','DNSService','ServiceStatus','DomainController','NICCheck',
            'AddressCheck','ZoneCount','Zones','ADIntegratedZoneCount','Forwarders',
            'StatisticsStatus','ServerStartTime','LastClearTime','Notes') { $row.$p=$r.$p }
        $row.IPAddresses=@($r.IPAddresses) -join '; '
        $row.ClientDNS=@($r.ClientDNS) -join '; '
        $row.InitialQueries=$r.TotalQueries
        if ($r.StatisticsStatus -eq 'OK') { $FirstSamples[$server]=$r }
    } catch { $row.Notes="Remote query failed: $($_.Exception.Message)" }
    $Rows += $row
}

# One common wait, rather than waiting separately on every DNS server.
if ($FirstSamples.Count) {
    Write-Host "Observing DNS traffic for at least $ObservationSeconds seconds ..." -ForegroundColor Yellow
    for ($remaining=$ObservationSeconds; $remaining -gt 0; $remaining-=10) {
        Write-Progress -Activity 'DNS observation' -Status "$remaining seconds remaining" `
            -PercentComplete (100 * ($ObservationSeconds-$remaining) / $ObservationSeconds)
        Start-Sleep -Seconds ([Math]::Min(10,$remaining))
    }
    Write-Progress -Activity 'DNS observation' -Completed
}
foreach ($row in $Rows) {
    if (-not $FirstSamples.ContainsKey($row.Server)) { continue }
    try {
        $first=$FirstSamples[$row.Server]
        $last=Invoke-Command -ComputerName $row.Server -ScriptBlock $SecondSampleBlock @RemoteParameters
        $row.FinalQueries=$last.TotalQueries
        $row.ObservationSeconds=[Math]::Round((([datetime]$last.SampleTime)-([datetime]$first.SampleTime)).TotalSeconds,1)
        if ($last.ServerStartTime -ne $first.ServerStartTime -or
            $last.LastClearTime -ne $first.LastClearTime -or
            $last.TotalQueries -lt $first.TotalQueries -or $row.ObservationSeconds -le 0) {
            $row.StatisticsStatus='Invalid interval'
            $row.Notes += '; Counter reset/restart or invalid timestamps; interval cannot establish usage'
        } else {
            $row.QueriesObserved=[decimal]$last.TotalQueries-[decimal]$first.TotalQueries
            $row.StatisticsStatus='OK'
        }
    } catch {
        $row.StatisticsStatus='Unknown'
        $row.Notes += "; Second sample failed: $($_.Exception.Message)"
    }
}

# Correlate only other audited servers' NIC DNS settings; this is partial coverage.
$NICFailures=@($Rows | Where-Object { $_.NICCheck -ne 'OK' }).Count
foreach ($row in $Rows) {
    if ($row.AddressCheck -eq 'OK' -and $row.IPAddresses) {
        $keys=@($row.IPAddresses -split '; ' | ForEach-Object { ConvertTo-AddressKey $_ })
        $references=@(foreach ($client in $Rows) {
            if ($client.Server -eq $row.Server -or $client.NICCheck -ne 'OK') { continue }
            foreach ($ip in ($client.ClientDNS -split '; ')) {
                if ($ip -and (ConvertTo-AddressKey $ip) -in $keys) { $client.Server; break }
            }
        })
        $row.ReferencedByServerCount=$references.Count
        $row.ReferencedByServers=$references -join '; '
    }
    if ($row.RemoteQuery -ne 'OK') { $row.Assessment='Unknown - remote query failed' }
    elseif ($row.DNSRole -eq 'Not Installed' -and $row.DNSService -eq 'Not Installed') {
        $row.Assessment='DNS Server not installed'
    }
    elseif ($row.DomainController -eq 'No' -and
        ($row.DNSRole -eq 'Installed' -or $row.DNSService -eq 'Installed')) {
        $row.Assessment='Removal candidate - DNS installed on non-domain controller'
        $row.Notes += '; Violates domain-controller-only DNS policy'
        if ($row.ReferencedByServerCount -gt 0) {
            $row.Notes += '; Redirect listed server DNS settings to domain controllers before removal'
        }
        if ($row.QueriesObserved -gt 0) {
            $row.Notes += '; DNS traffic observed; identify and redirect clients before removal'
        }
        $row.Notes += '; Check DHCP DNS options, other clients and DNS dependencies before removal'
    }
    elseif ($row.DomainController -eq 'Yes') {
        $row.Assessment='Domain controller - excluded from removal candidates'
    }
    else { $row.Assessment='Unknown - incomplete installation or domain-controller checks' }
    if ($NICFailures) { $row.Notes += "; NIC coverage incomplete: $NICFailures audited servers could not be checked" }
    $row.Notes=$row.Notes.Trim('; ')
}

$AuditPath=Join-Path $OutputDirectory 'Domain-DNS-Audit.csv'
$CandidatePath=Join-Path $OutputDirectory 'DNS-Review-Candidates.csv'
$Rows | Export-Csv -LiteralPath $AuditPath -NoTypeInformation -Encoding UTF8
$Candidates=@($Rows | Where-Object { $_.Assessment -like 'Removal candidate*' })
if ($Candidates.Count) {
    $Candidates | Export-Csv -LiteralPath $CandidatePath -NoTypeInformation -Encoding UTF8
} else {
    # Replace a prior run's candidates with an empty report retaining its columns.
    $header=($Rows[0] | ConvertTo-Csv -NoTypeInformation)[0]
    Set-Content -LiteralPath $CandidatePath -Value $header -Encoding UTF8
}
$Rows | Format-Table Server,DNSRole,ServiceStatus,ZoneCount,QueriesObserved,Assessment -Wrap -AutoSize
Write-Host "Audit complete: $AuditPath" -ForegroundColor Green
Write-Host "Review candidates: $($Candidates.Count) - $CandidatePath" -ForegroundColor Yellow
Write-Host 'Policy: DNS Server is permitted only on domain controllers. This audit makes no changes.' -ForegroundColor Yellow
