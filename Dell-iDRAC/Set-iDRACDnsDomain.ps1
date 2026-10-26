#Requires -Version 7.0
<#
.SYNOPSIS
  Audit or set Dell iDRAC9 DNS registration/domain settings using Redfish.
.DESCRIPTION
  Reads a CSV with an iDRAC column. Read-only by default.
  -Apply changes settings through the Redfish Manager Attributes endpoint.
.EXAMPLE
  .\Set-iDRACDnsDomain.ps1 -InputCsv .\iDRAC_List.csv -SkipCertificateCheck
.EXAMPLE
  .\Set-iDRACDnsDomain.ps1 -InputCsv .\Test-iDRACs.csv -Apply -SkipCertificateCheck -Confirm:$false
#>
[CmdletBinding(SupportsShouldProcess=$true,ConfirmImpact='High')]
param(
    [Parameter(Mandatory)][string]$InputCsv,
    [string]$Domain='umpq.umpquabank.com',
    [pscredential]$Credential,
    [switch]$Apply,
    [switch]$SkipCertificateCheck,
    [ValidateRange(5,120)][int]$TimeoutSeconds=30,
    [string]$OutputFolder=(Join-Path (Get-Location).Path 'iDRAC-DNS-Reports')
)
Set-StrictMode -Version Latest
$ErrorActionPreference='Stop'
if (-not (Test-Path -LiteralPath $InputCsv -PathType Leaf)) { throw "CSV not found: $InputCsv" }
if ($Domain -notmatch '^(?=.{1,253}$)[A-Za-z0-9](?:[A-Za-z0-9-]*[A-Za-z0-9])?(?:\.[A-Za-z0-9](?:[A-Za-z0-9-]*[A-Za-z0-9])?)+$') { throw "Invalid DNS domain: $Domain" }
$rows=@(Import-Csv -LiteralPath $InputCsv)
if (-not $rows.Count -or -not ($rows[0].PSObject.Properties.Name -contains 'iDRAC')) { throw 'CSV must contain at least one row and an iDRAC column.' }
$targets=@($rows | ForEach-Object { if ($null -ne $_.iDRAC) { $_.iDRAC.Trim() } } | Where-Object { $_ -and -not $_.StartsWith('#') } | Select-Object -Unique)
if (-not $targets.Count) { throw 'No iDRAC targets found.' }
foreach ($target in $targets) { if ($target -notmatch '^[a-zA-Z0-9][a-zA-Z0-9.\-]*$') { throw "Invalid target: $target" } }
if (-not $Credential) { $Credential=Get-Credential -Message 'iDRAC credentials' }
$auth=[Convert]::ToBase64String([Text.Encoding]::UTF8.GetBytes("$($Credential.UserName):$($Credential.GetNetworkCredential().Password)"))
$headers=@{ Authorization="Basic $auth"; Accept='application/json' }
$path='/redfish/v1/Managers/iDRAC.Embedded.1/Attributes'
$desired=[ordered]@{
    'NIC.1.DNSRegister'='Disabled'
    'NIC.1.DNSDomainNameFromDHCP'='Disabled'
    'NICStatic.1.DNSDomainName'=$Domain
}
function Request-Redfish {
    param([string]$HostName,[ValidateSet('GET','PATCH')][string]$Method,[object]$Body)
    $p=@{Uri="https://$HostName$path";Method=$Method;Headers=$headers;TimeoutSec=$TimeoutSeconds;ErrorAction='Stop'}
    if ($SkipCertificateCheck) { $p.SkipCertificateCheck=$true }
    if ($Method -eq 'PATCH') { $p.ContentType='application/json';$p.Body=($Body | ConvertTo-Json -Depth 5 -Compress) }
    Invoke-RestMethod @p
}
function Get-AttributeValue {
    param($Object,[string]$Name)
    $prop=$Object.PSObject.Properties[$Name]
    if ($null -eq $prop) { return $null }
    return [string]$prop.Value
}
New-Item -ItemType Directory -Path $OutputFolder -Force | Out-Null
$results=[System.Collections.Generic.List[object]]::new()
foreach ($target in $targets) {
    Write-Host "Checking $target ..."
    $row=[ordered]@{Timestamp=(Get-Date).ToString('o');iDRAC=$target;BeforeDNSRegister='';BeforeAutoDomain='';BeforeStaticDomain='';AfterDNSRegister='';AfterAutoDomain='';AfterStaticDomain='';Status='';Error=''}
    try {
        $before=Request-Redfish -HostName $target -Method GET
        $a=$before.Attributes
        foreach ($key in $desired.Keys) { if ($null -eq $a.PSObject.Properties[$key]) { throw "Firmware did not expose attribute $key; no changes made." } }
        $row.BeforeDNSRegister=Get-AttributeValue $a 'NIC.1.DNSRegister'
        $row.BeforeAutoDomain=Get-AttributeValue $a 'NIC.1.DNSDomainNameFromDHCP'
        $row.BeforeStaticDomain=Get-AttributeValue $a 'NICStatic.1.DNSDomainName'
        $changes=@{}
        foreach ($key in $desired.Keys) {
            if ((Get-AttributeValue $a $key) -ine [string]$desired[$key]) { $changes[$key]=$desired[$key] }
        }
        if (-not $changes.Count) { $row.Status='AlreadyCompliant' }
        elseif (-not $Apply) { $row.Status='WouldChange' }
        elseif ($PSCmdlet.ShouldProcess($target, "Set iDRAC DNS registration Disabled, auto domain Disabled, static domain $Domain")) {
            $null=Request-Redfish -HostName $target -Method PATCH -Body @{Attributes=$changes}
            $after=Request-Redfish -HostName $target -Method GET
            $row.AfterDNSRegister=Get-AttributeValue $after.Attributes 'NIC.1.DNSRegister'
            $row.AfterAutoDomain=Get-AttributeValue $after.Attributes 'NIC.1.DNSDomainNameFromDHCP'
            $row.AfterStaticDomain=Get-AttributeValue $after.Attributes 'NICStatic.1.DNSDomainName'
            if ($row.AfterDNSRegister -ieq 'Disabled' -and $row.AfterAutoDomain -ieq 'Disabled' -and $row.AfterStaticDomain -ieq $Domain) { $row.Status='Verified' }
            else { $row.Status='VerificationMismatch';$row.Error='Readback does not yet match requested settings. Check pending iDRAC jobs or apply requirements.' }
        }
        else { $row.Status='Skipped' }
    }
    catch {
        $row.Status='Failed'
        $row.Error=$_.Exception.Message
    }
    $results.Add([pscustomobject]$row)
}
$report=Join-Path $OutputFolder ("iDRAC-DNS-{0}.csv" -f (Get-Date -Format 'yyyyMMdd-HHmmss'))
$results | Export-Csv -LiteralPath $report -NoTypeInformation -Encoding utf8
$results | Format-Table iDRAC,BeforeDNSRegister,BeforeAutoDomain,BeforeStaticDomain,Status -AutoSize
Write-Host "Report: $report"
