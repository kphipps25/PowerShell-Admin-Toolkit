#Requires -Version 5.1
<#
.SYNOPSIS
  Dell iDRAC9 security audit and opt-in local account password rotation.
.DESCRIPTION
  Audits local Redfish accounts by username, checks an approved-user allowlist,
  and attempts to read the Dell IPMI-over-LAN setting. Audit mode never modifies iDRAC.
  -ChangePassword selects a separate password-change mode; -Apply is required to write.
  Reserved IPMI slot 1 is reported NotVerified (not inferred from Redfish).
.EXAMPLE
  .\Invoke-iDRACSecurity.ps1 -iDRAC idrac01.example.com -ApprovedUsers root,ExampleAdmin -ApprovedUserPatterns 'OME_*'
.EXAMPLE
  .\Invoke-iDRACSecurity.ps1 -ComputerList .\Examples\iDRAC-Servers.txt -ApprovedUsersFile .\Examples\ApprovedUsers.txt -Credential (Get-Credential)
#>
[CmdletBinding(DefaultParameterSetName='Single',SupportsShouldProcess=$true,ConfirmImpact='High')]
param(
    [Parameter(Mandatory,ParameterSetName='Single')][string]$iDRAC,
    [Parameter(Mandatory,ParameterSetName='List')][string]$ComputerList,
    [Parameter(Mandatory,ParameterSetName='Csv')][string]$InputCsv,
    [string[]]$ApprovedUsers = @(),
    [string]$ApprovedUsersFile,
    [string[]]$ApprovedUserPatterns = @(),
    [pscredential]$Credential,
    [switch]$AuditOnly,
    [switch]$ChangePassword,
    [switch]$Apply,
    [string]$Username,
    [switch]$SkipCertificateCheck,
    [string]$OutputFolder = (Join-Path (Get-Location).Path 'iDRAC-Audit-Reports'),
    [ValidateRange(3,120)][int]$TimeoutSeconds = 20,
    [ValidateRange(0,5)][int]$RetryCount = 1
)
Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'
if ($ApprovedUsersFile) {
    if (-not (Test-Path -LiteralPath $ApprovedUsersFile -PathType Leaf)) { throw "ApprovedUsersFile not found: $ApprovedUsersFile" }
    $ApprovedUsers += @(Get-Content -LiteralPath $ApprovedUsersFile | ForEach-Object { $_.Trim() } | Where-Object { $_ -and -not $_.StartsWith('#') })
}
$ApprovedUsers = @($ApprovedUsers | Where-Object { $_ } | Select-Object -Unique)
$ApprovedUserPatterns = @($ApprovedUserPatterns | Where-Object { $_ } | Select-Object -Unique)
if (-not $ChangePassword -and -not $ApprovedUsers.Count -and -not $ApprovedUserPatterns.Count) { throw 'Specify an approved username or pattern. An empty allowlist is not permitted.' }
$targets = switch ($PSCmdlet.ParameterSetName) {
    'Single' { @($iDRAC) }
    'List' {
        if (-not (Test-Path -LiteralPath $ComputerList -PathType Leaf)) { throw "ComputerList not found: $ComputerList" }
        @(Get-Content -LiteralPath $ComputerList)
    }
    'Csv' {
        if (-not (Test-Path -LiteralPath $InputCsv -PathType Leaf)) { throw "InputCsv not found: $InputCsv" }
        $rows = @(Import-Csv -LiteralPath $InputCsv)
        if ($rows.Count -and -not ($rows[0].PSObject.Properties.Name -contains 'iDRAC')) { throw 'CSV requires an iDRAC column.' }
        @($rows | ForEach-Object { $_.iDRAC })
    }
}
$targets = @($targets | ForEach-Object { if ($_){ $_.Trim() } } | Where-Object { $_ -and -not $_.StartsWith('#') } | Select-Object -Unique)
if (-not $targets.Count) { throw 'No iDRAC targets supplied.' }
foreach ($target in $targets) {
    if ($target -match '[/?#@\\:]' -or $target -match '^https?') { throw "Invalid target: $target. Supply hostname or IPv4 address only." }
}
if ($SkipCertificateCheck -and $PSVersionTable.PSVersion.Major -lt 7) { throw '-SkipCertificateCheck requires PowerShell 7 or later.' }
if ($SkipCertificateCheck) { Write-Warning 'TLS certificate validation is disabled for this run. Use only on trusted management networks.' }
if (-not $Credential) { $Credential = Get-Credential -Message 'iDRAC audit credential' }
# Password changes are a separate mode. Default audit remains read-only.
if ($Apply -and -not $ChangePassword) { throw '-Apply is only valid with -ChangePassword.' }
if ($ChangePassword -and $AuditOnly) { throw '-AuditOnly cannot be combined with -ChangePassword.' }
if ($ChangePassword) {
    if (-not $Username) { $Username = Read-Host 'Local iDRAC username to update' }
    if ([string]::IsNullOrWhiteSpace($Username)) { throw 'Username is required.' }
    $Username = $Username.Trim()
    $newPassword = $null
    if ($Apply) {
        $newPassword = Read-Host 'New password' -AsSecureString
        $again = Read-Host 'Confirm new password' -AsSecureString
        $a = [System.Net.NetworkCredential]::new('', $newPassword).Password
        $b = [System.Net.NetworkCredential]::new('', $again).Password
        if (-not $a -or $a -cne $b) { throw 'New passwords do not match or are empty.' }
        $a = $null; $b = $null; $again.Dispose()
    }
}
New-Item -ItemType Directory -Path $OutputFolder -Force | Out-Null
$runId = Get-Date -Format 'yyyyMMdd-HHmmss'
$inventory = [System.Collections.Generic.List[object]]::new()
$unauthorized = [System.Collections.Generic.List[object]]::new()
$missing = [System.Collections.Generic.List[object]]::new()
$ipmi = [System.Collections.Generic.List[object]]::new()
$errors = [System.Collections.Generic.List[object]]::new()
$summary = [System.Collections.Generic.List[object]]::new()
$stamp = (Get-Date).ToString('o')
$authString = [Convert]::ToBase64String([Text.Encoding]::UTF8.GetBytes("$($Credential.UserName):$($Credential.GetNetworkCredential().Password)"))
$headers = @{ Authorization = "Basic $authString"; Accept = 'application/json' }
function Invoke-RedfishGet {
    param([string]$HostName,[string]$Path)
    # Only relative paths returned by the same iDRAC are allowed (no cross-host credential forwarding).
    if (-not $Path.StartsWith('/') -or $Path.StartsWith('//')) { throw "Unsafe Redfish path: $Path" }
    $url = "https://$HostName$Path"
    for ($attempt=0; $attempt -le $RetryCount; $attempt++) {
        try {
            $request = @{ Method='Get'; Uri=$url; Headers=$headers; TimeoutSec=$TimeoutSeconds; ErrorAction='Stop' }
            if ($SkipCertificateCheck) { $request.SkipCertificateCheck = $true }
            return Invoke-RestMethod @request
        }
        catch {
            if ($attempt -eq $RetryCount) { throw "GET $Path failed: $($_.Exception.Message)" }
            Start-Sleep -Seconds ([Math]::Min(3,1+$attempt))
        }
    }
}
function Test-ApprovedName {
    param([string]$Name)
    if ($ApprovedUsers -ccontains $Name) { return $true }
    foreach ($pattern in $ApprovedUserPatterns) { if ($Name -clike $pattern) { return $true } }
    return $false
}
function Read-IpmiAttribute {
    param($Attributes)
    if (-not $Attributes) { return 'Unknown' }
    foreach ($key in @('IPMILan.1.Enable','IPMILan.Enable','iDRAC.IPMILan.Enable')) {
        $property = $Attributes.PSObject.Properties[$key]
        if ($null -ne $property) {
            $value = [string]$property.Value
            if ($value -in @('Enabled','1','True')) { return 'Enabled' }
            if ($value -in @('Disabled','0','False')) { return 'Disabled' }
            return "Unrecognized: $value"
        }
    }
    return 'Unknown'
}
if ($ChangePassword) {
    $passwordResults = [System.Collections.Generic.List[object]]::new()
    foreach ($hostName in $targets) {
        $state='Failed'; $detail=''; $accountUri=''
        Write-Host "Checking account '$Username' on $hostName ..."
        try {
            $service = Invoke-RedfishGet -HostName $hostName -Path '/redfish/v1/AccountService'
            $collectionPath = [string]$service.Accounts.'@odata.id'
            if (-not $collectionPath) { throw 'AccountService did not provide Accounts URI.' }
            $collection = Invoke-RedfishGet -HostName $hostName -Path $collectionPath
            $matches = @()
            foreach ($member in @($collection.Members)) {
                $uri = [string]$member.'@odata.id'
                if (-not $uri -or -not $uri.StartsWith('/') -or $uri.StartsWith('//') -or $uri.Contains('?') -or $uri.Contains('#')) { continue }
                $account = Invoke-RedfishGet -HostName $hostName -Path $uri
                if ([string]$account.UserName -ceq $Username) { $matches += $uri }
            }
            if ($matches.Count -ne 1) { throw "Expected exactly one account matching '$Username'; found $($matches.Count)." }
            $accountUri = $matches[0]
            if (-not $Apply) {
                $state='WouldChange'
            } elseif ($PSCmdlet.ShouldProcess("$hostName / $Username", 'Change local iDRAC password')) {
                $url = "https://$hostName$accountUri"
                $plain = [System.Net.NetworkCredential]::new('', $newPassword).Password
                try {
                    $payload = @{Password=$plain} | ConvertTo-Json -Compress
                    $req = @{Method='Patch';Uri=$url;Headers=$headers;Body=$payload;ContentType='application/json';TimeoutSec=$TimeoutSeconds;ErrorAction='Stop'}
                    if ($SkipCertificateCheck) { $req.SkipCertificateCheck=$true }
                    $null = Invoke-RestMethod @req
                } finally { $plain=$null; $payload=$null }
                $state='PatchAccepted'
                $detail='PATCH accepted; verify authentication separately using new password.'
            } else { $state='Skipped' }
        } catch {
            $detail=$_.Exception.Message
        }
        $passwordResults.Add([pscustomobject]@{Timestamp=(Get-Date).ToString('o');iDRAC=$hostName;Username=$Username;AccountUri=$accountUri;Status=$state;Detail=$detail})
    }
    $passwordReport = Join-Path $OutputFolder "iDRAC-PasswordChange-$runId.csv"
    $passwordResults | Export-Csv -Path $passwordReport -NoTypeInformation -Encoding UTF8
    $headers.Clear(); $authString=$null
    if ($null -ne $newPassword) { $newPassword.Dispose() }
    Write-Host "Password mode complete. Report: $passwordReport"
    $passwordResults | Format-Table iDRAC,Username,Status -AutoSize
    return
}
foreach ($hostName in $targets) {
    Write-Host "Auditing $hostName ..."
    $count=0; $unapprovedCount=0; $status='Success'; $ipmiState='Unknown'; $slot1Lan='Unknown'; $slot1Serial='Unknown'
    try {
        $service = Invoke-RedfishGet -HostName $hostName -Path '/redfish/v1/AccountService'
        $accountsPath = [string]$service.Accounts.'@odata.id'
        if (-not $accountsPath) { throw 'AccountService did not return Accounts URI.' }
        $collection = Invoke-RedfishGet -HostName $hostName -Path $accountsPath
        $members = @($collection.Members | Where-Object { $_ })
        $seen = [System.Collections.Generic.HashSet[string]]::new([System.StringComparer]::Ordinal)
        foreach ($member in $members) {
            $uri = [string]$member.'@odata.id'
            if (-not $uri) { continue }
            $account = Invoke-RedfishGet -HostName $hostName -Path $uri
            $name = [string]$account.UserName
            if ([string]::IsNullOrWhiteSpace($name)) { continue }
            $count++
            [void]$seen.Add($name)
            $approved = Test-ApprovedName $name
            $accountId = [string]$account.Id
            $inventory.Add([pscustomobject]@{Timestamp=$stamp;iDRAC=$hostName;AccountId=$accountId;Username=$name;Enabled=$account.Enabled;RoleId=$account.RoleId;Approved=$approved;AccountUri=$uri})
            if (-not $approved) {
                $unapprovedCount++
                $unauthorized.Add([pscustomobject]@{Timestamp=$stamp;iDRAC=$hostName;AccountId=$accountId;Username=$name;Enabled=$account.Enabled;Reason='Not approved'})
            }
        }
        foreach ($required in $ApprovedUsers) {
            if (-not $seen.Contains($required)) {
                $missing.Add([pscustomobject]@{Timestamp=$stamp;iDRAC=$hostName;Username=$required;Reason='Required username missing'})
            }
        }
        try {
            # Dell iDRAC9 exposes IPMI settings at this validated OEM attributes endpoint.
            $attributes = Invoke-RedfishGet -HostName $hostName -Path '/redfish/v1/Managers/iDRAC.Embedded.1/Attributes'
            $ipmiState = Read-IpmiAttribute $attributes.Attributes
            if ($attributes.Attributes) {
                $lanProperty = $attributes.Attributes.PSObject.Properties['Users.1.IpmiLanPrivilege']
                $serialProperty = $attributes.Attributes.PSObject.Properties['Users.1.IpmiSerialPrivilege']
                if ($null -ne $lanProperty) { $slot1Lan = [string]$lanProperty.Value }
                if ($null -ne $serialProperty) { $slot1Serial = [string]$serialProperty.Value }
            }
        } catch {
            $errors.Add([pscustomobject]@{Timestamp=$stamp;iDRAC=$hostName;Component='IPMIAttributes';Error=$_.Exception.Message})
        }
    } catch {
        $status='Failed'
        $errors.Add([pscustomobject]@{Timestamp=$stamp;iDRAC=$hostName;Component='AccountAudit';Error=$_.Exception.Message})
    }
    $ipmi.Add([pscustomobject]@{Timestamp=$stamp;iDRAC=$hostName;IPMIOverLAN=$ipmiState;ReservedIPMIUser='NotVerified';ReservedSlot1LanPrivilege=$slot1Lan;ReservedSlot1SerialPrivilege=$slot1Serial;Note='Privileges do not establish whether reserved slot 1 is enabled. Reserved account state is not verified.'})
    $summary.Add([pscustomobject]@{Timestamp=$stamp;iDRAC=$hostName;Status=$status;AccountsFound=$count;UnauthorizedFound=$unapprovedCount;IPMIOverLAN=$ipmiState})
}
$exports = @{
    'iDRAC-AccountInventory'=$inventory
    'iDRAC-UnauthorizedUsers'=$unauthorized
    'iDRAC-MissingUsers'=$missing
    'iDRAC-IPMISecurity'=$ipmi
    'iDRAC-AuditErrors'=$errors
    'iDRAC-AuditSummary'=$summary
}
foreach ($key in $exports.Keys) {
    $path = Join-Path $OutputFolder "$key-$runId.csv"
    if ($exports[$key].Count) { $exports[$key] | Export-Csv -Path $path -NoTypeInformation -Encoding UTF8 }
    else { 'No records' | Set-Content -Path (Join-Path $OutputFolder "$key-$runId.txt") -Encoding UTF8 }
}
$headers.Clear()
$authString=$null
Write-Host "Read-only audit complete. Reports: $OutputFolder"
$summary | Format-Table -AutoSize
