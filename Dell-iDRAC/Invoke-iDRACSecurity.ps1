#Requires -Version 5.1
<#
.SYNOPSIS
  Dell iDRAC9 security audit and opt-in local account password rotation.
.DESCRIPTION
  Audits local Redfish accounts by username, checks an approved-user allowlist,
  and attempts to read the Dell IPMI-over-LAN setting. Audit mode never modifies iDRAC.
  -ChangePassword, -ChangeRole, -DisableUnauthorized or -RemoveUnauthorized select
  separate management modes. -Apply is required to write. Default audit is read-only.
  Removal disables the slot and clears its role, then clears its username using PATCH.
  -ChangePassword -CreateIfMissing prompts for the role of new accounts (or use -RoleID).
  Reports per-account IPMI LAN/serial privilege and SOL setting when Dell OEM
  Users.<slot> attributes are exposed. Missing values are Unknown, not Disabled.
  Reserved IPMI slot 1 is reported NotVerified (not inferred from Redfish).
.EXAMPLE
  # Read-only audit for one controller.
  .\Invoke-iDRACSecurity.ps1 -iDRAC idrac01 -ApprovedUsers root,ExampleAdmin -ApprovedUserPatterns 'OME_*'
.EXAMPLE
  # Read-only audit from CSV (CSV header must be iDRAC).
  .\Invoke-iDRACSecurity.ps1 -InputCsv .\iDRAC_List.csv -ApprovedUsers root,ExampleAdmin -ApprovedUserPatterns 'OME_*' -SkipCertificateCheck
.EXAMPLE
  # Preview password change, then add -Apply to change it (prompts for username/password).
  .\Invoke-iDRACSecurity.ps1 -iDRAC idrac01 -ChangePassword -Username ExampleAdmin
.EXAMPLE
  # Preview password rotation and creation of missing accounts. Prompts once for the new account role.
  .\Invoke-iDRACSecurity.ps1 -InputCsv .\iDRAC_List.csv -ChangePassword -CreateIfMissing -Username ExampleAdmin
.EXAMPLE
  # Rotate password and create missing accounts with the same prompted password; prompts for new-account role.
  .\Invoke-iDRACSecurity.ps1 -InputCsv .\iDRAC_List.csv -ChangePassword -CreateIfMissing -Username ExampleAdmin -Apply
.EXAMPLE
  # Change account role; omit -Apply for preview.
  .\Invoke-iDRACSecurity.ps1 -iDRAC idrac01 -ChangeRole -Username ExampleAdmin -RoleID ReadOnly -Apply
.EXAMPLE
  # Preview disabling unapproved users; no changes without -Apply.
  .\Invoke-iDRACSecurity.ps1 -iDRAC idrac01 -ApprovedUsers root,ExampleAdmin,ExampleMonitoring,ExampleScanner -ApprovedUserPatterns 'OME_*' -DisableUnauthorized
.EXAMPLE
  # Disable unapproved users on one controller (prompts for each change).
  .\Invoke-iDRACSecurity.ps1 -iDRAC idrac01 -ApprovedUsers root,ExampleAdmin,ExampleMonitoring,ExampleScanner -ApprovedUserPatterns 'OME_*' -DisableUnauthorized -Apply
.EXAMPLE
  # Preview permanent removal; -Apply is required and prompts for each account.
  .\Invoke-iDRACSecurity.ps1 -iDRAC idrac01 -ApprovedUsers root,ExampleAdmin,ExampleMonitoring,ExampleScanner -ApprovedUserPatterns 'OME_*' -RemoveUnauthorized
.EXAMPLE
  # Clear unauthorized account slots via two Redfish PATCH requests; review preview first.
  .\Invoke-iDRACSecurity.ps1 -iDRAC idrac01 -ApprovedUsers root,ExampleAdmin,ExampleMonitoring,ExampleScanner -ApprovedUserPatterns 'OME_*' -RemoveUnauthorized -Apply
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
    [switch]$CreateIfMissing,
    [switch]$ChangeRole,
    [switch]$DisableUnauthorized,
    [switch]$RemoveUnauthorized,
    [ValidateSet('Administrator','Operator','ReadOnly','None')][string]$RoleID,
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
if (-not ($ChangePassword -or $ChangeRole) -and -not $ApprovedUsers.Count -and -not $ApprovedUserPatterns.Count) { throw 'Specify an approved username or pattern. An empty allowlist is not permitted.' }
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
# All write operations are explicitly selected and require -Apply.
if (($ChangePassword -and ($ChangeRole -or $DisableUnauthorized -or $RemoveUnauthorized)) -or
    ($ChangeRole -and ($DisableUnauthorized -or $RemoveUnauthorized)) -or
    ($DisableUnauthorized -and $RemoveUnauthorized)) { throw 'Choose only one management mode.' }
$manage = [bool]($ChangePassword -or $ChangeRole -or $DisableUnauthorized -or $RemoveUnauthorized)
if ($Apply -and -not $manage) { throw '-Apply requires a management mode.' }
if ($CreateIfMissing -and -not $ChangePassword) { throw '-CreateIfMissing requires -ChangePassword.' }
if ($ChangeRole -and -not $RoleID) { throw '-RoleID is required with -ChangeRole.' }
if ($RoleID -and -not ($ChangeRole -or ($ChangePassword -and $CreateIfMissing))) { throw '-RoleID requires -ChangeRole or -ChangePassword -CreateIfMissing.' }
if ($manage -and $AuditOnly) { throw '-AuditOnly cannot be combined with a management mode.' }
if (($DisableUnauthorized -or $RemoveUnauthorized) -and -not ($ApprovedUsers.Count -or $ApprovedUserPatterns.Count)) { throw 'An approved-user allowlist is required.' }
if ($ChangePassword -or $ChangeRole) {
    if (-not $Username) { $Username = Read-Host 'Local iDRAC username to update' }
    if ([string]::IsNullOrWhiteSpace($Username)) { throw 'Username is required.' }
    $Username = $Username.Trim()
    $newPassword = $null
    if ($ChangePassword -and $CreateIfMissing -and -not $RoleID) {
        do {
            $choice = (Read-Host 'Role for NEW accounts (Administrator, Operator, ReadOnly, None)').Trim()
            if ($choice -in @('Administrator','Operator','ReadOnly','None')) { $RoleID = $choice; break }
            Write-Warning 'Enter Administrator, Operator, ReadOnly, or None.'
        } while ($true)
    }
    if ($Apply -and $ChangePassword) {
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
if ($DisableUnauthorized -or $RemoveUnauthorized) {
    $action = if ($DisableUnauthorized) { 'Disable' } else { 'Remove' }
    $cleanup = [System.Collections.Generic.List[object]]::new()
    foreach ($hostName in $targets) {
        Write-Host "Reviewing unauthorized accounts on $hostName ..."
        try {
            $service = Invoke-RedfishGet -HostName $hostName -Path '/redfish/v1/AccountService'
            $accountsPath = [string]$service.Accounts.'@odata.id'
            if (-not $accountsPath) { throw 'AccountService did not provide Accounts URI.' }
            $collection = Invoke-RedfishGet -HostName $hostName -Path $accountsPath
            foreach ($member in @($collection.Members)) {
                $uri = [string]$member.'@odata.id'
                if (-not $uri -or $uri -notmatch '^/redfish/v1/AccountService/Accounts/[0-9]+$') { continue }
                $account = Invoke-RedfishGet -HostName $hostName -Path $uri
                $name = [string]$account.UserName
                if ([string]::IsNullOrWhiteSpace($name) -or (Test-ApprovedName $name)) { continue }
                $accountId = [string]$account.Id
                $state = 'WouldChange'; $detail = ''
                # Never alter root, the login account, or reserved slot 1, even if missing from allowlist.
                if ($name -ieq 'root' -or $name -ieq $Credential.UserName -or $accountId -eq '1') {
                    $state = 'Protected'; $detail = 'Protected root, current login, or reserved account slot.'
                } elseif ($DisableUnauthorized -and $account.Enabled -eq $false) {
                    $state = 'AlreadyDisabled'
                } elseif ($Apply) {
                    try {
                        if ($PSCmdlet.ShouldProcess("$hostName / $name / $accountId", "$action unauthorized local account")) {
                            $request = @{Method='Patch';Uri="https://$hostName$uri";Headers=$headers;TimeoutSec=$TimeoutSeconds;ErrorAction='Stop';ContentType='application/json'}
                            if ($SkipCertificateCheck) { $request.SkipCertificateCheck=$true }
                            if ($DisableUnauthorized) {
                                $request.Body = '{"Enabled":false}'
                                $null = Invoke-RestMethod @request
                                $check = Invoke-RedfishGet -HostName $hostName -Path $uri
                                if ($check.Enabled -eq $false) { $state='VerifiedDisabled' }
                                else { $state='VerificationFailed'; $detail='Account still enabled after PATCH.' }
                            } else {
                                # Dell account-slot removal: first disable and clear role,
                                # then clear username. Do not use HTTP DELETE (405 on iDRAC).
                                $request.Body = '{"Enabled":false,"RoleId":"None"}'
                                $null = Invoke-RestMethod @request
                                $check = Invoke-RedfishGet -HostName $hostName -Path $uri
                                if ($check.Enabled -ne $false -or [string]$check.RoleId -ne 'None') {
                                    $state='VerificationFailed'
                                    $detail='First PATCH did not confirm Enabled=false and RoleId=None; username was not cleared.'
                                } else {
                                    $request.Body = '{"UserName":""}'
                                    $null = Invoke-RestMethod @request
                                    $check = Invoke-RedfishGet -HostName $hostName -Path $uri
                                    if ([string]::IsNullOrWhiteSpace([string]$check.UserName) -and $check.Enabled -eq $false) {
                                        $state='VerifiedRemoved'
                                    } else {
                                        $state='VerificationFailed'
                                        $detail='Username was not cleared or account is still enabled after second PATCH.'
                                    }
                                }
                            }
                        } else { $state='Skipped' }
                    } catch { $state='Failed'; $detail=$_.Exception.Message }
                }
                $cleanup.Add([pscustomobject]@{Timestamp=(Get-Date).ToString('o');iDRAC=$hostName;AccountId=$accountId;Username=$name;Action=$action;Status=$state;Detail=$detail})
            }
        } catch {
            $cleanup.Add([pscustomobject]@{Timestamp=(Get-Date).ToString('o');iDRAC=$hostName;AccountId='';Username='';Action=$action;Status='Failed';Detail=$_.Exception.Message})
        }
    }
    $report = Join-Path $OutputFolder "iDRAC-Unauthorized-$action-$runId.csv"
    if ($cleanup.Count) { $cleanup | Export-Csv -LiteralPath $report -NoTypeInformation -Encoding UTF8 }
    else { Write-Host 'No unauthorized accounts found; no CSV generated.' }
    $headers.Clear(); $authString=$null
    Write-Host "Unauthorized account $action report: $report"
    $cleanup | Format-Table iDRAC,Username,Action,Status -AutoSize
    return
}
if ($ChangePassword -or $ChangeRole) {
    $passwordResults = [System.Collections.Generic.List[object]]::new()
    foreach ($hostName in $targets) {
        $state='Failed'; $detail=''; $accountUri=''; $beforeRole=''; $afterRole=''
        Write-Host "Checking account '$Username' on $hostName ..."
        try {
            $service = Invoke-RedfishGet -HostName $hostName -Path '/redfish/v1/AccountService'
            $collectionPath = [string]$service.Accounts.'@odata.id'
            if (-not $collectionPath) { throw 'AccountService did not provide Accounts URI.' }
            $collection = Invoke-RedfishGet -HostName $hostName -Path $collectionPath
            $matchingAccounts = @()
            $emptySlots = @()
            foreach ($member in @($collection.Members)) {
                $uri = [string]$member.'@odata.id'
                if (-not $uri -or $uri -notmatch '^/redfish/v1/AccountService/Accounts/([0-9]+)$') { continue }
                $slotId = [int]$Matches[1]
                $account = Invoke-RedfishGet -HostName $hostName -Path $uri
                if ([string]$account.UserName -ceq $Username) {
                    $matchingAccounts += [pscustomobject]@{Uri=$uri;Role=[string]$account.RoleId}
                } elseif ($slotId -gt 1 -and [string]::IsNullOrWhiteSpace([string]$account.UserName) -and $account.Enabled -eq $false) {
                    $emptySlots += [pscustomobject]@{Uri=$uri;Slot=$slotId}
                }
            }
            if ($matchingAccounts.Count -gt 1) { throw "Multiple accounts match '$Username'; refusing to modify." }
            if ($matchingAccounts.Count -eq 0) {
                if (-not ($ChangePassword -and $CreateIfMissing)) { throw "Account '$Username' not found." }
                if (-not $emptySlots.Count) { throw 'No empty disabled Redfish account slot available.' }
                $slot = @($emptySlots | Sort-Object Slot | Select-Object -First 1)[0]
                $accountUri = [string]$slot.Uri
                if (-not $Apply) {
                    $state='WouldCreate'; $detail="New account role: $RoleID; empty slot: $($slot.Slot)"
                } elseif ($PSCmdlet.ShouldProcess("$hostName / $Username / slot $($slot.Slot)", "Create local account with role $RoleID")) {
                    $plain=$null; $payload=$null
                    try {
                        $plain=[System.Net.NetworkCredential]::new('', $newPassword).Password
                        $payload=@{UserName=$Username;Password=$plain;RoleId=$RoleID;Enabled=$true} | ConvertTo-Json -Compress
                        $req=@{Method='Patch';Uri="https://$hostName$accountUri";Headers=$headers;Body=$payload;ContentType='application/json';TimeoutSec=$TimeoutSeconds;ErrorAction='Stop'}
                        if ($SkipCertificateCheck) { $req.SkipCertificateCheck=$true }
                        $null=Invoke-RestMethod @req
                    } finally { $plain=$null; $payload=$null }
                    $created=Invoke-RedfishGet -HostName $hostName -Path $accountUri
                    if ([string]$created.UserName -ceq $Username -and $created.Enabled -eq $true -and [string]$created.RoleId -ceq $RoleID) {
                        $state='VerifiedCreated'; $afterRole=[string]$created.RoleId
                        $detail='Account properties verified; verify password by authenticating separately.'
                    } else {
                        $state='VerificationMismatch'; $detail='Account properties did not match requested values.'
                    }
                } else { $state='Skipped' }
                $passwordResults.Add([pscustomobject]@{Timestamp=(Get-Date).ToString('o');iDRAC=$hostName;Username=$Username;AccountUri=$accountUri;BeforeRoleID='';RequestedRoleID=$RoleID;AfterRoleID=$afterRole;Status=$state;Detail=$detail})
                continue
            }
            $accountUri = [string]$matchingAccounts[0].Uri
            $beforeRole = [string]$matchingAccounts[0].Role
            if ($ChangeRole -and $beforeRole -ceq $RoleID) { $state='AlreadyCompliant'; $afterRole=$beforeRole }
            elseif (-not $Apply) {
                $state='WouldChange'
            } elseif ($PSCmdlet.ShouldProcess("$hostName / $Username", $(if ($ChangeRole) { "Change role to $RoleID" } else { 'Change local iDRAC password' }))) {
                $url = "https://$hostName$accountUri"
                $plain=$null; $payload=$null
                try {
                    if ($ChangeRole) { $payload=@{RoleId=$RoleID} | ConvertTo-Json -Compress }
                    else {
                        $plain=[System.Net.NetworkCredential]::new('', $newPassword).Password
                        $payload=@{Password=$plain} | ConvertTo-Json -Compress
                    }
                    $req=@{Method='Patch';Uri=$url;Headers=$headers;Body=$payload;ContentType='application/json';TimeoutSec=$TimeoutSeconds;ErrorAction='Stop'}
                    if ($SkipCertificateCheck) { $req.SkipCertificateCheck=$true }
                    $null=Invoke-RestMethod @req
                } finally { $plain=$null; $payload=$null }
                if ($ChangeRole) {
                    $updated=Invoke-RedfishGet -HostName $hostName -Path $accountUri
                    $afterRole=[string]$updated.RoleId
                    if ($afterRole -ceq $RoleID) { $state='Verified' }
                    else { $state='VerificationMismatch'; $detail="RoleId readback: $afterRole" }
                } else {
                    $state='PatchAccepted'
                    $detail='PATCH accepted; verify authentication separately using new password.'
                }
            } else { $state='Skipped' }
        } catch {
            $detail=$_.Exception.Message
        }
        $passwordResults.Add([pscustomobject]@{Timestamp=(Get-Date).ToString('o');iDRAC=$hostName;Username=$Username;AccountUri=$accountUri;BeforeRoleID=$beforeRole;RequestedRoleID=$(if ($ChangeRole) {$RoleID} else {''});AfterRoleID=$afterRole;Status=$state;Detail=$detail})
    }
    $passwordReport = Join-Path $OutputFolder "iDRAC-AccountChange-$runId.csv"
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
        # Read Dell OEM attributes once per controller. Missing attributes are reported as Unknown.
        $oemAttributes = $null
        try {
            $oemResponse = Invoke-RedfishGet -HostName $hostName -Path '/redfish/v1/Managers/iDRAC.Embedded.1/Attributes'
            $oemAttributes = $oemResponse.Attributes
            $ipmiState = Read-IpmiAttribute $oemAttributes
            if ($oemAttributes) {
                $p = $oemAttributes.PSObject.Properties['Users.1.IpmiLanPrivilege']
                if ($null -ne $p) { $slot1Lan = [string]$p.Value }
                $p = $oemAttributes.PSObject.Properties['Users.1.IpmiSerialPrivilege']
                if ($null -ne $p) { $slot1Serial = [string]$p.Value }
            }
        } catch {
            $errors.Add([pscustomobject]@{Timestamp=$stamp;iDRAC=$hostName;Component='IPMIAttributes';Error=$_.Exception.Message})
        }
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
            $lanPrivilege='Unknown'; $serialPrivilege='Unknown'; $solEnabled='Unknown'
            # Redfish Account Id is expected to match Dell's Users.<slot> attributes on iDRAC9.
            # Do not guess when the account Id is not a numeric slot.
            if ($oemAttributes -and $accountId -match '^[0-9]+$') {
                $slot = [int]$accountId
                foreach ($entry in @(
                    @{Key="Users.$slot.IpmiLanPrivilege";Name='Lan'},
                    @{Key="Users.$slot.IpmiSerialPrivilege";Name='Serial'},
                    @{Key="Users.$slot.SolEnable";Name='Sol'}
                )) {
                    $prop = $oemAttributes.PSObject.Properties[$entry.Key]
                    if ($null -eq $prop) { continue }
                    switch ($entry.Name) {
                        'Lan' { $lanPrivilege = [string]$prop.Value }
                        'Serial' { $serialPrivilege = [string]$prop.Value }
                        'Sol' { $solEnabled = [string]$prop.Value }
                    }
                }
            }
            $inventory.Add([pscustomobject]@{Timestamp=$stamp;iDRAC=$hostName;AccountId=$accountId;Username=$name;Enabled=$account.Enabled;RoleId=$account.RoleId;IPMILanPrivilege=$lanPrivilege;IPMISerialPrivilege=$serialPrivilege;SerialOverLAN=$solEnabled;IPMIOverLAN=$ipmiState;Approved=$approved;AccountUri=$uri})
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
