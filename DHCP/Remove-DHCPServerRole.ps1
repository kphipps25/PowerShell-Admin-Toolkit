#requires -Modules ActiveDirectory

<#
.SYNOPSIS
    Safely removes the DHCP Server role from servers identified
    in Domain-DHCP-Audit.csv.

.DESCRIPTION
    Workflow:

      1. Read candidate DHCP servers from CSV.
      2. Verify WinRM connectivity.
      3. Query CURRENT DHCP role/service/scope state.
      4. LOCK removal if DHCP scopes cannot be queried.
      5. LOCK removal if active IPv4 scopes exist.
      6. Require explicit per-server confirmation.
      7. Remove DHCP role WITHOUT rebooting.
      8. Verify DHCP Windows Feature removal.
      9. Remove C:\Users\Public\Desktop\dhcp.lnk.
     10. Record servers requiring reboot.
     11. Continue through all servers.
     12. Optionally remove DHCP authorization from AD.
     13. At the end, display all servers requiring reboot.
     14. Require REBOOT-ALL confirmation.
     15. Send reboot command to all approved servers.
     16. Monitor WinRM for all rebooted servers.
     17. After servers return, verify DHCP role, service, and shortcut.
     18. Export post-reboot verification CSV.
#>

Import-Module ActiveDirectory

$CSVFile = ".\Domain-DHCP-Audit.csv"
$AllowActiveScopeOverride = $false
$RemoveDHCPAuthorization = $false
$OfferRebootAtEnd = $true
$PostRebootTimeoutSeconds = 900
$WinRMPollSeconds = 10
$PostRebootSettleSeconds = 20
$DHCPShortcutPath = "C:\Users\Public\Desktop\dhcp.lnk"
$RemovalLog = ".\DHCP-Removal-Results.csv"
$ScopeBackup = ".\DHCP-Scope-Backup.csv"
$RebootList = ".\DHCP-Servers-Requiring-Reboot.csv"
$PostRebootLog = ".\DHCP-Post-Reboot-Verification.csv"

function Test-RemoteWinRM {
    param([Parameter(Mandatory)][string]$ComputerName)
    try {
        Test-WSMan -ComputerName $ComputerName -ErrorAction Stop | Out-Null
        Invoke-Command -ComputerName $ComputerName -ErrorAction Stop -ScriptBlock { $env:COMPUTERNAME } | Out-Null
        return $true
    } catch { return $false }
}

function Get-RemoteDHCPState {
    param([Parameter(Mandatory)][string]$ComputerName,[switch]$SkipScopeQuery)
    Invoke-Command -ComputerName $ComputerName -ErrorAction Stop -ScriptBlock {
        param($SkipScopeQuery)
        $Role = Get-WindowsFeature -Name DHCP -ErrorAction SilentlyContinue
        $RoleInstalled = ($Role -and $Role.InstallState -eq "Installed")
        $Service = Get-Service -Name DHCPServer -ErrorAction SilentlyContinue
        $ServiceInstalled = [bool]$Service
        $ServiceStatus = if ($Service) { $Service.Status.ToString() } else { "Not Installed" }
        $Scopes = @()
        $ScopeQuerySuccessful = $true
        $ScopeQueryError = ""
        if ($RoleInstalled -and -not $SkipScopeQuery) {
            try {
                Import-Module DhcpServer -ErrorAction Stop
                $Scopes = @(Get-DhcpServerv4Scope -ErrorAction Stop | Select-Object ScopeId,Name,State,StartRange,EndRange,SubnetMask)
            } catch {
                $ScopeQuerySuccessful = $false
                $ScopeQueryError = $_.Exception.Message
                $Scopes = @()
            }
        }
        $ActiveScopes = @($Scopes | Where-Object { $_.State.ToString() -eq "Active" })
        [PSCustomObject]@{
            ComputerName=$env:COMPUTERNAME; RoleInstalled=$RoleInstalled
            ServiceInstalled=$ServiceInstalled; ServiceStatus=$ServiceStatus
            ScopeQuerySuccessful=$ScopeQuerySuccessful; ScopeQueryError=$ScopeQueryError
            ScopeCount=@($Scopes).Count; ActiveScopeCount=@($ActiveScopes).Count
            Scopes=$Scopes; ActiveScopes=$ActiveScopes
        }
    } -ArgumentList ([bool]$SkipScopeQuery)
}

function Remove-RemoteDHCPShortcut {
    param([Parameter(Mandatory)][string]$ComputerName,[Parameter(Mandatory)][string]$ShortcutPath)
    Invoke-Command -ComputerName $ComputerName -ErrorAction Stop -ScriptBlock {
        param($ShortcutPath)
        if (Test-Path -LiteralPath $ShortcutPath) {
            Remove-Item -LiteralPath $ShortcutPath -Force -ErrorAction Stop
            if (Test-Path -LiteralPath $ShortcutPath) {
                [PSCustomObject]@{Found=$true;Removed=$false;Result="Removal Failed"}
            } else {
                [PSCustomObject]@{Found=$true;Removed=$true;Result="Removed"}
            }
        } else {
            [PSCustomObject]@{Found=$false;Removed=$false;Result="Not Present"}
        }
    } -ArgumentList $ShortcutPath
}

function Get-PostRebootDHCPVerification {
    param([Parameter(Mandatory)][string]$ComputerName,[Parameter(Mandatory)][string]$ShortcutPath)
    Invoke-Command -ComputerName $ComputerName -ErrorAction Stop -ScriptBlock {
        param($ShortcutPath)
        $Role = Get-WindowsFeature -Name DHCP -ErrorAction SilentlyContinue
        $RoleInstalled = ($Role -and $Role.InstallState -eq "Installed")
        $Service = Get-Service -Name DHCPServer -ErrorAction SilentlyContinue
        $ServiceInstalled = [bool]$Service
        $ServiceStatus = if ($Service) { $Service.Status.ToString() } else { "Not Installed" }
        $ShortcutPresent = Test-Path -LiteralPath $ShortcutPath
        [PSCustomObject]@{
            ComputerName=$env:COMPUTERNAME; RoleInstalled=$RoleInstalled
            ServiceInstalled=$ServiceInstalled; ServiceStatus=$ServiceStatus
            ShortcutPresent=$ShortcutPresent
        }
    } -ArgumentList $ShortcutPath
}

if (-not (Test-Path $CSVFile)) { Write-Host "ERROR: CSV file not found: $CSVFile" -ForegroundColor Red; exit 1 }
$CSV = Import-Csv $CSVFile
if (-not $CSV) { Write-Host "CSV contains no records." -ForegroundColor Yellow; exit 0 }

$TargetServers = @($CSV | Where-Object { $_.DHCPRole -eq "Installed" -or $_.DHCPService -eq "Installed" } | Sort-Object Server)
if ($TargetServers.Count -eq 0) { Write-Host "No DHCP servers found in CSV." -ForegroundColor Green; exit 0 }

$TargetServers | Format-Table Server,DHCPRole,DHCPService,ServiceStatus,Authorized,ScopeCount -AutoSize
Write-Host "No servers will reboot during DHCP removal. Required reboots are collected until the end." -ForegroundColor Cyan
if ((Read-Host "Type REMOVE-DHCP to begin") -cne "REMOVE-DHCP") { Write-Host "Cancelled. No changes made."; exit 0 }

$Results = foreach ($Target in $TargetServers) {
    $Server = $Target.Server
    Write-Host "\nProcessing: $Server" -ForegroundColor Cyan
    try {
        if (-not (Test-RemoteWinRM $Server)) {
            [PSCustomObject]@{Server=$Server;Action="LOCKED";Result="WinRM Unavailable";RoleBefore=$Target.DHCPRole;ServiceBefore=$Target.DHCPService;ServiceStatus="Unknown";ScopeCount="Unknown";ActiveScopes="Unknown";RoleAfter="Unknown";ServiceAfter="Unknown";Shortcut="Not Checked";RebootRequired="Unknown";Authorization=$Target.Authorized;Notes="Unable to establish WinRM connection"}
            continue
        }
        $DHCP = Get-RemoteDHCPState $Server
        if (-not $DHCP.RoleInstalled) {
            try { $ShortcutResult = Remove-RemoteDHCPShortcut $Server $DHCPShortcutPath } catch { $ShortcutResult=[PSCustomObject]@{Result="Check Failed"} }
            $ExistingNeedsReboot = $DHCP.ServiceInstalled
            [PSCustomObject]@{Server=$Server;Action="Cleanup";Result="Already Removed";RoleBefore="Not Installed";ServiceBefore=$(if($DHCP.ServiceInstalled){"Present"}else{"Not Installed"});ServiceStatus=$DHCP.ServiceStatus;ScopeCount=0;ActiveScopes=0;RoleAfter="Not Installed";ServiceAfter=$(if($DHCP.ServiceInstalled){"Pending Reboot"}else{"Not Installed"});Shortcut=$ShortcutResult.Result;RebootRequired=$(if($ExistingNeedsReboot){"Yes"}else{"No"});Authorization=$Target.Authorized;Notes=$(if($ExistingNeedsReboot){"Role already removed; service remains pending reboot"}else{""})}
            continue
        }
        if (-not $DHCP.ScopeQuerySuccessful) {
            [PSCustomObject]@{Server=$Server;Action="LOCKED";Result="Scope Query Failed";RoleBefore="Installed";ServiceBefore="Installed";ServiceStatus=$DHCP.ServiceStatus;ScopeCount="Unknown";ActiveScopes="Unknown";RoleAfter="Installed";ServiceAfter=$DHCP.ServiceStatus;Shortcut="Not Removed";RebootRequired="No";Authorization=$Target.Authorized;Notes=$DHCP.ScopeQueryError}
            continue
        }
        if ($DHCP.ScopeCount -gt 0) {
            foreach($Scope in $DHCP.Scopes) {
                [PSCustomObject]@{Server=$Server;ScopeId=$Scope.ScopeId;Name=$Scope.Name;State=$Scope.State;StartRange=$Scope.StartRange;EndRange=$Scope.EndRange;SubnetMask=$Scope.SubnetMask} |
                    Export-Csv -Path $ScopeBackup -NoTypeInformation -Append -Encoding UTF8
            }
        }
        if ($DHCP.ActiveScopeCount -gt 0) {
            $Proceed=$false
            if ($AllowActiveScopeOverride) { $Proceed=((Read-Host "Type REMOVE-ACTIVE-SCOPES-$Server to override") -ceq "REMOVE-ACTIVE-SCOPES-$Server") }
            if (-not $Proceed) {
                [PSCustomObject]@{Server=$Server;Action="LOCKED";Result="Active Scopes";RoleBefore="Installed";ServiceBefore="Installed";ServiceStatus=$DHCP.ServiceStatus;ScopeCount=$DHCP.ScopeCount;ActiveScopes=$DHCP.ActiveScopeCount;RoleAfter="Installed";ServiceAfter=$DHCP.ServiceStatus;Shortcut="Not Removed";RebootRequired="No";Authorization=$Target.Authorized;Notes="Active scope safety lock"}
                continue
            }
        }
        if ((Read-Host "Type REMOVE-$Server to continue") -cne "REMOVE-$Server") {
            [PSCustomObject]@{Server=$Server;Action="Skipped";Result="Operator Cancelled";RoleBefore="Installed";ServiceBefore="Installed";ServiceStatus=$DHCP.ServiceStatus;ScopeCount=$DHCP.ScopeCount;ActiveScopes=$DHCP.ActiveScopeCount;RoleAfter="Installed";ServiceAfter=$DHCP.ServiceStatus;Shortcut="Not Removed";RebootRequired="No";Authorization=$Target.Authorized;Notes=""}
            continue
        }
        $InstallResult = Invoke-Command -ComputerName $Server -ErrorAction Stop -ScriptBlock { Uninstall-WindowsFeature -Name DHCP -IncludeManagementTools }
        Start-Sleep 5
        $After = Get-RemoteDHCPState -ComputerName $Server -SkipScopeQuery
        if ($After.RoleInstalled) {
            [PSCustomObject]@{Server=$Server;Action="Remove DHCP";Result="Removal Failed";RoleBefore="Installed";ServiceBefore="Installed";ServiceStatus=$DHCP.ServiceStatus;ScopeCount=$DHCP.ScopeCount;ActiveScopes=$DHCP.ActiveScopeCount;RoleAfter="Installed";ServiceAfter=$After.ServiceStatus;Shortcut="Not Removed";RebootRequired=$InstallResult.RestartNeeded;Authorization=$Target.Authorized;Notes="DHCP Windows Feature still reports Installed"}
            continue
        }
        try { $ShortcutResult=Remove-RemoteDHCPShortcut $Server $DHCPShortcutPath } catch { $ShortcutResult=[PSCustomObject]@{Result="Removal Check Failed"} }
        $NeedsReboot = ($InstallResult.RestartNeeded.ToString() -eq "Yes" -or $After.ServiceInstalled)
        [PSCustomObject]@{Server=$Server;Action="Remove DHCP";Result=$(if($NeedsReboot){"Successfully Removed - Reboot Required"}else{"Successfully Removed"});RoleBefore="Installed";ServiceBefore=$(if($DHCP.ServiceInstalled){"Installed"}else{"Not Installed"});ServiceStatus=$DHCP.ServiceStatus;ScopeCount=$DHCP.ScopeCount;ActiveScopes=$DHCP.ActiveScopeCount;RoleAfter="Not Installed";ServiceAfter=$(if($After.ServiceInstalled){"Pending Reboot"}else{"Not Installed"});Shortcut=$ShortcutResult.Result;RebootRequired=$(if($NeedsReboot){"Yes"}else{"No"});Authorization=$Target.Authorized;Notes=$(if($NeedsReboot){"DHCP role removed; reboot deferred"}else{""})}
    } catch {
        [PSCustomObject]@{Server=$Server;Action="Error";Result="Error";RoleBefore=$Target.DHCPRole;ServiceBefore=$Target.DHCPService;ServiceStatus="Unknown";ScopeCount="Unknown";ActiveScopes="Unknown";RoleAfter="Unknown";ServiceAfter="Unknown";Shortcut="Unknown";RebootRequired="Unknown";Authorization=$Target.Authorized;Notes=$_.Exception.Message}
    }
}

$Results | Export-Csv $RemovalLog -NoTypeInformation -Encoding UTF8

if ($RemoveDHCPAuthorization -and (Read-Host "Type REMOVE-DHCP-AUTH to continue") -ceq "REMOVE-DHCP-AUTH") {
    try {
        Import-Module DhcpServer -ErrorAction Stop
        $AuthorizedDHCP=Get-DhcpServerInDC -ErrorAction Stop
        foreach($Target in $TargetServers) {
            $Server=$Target.Server
            $RemovalResult=@($Results|Where-Object Server -eq $Server)|Select-Object -First 1
            if(-not $RemovalResult -or $RemovalResult.Result -notlike "Successfully Removed*"){continue}
            $Authorized=@($AuthorizedDHCP|Where-Object {$_.DnsName -ieq $Server -or $_.DnsName.Split(".")[0] -ieq $Server.Split(".")[0]})|Select-Object -First 1
            if($Authorized){Remove-DhcpServerInDC -DnsName $Authorized.DnsName -IPAddress $Authorized.IPAddress -ErrorAction Stop}
        }
    } catch { Write-Host "DHCP authorization cleanup error: $($_.Exception.Message)" -ForegroundColor Red }
}

$ServersRequiringReboot=@($Results|Where-Object {$_.RebootRequired -eq "Yes" -and ($_.Result -like "Successfully Removed*" -or $_.Result -eq "Already Removed")})
if($ServersRequiringReboot.Count){
    $ServersRequiringReboot|Select-Object Server,Result,RoleAfter,ServiceAfter,Shortcut,Notes|Export-Csv $RebootList -NoTypeInformation -Encoding UTF8
}

$Results|Format-Table Server,Result,RoleAfter,ServiceAfter,Shortcut,RebootRequired -AutoSize
$ServersActuallyRebooted=@()
if($OfferRebootAtEnd -and $ServersRequiringReboot.Count -gt 0){
    $ServersRequiringReboot|Format-Table Server,RoleAfter,ServiceAfter,Shortcut -AutoSize
    if((Read-Host "Type REBOOT-ALL to reboot ALL servers above") -ceq "REBOOT-ALL"){
        $RebootResults=foreach($Item in $ServersRequiringReboot){
            try{Restart-Computer -ComputerName $Item.Server -Force -ErrorAction Stop;[PSCustomObject]@{Server=$Item.Server;RebootCommand="Sent"}}
            catch{[PSCustomObject]@{Server=$Item.Server;RebootCommand="Failed"}}
            Start-Sleep 2
        }
        $ServersActuallyRebooted=@($RebootResults|Where-Object RebootCommand -eq "Sent")
    }
}

$PostRebootResults=@()
if($ServersActuallyRebooted.Count -gt 0){
    $PendingServers=@{}
    foreach($Item in $ServersActuallyRebooted){$PendingServers[$Item.Server]=$true}
    $Timer=[Diagnostics.Stopwatch]::StartNew()
    while($PendingServers.Count -gt 0 -and $Timer.Elapsed.TotalSeconds -lt $PostRebootTimeoutSeconds){
        foreach($Server in @($PendingServers.Keys)){
            if(Test-RemoteWinRM $Server){$PendingServers.Remove($Server)}
        }
        if($PendingServers.Count){Start-Sleep $WinRMPollSeconds}
    }
    $Timer.Stop()
    Start-Sleep $PostRebootSettleSeconds
    $PostRebootResults=foreach($Item in $ServersActuallyRebooted){
        $Server=$Item.Server
        if($PendingServers.ContainsKey($Server)){
            [PSCustomObject]@{Server=$Server;WinRM="Timeout";DHCPRole="Unable to Verify";DHCPService="Unable to Verify";Shortcut="Unable to Verify";Verification="FAILED";Notes="Server did not return through WinRM before timeout"}
            continue
        }
        try{
            $Verify=Get-PostRebootDHCPVerification $Server $DHCPShortcutPath
            $RoleResult=if($Verify.RoleInstalled){"INSTALLED"}else{"Not Installed"}
            $ServiceResult=if($Verify.ServiceInstalled){$Verify.ServiceStatus}else{"Not Installed"}
            $ShortcutResult=if($Verify.ShortcutPresent){"Present"}else{"Not Present"}
            $Passed=(-not $Verify.RoleInstalled -and -not $Verify.ServiceInstalled -and -not $Verify.ShortcutPresent)
            [PSCustomObject]@{Server=$Server;WinRM="Available";DHCPRole=$RoleResult;DHCPService=$ServiceResult;Shortcut=$ShortcutResult;Verification=$(if($Passed){"PASSED"}else{"FAILED"});Notes=$(if($Passed){""}else{"One or more DHCP components remain after reboot"})}
        }catch{
            [PSCustomObject]@{Server=$Server;WinRM="Available";DHCPRole="Unable to Verify";DHCPService="Unable to Verify";Shortcut="Unable to Verify";Verification="ERROR";Notes=$_.Exception.Message}
        }
    }
    $PostRebootResults|Export-Csv $PostRebootLog -NoTypeInformation -Encoding UTF8
    $PostRebootResults|Format-Table Server,WinRM,DHCPRole,DHCPService,Shortcut,Verification -AutoSize
}

$Successful=@($Results|Where-Object Result -like "Successfully Removed*").Count
$Failed=@($Results|Where-Object {$_.Result -eq "Removal Failed" -or $_.Result -eq "Error"}).Count
$Locked=@($Results|Where-Object Action -eq "LOCKED").Count
$PostRebootPassed=@($PostRebootResults|Where-Object Verification -eq "PASSED").Count
$PostRebootFailed=@($PostRebootResults|Where-Object {$_.Verification -eq "FAILED" -or $_.Verification -eq "ERROR"}).Count

Write-Host "\nSUMMARY" -ForegroundColor Green
Write-Host "DHCP successfully removed : $Successful"
Write-Host "DHCP removal failures     : $Failed"
Write-Host "Safety locked             : $Locked"
Write-Host "Servers rebooted          : $($ServersActuallyRebooted.Count)"
Write-Host "Post-reboot passed        : $PostRebootPassed"
Write-Host "Post-reboot failed        : $PostRebootFailed"
Write-Host "\nRemoval results: $RemovalLog"
if(Test-Path $ScopeBackup){Write-Host "Scope backup: $ScopeBackup"}
if(Test-Path $RebootList){Write-Host "Reboot list: $RebootList"}
if(Test-Path $PostRebootLog){Write-Host "Post-reboot verification: $PostRebootLog"}
Write-Host "\nDHCP removal and verification complete." -ForegroundColor Green
