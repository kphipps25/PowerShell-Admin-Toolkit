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
      9. Remove:
             C:\Users\Public\Desktop\dhcp.lnk
     10. Record servers requiring reboot.
     11. Continue through all servers.
     12. Optionally remove DHCP authorization from AD.
     13. At the end, display all servers requiring reboot.
     14. Require REBOOT-ALL confirmation.
     15. Send reboot command to all approved servers.
     16. Monitor WinRM for all rebooted servers.
     17. After servers return, verify:
             DHCP role       = Not Installed
             DHCPServer svc  = Not Installed
             DHCP shortcut   = Not Present
     18. Export post-reboot verification CSV.

.NOTES
    DHCP role removal and server reboot are deliberately
    separated so a reboot cannot interrupt role-removal
    verification.

    Recommended:

        $AllowActiveScopeOverride = $false
        $RemoveDHCPAuthorization  = $false
        $OfferRebootAtEnd         = $true
#>


Import-Module ActiveDirectory


# ============================================================
# CONFIGURATION
# ============================================================

$CSVFile = ".\Domain-DHCP-Audit.csv"


# ------------------------------------------------------------
# SAFETY
# ------------------------------------------------------------

$AllowActiveScopeOverride = $false


# ------------------------------------------------------------
# DHCP AUTHORIZATION
# ------------------------------------------------------------

$RemoveDHCPAuthorization = $false


# ------------------------------------------------------------
# REBOOT
# ------------------------------------------------------------

$OfferRebootAtEnd = $true


# Maximum amount of time to wait for each rebooted server
# to become available through WinRM.
#
# 900 seconds = 15 minutes
#
$PostRebootTimeoutSeconds = 900


# How often to retry unavailable servers
$WinRMPollSeconds = 10


# Additional time after WinRM becomes available before
# performing DHCP verification.
$PostRebootSettleSeconds = 20


# ------------------------------------------------------------
# DHCP SHORTCUT
# ------------------------------------------------------------

$DHCPShortcutPath = "C:\Users\Public\Desktop\dhcp.lnk"


# ------------------------------------------------------------
# OUTPUT FILES
# ------------------------------------------------------------

$RemovalLog = ".\DHCP-Removal-Results.csv"

$ScopeBackup = ".\DHCP-Scope-Backup.csv"

$RebootList = ".\DHCP-Servers-Requiring-Reboot.csv"

$PostRebootLog = ".\DHCP-Post-Reboot-Verification.csv"


# ============================================================
# FUNCTION: TEST WINRM
# ============================================================

function Test-RemoteWinRM {

    param (

        [Parameter(Mandatory)]
        [string]$ComputerName
    )


    try {

        Test-WSMan `
            -ComputerName $ComputerName `
            -ErrorAction Stop |
            Out-Null


        Invoke-Command `
            -ComputerName $ComputerName `
            -ErrorAction Stop `
            -ScriptBlock {

                $env:COMPUTERNAME

            } |
            Out-Null


        return $true
    }

    catch {

        return $false
    }
}


# ============================================================
# FUNCTION: GET DHCP STATE
# ============================================================

function Get-RemoteDHCPState {

    param (

        [Parameter(Mandatory)]
        [string]$ComputerName,

        [switch]$SkipScopeQuery
    )


    Invoke-Command `
        -ComputerName $ComputerName `
        -ErrorAction Stop `
        -ScriptBlock {

            param (
                $SkipScopeQuery
            )


            # ------------------------------------------------
            # DHCP ROLE
            # ------------------------------------------------

            $Role = Get-WindowsFeature `
                -Name DHCP `
                -ErrorAction SilentlyContinue


            $RoleInstalled = (
                $Role -and
                $Role.InstallState -eq "Installed"
            )


            # ------------------------------------------------
            # DHCP SERVICE
            # ------------------------------------------------

            $Service = Get-Service `
                -Name DHCPServer `
                -ErrorAction SilentlyContinue


            $ServiceInstalled = [bool]$Service


            $ServiceStatus = if ($Service) {

                $Service.Status.ToString()
            }

            else {

                "Not Installed"
            }


            # ------------------------------------------------
            # DHCP SCOPES
            # ------------------------------------------------

            $Scopes = @()

            $ScopeQuerySuccessful = $true

            $ScopeQueryError = ""


            if (
                $RoleInstalled -and
                -not $SkipScopeQuery
            ) {

                try {

                    Import-Module DhcpServer `
                        -ErrorAction Stop


                    $Scopes = @(

                        Get-DhcpServerv4Scope `
                            -ErrorAction Stop |

                        Select-Object `
                            ScopeId,
                            Name,
                            State,
                            StartRange,
                            EndRange,
                            SubnetMask
                    )
                }

                catch {

                    $ScopeQuerySuccessful = $false

                    $ScopeQueryError = $_.Exception.Message

                    $Scopes = @()
                }
            }


            # ------------------------------------------------
            # ACTIVE SCOPES
            # ------------------------------------------------

            $ActiveScopes = @(

                $Scopes |

                    Where-Object {

                        $_.State.ToString() -eq "Active"
                    }
            )


            # ------------------------------------------------
            # RETURN
            # ------------------------------------------------

            [PSCustomObject]@{

                ComputerName = $env:COMPUTERNAME

                RoleInstalled = $RoleInstalled

                ServiceInstalled = $ServiceInstalled

                ServiceStatus = $ServiceStatus

                ScopeQuerySuccessful = $ScopeQuerySuccessful

                ScopeQueryError = $ScopeQueryError

                ScopeCount = @($Scopes).Count

                ActiveScopeCount = @($ActiveScopes).Count

                Scopes = $Scopes

                ActiveScopes = $ActiveScopes
            }

        } `
        -ArgumentList ([bool]$SkipScopeQuery)
}


# ============================================================
# FUNCTION: REMOVE DHCP SHORTCUT
# ============================================================

function Remove-RemoteDHCPShortcut {

    param (

        [Parameter(Mandatory)]
        [string]$ComputerName,

        [Parameter(Mandatory)]
        [string]$ShortcutPath
    )


    Invoke-Command `
        -ComputerName $ComputerName `
        -ErrorAction Stop `
        -ScriptBlock {

            param (
                $ShortcutPath
            )


            if (
                Test-Path `
                    -LiteralPath $ShortcutPath
            ) {

                Remove-Item `
                    -LiteralPath $ShortcutPath `
                    -Force `
                    -ErrorAction Stop


                if (
                    Test-Path `
                        -LiteralPath $ShortcutPath
                ) {

                    [PSCustomObject]@{

                        Found = $true

                        Removed = $false

                        Result = "Removal Failed"
                    }
                }

                else {

                    [PSCustomObject]@{

                        Found = $true

                        Removed = $true

                        Result = "Removed"
                    }
                }
            }

            else {

                [PSCustomObject]@{

                    Found = $false

                    Removed = $false

                    Result = "Not Present"
                }
            }

        } `
        -ArgumentList $ShortcutPath
}


# ============================================================
# FUNCTION: POST-REBOOT VERIFICATION
# ============================================================

function Get-PostRebootDHCPVerification {

    param (

        [Parameter(Mandatory)]
        [string]$ComputerName,

        [Parameter(Mandatory)]
        [string]$ShortcutPath
    )


    Invoke-Command `
        -ComputerName $ComputerName `
        -ErrorAction Stop `
        -ScriptBlock {

            param (
                $ShortcutPath
            )


            # ------------------------------------------------
            # DHCP FEATURE
            # ------------------------------------------------

            $Role = Get-WindowsFeature `
                -Name DHCP `
                -ErrorAction SilentlyContinue


            $RoleInstalled = (
                $Role -and
                $Role.InstallState -eq "Installed"
            )


            # ------------------------------------------------
            # DHCP SERVICE
            # ------------------------------------------------

            $Service = Get-Service `
                -Name DHCPServer `
                -ErrorAction SilentlyContinue


            $ServiceInstalled = [bool]$Service


            $ServiceStatus = if ($Service) {

                $Service.Status.ToString()
            }

            else {

                "Not Installed"
            }


            # ------------------------------------------------
            # SHORTCUT
            # ------------------------------------------------

            $ShortcutPresent = Test-Path `
                -LiteralPath $ShortcutPath


            # ------------------------------------------------
            # RETURN
            # ------------------------------------------------

            [PSCustomObject]@{

                ComputerName = $env:COMPUTERNAME

                RoleInstalled = $RoleInstalled

                ServiceInstalled = $ServiceInstalled

                ServiceStatus = $ServiceStatus

                ShortcutPresent = $ShortcutPresent
            }

        } `
        -ArgumentList $ShortcutPath
}


# ============================================================
# VERIFY CSV
# ============================================================

if (-not (
    Test-Path $CSVFile
)) {

    Write-Host ""

    Write-Host "ERROR: CSV file not found:" `
        -ForegroundColor Red

    Write-Host $CSVFile `
        -ForegroundColor Yellow

    exit 1
}


# ============================================================
# IMPORT CSV
# ============================================================

Write-Host ""

Write-Host "Reading DHCP audit CSV..." `
    -ForegroundColor Cyan


$CSV = Import-Csv $CSVFile


if (-not $CSV) {

    Write-Host ""

    Write-Host "CSV contains no records." `
        -ForegroundColor Yellow

    exit 0
}


# ============================================================
# DHCP CANDIDATES
# ============================================================

$TargetServers = @(

    $CSV |

        Where-Object {

            $_.DHCPRole -eq "Installed" -or

            $_.DHCPService -eq "Installed"
        } |

        Sort-Object Server
)


if (
    $TargetServers.Count -eq 0
) {

    Write-Host ""

    Write-Host "No DHCP servers found in CSV." `
        -ForegroundColor Green

    exit 0
}


# ============================================================
# DISPLAY TARGETS
# ============================================================

Write-Host ""

Write-Host "============================================================" `
    -ForegroundColor Yellow

Write-Host "             DHCP REMOVAL CANDIDATES" `
    -ForegroundColor Yellow

Write-Host "============================================================" `
    -ForegroundColor Yellow

Write-Host ""


$TargetServers |

    Format-Table `
        Server,
        DHCPRole,
        DHCPService,
        ServiceStatus,
        Authorized,
        ScopeCount `
        -AutoSize


Write-Host ""

Write-Host "No servers will reboot during DHCP removal." `
    -ForegroundColor Cyan

Write-Host "Required reboots will be collected until the end." `
    -ForegroundColor Cyan

Write-Host ""


# ============================================================
# INITIAL CONFIRMATION
# ============================================================

$Confirmation = Read-Host `
    "Type REMOVE-DHCP to begin"


if (
    $Confirmation -cne
    "REMOVE-DHCP"
) {

    Write-Host ""

    Write-Host "Cancelled. No changes made." `
        -ForegroundColor Green

    exit 0
}


# ============================================================
# PROCESS SERVERS
# ============================================================

$Results = foreach (
    $Target in $TargetServers
) {

    $Server = $Target.Server


    Write-Host ""

    Write-Host "============================================================" `
        -ForegroundColor Cyan

    Write-Host "Processing: $Server" `
        -ForegroundColor Cyan

    Write-Host "============================================================" `
        -ForegroundColor Cyan


    try {

        # ====================================================
        # WINRM
        # ====================================================

        if (-not (
            Test-RemoteWinRM `
                -ComputerName $Server
        )) {

            Write-Host ""

            Write-Host "LOCKED: WinRM unavailable." `
                -ForegroundColor Red


            [PSCustomObject]@{

                Server = $Server
                Action = "LOCKED"
                Result = "WinRM Unavailable"

                RoleBefore = $Target.DHCPRole
                ServiceBefore = $Target.DHCPService

                ServiceStatus = "Unknown"

                ScopeCount = "Unknown"
                ActiveScopes = "Unknown"

                RoleAfter = "Unknown"
                ServiceAfter = "Unknown"

                Shortcut = "Not Checked"

                RebootRequired = "Unknown"

                Authorization = $Target.Authorized

                Notes = "Unable to establish WinRM connection"
            }

            continue
        }


        # ====================================================
        # CURRENT DHCP STATE
        # ====================================================

        $DHCP = Get-RemoteDHCPState `
            -ComputerName $Server


        # ====================================================
        # ALREADY REMOVED
        # ====================================================

        if (-not $DHCP.RoleInstalled) {

            Write-Host ""

            Write-Host "DHCP role already removed." `
                -ForegroundColor Green


            try {

                $ShortcutResult = Remove-RemoteDHCPShortcut `
                    -ComputerName $Server `
                    -ShortcutPath $DHCPShortcutPath
            }

            catch {

                $ShortcutResult = [PSCustomObject]@{

                    Result = "Check Failed"
                }
            }


            $ExistingNeedsReboot = (
                $DHCP.ServiceInstalled
            )


            [PSCustomObject]@{

                Server = $Server
                Action = "Cleanup"
                Result = "Already Removed"

                RoleBefore = "Not Installed"

                ServiceBefore = if (
                    $DHCP.ServiceInstalled
                ) {
                    "Present"
                }
                else {
                    "Not Installed"
                }

                ServiceStatus = $DHCP.ServiceStatus

                ScopeCount = 0
                ActiveScopes = 0

                RoleAfter = "Not Installed"

                ServiceAfter = if (
                    $DHCP.ServiceInstalled
                ) {
                    "Pending Reboot"
                }
                else {
                    "Not Installed"
                }

                Shortcut = $ShortcutResult.Result

                RebootRequired = if (
                    $ExistingNeedsReboot
                ) {
                    "Yes"
                }
                else {
                    "No"
                }

                Authorization = $Target.Authorized

                Notes = if (
                    $ExistingNeedsReboot
                ) {
                    "Role already removed; service remains pending reboot"
                }
                else {
                    ""
                }
            }

            continue
        }


        # ====================================================
        # SCOPE QUERY LOCK
        # ====================================================

        if (-not $DHCP.ScopeQuerySuccessful) {

            Write-Host ""

            Write-Host "SCOPE QUERY SAFETY LOCK" `
                -ForegroundColor Red

            Write-Host ""

            Write-Host $DHCP.ScopeQueryError `
                -ForegroundColor Yellow


            [PSCustomObject]@{

                Server = $Server
                Action = "LOCKED"
                Result = "Scope Query Failed"

                RoleBefore = "Installed"
                ServiceBefore = "Installed"

                ServiceStatus = $DHCP.ServiceStatus

                ScopeCount = "Unknown"
                ActiveScopes = "Unknown"

                RoleAfter = "Installed"
                ServiceAfter = $DHCP.ServiceStatus

                Shortcut = "Not Removed"

                RebootRequired = "No"

                Authorization = $Target.Authorized

                Notes = $DHCP.ScopeQueryError
            }

            continue
        }


        # ====================================================
        # DISPLAY DHCP STATE
        # ====================================================

        Write-Host ""

        Write-Host "Current DHCP state:"

        Write-Host "  Role installed:  $($DHCP.RoleInstalled)"

        Write-Host "  Service present: $($DHCP.ServiceInstalled)"

        Write-Host "  Service status:  $($DHCP.ServiceStatus)"

        Write-Host "  Total scopes:    $($DHCP.ScopeCount)"

        Write-Host "  ACTIVE scopes:   $($DHCP.ActiveScopeCount)"


        # ====================================================
        # BACKUP SCOPES
        # ====================================================

        if (
            $DHCP.ScopeCount -gt 0
        ) {

            $ScopeBackupRows = foreach (
                $Scope in $DHCP.Scopes
            ) {

                [PSCustomObject]@{

                    Server = $Server
                    ScopeId = $Scope.ScopeId
                    Name = $Scope.Name
                    State = $Scope.State
                    StartRange = $Scope.StartRange
                    EndRange = $Scope.EndRange
                    SubnetMask = $Scope.SubnetMask
                }
            }


            $ScopeBackupRows |

                Export-Csv `
                    -Path $ScopeBackup `
                    -NoTypeInformation `
                    -Append `
                    -Encoding UTF8
        }


        # ====================================================
        # ACTIVE SCOPE LOCK
        # ====================================================

        if (
            $DHCP.ActiveScopeCount -gt 0
        ) {

            Write-Host ""

            Write-Host "ACTIVE SCOPE SAFETY LOCK" `
                -ForegroundColor Red

            Write-Host ""


            $DHCP.ActiveScopes |

                Format-Table `
                    ScopeId,
                    Name,
                    State,
                    StartRange,
                    EndRange `
                    -AutoSize


            if (
                $AllowActiveScopeOverride
            ) {

                $Override = Read-Host `
                    "Type REMOVE-ACTIVE-SCOPES-$Server to override"


                if (
                    $Override -cne
                    "REMOVE-ACTIVE-SCOPES-$Server"
                ) {

                    [PSCustomObject]@{

                        Server = $Server
                        Action = "LOCKED"
                        Result = "Active Scopes"

                        RoleBefore = "Installed"
                        ServiceBefore = "Installed"

                        ServiceStatus = $DHCP.ServiceStatus

                        ScopeCount = $DHCP.ScopeCount
                        ActiveScopes = $DHCP.ActiveScopeCount

                        RoleAfter = "Installed"
                        ServiceAfter = $DHCP.ServiceStatus

                        Shortcut = "Not Removed"

                        RebootRequired = "No"

                        Authorization = $Target.Authorized

                        Notes = "Active scope safety lock"
                    }

                    continue
                }
            }

            else {

                [PSCustomObject]@{

                    Server = $Server
                    Action = "LOCKED"
                    Result = "Active Scopes"

                    RoleBefore = "Installed"
                    ServiceBefore = "Installed"

                    ServiceStatus = $DHCP.ServiceStatus

                    ScopeCount = $DHCP.ScopeCount
                    ActiveScopes = $DHCP.ActiveScopeCount

                    RoleAfter = "Installed"
                    ServiceAfter = $DHCP.ServiceStatus

                    Shortcut = "Not Removed"

                    RebootRequired = "No"

                    Authorization = $Target.Authorized

                    Notes = "Active scope safety lock"
                }

                continue
            }
        }


        # ====================================================
        # PER SERVER CONFIRMATION
        # ====================================================

        Write-Host ""

        Write-Host "READY TO REMOVE DHCP FROM: $Server" `
            -ForegroundColor Yellow

        Write-Host ""

        Write-Host "Scopes:        $($DHCP.ScopeCount)"
        Write-Host "Active scopes: $($DHCP.ActiveScopeCount)"

        Write-Host ""


        $ServerConfirmation = Read-Host `
            "Type REMOVE-$Server to continue"


        if (
            $ServerConfirmation -cne
            "REMOVE-$Server"
        ) {

            [PSCustomObject]@{

                Server = $Server
                Action = "Skipped"
                Result = "Operator Cancelled"

                RoleBefore = "Installed"
                ServiceBefore = "Installed"

                ServiceStatus = $DHCP.ServiceStatus

                ScopeCount = $DHCP.ScopeCount
                ActiveScopes = $DHCP.ActiveScopeCount

                RoleAfter = "Installed"
                ServiceAfter = $DHCP.ServiceStatus

                Shortcut = "Not Removed"

                RebootRequired = "No"

                Authorization = $Target.Authorized

                Notes = ""
            }

            continue
        }


        # ====================================================
        # REMOVE DHCP ROLE
        #
        # DELIBERATELY NO -Restart
        # ====================================================

        Write-Host ""

        Write-Host "Removing DHCP role..." `
            -ForegroundColor Yellow


        $InstallResult = Invoke-Command `
            -ComputerName $Server `
            -ErrorAction Stop `
            -ScriptBlock {

                Uninstall-WindowsFeature `
                    -Name DHCP `
                    -IncludeManagementTools
            }


        Write-Host ""

        Write-Host "Windows Feature result:" `
            -ForegroundColor Gray

        Write-Host "  Success:       $($InstallResult.Success)"
        Write-Host "  RestartNeeded: $($InstallResult.RestartNeeded)"
        Write-Host "  ExitCode:      $($InstallResult.ExitCode)"


        # ====================================================
        # VERIFY ROLE REMOVAL
        # ====================================================

        Start-Sleep -Seconds 5


        $After = Get-RemoteDHCPState `
            -ComputerName $Server `
            -SkipScopeQuery


        if (
            $After.RoleInstalled
        ) {

            [PSCustomObject]@{

                Server = $Server
                Action = "Remove DHCP"
                Result = "Removal Failed"

                RoleBefore = "Installed"
                ServiceBefore = "Installed"

                ServiceStatus = $DHCP.ServiceStatus

                ScopeCount = $DHCP.ScopeCount
                ActiveScopes = $DHCP.ActiveScopeCount

                RoleAfter = "Installed"
                ServiceAfter = $After.ServiceStatus

                Shortcut = "Not Removed"

                RebootRequired = $InstallResult.RestartNeeded

                Authorization = $Target.Authorized

                Notes = "DHCP Windows Feature still reports Installed"
            }

            continue
        }


        Write-Host ""

        Write-Host "DHCP Windows Feature removed." `
            -ForegroundColor Green


        # ====================================================
        # REMOVE SHORTCUT
        # ====================================================

        try {

            $ShortcutResult = Remove-RemoteDHCPShortcut `
                -ComputerName $Server `
                -ShortcutPath $DHCPShortcutPath


            Write-Host "Shortcut: $($ShortcutResult.Result)" `
                -ForegroundColor Green
        }

        catch {

            $ShortcutResult = [PSCustomObject]@{

                Result = "Removal Check Failed"
            }


            Write-Host ""

            Write-Host "WARNING: Shortcut cleanup failed." `
                -ForegroundColor Yellow
        }


        # ====================================================
        # REBOOT REQUIREMENT
        # ====================================================

        $NeedsReboot = (
            $InstallResult.RestartNeeded -eq "Yes" -or
            $After.ServiceInstalled
        )


        # ====================================================
        # RESULT
        # ====================================================

        [PSCustomObject]@{

            Server = $Server
            Action = "Remove DHCP"

            Result = if (
                $NeedsReboot
            ) {
                "Successfully Removed - Reboot Required"
            }
            else {
                "Successfully Removed"
            }

            RoleBefore = "Installed"

            ServiceBefore = if (
                $DHCP.ServiceInstalled
            ) {
                "Installed"
            }
            else {
                "Not Installed"
            }

            ServiceStatus = $DHCP.ServiceStatus

            ScopeCount = $DHCP.ScopeCount
            ActiveScopes = $DHCP.ActiveScopeCount

            RoleAfter = "Not Installed"

            ServiceAfter = if (
                $After.ServiceInstalled
            ) {
                "Pending Reboot"
            }
            else {
                "Not Installed"
            }

            Shortcut = $ShortcutResult.Result

            RebootRequired = if (
                $NeedsReboot
            ) {
                "Yes"
            }
            else {
                "No"
            }

            Authorization = $Target.Authorized

            Notes = if (
                $NeedsReboot
            ) {
                "DHCP role removed; reboot deferred"
            }
            else {
                ""
            }
        }
    }

    catch {

        Write-Host ""

        Write-Host "ERROR processing $Server" `
            -ForegroundColor Red

        Write-Host $_.Exception.Message `
            -ForegroundColor Red


        [PSCustomObject]@{

            Server = $Server
            Action = "Error"
            Result = "Error"

            RoleBefore = $Target.DHCPRole
            ServiceBefore = $Target.DHCPService

            ServiceStatus = "Unknown"

            ScopeCount = "Unknown"
            ActiveScopes = "Unknown"

            RoleAfter = "Unknown"
            ServiceAfter = "Unknown"

            Shortcut = "Unknown"

            RebootRequired = "Unknown"

            Authorization = $Target.Authorized

            Notes = $_.Exception.Message
        }
    }
}


# ============================================================
# EXPORT REMOVAL RESULTS
# ============================================================

$Results |

    Export-Csv `
        -Path $RemovalLog `
        -NoTypeInformation `
        -Encoding UTF8


# ============================================================
# OPTIONAL DHCP AUTHORIZATION CLEANUP
# ============================================================

if (
    $RemoveDHCPAuthorization
) {

    Write-Host ""

    Write-Host "============================================================" `
        -ForegroundColor Red

    Write-Host "         DHCP AUTHORIZATION CLEANUP ENABLED" `
        -ForegroundColor Red

    Write-Host "============================================================" `
        -ForegroundColor Red

    Write-Host ""


    $AuthConfirmation = Read-Host `
        "Type REMOVE-DHCP-AUTH to continue"


    if (
        $AuthConfirmation -ceq
        "REMOVE-DHCP-AUTH"
    ) {

        try {

            Import-Module DhcpServer `
                -ErrorAction Stop


            $AuthorizedDHCP = Get-DhcpServerInDC `
                -ErrorAction Stop


            foreach (
                $Target in $TargetServers
            ) {

                $Server = $Target.Server


                $RemovalResult = @(

                    $Results |

                        Where-Object {

                            $_.Server -eq $Server
                        }

                ) | Select-Object -First 1


                if (
                    -not $RemovalResult -or
                    $RemovalResult.Result -notlike
                    "Successfully Removed*"
                ) {

                    continue
                }


                $Authorized = @(

                    $AuthorizedDHCP |

                        Where-Object {

                            $_.DnsName -ieq $Server -or

                            (
                                $_.DnsName.Split(".")[0] -ieq
                                $Server.Split(".")[0]
                            )
                        }

                ) | Select-Object -First 1


                if ($Authorized) {

                    try {

                        Remove-DhcpServerInDC `
                            -DnsName $Authorized.DnsName `
                            -IPAddress $Authorized.IPAddress `
                            -ErrorAction Stop


                        Write-Host ""

                        Write-Host "Authorization removed: $Server" `
                            -ForegroundColor Green
                    }

                    catch {

                        Write-Host ""

                        Write-Host "Authorization removal failed: $Server" `
                            -ForegroundColor Red

                        Write-Host $_.Exception.Message `
                            -ForegroundColor Red
                    }
                }
            }
        }

        catch {

            Write-Host ""

            Write-Host "DHCP authorization query failed." `
                -ForegroundColor Red

            Write-Host $_.Exception.Message `
                -ForegroundColor Red
        }
    }
}


# ============================================================
# BUILD REBOOT LIST
# ============================================================

$ServersRequiringReboot = @(

    $Results |

        Where-Object {

            $_.RebootRequired -eq "Yes" -and

            (
                $_.Result -like "Successfully Removed*" -or
                $_.Result -eq "Already Removed"
            )
        }
)


# ============================================================
# EXPORT REBOOT LIST
# ============================================================

if (
    $ServersRequiringReboot.Count -gt 0
) {

    $ServersRequiringReboot |

        Select-Object `
            Server,
            Result,
            RoleAfter,
            ServiceAfter,
            Shortcut,
            Notes |

        Export-Csv `
            -Path $RebootList `
            -NoTypeInformation `
            -Encoding UTF8
}


# ============================================================
# DISPLAY PRE-REBOOT RESULTS
# ============================================================

Write-Host ""

Write-Host "============================================================" `
    -ForegroundColor Green

Write-Host "                 DHCP REMOVAL RESULTS" `
    -ForegroundColor Green

Write-Host "============================================================" `
    -ForegroundColor Green

Write-Host ""


$Results |

    Format-Table `
        Server,
        Result,
        RoleAfter,
        ServiceAfter,
        Shortcut,
        RebootRequired `
        -AutoSize


# ============================================================
# END-OF-RUN REBOOT
# ============================================================

$ServersActuallyRebooted = @()


if (
    $OfferRebootAtEnd -and
    $ServersRequiringReboot.Count -gt 0
) {

    Write-Host ""

    Write-Host "============================================================" `
        -ForegroundColor Red

    Write-Host "               SERVERS REQUIRING REBOOT" `
        -ForegroundColor Red

    Write-Host "============================================================" `
        -ForegroundColor Red

    Write-Host ""


    $ServersRequiringReboot |

        Format-Table `
            Server,
            RoleAfter,
            ServiceAfter,
            Shortcut `
            -AutoSize


    Write-Host ""

    Write-Host "Type REBOOT-ALL to reboot ALL servers above." `
        -ForegroundColor Yellow

    Write-Host ""


    $RebootConfirmation = Read-Host `
        "Reboot confirmation"


    if (
        $RebootConfirmation -ceq
        "REBOOT-ALL"
    ) {

        Write-Host ""

        Write-Host "Sending reboot commands..." `
            -ForegroundColor Yellow


        $RebootResults = foreach (
            $Item in $ServersRequiringReboot
        ) {

            $Server = $Item.Server


            try {

                Write-Host ""

                Write-Host "Rebooting $Server..." `
                    -ForegroundColor Yellow


                Restart-Computer `
                    -ComputerName $Server `
                    -Force `
                    -ErrorAction Stop


                Write-Host "Reboot command accepted." `
                    -ForegroundColor Green


                [PSCustomObject]@{

                    Server = $Server
                    RebootCommand = "Sent"
                }
            }

            catch {

                Write-Host ""

                Write-Host "Reboot command failed: $Server" `
                    -ForegroundColor Red

                Write-Host $_.Exception.Message `
                    -ForegroundColor Red


                [PSCustomObject]@{

                    Server = $Server
                    RebootCommand = "Failed"
                }
            }


            Start-Sleep -Seconds 2
        }


        $ServersActuallyRebooted = @(

            $RebootResults |

                Where-Object {

                    $_.RebootCommand -eq "Sent"
                }
        )
    }
}


# ============================================================
# POST-REBOOT MONITORING
# ============================================================

$PostRebootResults = @()


if (
    $ServersActuallyRebooted.Count -gt 0
) {

    Write-Host ""

    Write-Host "============================================================" `
        -ForegroundColor Cyan

    Write-Host "             POST-REBOOT MONITORING" `
        -ForegroundColor Cyan

    Write-Host "============================================================" `
        -ForegroundColor Cyan

    Write-Host ""

    Write-Host "Monitoring $($ServersActuallyRebooted.Count) server(s)." `
        -ForegroundColor Cyan

    Write-Host "Timeout: $PostRebootTimeoutSeconds seconds" `
        -ForegroundColor Gray

    Write-Host ""


    # --------------------------------------------------------
    # Build pending-server table.
    #
    # We wait for ALL servers together instead of waiting
    # for one server at a time.
    # --------------------------------------------------------

    $PendingServers = @{

    }


    foreach (
        $Item in $ServersActuallyRebooted
    ) {

        $PendingServers[$Item.Server] = [PSCustomObject]@{

            Server = $Item.Server

            Ready = $false

            ReadyTime = $null
        }
    }


    $MonitorTimer = [System.Diagnostics.Stopwatch]::StartNew()


    # --------------------------------------------------------
    # MONITOR ALL SERVERS
    # --------------------------------------------------------

    while (
        $PendingServers.Count -gt 0 -and
        $MonitorTimer.Elapsed.TotalSeconds -lt
        $PostRebootTimeoutSeconds
    ) {

        foreach (
            $Server in @($PendingServers.Keys)
        ) {

            if (
                Test-RemoteWinRM `
                    -ComputerName $Server
            ) {

                Write-Host "$Server : WinRM available" `
                    -ForegroundColor Green


                $PendingServers.Remove($Server)
            }

            else {

                Write-Host "$Server : waiting..." `
                    -ForegroundColor Gray
            }
        }


        if (
            $PendingServers.Count -gt 0
        ) {

            Write-Host ""

            Write-Host "$($PendingServers.Count) server(s) still unavailable." `
                -ForegroundColor Gray

            Write-Host ""


            Start-Sleep `
                -Seconds $WinRMPollSeconds
        }
    }


    $MonitorTimer.Stop()


    # --------------------------------------------------------
    # WINDOWS SETTLE PERIOD
    # --------------------------------------------------------

    Write-Host ""

    Write-Host "WinRM monitoring complete." `
        -ForegroundColor Cyan


    Write-Host `
        "Waiting $PostRebootSettleSeconds seconds for returned servers to settle..." `
        -ForegroundColor Gray


    Start-Sleep `
        -Seconds $PostRebootSettleSeconds


    # ========================================================
    # FINAL VERIFICATION OF EACH SERVER
    # ========================================================

    $PostRebootResults = foreach (
        $Item in $ServersActuallyRebooted
    ) {

        $Server = $Item.Server


        Write-Host ""

        Write-Host "------------------------------------------------------------" `
            -ForegroundColor Cyan

        Write-Host "Final verification: $Server" `
            -ForegroundColor Cyan

        Write-Host "------------------------------------------------------------" `
            -ForegroundColor Cyan


        # ----------------------------------------------------
        # SERVER DID NOT RETURN
        # ----------------------------------------------------

        if (
            $PendingServers.ContainsKey($Server)
        ) {

            Write-Host ""

            Write-Host "TIMEOUT: Server did not return through WinRM." `
                -ForegroundColor Red


            [PSCustomObject]@{

                Server = $Server

                WinRM = "Timeout"

                DHCPRole = "Unable to Verify"

                DHCPService = "Unable to Verify"

                Shortcut = "Unable to Verify"

                Verification = "FAILED"

                Notes = "Server did not return through WinRM before timeout"
            }


            continue
        }


        # ----------------------------------------------------
        # QUERY FINAL STATE
        # ----------------------------------------------------

        try {

            $Verify = Get-PostRebootDHCPVerification `
                -ComputerName $Server `
                -ShortcutPath $DHCPShortcutPath


            # ------------------------------------------------
            # ROLE
            # ------------------------------------------------

            $RoleResult = if (
                $Verify.RoleInstalled
            ) {

                "INSTALLED"
            }

            else {

                "Not Installed"
            }


            # ------------------------------------------------
            # SERVICE
            # ------------------------------------------------

            $ServiceResult = if (
                $Verify.ServiceInstalled
            ) {

                $Verify.ServiceStatus
            }

            else {

                "Not Installed"
            }


            # ------------------------------------------------
            # SHORTCUT
            # ------------------------------------------------

            $ShortcutResult = if (
                $Verify.ShortcutPresent
            ) {

                "Present"
            }

            else {

                "Not Present"
            }


            # ------------------------------------------------
            # OVERALL RESULT
            # ------------------------------------------------

            $VerificationPassed = (

                -not $Verify.RoleInstalled -and

                -not $Verify.ServiceInstalled -and

                -not $Verify.ShortcutPresent
            )


            if (
                $VerificationPassed
            ) {

                $OverallResult = "PASSED"

                Write-Host ""

                Write-Host "POST-REBOOT VERIFICATION PASSED" `
                    -ForegroundColor Green
            }

            else {

                $OverallResult = "FAILED"

                Write-Host ""

                Write-Host "POST-REBOOT VERIFICATION FAILED" `
                    -ForegroundColor Red
            }


            Write-Host ""

            Write-Host "  DHCP Role:     $RoleResult"

            Write-Host "  DHCP Service:  $ServiceResult"

            Write-Host "  DHCP Shortcut: $ShortcutResult"


            [PSCustomObject]@{

                Server = $Server

                WinRM = "Available"

                DHCPRole = $RoleResult

                DHCPService = $ServiceResult

                Shortcut = $ShortcutResult

                Verification = $OverallResult

                Notes = if (
                    $VerificationPassed
                ) {
                    ""
                }
                else {
                    "One or more DHCP components remain after reboot"
                }
            }
        }

        catch {

            Write-Host ""

            Write-Host "Verification error:" `
                -ForegroundColor Red

            Write-Host $_.Exception.Message `
                -ForegroundColor Red


            [PSCustomObject]@{

                Server = $Server

                WinRM = "Available"

                DHCPRole = "Unable to Verify"

                DHCPService = "Unable to Verify"

                Shortcut = "Unable to Verify"

                Verification = "ERROR"

                Notes = $_.Exception.Message
            }
        }
    }


    # ========================================================
    # EXPORT POST-REBOOT RESULTS
    # ========================================================

    $PostRebootResults |

        Export-Csv `
            -Path $PostRebootLog `
            -NoTypeInformation `
            -Encoding UTF8


    # ========================================================
    # DISPLAY POST-REBOOT RESULTS
    # ========================================================

    Write-Host ""

    Write-Host "============================================================" `
        -ForegroundColor Cyan

    Write-Host "           POST-REBOOT VERIFICATION RESULTS" `
        -ForegroundColor Cyan

    Write-Host "============================================================" `
        -ForegroundColor Cyan

    Write-Host ""


    $PostRebootResults |

        Format-Table `
            Server,
            WinRM,
            DHCPRole,
            DHCPService,
            Shortcut,
            Verification `
            -AutoSize
}


# ============================================================
# FINAL SUMMARY
# ============================================================

$Successful = @(

    $Results |

        Where-Object {

            $_.Result -like "Successfully Removed*"
        }
).Count


$Failed = @(

    $Results |

        Where-Object {

            $_.Result -eq "Removal Failed" -or

            $_.Result -eq "Error"
        }
).Count


$Locked = @(

    $Results |

        Where-Object {

            $_.Action -eq "LOCKED"
        }
).Count


$PostRebootPassed = @(

    $PostRebootResults |

        Where-Object {

            $_.Verification -eq "PASSED"
        }
).Count


$PostRebootFailed = @(

    $PostRebootResults |

        Where-Object {

            $_.Verification -eq "FAILED" -or

            $_.Verification -eq "ERROR"
        }
).Count


# ============================================================
# DISPLAY SUMMARY
# ============================================================

Write-Host ""

Write-Host "============================================================" `
    -ForegroundColor Green

Write-Host "                       SUMMARY" `
    -ForegroundColor Green

Write-Host "============================================================" `
    -ForegroundColor Green

Write-Host ""

Write-Host "DHCP successfully removed : $Successful" `
    -ForegroundColor Green

Write-Host "DHCP removal failures     : $Failed"

Write-Host "Safety locked             : $Locked"

Write-Host "Servers rebooted          : $($ServersActuallyRebooted.Count)"

Write-Host "Post-reboot passed        : $PostRebootPassed" `
    -ForegroundColor Green

Write-Host "Post-reboot failed        : $PostRebootFailed" `
    -ForegroundColor $(

        if (
            $PostRebootFailed -gt 0
        ) {
            "Red"
        }
        else {
            "Green"
        }
    )


# ============================================================
# OUTPUT FILES
# ============================================================

Write-Host ""

Write-Host "Removal results:" `
    -ForegroundColor Cyan

Write-Host $RemovalLog


if (
    Test-Path $ScopeBackup
) {

    Write-Host ""

    Write-Host "Scope backup:" `
        -ForegroundColor Cyan

    Write-Host $ScopeBackup
}


if (
    Test-Path $RebootList
) {

    Write-Host ""

    Write-Host "Reboot list:" `
        -ForegroundColor Cyan

    Write-Host $RebootList
}


if (
    Test-Path $PostRebootLog
) {

    Write-Host ""

    Write-Host "Post-reboot verification:" `
        -ForegroundColor Cyan

    Write-Host $PostRebootLog
}


Write-Host ""

Write-Host "============================================================" `
    -ForegroundColor Green

Write-Host "DHCP removal and verification complete." `
    -ForegroundColor Green

Write-Host "============================================================" `
    -ForegroundColor Green

Write-Host ""
