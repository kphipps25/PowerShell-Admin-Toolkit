<#
.SYNOPSIS
    Reboots all servers listed in DHCP-Servers-Requiring-Reboot.csv
    and performs post-reboot DHCP verification.

.DESCRIPTION
    Workflow:

      1. Read servers from DHCP-Servers-Requiring-Reboot.csv.
      2. Display all servers found in the CSV.
      3. Require REBOOT-ALL confirmation.
      4. Send reboot commands to all servers.
      5. Monitor all rebooted servers together for WinRM.
      6. Wait for Windows to settle.
      7. Verify:
             DHCP role       = Not Installed
             DHCPServer svc  = Not Installed
             DHCP shortcut   = Not Present
      8. Export verification results to CSV.

.NOTES
    The script does not modify or delete the original
    DHCP-Servers-Requiring-Reboot.csv file.
#>

# ============================================================
# CONFIGURATION
# ============================================================

$CSVFile = ".\DHCP-Servers-Requiring-Reboot.csv"
$PostRebootLog = ".\DHCP-Post-Reboot-Verification.csv"
$DHCPShortcutPath = "C:\Users\Public\Desktop\dhcp.lnk"

# 900 seconds = 15 minutes
$PostRebootTimeoutSeconds = 900

# How often to retry unavailable servers.
$WinRMPollSeconds = 10

# Additional time after servers return before final verification.
$PostRebootSettleSeconds = 20


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
# FUNCTION: POST-REBOOT DHCP VERIFICATION
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

            $Role = Get-WindowsFeature `
                -Name DHCP `
                -ErrorAction SilentlyContinue

            $RoleInstalled = (
                $Role -and
                $Role.InstallState -eq "Installed"
            )

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

            $ShortcutPresent = Test-Path `
                -LiteralPath $ShortcutPath

            [PSCustomObject]@{
                ComputerName    = $env:COMPUTERNAME
                RoleInstalled   = $RoleInstalled
                ServiceInstalled = $ServiceInstalled
                ServiceStatus   = $ServiceStatus
                ShortcutPresent = $ShortcutPresent
            }

        } `
        -ArgumentList $ShortcutPath
}


# ============================================================
# VERIFY CSV
# ============================================================

if (-not (Test-Path $CSVFile)) {

    Write-Host ""
    Write-Host "ERROR: CSV file not found:" -ForegroundColor Red
    Write-Host $CSVFile -ForegroundColor Yellow
    Write-Host ""

    exit 1
}


# ============================================================
# IMPORT SERVER LIST
# ============================================================

$Servers = @(
    Import-Csv $CSVFile |
        Where-Object {
            -not [string]::IsNullOrWhiteSpace($_.Server)
        } |
        Select-Object -ExpandProperty Server -Unique
)

if ($Servers.Count -eq 0) {

    Write-Host ""
    Write-Host "No servers found in CSV." -ForegroundColor Yellow
    Write-Host ""

    exit 0
}


# ============================================================
# DISPLAY SERVERS
# ============================================================

Write-Host ""
Write-Host "============================================================" -ForegroundColor Red
Write-Host "                  SERVERS TO REBOOT" -ForegroundColor Red
Write-Host "============================================================" -ForegroundColor Red
Write-Host ""

$Servers | ForEach-Object {
    Write-Host "  $_" -ForegroundColor Yellow
}

Write-Host ""
Write-Host "Servers in CSV       : $($Servers.Count)" -ForegroundColor Cyan
Write-Host ""


# ============================================================
# CONFIRMATION
# ============================================================

Write-Host ""
Write-Host "Type REBOOT-ALL to reboot ALL servers above." -ForegroundColor Yellow
Write-Host ""

$Confirmation = Read-Host "Reboot confirmation"

if ($Confirmation -cne "REBOOT-ALL") {

    Write-Host ""
    Write-Host "Cancelled. No servers were rebooted." -ForegroundColor Green
    Write-Host ""

    exit 0
}


# ============================================================
# SEND REBOOT COMMANDS
# ============================================================

Write-Host ""
Write-Host "============================================================" -ForegroundColor Yellow
Write-Host "                 SENDING REBOOTS" -ForegroundColor Yellow
Write-Host "============================================================" -ForegroundColor Yellow
Write-Host ""

$RebootResults = foreach ($Server in $Servers) {

    try {

        Write-Host "Rebooting $Server..." -ForegroundColor Yellow

        Restart-Computer `
            -ComputerName $Server `
            -Force `
            -ErrorAction Stop

        Write-Host "  Reboot command accepted." -ForegroundColor Green

        [PSCustomObject]@{
            Server                = $Server
            RebootCommand         = "Sent"
        }
    }
    catch {

        Write-Host "  Reboot command failed." -ForegroundColor Red
        Write-Host "  $($_.Exception.Message)" -ForegroundColor Red

        [PSCustomObject]@{
            Server                = $Server
            RebootCommand         = "Failed"
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

if ($ServersActuallyRebooted.Count -eq 0) {

    Write-Host ""
    Write-Host "No reboot commands were successfully sent." -ForegroundColor Red
    Write-Host ""

    exit 1
}


# ============================================================
# POST-REBOOT MONITORING
# ============================================================

Write-Host ""
Write-Host "============================================================" -ForegroundColor Cyan
Write-Host "             POST-REBOOT MONITORING" -ForegroundColor Cyan
Write-Host "============================================================" -ForegroundColor Cyan
Write-Host ""

Write-Host "Monitoring $($ServersActuallyRebooted.Count) server(s)." -ForegroundColor Cyan
Write-Host "Timeout: $PostRebootTimeoutSeconds seconds" -ForegroundColor Gray
Write-Host ""

$PendingServers = @{}

foreach ($Item in $ServersActuallyRebooted) {

    $PendingServers[$Item.Server] = $true
}

$MonitorTimer = [System.Diagnostics.Stopwatch]::StartNew()

while (
    $PendingServers.Count -gt 0 -and
    $MonitorTimer.Elapsed.TotalSeconds -lt $PostRebootTimeoutSeconds
) {

    foreach ($Server in @($PendingServers.Keys)) {

        if (Test-RemoteWinRM -ComputerName $Server) {

            Write-Host "$Server : WinRM available" -ForegroundColor Green
            $PendingServers.Remove($Server)
        }
        else {

            Write-Host "$Server : waiting for WinRM..." -ForegroundColor Gray
        }
    }

    if ($PendingServers.Count -gt 0) {

        Write-Host ""
        Write-Host "$($PendingServers.Count) server(s) still pending." -ForegroundColor Gray
        Write-Host ""

        Start-Sleep -Seconds $WinRMPollSeconds
    }
}

$MonitorTimer.Stop()


# ============================================================
# WINDOWS SETTLE PERIOD
# ============================================================

Write-Host ""
Write-Host "Reboot monitoring complete." -ForegroundColor Cyan

if ($PendingServers.Count -eq 0) {
    Write-Host "All rebooted servers returned successfully." -ForegroundColor Green
}
else {
    Write-Host "$($PendingServers.Count) server(s) did not complete reboot verification." -ForegroundColor Red
}

Write-Host ""
Write-Host "Waiting $PostRebootSettleSeconds seconds for returned servers to settle..." -ForegroundColor Gray

Start-Sleep -Seconds $PostRebootSettleSeconds


# ============================================================
# FINAL DHCP VERIFICATION
# ============================================================

$PostRebootResults = foreach ($Item in $ServersActuallyRebooted) {

    $Server = $Item.Server

    Write-Host ""
    Write-Host "------------------------------------------------------------" -ForegroundColor Cyan
    Write-Host "Final verification: $Server" -ForegroundColor Cyan
    Write-Host "------------------------------------------------------------" -ForegroundColor Cyan

    if ($PendingServers.ContainsKey($Server)) {

        Write-Host ""
        Write-Host "TIMEOUT: Server did not return through WinRM." -ForegroundColor Red

        [PSCustomObject]@{
            Server       = $Server
            Reboot       = "Timeout"
            WinRM        = "Unable to Verify"
            DHCPRole     = "Unable to Verify"
            DHCPService  = "Unable to Verify"
            Shortcut     = "Unable to Verify"
            Verification = "FAILED"
            Notes        = "Server did not return through WinRM before timeout"
        }

        continue
    }

    try {

        $Verify = Get-PostRebootDHCPVerification `
            -ComputerName $Server `
            -ShortcutPath $DHCPShortcutPath

        $RoleResult = if ($Verify.RoleInstalled) {
            "INSTALLED"
        }
        else {
            "Not Installed"
        }

        $ServiceResult = if ($Verify.ServiceInstalled) {
            $Verify.ServiceStatus
        }
        else {
            "Not Installed"
        }

        $ShortcutResult = if ($Verify.ShortcutPresent) {
            "Present"
        }
        else {
            "Not Present"
        }

        $VerificationPassed = (
            -not $Verify.RoleInstalled -and
            -not $Verify.ServiceInstalled -and
            -not $Verify.ShortcutPresent
        )

        if ($VerificationPassed) {

            $OverallResult = "PASSED"

            Write-Host ""
            Write-Host "POST-REBOOT VERIFICATION PASSED" -ForegroundColor Green
        }
        else {

            $OverallResult = "FAILED"

            Write-Host ""
            Write-Host "POST-REBOOT VERIFICATION FAILED" -ForegroundColor Red
        }

        Write-Host ""
        Write-Host "  Reboot:        Returned through WinRM"
        Write-Host "  DHCP Role:     $RoleResult"
        Write-Host "  DHCP Service:  $ServiceResult"
        Write-Host "  DHCP Shortcut: $ShortcutResult"

        [PSCustomObject]@{
            Server       = $Server
            Reboot       = "Returned"
            WinRM        = "Available"
            DHCPRole     = $RoleResult
            DHCPService  = $ServiceResult
            Shortcut     = $ShortcutResult
            Verification = $OverallResult
            Notes        = if ($VerificationPassed) { "" } else { "One or more DHCP post-reboot checks failed" }
        }
    }
    catch {

        Write-Host ""
        Write-Host "Verification error:" -ForegroundColor Red
        Write-Host $_.Exception.Message -ForegroundColor Red

        [PSCustomObject]@{
            Server       = $Server
            Reboot       = "Confirmed"
            WinRM        = "Available"
            DHCPRole     = "Unable to Verify"
            DHCPService  = "Unable to Verify"
            Shortcut     = "Unable to Verify"
            Verification = "ERROR"
            Notes        = $_.Exception.Message
        }
    }
}


# ============================================================
# EXPORT POST-REBOOT RESULTS
# ============================================================

$PostRebootResults |
    Export-Csv `
        -Path $PostRebootLog `
        -NoTypeInformation `
        -Encoding UTF8


# ============================================================
# DISPLAY RESULTS
# ============================================================

Write-Host ""
Write-Host "============================================================" -ForegroundColor Cyan
Write-Host "           POST-REBOOT VERIFICATION RESULTS" -ForegroundColor Cyan
Write-Host "============================================================" -ForegroundColor Cyan
Write-Host ""

$PostRebootResults |
    Format-Table `
        Server,
        Reboot,
        WinRM,
        DHCPRole,
        DHCPService,
        Shortcut,
        Verification `
        -AutoSize


# ============================================================
# SUMMARY
# ============================================================

$Passed = @(
    $PostRebootResults |
        Where-Object {
            $_.Verification -eq "PASSED"
        }
).Count

$Failed = @(
    $PostRebootResults |
        Where-Object {
            $_.Verification -eq "FAILED" -or
            $_.Verification -eq "ERROR"
        }
).Count

$RebootCommandFailures = @(
    $RebootResults |
        Where-Object {
            $_.RebootCommand -eq "Failed"
        }
).Count

Write-Host ""
Write-Host "============================================================" -ForegroundColor Green
Write-Host "                       SUMMARY" -ForegroundColor Green
Write-Host "============================================================" -ForegroundColor Green
Write-Host ""

Write-Host "Servers in CSV          : $($Servers.Count)"
Write-Host "Reboot commands sent    : $($ServersActuallyRebooted.Count)"
Write-Host "Reboot command failures : $RebootCommandFailures"
Write-Host "Verification passed     : $Passed" -ForegroundColor Green
Write-Host "Verification failed     : $Failed" -ForegroundColor $(if ($Failed -gt 0) { "Red" } else { "Green" })

Write-Host ""
Write-Host "Verification results:" -ForegroundColor Cyan
Write-Host $PostRebootLog

Write-Host ""
Write-Host "============================================================" -ForegroundColor Green
Write-Host "Reboot and DHCP verification complete." -ForegroundColor Green
Write-Host "============================================================" -ForegroundColor Green
Write-Host ""
