#requires -Modules ActiveDirectory

<#
.SYNOPSIS
    Audits every Windows Server in Active Directory for DHCP.

.DESCRIPTION
    Checks:
      - Every enabled Windows Server computer account in AD
      - DHCP Server Windows role
      - DHCP Server service
      - DHCP service status
      - DHCP authorization in Active Directory
      - DHCP IPv4 scopes
      - Scope state
      - Scope network/range
      - Number of scopes

    Results are displayed on screen and exported to CSV.

.NOTES
    Requires:
      - ActiveDirectory PowerShell module
      - PowerShell Remoting to target servers
      - Appropriate permissions
      - DHCP PowerShell module on servers being queried
#>

Import-Module ActiveDirectory

$OutputFile = ".\Domain-DHCP-Audit.csv"

Write-Host ""
Write-Host "============================================" -ForegroundColor Cyan
Write-Host "       DOMAIN DHCP SERVER AUDIT" -ForegroundColor Cyan
Write-Host "============================================" -ForegroundColor Cyan
Write-Host ""

# ------------------------------------------------------------
# Get DHCP servers authorized in Active Directory
# ------------------------------------------------------------

Write-Host "Checking DHCP authorization in Active Directory..." -ForegroundColor Yellow

try {
    $AuthorizedDHCP = Get-DhcpServerInDC -ErrorAction Stop
}
catch {
    Write-Warning "Unable to retrieve DHCP authorization information."
    $AuthorizedDHCP = @()
}

$AuthorizedNames = @()

foreach ($DHCP in $AuthorizedDHCP) {

    if ($DHCP.DnsName) {
        $AuthorizedNames += $DHCP.DnsName.ToLower()
    }

    if ($DHCP.IPAddress) {
        $AuthorizedNames += $DHCP.IPAddress.ToString()
    }
}

# ------------------------------------------------------------
# Get every enabled Windows Server in AD
# ------------------------------------------------------------

Write-Host "Finding Windows Servers in Active Directory..." -ForegroundColor Yellow

$Servers = Get-ADComputer `
    -Filter 'Enabled -eq $true' `
    -Properties OperatingSystem, DNSHostName, IPv4Address |
    Where-Object {
        $_.OperatingSystem -like "*Server*"
    } |
    Sort-Object Name

Write-Host ""
Write-Host "Found $($Servers.Count) Windows Servers." -ForegroundColor Green
Write-Host ""

# ------------------------------------------------------------
# Audit each server
# ------------------------------------------------------------

$Results = foreach ($Computer in $Servers) {

    $Server = if ($Computer.DNSHostName) {
        $Computer.DNSHostName
    }
    else {
        $Computer.Name
    }

    Write-Host "Checking $Server ..." -ForegroundColor Cyan

    # Determine whether server is authorized in AD
    $IsAuthorized = $false

    foreach ($Name in $AuthorizedNames) {

        if ($Name -ieq $Server -or
            $Name -ieq $Computer.Name -or
            $Name -eq $Computer.IPv4Address) {

            $IsAuthorized = $true
            break
        }
    }

    # Test connectivity
    if (-not (Test-Connection -ComputerName $Server -Count 1 -Quiet -ErrorAction SilentlyContinue)) {

        [PSCustomObject]@{
            Server          = $Server
            IPAddress       = $Computer.IPv4Address
            OperatingSystem = $Computer.OperatingSystem
            Reachable       = "No"
            DHCPRole        = "Unknown"
            DHCPService     = "Unknown"
            ServiceStatus   = "Unknown"
            Authorized      = if ($IsAuthorized) { "YES" } else { "NO" }
            ScopeCount      = "Unknown"
            Scopes          = ""
            Notes           = "Server did not respond to ping"
        }

        continue
    }

    try {

        $RemoteResult = Invoke-Command `
            -ComputerName $Server `
            -ErrorAction Stop `
            -ScriptBlock {

                # ------------------------------------------------
                # Check DHCP Windows Role
                # ------------------------------------------------

                $Role = Get-WindowsFeature `
                    -Name DHCP `
                    -ErrorAction SilentlyContinue

                $DHCPRoleInstalled = $false

                if ($Role -and $Role.InstallState -eq "Installed") {
                    $DHCPRoleInstalled = $true
                }

                # ------------------------------------------------
                # Check DHCP Service
                # ------------------------------------------------

                $Service = Get-Service `
                    -Name DHCPServer `
                    -ErrorAction SilentlyContinue

                $DHCPServiceInstalled = $false
                $ServiceStatus = "Not Installed"

                if ($Service) {
                    $DHCPServiceInstalled = $true
                    $ServiceStatus = $Service.Status
                }

                # ------------------------------------------------
                # Get DHCP Scopes
                # ------------------------------------------------

                $Scopes = @()

                if ($DHCPServiceInstalled) {

                    try {

                        Import-Module DhcpServer -ErrorAction SilentlyContinue

                        $Scopes = Get-DhcpServerv4Scope `
                            -ErrorAction Stop |
                            Select-Object ScopeId, Name, State, StartRange, EndRange

                    }
                    catch {
                        $Scopes = @()
                    }
                }

                # ------------------------------------------------
                # Return results
                # ------------------------------------------------

                [PSCustomObject]@{

                    DHCPRoleInstalled   = $DHCPRoleInstalled
                    DHCPServiceInstalled = $DHCPServiceInstalled
                    ServiceStatus       = $ServiceStatus

                    ScopeCount          = @($Scopes).Count

                    Scopes              = (
                        $Scopes |
                        ForEach-Object {
                            "$($_.ScopeId) [$($_.State)] $($_.StartRange)-$($_.EndRange)"
                        }
                    ) -join "; "

                    ScopeDetails        = $Scopes
                }
            }

        # --------------------------------------------------------
        # Determine notes
        # --------------------------------------------------------

        $Notes = ""

        if ($RemoteResult.DHCPRoleInstalled -eq $true -and
            $RemoteResult.DHCPServiceInstalled -eq $true -and
            $IsAuthorized -eq $false) {

            $Notes = "WARNING: DHCP installed but NOT authorized in AD"
        }

        elseif ($IsAuthorized -eq $true -and
                $RemoteResult.DHCPServiceInstalled -eq $false) {

            $Notes = "WARNING: Authorized in AD but DHCP service not installed"
        }

        elseif ($RemoteResult.DHCPServiceInstalled -eq $true -and
                $RemoteResult.ScopeCount -eq 0) {

            $Notes = "DHCP installed but no IPv4 scopes found"
        }

        [PSCustomObject]@{
            Server          = $Server
            IPAddress       = $Computer.IPv4Address
            OperatingSystem = $Computer.OperatingSystem
            Reachable       = "Yes"
            DHCPRole        = if ($RemoteResult.DHCPRoleInstalled) {
                "Installed"
            }
            else {
                "Not Installed"
            }
            DHCPService     = if ($RemoteResult.DHCPServiceInstalled) {
                "Installed"
            }
            else {
                "Not Installed"
            }
            ServiceStatus   = $RemoteResult.ServiceStatus
            Authorized      = if ($IsAuthorized) { "YES" } else { "NO" }
            ScopeCount      = $RemoteResult.ScopeCount
            Scopes          = $RemoteResult.Scopes
            Notes           = $Notes
        }
    }
    catch {

        [PSCustomObject]@{
            Server          = $Server
            IPAddress       = $Computer.IPv4Address
            OperatingSystem = $Computer.OperatingSystem
            Reachable       = "Yes"
            DHCPRole        = "Unable to Query"
            DHCPService     = "Unable to Query"
            ServiceStatus   = "Unknown"
            Authorized      = if ($IsAuthorized) { "YES" } else { "NO" }
            ScopeCount      = "Unknown"
            Scopes          = ""
            Notes           = "Remote query failed: $($_.Exception.Message)"
        }
    }
}

# ------------------------------------------------------------
# Display complete results
# ------------------------------------------------------------

Write-Host ""
Write-Host "============================================" -ForegroundColor Green
Write-Host "             COMPLETE RESULTS" -ForegroundColor Green
Write-Host "============================================" -ForegroundColor Green
Write-Host ""

$Results |
    Format-Table `
        Server,
        DHCPRole,
        DHCPService,
        ServiceStatus,
        Authorized,
        ScopeCount,
        Notes `
        -AutoSize

# ------------------------------------------------------------
# Show DHCP servers only
# ------------------------------------------------------------

Write-Host ""
Write-Host "============================================" -ForegroundColor Yellow
Write-Host "             DHCP SERVERS FOUND" -ForegroundColor Yellow
Write-Host "============================================" -ForegroundColor Yellow
Write-Host ""

$DHCPServers = $Results |
    Where-Object {
        $_.DHCPRole -eq "Installed" -or
        $_.DHCPService -eq "Installed" -or
        $_.Authorized -eq "YES"
    }

if ($DHCPServers) {

    $DHCPServers |
        Format-Table `
            Server,
            DHCPRole,
            DHCPService,
            ServiceStatus,
            Authorized,
            ScopeCount,
            Scopes,
            Notes `
            -Wrap -AutoSize
}
else {

    Write-Host "No DHCP servers found." -ForegroundColor Green
}

# ------------------------------------------------------------
# Show potential problems
# ------------------------------------------------------------

Write-Host ""
Write-Host "============================================" -ForegroundColor Red
Write-Host "             POTENTIAL PROBLEMS" -ForegroundColor Red
Write-Host "============================================" -ForegroundColor Red
Write-Host ""

$Problems = $Results |
    Where-Object {
        $_.Notes -ne ""
    }

if ($Problems) {

    $Problems |
        Format-Table `
            Server,
            Authorized,
            DHCPRole,
            DHCPService,
            ServiceStatus,
            ScopeCount,
            Notes `
            -Wrap -AutoSize
}
else {

    Write-Host "No obvious DHCP configuration problems found." -ForegroundColor Green
}

# ------------------------------------------------------------
# Export results
# ------------------------------------------------------------

$Results |
    Export-Csv `
        -Path $OutputFile `
        -NoTypeInformation `
        -Encoding UTF8

Write-Host ""
Write-Host "============================================" -ForegroundColor Green
Write-Host "Audit complete." -ForegroundColor Green
Write-Host "Results saved to:" -ForegroundColor Green
Write-Host "$((Get-Location).Path)\Domain-DHCP-Audit.csv" -ForegroundColor White
Write-Host "============================================" -ForegroundColor Green
