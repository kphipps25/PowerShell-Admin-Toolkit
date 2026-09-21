# PowerShell Admin Toolkit

A collection of PowerShell scripts for Windows Server and infrastructure administration.

## DHCP

### Remove-DHCPServerRole.ps1

Safely removes the DHCP Server role from servers identified in `Domain-DHCP-Audit.csv`.

Key safeguards and behavior:

- Re-checks the current DHCP role, service, and IPv4 scopes before making changes.
- Fails closed if DHCP scopes cannot be queried.
- Blocks removal when active DHCP scopes exist unless the override option is explicitly enabled.
- Requires explicit confirmation before removing DHCP from each server.
- Removes the DHCP role without immediately rebooting the server.
- Removes `C:\Users\Public\Desktop\dhcp.lnk` after successful role removal.
- Collects all servers requiring reboot and offers one `REBOOT-ALL` confirmation at the end.
- Sends reboot requests as a batch.
- Monitors WinRM for rebooted servers.
- Performs post-reboot verification of the DHCP role, DHCPServer service, and desktop shortcut.
- Exports removal, reboot, scope-backup, and post-reboot verification CSV files.

### Important

Review the configuration section of the script before running it in production.

The default active-scope behavior is deliberately conservative:

```powershell
$AllowActiveScopeOverride = $false
```

DHCP authorization cleanup is also disabled by default:

```powershell
$RemoveDHCPAuthorization = $false
```

Run the script from an elevated PowerShell session using an account with the required Active Directory and remote server administrative permissions.
