# Dell iDRAC Security Audit — v1.0 (read-only)

Audits Dell iDRAC9 local Redfish accounts against a caller-supplied allowlist and attempts to read IPMI-over-LAN status. **No changes are made to any iDRAC.**

## Requirements
- Windows PowerShell 5.1 or PowerShell 7.x
- Network access to iDRAC HTTPS (TCP 443)
- iDRAC account with permission to enumerate local accounts
- Valid iDRAC TLS certificate trusted by the computer running the script (certificate checks are **not** bypassed)

## Examples

Audit one iDRAC:

~~~powershell
.\Invoke-iDRACSecurity.ps1 -iDRAC idrac01.example.com -ApprovedUsers "root","ExampleAdmin","SNMPv3User" -ApprovedUserPatterns "OME_*" -Credential (Get-Credential)
~~~

Audit a list of iDRACs:

~~~powershell
.\Invoke-iDRACSecurity.ps1 -ComputerList .\Examples\iDRAC-Servers.txt -ApprovedUsersFile .\Examples\ApprovedUsers.txt -ApprovedUserPatterns "OME_*" -Credential (Get-Credential)
~~~

Audit from CSV (requires an \`iDRAC\` column):

~~~powershell
.\Invoke-iDRACSecurity.ps1 -InputCsv .\Examples\iDRAC-Servers.csv -ApprovedUsers root,ExampleAdmin -ApprovedUserPatterns "OME_*"
~~~

\`-AuditOnly\` is accepted but optional: **all operations are read-only** in this release.

## Reports
Reports are written to \`.\iDRAC-Audit-Reports\` by default:
- \`iDRAC-AccountInventory-*.csv\`
- \`iDRAC-UnauthorizedUsers-*.csv\`
- \`iDRAC-MissingUsers-*.csv\`
- \`iDRAC-IPMISecurity-*.csv\`
- \`iDRAC-AuditErrors-*.csv\`
- \`iDRAC-AuditSummary-*.csv\`

When a report has no records, a matching \`.txt\` file is written instead.

## Interpretation and limitations
- Approved exact usernames are case-sensitive. Approved patterns use PowerShell wildcard matching and are also case-sensitive.
- \`OME_*\` permits any username with that prefix; use only if this matches your approved management-account policy.
- \`IPMIOverLAN = Unknown\` means the relevant Dell OEM attribute was not available or could not be read. **It does not mean disabled.**
- \`ReservedIPMIUser = NotVerified\` means the script has **not** established the status of IPMI slot 1. Redfish account enumeration alone is insufficient.
- The script does **not** determine whether any tool is actively using UDP 623. Confirm traffic and management dependencies separately before future IPMI remediation.
- A successful account audit does not prove that the entire management configuration is compliant.
- This version has not yet been tested against a live iDRAC9. **Test on one iDRAC first** and review reports before using it against hundreds.

## Planned future enhancements
Explicitly authorized account disabling/deletion, backup-account password rotation, reserved IPMI-user checks, and IPMI-over-LAN remediation. None are included in v1.0.

No company-specific credentials or inventory are included in this repository.
