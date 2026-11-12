#requires -Version 5.1
<#
.SYNOPSIS
  Audit or maintain one SCVMM Windows Server 2025 Hyper-V update baseline.
.DESCRIPTION
  No remediation, patch installation, host maintenance, migration or reboot commands.
  Superseded baseline entries are removed ONLY when a replacement relationship is
  explicitly exposed in the SCVMM update objects and the replacement is in baseline.
  If the installed VMM version does not expose that relationship, removal is skipped.
.EXAMPLE
  .\Update-SCVMMMonthlyBaseline.ps1 -AuditOnly
.EXAMPLE
  .\Update-SCVMMMonthlyBaseline.ps1 -Apply
.EXAMPLE
  .\Update-SCVMMMonthlyBaseline.ps1 -ReportOnly
#>
[CmdletBinding(DefaultParameterSetName='Audit')]
param(
 [Parameter(ParameterSetName='Audit')][switch]$AuditOnly,
 [Parameter(Mandatory,ParameterSetName='Apply')][switch]$Apply,
 [Parameter(Mandatory,ParameterSetName='Report')][switch]$ReportOnly,
 [string]$VMMServerName = 'X05919AT70100V',
 [string]$UpdateServerName = 'X01337AA01000V',
 [string]$BaselineName = 'Windows Server 2025 - Hyper-V Test',
 [string]$OutputDirectory = 'C:\SCVMM-MonthlyBaseline\Reports',
 [switch]$SkipSynchronization,
 [switch]$SkipComplianceScan
)
Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'
$mode = if ($Apply) {'Apply'} elseif ($ReportOnly) {'ReportOnly'} else {'AuditOnly'}
$stamp = Get-Date -Format 'yyyyMMdd-HHmmss'
New-Item -Path $OutputDirectory -ItemType Directory -Force | Out-Null
$prefix = Join-Path $OutputDirectory "SCVMM-$stamp-$mode"
$transcriptStarted = $false
try { Start-Transcript -Path "$prefix.log" -ErrorAction Stop | Out-Null; $transcriptStarted=$true } catch { Write-Warning "Transcript unavailable: $_" }

function PropertyValue($Object, [string]$Name) {
 if ($null -eq $Object) { return $null }
 $p = $Object.PSObject.Properties[$Name]
 if ($null -ne $p) { return $p.Value }
 return $null
}
function UpdateId($Update) {
 $id = PropertyValue $Update 'ID'
 if ($null -eq $id) { throw "Update missing ID: $($Update.Name)" }
 return [string]$id
}
function UpdateTitle($Update) {
 $name = PropertyValue $Update 'Name'
 if (-not $name) { $name = PropertyValue $Update 'Title' }
 return [string]$name
}
function KBText($Update) {
 foreach($prop in @('KBArticle','KBArticleID','KBArticleIds','KBArticleIDs')) {
  $v = PropertyValue $Update $prop
  if ($v) { return (@($v) -join ',') }
 }
 return ''
}
function IsEligible($Update) {
 $name = UpdateTitle $Update
 if ($name -notmatch '(?i)Windows Server 2025|Windows Server,? version 24H2|Windows Server 24H2') { return $false }
 if ($name -match '(?i)preview|insider|dynamic update|setup update|feature update|upgrade|driver|firmware|language pack|arm64|x86') { return $false }
 if ($name -notmatch '(?i)cumulative update') { return $false }
 if ($name -match '(?i)\.NET') { return $true }
 if ($name -match '(?i)Windows Server') { return $true }
 return $false
}
function IsSuperseded($Update) {
 foreach($prop in @('IsSuperseded','Superseded')) {
  $v = PropertyValue $Update $prop
  if ($v -is [bool] -and $v) { return $true }
 }
 return $false
}
function ReplacementIds($Update) {
 # Different VMM versions expose different metadata. Never infer replacement from KB/date.
 $ids = @()
 foreach($prop in @('SupersededBy','SupersededByUpdates','SupersededByUpdateIds')) {
  $v = PropertyValue $Update $prop
  if ($null -eq $v) { continue }
  foreach($item in @($v)) {
   if ($null -eq $item) { continue }
   $id = PropertyValue $item 'ID'
   if ($id) { $ids += [string]$id; continue }
   $g = [guid]::Empty
   if ([guid]::TryParse([string]$item,[ref]$g)) { $ids += [string]$g }
  }
 }
 return @($ids | Select-Object -Unique)
}
function SaveRows([string]$Suffix,$Rows) {
 $path = "$prefix-$Suffix.csv"
 @($Rows) | Export-Csv -Path $path -NoTypeInformation -Encoding UTF8
 Write-Host "Report: $path"
}
function BaselineUpdates($Baseline) {
 $updates = PropertyValue $Baseline 'Updates'
 if ($null -eq $updates) { throw 'Baseline.Updates not exposed. Stopping to avoid unsafe changes.' }
 return @($updates)
}
try {
 Import-Module VirtualMachineManager -ErrorAction Stop
 $vmm = Get-SCVMMServer -ComputerName $VMMServerName -ErrorAction Stop
 $matches = @(Get-SCBaseline -VMMServer $vmm -Name $BaselineName -ErrorAction Stop)
 if ($matches.Count -ne 1) { throw "Expected one baseline named '$BaselineName'; found $($matches.Count)." }
 $baseline = $matches[0]
 $original = @(BaselineUpdates $baseline)
 $originalIds = @{}; foreach($u in $original) { $originalIds[(UpdateId $u)] = $true }
 $original | ForEach-Object {
  [pscustomobject]@{ID=UpdateId $_;Name=UpdateTitle $_;KB=KBText $_}
 } | Export-Csv "$prefix-BaselineBackup.csv" -NoTypeInformation -Encoding UTF8
 Write-Host "Mode: $mode | Baseline: $BaselineName | Existing updates: $($original.Count)"
 Write-Host 'Baseline membership backup saved; assignment scope will not be changed.'

 if ($ReportOnly) {
  $status = @(Get-SCComplianceStatus -VMMServer $vmm -All -ErrorAction Stop)
  $status | Select-Object * | Export-Clixml "$prefix-Compliance.xml"
  Write-Host "Compliance snapshot: $prefix-Compliance.xml"
  return
 }

 if (-not $SkipSynchronization) {
  if ($Apply) {
   $wsus = Get-SCUpdateServer -VMMServer $vmm -ComputerName $UpdateServerName -ErrorAction Stop
   if (-not $wsus) { throw "SCVMM update server not found: $UpdateServerName" }
   Write-Host 'Starting SCVMM catalog synchronization (not a WSUS upstream sync)...'
   Start-SCUpdateServerSynchronization -VMMServer $vmm -UpdateServer $wsus -ErrorAction Stop | Out-Null
   Write-Host 'SCVMM catalog synchronization returned. Check VMM Jobs for completion before trusting catalog freshness.'
  } else {
   Write-Host 'AuditOnly: skipping synchronization (read-only).'
  }
 }
 $catalog = @(Get-SCUpdate -VMMServer $vmm -ErrorAction Stop)
 $eligible = @($catalog | Where-Object { IsEligible $_ })
 $eligibleIds = @{}; foreach($u in $eligible) { $eligibleIds[(UpdateId $u)] = $true }
 $adds = @($eligible | Where-Object { -not $originalIds.ContainsKey((UpdateId $_)) -and -not (IsSuperseded $_) })
 $addIds = @{}; foreach($u in $adds) { $addIds[(UpdateId $u)] = $true }
 $removes = @()
 $retained = @()
 foreach($u in $original) {
  if (-not (IsSuperseded $u)) { continue }
  $replacements = @(ReplacementIds $u)
  $verified = @($replacements | Where-Object { $eligibleIds.ContainsKey($_) -and ($originalIds.ContainsKey($_) -or $addIds.ContainsKey($_)) })
  if ($verified.Count -gt 0) { $removes += $u }
  else { $retained += $u }
 }
 $plan = @()
 foreach($u in $adds) { $plan += [pscustomobject]@{Action='Add';ID=UpdateId $u;KB=KBText $u;Name=UpdateTitle $u;Reason='Eligible, not superseded'} }
 foreach($u in $removes) { $plan += [pscustomobject]@{Action='Remove';ID=UpdateId $u;KB=KBText $u;Name=UpdateTitle $u;Reason='Explicit replacement relationship found'} }
 foreach($u in $retained) { $plan += [pscustomobject]@{Action='Retain';ID=UpdateId $u;KB=KBText $u;Name=UpdateTitle $u;Reason='Replacement not verifiable; do not remove'} }
 SaveRows 'Plan' $plan
 Write-Host "Candidates: add=$($adds.Count), remove=$($removes.Count), retained-superseded=$($retained.Count)"
 if (-not $Apply) { Write-Host 'AUDIT ONLY: No changes made.'; return }

 # Re-read baseline to avoid overwriting changes made while catalog was being examined.
 $current = Get-SCBaseline -VMMServer $vmm -Name $BaselineName -ErrorAction Stop
 $currentIds = @((BaselineUpdates $current) | ForEach-Object { UpdateId $_ } | Sort-Object)
 $expectedIds = @($originalIds.Keys | Sort-Object)
 if ((Compare-Object $currentIds $expectedIds).Count -gt 0) { throw 'Baseline changed during planning. No changes applied.' }
 foreach($u in $adds) {
  Set-SCBaseline -VMMServer $vmm -Baseline $current -AddUpdates $u -ErrorAction Stop | Out-Null
  $current = Get-SCBaseline -VMMServer $vmm -Name $BaselineName -ErrorAction Stop
  if ((UpdateId $u) -notin @((BaselineUpdates $current) | ForEach-Object { UpdateId $_ })) { throw "Failed to verify addition: $(UpdateTitle $u)" }
  Write-Host "ADDED: $(UpdateTitle $u)"
 }
 foreach($u in $removes) {
  $current = Get-SCBaseline -VMMServer $vmm -Name $BaselineName -ErrorAction Stop
  $idsNow = @((BaselineUpdates $current) | ForEach-Object { UpdateId $_ })
  $replacement = @(ReplacementIds $u | Where-Object { $_ -in $idsNow -and $eligibleIds.ContainsKey($_) })
  if ($replacement.Count -eq 0) { Write-Warning "Retaining $(UpdateTitle $u): replacement not present"; continue }
  Set-SCBaseline -VMMServer $vmm -Baseline $current -RemoveUpdates $u -ErrorAction Stop | Out-Null
  Write-Host "REMOVED: $(UpdateTitle $u)"
 }
 Write-Host 'Baseline changes completed. No update remediation was requested.'
 if (-not $SkipComplianceScan) {
  # Do not guess host-group inheritance; scan the baseline's explicitly assigned clusters.
  $current = Get-SCBaseline -VMMServer $vmm -Name $BaselineName -ErrorAction Stop
  $scopes = PropertyValue $current 'AssignmentScope'
  if ($null -eq $scopes) { $scopes = PropertyValue $current 'AssignmentScopes' }
  if ($null -eq $scopes) {
   Write-Warning 'Assignment scope property unavailable. Skipping scans; use VMM console to scan assigned hosts.'
  } else {
   foreach($scope in @($scopes)) {
    if ($scope.GetType().Name -match 'HostCluster') {
     try { Start-SCComplianceScan -VMMServer $vmm -VMHostCluster $scope -Baseline $current -ErrorAction Stop | Out-Null; Write-Host "SCANNED cluster: $($scope.Name)" }
     catch { Write-Warning "Scan failed for $($scope.Name): $_" }
    } else { Write-Warning "Scope '$($scope.Name)' is not a cluster object; scan manually or extend discovery after validating host-group inheritance." }
   }
  }
 }
} catch {
 Write-Error "Stopped: $($_.Exception.Message)"
 exit 1
} finally {
 if ($transcriptStarted) { Stop-Transcript | Out-Null }
}
